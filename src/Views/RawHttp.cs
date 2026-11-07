using System.Diagnostics;
using System.IO.Compression;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;

namespace TryZ.Views;

/// <summary>One HTTP exchange performed by <see cref="RawHttp"/>.</summary>
internal sealed class RawHttpResponse
{
    public int Status { get; init; }
    public string Head { get; init; } = string.Empty;
    public byte[] Body { get; init; } = Array.Empty<byte>();
    public long WireBytes { get; init; }
    public double ElapsedMs { get; init; }
    public bool Truncated { get; init; }
    public bool BodyDecoded { get; init; }
    public List<KeyValuePair<string, string>> Headers { get; init; } = new();

    public string? Header(string name) =>
        Headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;
}

/// <summary>
/// Sends a request exactly as written over a plain TCP socket (optionally wrapped in TLS) and reads the raw response.
/// Used by the HTTP Workbench, where the user controls every byte of the request.
/// </summary>
internal static class RawHttp
{
    public const int MaxResponseBytes = 2 * 1024 * 1024;
    private const int MaxHeadBytes = 256 * 1024;

    public static async Task<RawHttpResponse> SendAsync(string host, int port, bool tls, byte[] request, bool isHead, CancellationToken token)
    {
        var clock = Stopwatch.StartNew();
        using var tcp = new TcpClient { NoDelay = true };
        await tcp.ConnectAsync(host, port, token).ConfigureAwait(false);
        Stream stream = tcp.GetStream();
        SslStream? ssl = null;
        try
        {
            if (tls)
            {
                ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = host,
                    // The workbench must reach hosts with self-signed or expired certificates; TLS problems are reported by the scan.
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true,
                }, token).ConfigureAwait(false);
                stream = ssl;
            }
            await stream.WriteAsync(request, token).ConfigureAwait(false);
            await stream.FlushAsync(token).ConfigureAwait(false);

            var reader = new WireReader(stream, token);
            while (true)
            {
                var (status, head, headers) = await ReadHeadAsync(reader).ConfigureAwait(false);
                // Interim responses (100 Continue, 103 Early Hints) are followed by the real one.
                if (status is >= 100 and < 200 and not 101) continue;

                var body = new MemoryStream();
                bool truncated = await ReadBodyAsync(reader, status, headers, isHead, body).ConfigureAwait(false);
                byte[] bytes = body.ToArray();
                bool decoded = false;
                string? encoding = headers.FirstOrDefault(h => h.Key.Equals("Content-Encoding", StringComparison.OrdinalIgnoreCase)).Value;
                if (!truncated && bytes.Length > 0 && encoding != null && TryDecompress(bytes, encoding.Trim(), out var plain))
                {
                    bytes = plain;
                    decoded = true;
                }
                return new RawHttpResponse
                {
                    Status = status,
                    Head = head,
                    Body = bytes,
                    WireBytes = reader.Total,
                    ElapsedMs = clock.Elapsed.TotalMilliseconds,
                    Truncated = truncated,
                    BodyDecoded = decoded,
                    Headers = headers,
                };
            }
        }
        finally
        {
            ssl?.Dispose();
        }
    }

    private static async Task<(int Status, string Head, List<KeyValuePair<string, string>> Headers)> ReadHeadAsync(WireReader reader)
    {
        var head = new StringBuilder();
        string? statusLine = await reader.ReadLineAsync(MaxHeadBytes).ConfigureAwait(false);
        while (statusLine != null && statusLine.Length == 0)
            statusLine = await reader.ReadLineAsync(MaxHeadBytes).ConfigureAwait(false);
        if (statusLine == null) throw new InvalidDataException("The server closed the connection without sending a response.");
        if (!statusLine.StartsWith("HTTP/", StringComparison.Ordinal))
            throw new InvalidDataException($"The server did not answer with HTTP. First line: {Printable(statusLine, 200)}");
        head.Append(statusLine);
        var parts = statusLine.Split(' ', 3);
        int status = parts.Length > 1 && int.TryParse(parts[1], out int code) ? code : 0;

        var headers = new List<KeyValuePair<string, string>>();
        while (true)
        {
            string? line = await reader.ReadLineAsync(MaxHeadBytes).ConfigureAwait(false);
            if (line == null || line.Length == 0) break;
            if (head.Length > MaxHeadBytes) throw new InvalidDataException("Response headers exceed 256 KB.");
            head.Append("\r\n").Append(line);
            int colon = line.IndexOf(':');
            if (colon > 0) headers.Add(new(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        return (status, head.ToString(), headers);
    }

    private static async Task<bool> ReadBodyAsync(WireReader reader, int status, List<KeyValuePair<string, string>> headers, bool isHead, MemoryStream body)
    {
        if (isHead || status is 204 or 304 || status < 200) return false;
        string? te = headers.FirstOrDefault(h => h.Key.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).Value;
        string? cl = headers.FirstOrDefault(h => h.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)).Value;
        var buffer = new byte[16384];

        if (te != null && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            while (true)
            {
                string? sizeLine = await reader.ReadLineAsync(4096).ConfigureAwait(false);
                if (sizeLine == null) return false;
                int semi = sizeLine.IndexOf(';');
                string hex = (semi >= 0 ? sizeLine[..semi] : sizeLine).Trim();
                if (hex.Length == 0) continue;
                if (!long.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out long size) || size < 0)
                    throw new InvalidDataException($"Invalid chunk size \"{Printable(hex, 40)}\".");
                if (size == 0)
                {
                    // Trailer section ends with an empty line.
                    while (true)
                    {
                        string? trailer = await reader.ReadLineAsync(4096).ConfigureAwait(false);
                        if (trailer == null || trailer.Length == 0) break;
                    }
                    return false;
                }
                if (body.Length + size > MaxResponseBytes)
                {
                    await CopyAsync(reader, body, MaxResponseBytes - body.Length, buffer).ConfigureAwait(false);
                    return true;
                }
                if (await CopyAsync(reader, body, size, buffer).ConfigureAwait(false) < size) return false;
                await reader.ReadLineAsync(16).ConfigureAwait(false);
            }
        }

        if (cl != null && long.TryParse(cl, out long length) && length >= 0)
        {
            long want = Math.Min(length, MaxResponseBytes);
            await CopyAsync(reader, body, want, buffer).ConfigureAwait(false);
            return length > MaxResponseBytes;
        }

        // No framing: the body runs until the server closes the connection.
        long got = await CopyAsync(reader, body, MaxResponseBytes, buffer).ConfigureAwait(false);
        if (got < MaxResponseBytes) return false;
        return await reader.ReadAsync(buffer, 0, 1).ConfigureAwait(false) > 0;
    }

    private static async Task<long> CopyAsync(WireReader reader, MemoryStream target, long count, byte[] buffer)
    {
        long done = 0;
        while (done < count)
        {
            int n = await reader.ReadAsync(buffer, 0, (int)Math.Min(buffer.Length, count - done)).ConfigureAwait(false);
            if (n == 0) break;
            target.Write(buffer, 0, n);
            done += n;
        }
        return done;
    }

    private static bool TryDecompress(byte[] data, string encoding, out byte[] result)
    {
        result = data;
        try
        {
            using var input = new MemoryStream(data);
            using Stream? decoder = encoding.ToLowerInvariant() switch
            {
                "gzip" or "x-gzip" => new GZipStream(input, CompressionMode.Decompress),
                "deflate" => new ZLibStream(input, CompressionMode.Decompress),
                "br" => new BrotliStream(input, CompressionMode.Decompress),
                _ => null,
            };
            if (decoder == null) return false;
            using var output = new MemoryStream();
            var buffer = new byte[16384];
            int n;
            while ((n = decoder.Read(buffer, 0, buffer.Length)) > 0)
            {
                output.Write(buffer, 0, n);
                if (output.Length > MaxResponseBytes * 4L) return false;
            }
            result = output.ToArray();
            return true;
        }
        catch (InvalidDataException)
        {
            return false;
        }
        catch (IOException)
        {
            return false;
        }
    }

    public static string Printable(string text, int max)
    {
        var sb = new StringBuilder(Math.Min(text.Length, max));
        foreach (char c in text)
        {
            if (sb.Length >= max) { sb.Append("..."); break; }
            sb.Append(c is >= ' ' and < (char)127 ? c : '.');
        }
        return sb.ToString();
    }

    /// <summary>Buffered reader over the response stream that counts every byte received.</summary>
    private sealed class WireReader(Stream stream, CancellationToken token)
    {
        private byte[] _buf = new byte[16384];
        private int _pos, _len;

        public long Total { get; private set; }

        private async Task<bool> FillAsync()
        {
            if (_pos == _len) _pos = _len = 0;
            if (_len == _buf.Length)
            {
                if (_pos > 0)
                {
                    Buffer.BlockCopy(_buf, _pos, _buf, 0, _len - _pos);
                    _len -= _pos;
                    _pos = 0;
                }
                else
                {
                    Array.Resize(ref _buf, _buf.Length * 2);
                }
            }
            int n = await stream.ReadAsync(_buf.AsMemory(_len), token).ConfigureAwait(false);
            if (n == 0) return false;
            _len += n;
            Total += n;
            return true;
        }

        public async Task<string?> ReadLineAsync(int max)
        {
            while (true)
            {
                int idx = Array.IndexOf(_buf, (byte)'\n', _pos, _len - _pos);
                if (idx >= 0)
                {
                    string line = Encoding.Latin1.GetString(_buf, _pos, idx - _pos).TrimEnd('\r');
                    _pos = idx + 1;
                    return line;
                }
                if (_len - _pos > max) throw new InvalidDataException("Response line too long.");
                if (!await FillAsync().ConfigureAwait(false))
                {
                    if (_len == _pos) return null;
                    string rest = Encoding.Latin1.GetString(_buf, _pos, _len - _pos);
                    _pos = _len;
                    return rest;
                }
            }
        }

        public async Task<int> ReadAsync(byte[] dest, int offset, int count)
        {
            if (_pos == _len && !await FillAsync().ConfigureAwait(false)) return 0;
            int n = Math.Min(count, _len - _pos);
            Buffer.BlockCopy(_buf, _pos, dest, offset, n);
            _pos += n;
            return n;
        }
    }
}
