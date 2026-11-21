using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using TryZ.Data;

namespace TryZ.Views;

/// <summary>Manual HTTP request editor: the request text is sent as written and the raw response is shown.</summary>
internal sealed class WorkbenchView : ModuleView
{
    private const int TimeoutSeconds = 15;
    private const int MaxRedirects = 5;

    private readonly SkinCombo _method = new();
    private readonly TextField _url = new(IconId.Globe) { Mono = true };
    private readonly SkinButton _send = new("Send", IconId.Send, ButtonLook.Oxblood);
    private readonly SkinCheck _follow = new("Follow redirects");
    private readonly CodeView _request = new() { Syntax = new HttpSyntax() };
    private readonly CodeView _response = new() { ReadOnly = true, Syntax = new HttpSyntax() };
    private readonly SkinPanel _reqPanel = new();
    private readonly SkinPanel _resPanel = new();
    private readonly SkinLabel _reqCaption = new("Request", true) { TextColor = Theme.Brass };
    private readonly SkinLabel _resCaption = new("Response", true) { TextColor = Theme.Brass };
    private readonly SkinLabel _resStats = new() { TextColor = Theme.TextDim, Alignment = TextFormatFlags.Right };
    private readonly SkinLabel _reqStats = new() { TextColor = Theme.TextDim, Alignment = TextFormatFlags.Right };
    private readonly SplitBox _split;
    private CancellationTokenSource? _inFlight;
    private bool _rewriting;

    public WorkbenchView(IShell shell) : base(shell)
    {
        _method.AddRange("GET", "HEAD", "OPTIONS", "POST", "PUT", "TRACE");
        _method.SelectedIndex = 0;
        _method.SelectionChanged += (_, _) => RewriteRequestLine();
        _url.Value = InitialUrl(shell.Settings.LastTarget);
        _url.Edit.TextChanged += (_, _) => RewriteRequestLine();
        _url.Edit.KeyDown += (_, e) =>
        {
            if (e.KeyCode != Keys.Return) return;
            StartSend();
            e.SuppressKeyPress = true;
        };
        _send.Click += (_, _) => StartSend();
        _request.Value = BuildDefaultRequest();
        _request.TextEdited += (_, _) => UpdateStats();
        _response.Value = "(No response yet. Edit the request and press Send. The request is sent exactly as written to the host in the URL field.)";

        _reqPanel.Controls.AddRange(new Control[] { _reqCaption, _reqStats, _request });
        _resPanel.Controls.AddRange(new Control[] { _resCaption, _resStats, _response });
        _reqPanel.Layout += (_, _) => LayoutPane(_reqPanel, _reqCaption, _reqStats, _request);
        _resPanel.Layout += (_, _) => LayoutPane(_resPanel, _resCaption, _resStats, _response);
        _split = new SplitBox(true, _reqPanel, _resPanel, 390) { MinFirst = 200, MinSecond = 200 };
        Controls.AddRange(new Control[] { _method, _url, _send, _follow, _split });
        UpdateStats();
    }

    public override string Title => "HTTP Workbench";
    public override IconId IconKind => IconId.Workbench;
    public override string Subtitle => $"Raw HTTP/1.1 over TCP or TLS  |  {TimeoutSeconds} s timeout, {RawHttp.MaxResponseBytes / (1024 * 1024)} MB response cap";

    /// <summary>Loads a URL with a fresh request for it (used by the crawler, discovery and session views).</summary>
    public void Load(string method, string url)
    {
        _rewriting = true;
        try
        {
            int idx = _method.Items.IndexOf(method);
            _method.SelectedIndex = idx >= 0 ? idx : 0;
            _url.Value = url;
        }
        finally
        {
            _rewriting = false;
        }
        _request.Value = BuildDefaultRequest();
        UpdateStats();
    }

    private static string InitialUrl(string lastTarget)
    {
        string t = (lastTarget ?? string.Empty).Trim();
        if (Uri.TryCreate(t, UriKind.Absolute, out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps)) return u.ToString();
        if (t.Length > 0 && t.IndexOfAny(new[] { '/', ',', ' ', '-', '*' }) < 0 && Uri.CheckHostName(t) != UriHostNameType.Unknown)
            return Uri.CheckHostName(t) == UriHostNameType.IPv6 ? $"http://[{t}]/" : $"http://{t}/";
        return "http://127.0.0.1/";
    }

    private bool TryGetTarget(out Uri uri)
    {
        string text = _url.Value.Trim();
        if (!text.Contains("://", StringComparison.Ordinal)) text = "http://" + text;
        if (Uri.TryCreate(text, UriKind.Absolute, out var parsed) && (parsed.Scheme == Uri.UriSchemeHttp || parsed.Scheme == Uri.UriSchemeHttps) && parsed.Host.Length > 0)
        {
            uri = parsed;
            return true;
        }
        uri = null!;
        return false;
    }

    private static string HostHeader(Uri uri) => uri.IsDefaultPort ? uri.Authority : $"{uri.Host}:{uri.Port}";

    private string BuildDefaultRequest()
    {
        string method = _method.Value.Length > 0 ? _method.Value : "GET";
        if (!TryGetTarget(out var uri)) return $"{method} / HTTP/1.1\r\nHost: \r\nConnection: close\r\n\r\n";
        string ua = string.IsNullOrWhiteSpace(Shell.Settings.UserAgent) ? "TryZ-Workbench/1.0" : Shell.Settings.UserAgent;
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(uri.PathAndQuery).Append(" HTTP/1.1\r\n");
        sb.Append("Host: ").Append(HostHeader(uri)).Append("\r\n");
        sb.Append("User-Agent: ").Append(ua).Append("\r\n");
        sb.Append("Accept: */*\r\n");
        sb.Append("Accept-Encoding: gzip, deflate, br\r\n");
        sb.Append("Connection: close\r\n");
        if (method is "POST" or "PUT") sb.Append("Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n");
        sb.Append("\r\n");
        return sb.ToString();
    }

    private void LayoutPane(Control panel, Control caption, Control stats, Control code)
    {
        int w = panel.Width;
        int capW = Px(70);
        caption.SetBounds(0, 0, capW, Px(18));
        stats.SetBounds(capW, 0, Math.Max(0, w - capW), Px(18));
        code.SetBounds(0, Px(19), w, Math.Max(0, panel.Height - Px(19)));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        int h = Px(22);
        int methodW = Px(76), sendW = Px(82), followW = Px(112);
        _method.SetBounds(b.X, b.Y, methodW, h);
        _follow.SetBounds(b.Right - followW, b.Y + Px(3), followW, Px(17));
        _send.SetBounds(b.Right - followW - sendW - Px(5), b.Y, sendW, h);
        int urlX = b.X + methodW + Px(4);
        _url.SetBounds(urlX, b.Y, _send.Left - urlX - Px(4), h);
        _split.SetBounds(b.X, b.Y + h + Px(6), b.Width, Math.Max(0, b.Height - h - Px(6)));
    }

    /// <summary>Keeps the request line and Host header in step with the method box and URL field.</summary>
    private void RewriteRequestLine()
    {
        if (_rewriting || !TryGetTarget(out var uri)) return;
        var lines = _request.Lines.ToList();
        if (lines.Count == 0) lines.Add(string.Empty);
        string version = "HTTP/1.1";
        var first = lines[0].Split(' ');
        if (first.Length >= 3 && first[^1].StartsWith("HTTP/", StringComparison.Ordinal)) version = first[^1];
        lines[0] = $"{_method.Value} {uri.PathAndQuery} {version}";
        bool hostSet = false;
        for (int i = 1; i < lines.Count && lines[i].Length > 0; i++)
        {
            if (lines[i].StartsWith("Host:", StringComparison.OrdinalIgnoreCase))
            {
                lines[i] = "Host: " + HostHeader(uri);
                hostSet = true;
                break;
            }
        }
        if (!hostSet) lines.Insert(1, "Host: " + HostHeader(uri));
        _request.Value = string.Join("\r\n", lines);
        UpdateStats();
    }

    private void UpdateStats() =>
        _reqStats.Caption = $"{_request.Lines.Count} lines, {Encoding.UTF8.GetByteCount(_request.Value)} bytes";

    private void StartSend()
    {
        if (_inFlight != null) return;
        _ = SendAsync();
    }

    private sealed record ParsedRequest(string Method, byte[] Bytes, string FirstLine);

    /// <summary>Turns the editor text into wire bytes: CRLF line endings, Host and Content-Length fixed up, body as UTF-8.</summary>
    private static ParsedRequest? ParseRequest(IReadOnlyList<string> lines, Uri target, out string error)
    {
        error = string.Empty;
        int start = 0;
        while (start < lines.Count && lines[start].Trim().Length == 0) start++;
        if (start >= lines.Count)
        {
            error = "The request is empty.";
            return null;
        }
        var requestLine = lines[start].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (requestLine.Length < 2)
        {
            error = "The first line must be \"METHOD /path HTTP/1.1\".";
            return null;
        }
        string method = requestLine[0].ToUpperInvariant();
        string path = requestLine[1];
        string version = requestLine.Length >= 3 ? requestLine[2] : "HTTP/1.1";

        var headers = new List<string>();
        int i = start + 1;
        for (; i < lines.Count; i++)
        {
            if (lines[i].Length == 0) { i++; break; }
            if (lines[i].IndexOf(':') <= 0)
            {
                error = $"Header line {i + 1} has no colon: {RawHttp.Printable(lines[i], 60)}";
                return null;
            }
            headers.Add(lines[i]);
        }
        string body = i < lines.Count ? string.Join("\r\n", lines.Skip(i)) : string.Empty;
        byte[] bodyBytes = Encoding.UTF8.GetBytes(body);

        bool Has(string name) => headers.Any(h => h.StartsWith(name + ":", StringComparison.OrdinalIgnoreCase));
        if (!Has("Host")) headers.Insert(0, "Host: " + HostHeader(target));
        if (!Has("Transfer-Encoding"))
        {
            headers.RemoveAll(h => h.StartsWith("Content-Length:", StringComparison.OrdinalIgnoreCase));
            if (bodyBytes.Length > 0 || method is "POST" or "PUT" or "PATCH") headers.Add($"Content-Length: {bodyBytes.Length}");
        }
        if (!Has("Connection")) headers.Add("Connection: close");

        string firstLine = $"{method} {path} {version}";
        var head = new StringBuilder();
        head.Append(firstLine).Append("\r\n");
        foreach (var h in headers) head.Append(h).Append("\r\n");
        head.Append("\r\n");
        byte[] headBytes = Encoding.Latin1.GetBytes(head.ToString());
        var all = new byte[headBytes.Length + bodyBytes.Length];
        Buffer.BlockCopy(headBytes, 0, all, 0, headBytes.Length);
        Buffer.BlockCopy(bodyBytes, 0, all, headBytes.Length, bodyBytes.Length);
        return new ParsedRequest(method, all, firstLine);
    }

    private async Task SendAsync()
    {
        if (!TryGetTarget(out var target))
        {
            Shell.Notify("Workbench", "Enter an http:// or https:// URL in the address field.", IconId.Warning);
            return;
        }
        var parsed = ParseRequest(_request.Lines, target, out string error);
        if (parsed == null)
        {
            Shell.Notify("Workbench", error, IconId.Warning);
            return;
        }

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(TimeoutSeconds));
        _inFlight = cts;
        _send.Enabled = false;
        _send.Caption = "Wait";
        _resStats.Caption = $"Connecting to {target.Authority}...";
        var output = new StringBuilder();
        string summary;
        try
        {
            var current = target;
            var request = parsed;
            RawHttpResponse? response = null;
            long totalBytes = 0;
            double totalMs = 0;
            for (int hop = 0; ; hop++)
            {
                bool tls = current.Scheme == Uri.UriSchemeHttps;
                var req = request;
                var hostName = current.DnsSafeHost;
                int port = current.Port;
                response = await Task.Run(() => RawHttp.SendAsync(hostName, port, tls, req.Bytes, req.Method == "HEAD", cts.Token), cts.Token);
                totalBytes += response.WireBytes;
                totalMs += response.ElapsedMs;
                AppendResponse(output, response);
                Shell.LogUser("workbench", $"{req.FirstLine.Split(' ')[0]} {current} -> {response.Status} ({response.WireBytes:N0} bytes, {response.ElapsedMs:0} ms)");

                string? location = response.Header("Location");
                if (!_follow.Checked || response.Status is not (301 or 302 or 303 or 307 or 308) || location == null || hop >= MaxRedirects) break;
                if (!Uri.TryCreate(current, location, out var next) || (next.Scheme != Uri.UriSchemeHttp && next.Scheme != Uri.UriSchemeHttps)) break;
                bool keepMethod = response.Status is 307 or 308 && req.Method != "POST";
                string method = keepMethod ? req.Method : (req.Method == "HEAD" ? "HEAD" : "GET");
                string ua = string.IsNullOrWhiteSpace(Shell.Settings.UserAgent) ? "TryZ-Workbench/1.0" : Shell.Settings.UserAgent;
                string text = $"{method} {next.PathAndQuery} HTTP/1.1\r\nHost: {HostHeader(next)}\r\nUser-Agent: {ua}\r\nAccept: */*\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: close\r\n\r\n";
                request = new ParsedRequest(method, Encoding.Latin1.GetBytes(text), text[..text.IndexOf('\r')]);
                output.Append("\r\n\r\n--- redirect ").Append(hop + 1).Append(": ").Append(next).Append(" ---\r\n\r\n");
                current = next;
            }
            summary = $"{response!.Status}, {totalBytes:N0} bytes, {totalMs:0} ms{(response.Truncated ? ", truncated at 2 MB" : string.Empty)}";
        }
        catch (OperationCanceledException)
        {
            output.Append($"(No complete response within {TimeoutSeconds} s.)");
            summary = "Timed out";
        }
        catch (SocketException ex)
        {
            output.Append($"(Connection to {target.Authority} failed: {ex.SocketErrorCode}, {ex.Message})");
            summary = "Connection failed";
        }
        catch (AuthenticationException ex)
        {
            output.Append($"(TLS handshake with {target.Authority} failed: {ex.Message})");
            summary = "TLS failed";
        }
        catch (IOException ex)
        {
            output.Append($"(Connection error: {ex.Message})");
            summary = "Connection error";
        }
        catch (InvalidDataException ex)
        {
            output.Append($"(Invalid response: {ex.Message})");
            summary = "Invalid response";
        }
        finally
        {
            _inFlight = null;
            _send.Enabled = true;
            _send.Caption = "Send";
        }
        _response.Value = output.ToString();
        _resStats.Caption = summary;
    }

    private static void AppendResponse(StringBuilder output, RawHttpResponse r)
    {
        output.Append(r.Head).Append("\r\n\r\n");
        if (r.Body.Length == 0) return;
        string? type = r.Header("Content-Type");
        if (!IsText(type, r.Body))
        {
            output.Append($"(binary body, {r.Body.Length:N0} bytes{(type != null ? ", " + type : string.Empty)})\r\n");
            int n = Math.Min(r.Body.Length, 512);
            for (int i = 0; i < n; i += 16)
            {
                output.Append(i.ToString("x4")).Append("  ");
                for (int j = i; j < i + 16 && j < n; j++) output.Append(r.Body[j].ToString("x2")).Append(' ');
                output.Append("\r\n");
            }
            return;
        }
        if (r.BodyDecoded) output.Append("(body decoded from ").Append(r.Header("Content-Encoding")).Append(")\r\n");
        output.Append(DecodeText(r.Body, type));
        if (r.Truncated) output.Append("\r\n\r\n(response truncated at 2 MB)");
    }

    private static bool IsText(string? type, byte[] body)
    {
        if (type != null)
        {
            string t = type.ToLowerInvariant();
            if (t.StartsWith("text/", StringComparison.Ordinal) || t.Contains("json") || t.Contains("xml") || t.Contains("javascript")
                || t.Contains("x-www-form-urlencoded") || t.Contains("html"))
                return true;
            if (t.StartsWith("image/", StringComparison.Ordinal) || t.StartsWith("audio/", StringComparison.Ordinal) || t.StartsWith("video/", StringComparison.Ordinal)
                || t.Contains("octet-stream") || t.Contains("zip") || t.Contains("pdf") || t.Contains("font"))
                return false;
        }
        int sample = Math.Min(body.Length, 1024), control = 0;
        for (int i = 0; i < sample; i++)
            if (body[i] < 9 || (body[i] > 13 && body[i] < 32)) control++;
        return control * 20 < Math.Max(1, sample);
    }

    private static string DecodeText(byte[] body, string? type)
    {
        Encoding encoding = Encoding.UTF8;
        if (type != null)
        {
            int at = type.IndexOf("charset=", StringComparison.OrdinalIgnoreCase);
            if (at >= 0)
            {
                string name = type[(at + 8)..].Split(';')[0].Trim().Trim('"', '\'');
                try
                {
                    encoding = Encoding.GetEncoding(name);
                }
                catch (ArgumentException)
                {
                    encoding = Encoding.UTF8;
                }
            }
        }
        return encoding.GetString(body);
    }

    public override void SyncData() { }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _inFlight?.Cancel();
        base.Dispose(disposing);
    }
}
