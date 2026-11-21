using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Passively identifies possible dangling provider aliases without claiming or probing resources.</summary>
internal static class TakeoverCheck
{
    private const string Source = "takeover";
    private static readonly (string Suffix, string Provider)[] Providers =
    [
        ("azurewebsites.net", "Azure App Service"), ("cloudapp.azure.com", "Azure Cloud Services"),
        ("github.io", "GitHub Pages"), ("herokudns.com", "Heroku"), ("herokuapp.com", "Heroku"),
        ("cloudfront.net", "CloudFront"), ("pages.dev", "Cloudflare Pages"),
        ("netlify.app", "Netlify"), ("netlify.com", "Netlify"), ("s3.amazonaws.com", "Amazon S3"),
    ];

    public static async Task RunAsync(ScanContext ctx, int taskId)
    {
        var names = ctx.ObservedHostnames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).Take(1000).ToArray();
        var resolvers = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .SelectMany(n => n.GetIPProperties().DnsAddresses)
            .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Where(a => !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any))
            .Distinct().Take(4).ToArray();
        if (resolvers.Length == 0)
        {
            ctx.Log(LogLevel.Warn, Source, "No system DNS resolver is available; dangling alias check skipped");
            return;
        }
        ctx.Log(LogLevel.Info, Source, $"Checking {names.Length} observed name(s) for dangling provider aliases (DNS only)");
        int done = 0, candidateCount = 0;
        await Parallel.ForEachAsync(names, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(ctx.Options.Threads, 8), CancellationToken = ctx.Token }, async (name, _) =>
        {
            try
            {
                if (!TryBuildQuery(name, out var query, out ushort id)) return;
                foreach (var resolver in resolvers)
                {
                    await ctx.GateAsync().ConfigureAwait(false);
                    await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
                    byte[]? response = null;
                    try
                    {
                        using var work = ctx.BeginWork();
                        using var udp = new UdpClient(resolver.AddressFamily);
                        udp.Connect(new IPEndPoint(resolver, 53));
                        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
                        timeout.CancelAfter(Math.Clamp(ctx.Options.ReadTimeoutMs, 500, 5000));
                        await udp.SendAsync(query, timeout.Token).ConfigureAwait(false);
                        response = (await udp.ReceiveAsync(timeout.Token).ConfigureAwait(false)).Buffer;
                    }
                    catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested) { }
                    catch (SocketException) { }
                    finally { ctx.Concurrency.Release(); }
                    if (response == null) continue;
                    // Only NXDOMAIN plus a connected CNAME chain is useful; other valid replies must not trigger a finding.
                    if (TryReadDangling(response, id, name, out var chain, out var provider))
                    {
                        Interlocked.Increment(ref candidateCount);
                        ctx.AddFinding(Severity.Low, $"Potential dangling DNS alias ({name})", name, 0, 350,
                            $"The DNS response contains an alias chain to {provider} ending in NXDOMAIN. This may be a dangling third-party resource, but DNS alone does not establish that it can be claimed or exploited.",
                            $"Resolver: {resolver}\nDNS result: NXDOMAIN\nCNAME chain: {string.Join(" -> ", chain)}",
                            "Verify the DNS record and provider resource ownership manually. Remove stale aliases or restore and secure the intended resource; do not claim resources without authorization.",
                            new FindingDetails { RuleId = "potential-dangling-dns-alias", Proto = "dns", Confidence = Confidence.Tentative });
                    }
                    break;
                }
            }
            finally
            {
                int completed = Interlocked.Increment(ref done);
                ctx.UpdateTask(taskId, TaskState.Running, names.Length == 0 ? 100 : 100 * completed / names.Length);
            }
        }).ConfigureAwait(false);
        ctx.Log(LogLevel.Info, Source, $"DNS alias check finished: {candidateCount} potential issue(s); manual verification required");
    }

    internal static bool TryBuildQuery(string name, out byte[] query, out ushort id)
    {
        query = Array.Empty<byte>(); id = 0;
        try
        {
            string ascii = new IdnMapping().GetAscii(name.TrimEnd('.')).ToLowerInvariant();
            string[] labels = ascii.Split('.');
            if (ascii.Length > 253 || labels.Any(l => l.Length is 0 or > 63 || l.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-')))) return false;
            var data = new List<byte>(ascii.Length + 18);
            id = (ushort)RandomNumberGenerator.GetInt32(65536);
            data.Add((byte)(id >> 8)); data.Add((byte)id);
            data.AddRange([1, 0, 0, 1, 0, 0, 0, 0, 0, 0]); // recursion desired, one question
            foreach (string label in labels) { data.Add((byte)label.Length); data.AddRange(Encoding.ASCII.GetBytes(label)); }
            data.AddRange([0, 0, 1, 0, 1]); // A IN: NXDOMAIN means the name itself does not exist
            query = data.ToArray(); return true;
        }
        catch (ArgumentException) { return false; }
    }

    internal static bool TryReadDangling(byte[] data, ushort id, string name, out List<string> chain, out string provider)
    {
        chain = new List<string>(); provider = string.Empty;
        if (data.Length < 12 || Read16(data, 0) != id) return false;
        int flags = Read16(data, 2);
        if ((flags & 0x8000) == 0 || (flags & 0x7800) != 0 || (flags & 0x0200) != 0 || (flags & 15) != 3 || Read16(data, 4) != 1) return false;
        int answerCount = Read16(data, 6), pos = 12;
        if (answerCount > 256 || !TryName(data, ref pos, out var question) || pos + 4 > data.Length) return false;
        string normalized;
        try { normalized = new IdnMapping().GetAscii(name.TrimEnd('.')); }
        catch (ArgumentException) { return false; }
        if (!question.Equals(normalized, StringComparison.OrdinalIgnoreCase) || Read16(data, pos) != 1 || Read16(data, pos + 2) != 1) return false;
        pos += 4;
        var aliases = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < answerCount; i++)
        {
            if (!TryName(data, ref pos, out var owner) || pos + 10 > data.Length) return false;
            int type = Read16(data, pos), dnsClass = Read16(data, pos + 2), length = Read16(data, pos + 8);
            pos += 10;
            if (pos + length > data.Length) return false;
            if (type == 5 && dnsClass == 1)
            {
                int end = pos + length, at = pos;
                if (!TryName(data, ref at, out var target) || at != end || aliases.ContainsKey(owner)) return false;
                aliases.Add(owner, target);
            }
            pos += length;
        }
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        string current = normalized;
        chain.Add(current);
        while (aliases.TryGetValue(current, out var next))
        {
            if (!seen.Add(current) || chain.Count > 16) return false;
            chain.Add(next); current = next;
        }
        if (chain.Count < 2) return false;
        foreach (var item in Providers)
            if (current.Length > item.Suffix.Length && current.EndsWith("." + item.Suffix, StringComparison.OrdinalIgnoreCase))
            { provider = item.Provider; return true; }
        return false;
    }

    private static int Read16(byte[] data, int pos) => BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(pos, 2));

    private static bool TryName(byte[] data, ref int pos, out string name)
    {
        name = string.Empty;
        var parts = new List<string>();
        var seen = new HashSet<int>();
        int at = pos, end = -1, total = 0;
        while (at < data.Length && seen.Add(at))
        {
            int length = data[at++];
            if (length == 0)
            {
                pos = end < 0 ? at : end;
                name = string.Join('.', parts);
                return total <= 253;
            }
            if ((length & 0xc0) == 0xc0)
            {
                if (at >= data.Length) return false;
                int pointer = ((length & 0x3f) << 8) | data[at++];
                if (pointer >= data.Length) return false;
                if (end < 0) end = at;
                at = pointer; continue;
            }
            if ((length & 0xc0) != 0 || length > 63 || at + length > data.Length) return false;
            for (int i = at; i < at + length; i++)
                if (!(char.IsAsciiLetterOrDigit((char)data[i]) || data[i] == (byte)'-')) return false;
            parts.Add(Encoding.ASCII.GetString(data, at, length)); total += length + (parts.Count > 1 ? 1 : 0);
            at += length;
        }
        return false;
    }
}
