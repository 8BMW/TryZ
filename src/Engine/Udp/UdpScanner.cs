using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Bounded, protocol-aware UDP probes. Silence is never treated as proof of an open port.</summary>
internal static class UdpScanner
{
    private sealed record Probe(int Port, string Name, byte[] Request, Func<byte[], bool> Matches);

    private static List<Probe> CreateProbes()
    {
        byte[] id = RandomNumberGenerator.GetBytes(2);
        byte[] dns = [id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]; // root NS
        byte[] ntp = new byte[48]; ntp[0] = 0x23;
        byte[] stamp = RandomNumberGenerator.GetBytes(8); stamp.CopyTo(ntp, 40);
        byte[] nb = [id[0], id[1], 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20,
            0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0, 0, 0x21, 0, 1];
        // SNMP v1 GET sysDescr.0. A fresh positive request ID correlates the response to this probe.
        int snmpId = RandomNumberGenerator.GetInt32(256, 32768);
        byte[] snmp = [0x30,0x27,0x02,0x01,0,0x04,0x06,0x70,0x75,0x62,0x6c,0x69,0x63,0xa0,0x1a,0x02,0x02,0x54,0x7a,0x02,0x01,0,0x02,0x01,0,0x30,0x0e,0x30,0x0c,0x06,0x08,0x2b,0x06,0x01,0x02,0x01,0x01,0x01,0x00,0x05,0];
        snmp[17] = (byte)(snmpId >> 8); snmp[18] = (byte)snmpId;
        byte[] ssdp = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n");
        return [
            new(53, "dns", dns, b => b.Length >= dns.Length && b[0] == id[0] && b[1] == id[1]
                && (b[2] & 0xf8) == 0x80 && b[4] == 0 && b[5] == 1 && b.AsSpan(12, 5).SequenceEqual(dns.AsSpan(12, 5))),
            new(123, "ntp", ntp, b => b.Length >= 48 && (b[0] & 7) == 4 && b.AsSpan(24, 8).SequenceEqual(stamp)),
            new(137, "netbios-ns", nb, b => MatchesNetbios(b, id)),
            new(161, "snmp", snmp, b => MatchesSnmp(b, snmpId)),
            new(1900, "ssdp", ssdp, MatchesSsdp),
        ];
    }

    private static bool MatchesNetbios(byte[] bytes, byte[] id)
    {
        if (bytes.Length < 12 || bytes[0] != id[0] || bytes[1] != id[1] || (bytes[2] & 0xf8) != 0x80
            || (bytes[3] & 0x0f) != 0 || bytes[4] != 0 || bytes[5] > 1 || bytes[6] != 0 || bytes[7] is 0 or > 16) return false;
        int at = 12;
        if (bytes[5] == 1)
        {
            if (!SkipDnsName(bytes, ref at) || at + 4 > bytes.Length || bytes[at] != 0 || bytes[at + 1] != 0x21
                || bytes[at + 2] != 0 || bytes[at + 3] != 1) return false;
            at += 4;
        }
        for (int i = 0; i < bytes[7]; i++)
        {
            if (!SkipDnsName(bytes, ref at) || at + 10 > bytes.Length) return false;
            int type = (bytes[at] << 8) | bytes[at + 1], dnsClass = (bytes[at + 2] << 8) | bytes[at + 3];
            int size = (bytes[at + 8] << 8) | bytes[at + 9];
            at += 10;
            if (at + size > bytes.Length) return false;
            if (type == 0x21 && dnsClass == 1 && size >= 7 && bytes[at] <= (size - 7) / 18) return true;
            at += size;
        }
        return false;
    }

    private static bool SkipDnsName(byte[] bytes, ref int at)
    {
        int length = 0;
        while (at < bytes.Length)
        {
            int label = bytes[at++];
            if (label == 0) return true;
            if ((label & 0xc0) == 0xc0)
            {
                if (at >= bytes.Length) return false;
                int pointer = ((label & 0x3f) << 8) | bytes[at++];
                return pointer >= 12 && pointer < at - 2;
            }
            if ((label & 0xc0) != 0 || at + label > bytes.Length || (length += label + 1) > 255) return false;
            at += label;
        }
        return false;
    }

    private static bool MatchesSnmp(byte[] bytes, int id)
    {
        try
        {
            var reader = new AsnReader(bytes, AsnEncodingRules.BER);
            var message = reader.ReadSequence();
            if (message.ReadInteger() != 0 || !message.ReadOctetString().AsSpan().SequenceEqual("public"u8)) return false;
            var pdu = message.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2, isConstructed: true));
            if (pdu.ReadInteger() != id) return false;
            _ = pdu.ReadInteger(); // error status; errors still establish that an SNMP agent answered
            _ = pdu.ReadInteger(); // error index
            var bindings = pdu.ReadSequence();
            var binding = bindings.ReadSequence();
            if (binding.ReadObjectIdentifier() != "1.3.6.1.2.1.1.1.0") return false;
            _ = binding.ReadEncodedValue();
            return !binding.HasData && !bindings.HasData && !pdu.HasData && !message.HasData && !reader.HasData;
        }
        catch (AsnContentException) { return false; }
    }

    private static bool MatchesSsdp(byte[] bytes)
    {
        string text = Encoding.ASCII.GetString(bytes);
        int lineEnd = text.IndexOf("\r\n", StringComparison.Ordinal);
        if (lineEnd < 0) return false;
        string status = text[..lineEnd];
        if (!(status.StartsWith("HTTP/1.1 200 ", StringComparison.OrdinalIgnoreCase)
            || status.Equals("HTTP/1.1 200", StringComparison.OrdinalIgnoreCase)
            || status.StartsWith("HTTP/1.0 200 ", StringComparison.OrdinalIgnoreCase)
            || status.Equals("HTTP/1.0 200", StringComparison.OrdinalIgnoreCase))) return false;
        return text.Split("\r\n").Any(line => line.StartsWith("ST:", StringComparison.OrdinalIgnoreCase) && line[3..].Trim().Length > 0);
    }

    public static async Task<List<OpenService>> ScanAsync(ScanContext ctx, LiveHost host, int taskId)
    {
        var probes = CreateProbes();
        var found = new List<OpenService>();
        int done = 0;
        await Parallel.ForEachAsync(probes, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(probes.Count, ctx.Options.Threads), CancellationToken = ctx.Token }, async (probe, _) =>
        {
            var answer = await ProbeAsync(ctx, host.Address, probe).ConfigureAwait(false);
            if (answer)
            {
                var svc = new OpenService { Host = host, Port = probe.Port, Proto = "udp", Service = probe.Name, Banner = "Protocol response received" };
                lock (found) found.Add(svc);
                ctx.Emit(new PortFound(new PortRecord { HostIp = host.Ip, Port = probe.Port, Proto = "udp", State = "open", Service = probe.Name, Banner = svc.Banner, Risk = Severity.Info }));
                ctx.Log(LogLevel.Info, "udp", $"{host.Ip}:{probe.Port}/udp open ({probe.Name} response)");
            }
            else ctx.Log(LogLevel.Debug, "udp", $"{host.Ip}:{probe.Port}/udp no matching response (closed or open|filtered)");
            ctx.UpdateTask(taskId, TaskState.Running, Interlocked.Increment(ref done) * 100 / probes.Count);
        }).ConfigureAwait(false);
        found.Sort((a, b) => a.Port.CompareTo(b.Port));
        ctx.Log(LogLevel.Info, "udp", $"{host.Ip}: {found.Count} UDP service(s) responded; silence is inconclusive");
        return found;
    }

    private static async Task<bool> ProbeAsync(ScanContext ctx, IPAddress address, Probe probe)
    {
        for (int attempt = 0; attempt <= ctx.Options.Retries; attempt++)
        {
            await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
            try
            {
                await ctx.GateAsync().ConfigureAwait(false);
                using var work = ctx.BeginWork();
                using var socket = new Socket(address.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
                timeout.CancelAfter(ctx.Options.ReadTimeoutMs);
                var watch = Stopwatch.StartNew();
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, probe.Port), timeout.Token).ConfigureAwait(false);
                    await socket.SendAsync(probe.Request, SocketFlags.None, timeout.Token).ConfigureAwait(false);
                    byte[] buffer = new byte[8192];
                    int received = await socket.ReceiveAsync(buffer, SocketFlags.None, timeout.Token).ConfigureAwait(false);
                    ctx.CountRequest(watch.Elapsed.TotalMilliseconds);
                    if (probe.Matches(buffer[..received])) return true;
                }
                catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested) { ctx.CountRequest(-1); }
                catch (SocketException) { ctx.CountRequest(-1); return false; }
            }
            finally { ctx.Concurrency.Release(); }
        }
        return false;
    }
}
