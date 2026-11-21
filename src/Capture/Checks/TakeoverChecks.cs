#if DEBUG
using System.Text;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

internal sealed class TakeoverChecks : ICheckSuite
{
    public string Name => "takeover";
    public Task RunAsync(CheckContext c)
    {
        const string name = "www.example.test";
        c.Check("construct query", TakeoverCheck.TryBuildQuery(name, out var query, out ushort id));
        var valid = Response(query, "site.azurewebsites.net", 3);
        c.Check("recognizes chained NXDOMAIN", TakeoverCheck.TryReadDangling(valid, id, name, out var chain, out var provider)
            && chain.Count == 2 && provider == "Azure App Service");
        c.Check("ignores successful response", !TakeoverCheck.TryReadDangling(Response(query, "site.azurewebsites.net", 0), id, name, out _, out _));
        c.Check("ignores unknown provider", !TakeoverCheck.TryReadDangling(Response(query, "site.example.net", 3), id, name, out _, out _));
        c.Check("rejects suffix spoof", !TakeoverCheck.TryReadDangling(Response(query, "site.azurewebsites.net.evil.test", 3), id, name, out _, out _));
        c.Check("rejects unrelated question", !TakeoverCheck.TryReadDangling(valid, id, "other.example.test", out _, out _));
        c.Check("rejects wrong transaction", !TakeoverCheck.TryReadDangling(valid, (ushort)(id ^ 1), name, out _, out _));
        c.Check("rejects truncated response", !TakeoverCheck.TryReadDangling(valid[..^1], id, name, out _, out _));
        var truncated = (byte[])valid.Clone(); truncated[2] |= 2;
        c.Check("rejects truncated DNS flag", !TakeoverCheck.TryReadDangling(truncated, id, name, out _, out _));
        var loop = (byte[])valid.Clone();
        int answer = query.Length;
        loop[answer] = 0xc0; loop[answer + 1] = (byte)answer;
        c.Check("rejects compression pointer loop", !TakeoverCheck.TryReadDangling(loop, id, name, out _, out _));
        c.Check("rejects invalid query name", !TakeoverCheck.TryBuildQuery("bad..example", out _, out _));
        return Task.CompletedTask;
    }

    private static byte[] Response(byte[] query, string target, byte rcode)
    {
        var result = query.ToList();
        result[2] = 0x81; result[3] = (byte)(0x80 | rcode); result[7] = 1;
        result.AddRange([0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60]);
        var encoded = new List<byte>();
        foreach (string label in target.Split('.')) { encoded.Add((byte)label.Length); encoded.AddRange(Encoding.ASCII.GetBytes(label)); }
        encoded.Add(0);
        result.Add((byte)(encoded.Count >> 8)); result.Add((byte)encoded.Count); result.AddRange(encoded);
        return result.ToArray();
    }
}
#endif
