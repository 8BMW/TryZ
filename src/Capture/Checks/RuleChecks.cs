#if DEBUG
using System.Net;
using System.Threading.Channels;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

internal sealed class RuleChecks : ICheckSuite
{
    public string Name => "rules";
    public async Task RunAsync(CheckContext c)
    {
        using var site = TestSite.TryStartAny();
        if (!c.Check("local test server available", site != null)) return;
        var dir = Path.Combine(c.TempDir, "rules");
        Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(Path.Combine(dir, "a.json"), """
        {"id":"json-match","name":"JSON matched","severity":"Medium","cwe":200,"description":"Observed test content.","remediation":"Remove test content.","path":"/","status":200,"bodyContains":"Test site home"}
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "b.yaml"), """
        id: yaml-match
        name: YAML matched
        severity: Low
        cwe: 200
        description: Test server header observed.
        remediation: Remove test header.
        method: HEAD
        path: /
        status: 200
        headerName: Server
        headerContains: TryZ-SelfTest
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "c.json"), """
        {"id":"no-match","name":"Must not match","description":"test","remediation":"test","path":"/","status":404,"bodyContains":"Test site home"}
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "d.json"), """
        {"id":"bad-origin","name":"Bad target","description":"test","remediation":"test","path":"//example.com/","bodyContains":"example"}
        """);
        var opts = new ScanOptions { Threads = 2, UseCustomRules = true, RulesDirectory = dir, MaxRequestsPerSecond = 1000 };
        using var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, opts), Channel.CreateUnbounded<ScanEvent>().Writer, CancellationToken.None);
        var svc = new OpenService { Host = new LiveHost { Address = IPAddress.Loopback, Hostname = "127.0.0.1" }, Port = site!.Port, Http = true };
        await DetectionRules.LoadAsync(ctx);
        await DetectionRules.RunHttpRulesAsync(ctx, svc);
        var findings = ctx.FindingsSnapshot();
        c.Equal("JSON and YAML rules match", 2, findings.Count);
        c.Check("JSON rule carries its stable ID", findings.Any(f => f.RuleId == "custom.json-match"));
        c.Check("YAML header rule matches", findings.Any(f => f.RuleId == "custom.yaml-match"));
        c.Check("non-matching and unsafe rules produce no finding", findings.All(f => f.RuleId != "custom.no-match" && f.RuleId != "custom.bad-origin"));
        using var off = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, new ScanOptions { Threads = 2, UseCustomRules = false, RulesDirectory = dir }), Channel.CreateUnbounded<ScanEvent>().Writer, CancellationToken.None);
        await DetectionRules.LoadAsync(off);
        await DetectionRules.RunHttpRulesAsync(off, svc);
        c.Equal("disabled custom rules do not run", 0, off.FindingCount);
    }
}
#endif
