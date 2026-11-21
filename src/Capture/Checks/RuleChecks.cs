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
        OfflineChecks(c);
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
        await File.WriteAllTextAsync(Path.Combine(dir, "e.json"), """
        {"id":"multi-path","name":"Second path matched","description":"test","remediation":"test","paths":["/nothing-here","/.git/HEAD"],"statuses":[200],"bodyContains":"ref:"}
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "f.yaml"), """
        id: hsts-absent
        name: HSTS header absent
        description: No HSTS.
        remediation: Send Strict-Transport-Security.
        method: HEAD
        headerName: Strict-Transport-Security
        headerAbsent: true
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "g.json"), """
        {"id":"status-only","name":"Missing page answers 404","description":"test","remediation":"test","path":"/no-such-page","statuses":[404,410]}
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "h.json"), """
        {"id":"server-not-hidden","name":"Server header not hidden","description":"test","remediation":"test","headerName":"Server","headerNotContains":"hidden"}
        """);
        await File.WriteAllTextAsync(Path.Combine(dir, "i.json"), """
        {"id":"negative-fails","name":"Must not match negative","description":"test","remediation":"test","bodyNotContains":"Test site home"}
        """);
        var opts = new ScanOptions { Threads = 2, UseCustomRules = true, RulesDirectory = dir, MaxRequestsPerSecond = 1000 };
        using var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, opts), Channel.CreateUnbounded<ScanEvent>().Writer, CancellationToken.None);
        var svc = new OpenService { Host = new LiveHost { Address = IPAddress.Loopback, Hostname = "127.0.0.1" }, Port = site!.Port, Http = true };
        await DetectionRules.LoadAsync(ctx);
        await DetectionRules.RunHttpRulesAsync(ctx, svc);
        var findings = ctx.FindingsSnapshot();
        c.Equal("JSON, YAML and extended rules match", 6, findings.Count);
        c.Check("later path matches when the first misses", findings.Any(f => f.RuleId == "custom.multi-path" && f.Evidence.Contains("/.git/HEAD")));
        c.Check("absent header matches", findings.Any(f => f.RuleId == "custom.hsts-absent" && f.Evidence.Contains("absent")));
        c.Check("status-only rule matches", findings.Any(f => f.RuleId == "custom.status-only"));
        c.Check("header not-contains matches", findings.Any(f => f.RuleId == "custom.server-not-hidden"));
        c.Check("body not-contains blocks a match", findings.All(f => f.RuleId != "custom.negative-fails"));
        c.Check("JSON rule carries its stable ID", findings.Any(f => f.RuleId == "custom.json-match"));
        c.Check("YAML header rule matches", findings.Any(f => f.RuleId == "custom.yaml-match"));
        c.Check("non-matching and unsafe rules produce no finding", findings.All(f => f.RuleId != "custom.no-match" && f.RuleId != "custom.bad-origin"));
        using var off = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, new ScanOptions { Threads = 2, UseCustomRules = false, RulesDirectory = dir }), Channel.CreateUnbounded<ScanEvent>().Writer, CancellationToken.None);
        await DetectionRules.LoadAsync(off);
        await DetectionRules.RunHttpRulesAsync(off, svc);
        c.Equal("disabled custom rules do not run", 0, off.FindingCount);
    }

    private static void OfflineChecks(CheckContext c)
    {
        static DetectionRules.Definition D() => new() { Id = "t", Name = "t", Description = "t", Remediation = "t" };
        var basic = D(); basic.BodyContains = "x";
        c.Check("minimal rule loads", DetectionRules.TryValidate(basic).Loaded);
        var both = D(); both.BodyContains = "x"; both.Path = "/a"; both.Paths = ["/b"];
        c.Check("path and paths together rejected", DetectionRules.TryValidate(both).Error.Contains("not both"));
        var many = D(); many.BodyContains = "x"; many.Paths = Enumerable.Range(0, 17).Select(i => "/p" + i).ToList();
        c.Check("too many paths rejected", !DetectionRules.TryValidate(many).Loaded);
        var badPath = D(); badPath.BodyContains = "x"; badPath.Paths = ["/ok", "//evil.example/"];
        c.Check("every path is checked for origin", DetectionRules.TryValidate(badPath).Error.Contains("//evil.example/"));
        var badStatus = D(); badStatus.Statuses = [200, 99];
        c.Check("bad status in list rejected", !DetectionRules.TryValidate(badStatus).Loaded);
        var nothing = D();
        c.Check("a rule needs some condition", DetectionRules.TryValidate(nothing).Error.Contains("condition"));
        var mixed = D(); mixed.HeaderName = "X-Test"; mixed.HeaderAbsent = true; mixed.HeaderContains = "y";
        c.Check("absent plus contains rejected", !DetectionRules.TryValidate(mixed).Loaded);
        var absentNoName = D(); absentNoName.HeaderAbsent = true;
        c.Check("absent needs a header name", !DetectionRules.TryValidate(absentNoName).Loaded);
        var headBody = D(); headBody.Method = "HEAD"; headBody.BodyNotContains = "x";
        c.Check("HEAD cannot use body negatives", !DetectionRules.TryValidate(headBody).Loaded);
        var nullPaths = D(); nullPaths.BodyContains = "x"; nullPaths.Paths = [null!];
        c.Check("null path rejected", !DetectionRules.TryValidate(nullPaths).Loaded);

        var notHidden = D(); notHidden.HeaderName = "Server"; notHidden.HeaderNotContains = "hidden";
        c.Check("not-contains matches a visible header", DetectionRules.MatchesForTest(notHidden, 200, "nginx/1.25", ""));
        c.Check("not-contains fails when text present", !DetectionRules.MatchesForTest(notHidden, 200, "HIDDEN", ""));
        c.Check("not-contains matches a missing header", DetectionRules.MatchesForTest(notHidden, 200, null, ""));
        var absent = D(); absent.HeaderName = "X-Frame-Options"; absent.HeaderAbsent = true;
        c.Check("absent matches missing header", DetectionRules.MatchesForTest(absent, 200, null, ""));
        c.Check("absent fails when header present", !DetectionRules.MatchesForTest(absent, 200, "DENY", ""));
        var present = D(); present.HeaderName = "Server"; present.HeaderContains = "nginx";
        c.Check("positive header needs the header", !DetectionRules.MatchesForTest(present, 200, null, ""));
        var anyStatus = D(); anyStatus.Statuses = [401, 403]; anyStatus.Status = 407;
        c.Check("status and statuses combine", DetectionRules.MatchesForTest(anyStatus, 407, null, "") && DetectionRules.MatchesForTest(anyStatus, 403, null, "") && !DetectionRules.MatchesForTest(anyStatus, 200, null, ""));
        var negBody = D(); negBody.BodyContains = "login"; negBody.BodyNotContains = "captcha";
        c.Check("body contains and not-contains together", DetectionRules.MatchesForTest(negBody, 200, null, "Login form") && !DetectionRules.MatchesForTest(negBody, 200, null, "login with CAPTCHA"));
    }
}
#endif
