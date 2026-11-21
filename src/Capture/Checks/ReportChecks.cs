#if DEBUG
using System.Text.Json;
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Capture.Checks;

/// <summary>Report content: escaping of hostile scan data, empty sessions and the remediation plan exports.</summary>
internal sealed class ReportChecks : ICheckSuite
{
    public string Name => "report";

    private const string Hostile = "=HYPERLINK(\"http://x\")<script>alert(1)</script>*bold* [link](javascript:x) `code`";

    public Task RunAsync(CheckContext c)
    {
        Escaping(c);
        EmptySession(c);
        Plan(c);
        PlanExports(c);
        return Task.CompletedTask;
    }

    private static void Escaping(CheckContext c)
    {
        var s = new Session { Target = "<b>target</b>", Profile = "Quick Audit" };
        s.Apply(new FindingFound(F(1, "x.rule", Hostile, Severity.High, evidence: Hostile)));
        string html = ReportWriter.BuildHtml(s, "<i>footer</i>");
        c.Check("HTML escapes finding text", !html.Contains("<script>", StringComparison.Ordinal) && html.Contains("&lt;script&gt;", StringComparison.Ordinal));
        c.Check("HTML escapes footer and target", !html.Contains("<i>footer</i>", StringComparison.Ordinal) && !html.Contains("<b>target</b>", StringComparison.Ordinal));
        string csv = ReportWriter.BuildFindingsCsv(s);
        c.Check("CSV neutralises formulas", csv.Contains("\"'=HYPERLINK(\"\"http://x\"\")", StringComparison.Ordinal));
        c.Check("CSV quotes embedded commas and quotes", ReportWriter.Csv("a,\"b\"") == "\"a,\"\"b\"\"\"");
        foreach (char lead in "=+-@\t\r")
            c.Check($"CSV prefixes 0x{(int)lead:x2}", ReportWriter.Csv(lead + "1").StartsWith("\"'", StringComparison.Ordinal));
        string md = StructuredReport.Markdown(s, "");
        c.Check("Markdown has no raw HTML", !md.Contains("<script>", StringComparison.Ordinal));
        c.Check("Markdown escapes emphasis, links and code", md.Contains("\\*bold\\*", StringComparison.Ordinal) && md.Contains("\\[link\\]", StringComparison.Ordinal) && md.Contains("\\`code\\`", StringComparison.Ordinal));
        c.Check("Markdown keeps multi-line text inside its block", StructuredReport.Md("a\r\nb") == "a  \nb");
        using (var json = JsonDocument.Parse(StructuredReport.FindingsJson(s)))
            c.Equal("JSON preserves raw text", Hostile, json.RootElement.GetProperty("findings")[0].GetProperty("title").GetString());
        using (var sarif = JsonDocument.Parse(StructuredReport.Sarif(s)))
            c.Check("SARIF is valid JSON with a result", sarif.RootElement.GetProperty("runs")[0].GetProperty("results").GetArrayLength() == 1);
    }

    private static void EmptySession(CheckContext c)
    {
        var s = new Session();
        c.Check("empty HTML renders", ReportWriter.BuildHtml(s, "").Contains("</html>", StringComparison.Ordinal));
        c.Equal("empty CSV is header only", 1, ReportWriter.BuildFindingsCsv(s).Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
        c.Check("empty Markdown says so", StructuredReport.Markdown(s, "").Contains("No findings recorded", StringComparison.Ordinal));
        using (var json = JsonDocument.Parse(StructuredReport.FindingsJson(s)))
            c.Equal("empty JSON has no findings", 0, json.RootElement.GetProperty("findings").GetArrayLength());
        c.Equal("empty plan", 0, RemediationPlan.Build(s, includeClosed: true).Count);
        c.Check("empty plan Markdown says so", RemediationPlan.Markdown(s, false, "").Contains("No findings to remediate", StringComparison.Ordinal));
        c.Equal("empty plan CSV is header only", 1, RemediationPlan.Csv(s, false).Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);
    }

    private static void Plan(CheckContext c)
    {
        var s = PlanSession();
        var ranked = RemediationPlan.Rank(s.Findings.Items, includeClosed: false);
        c.Equal("closed findings excluded", 4, ranked.Count);
        c.Check("ranks are 1..n", ranked.Select(e => e.Rank).SequenceEqual(Enumerable.Range(1, ranked.Count)));
        c.Check("ranked by score", ranked.Zip(ranked.Skip(1)).All(p => p.First.Priority.Score >= p.Second.Priority.Score));
        c.Equal("KEV medium outranks plain high", "Exploited medium", ranked[0].Finding.Title);
        c.Check("equal scores keep discovery order", ranked[1].Finding.Id < ranked[2].Finding.Id && ranked[1].Priority.Score == ranked[2].Priority.Score);
        c.Equal("closed findings can be included", 5, RemediationPlan.Rank(s.Findings.Items, includeClosed: true).Count);

        var actions = RemediationPlan.Group(ranked);
        c.Equal("same rule and fix grouped", 3, actions.Count);
        var grouped = actions.Single(a => a.Entries.Count == 2);
        c.Check("group lists every endpoint", grouped.Entries.Select(e => e.Finding.Host).Order().SequenceEqual(new[] { "192.0.2.10", "192.0.2.11" }));
        c.Equal("group takes best priority", grouped.Entries.Max(e => e.Priority.Score), grouped.Score);
        c.Equal("actions ordered by best rank", PriorityTier.FixNow, actions[0].Tier);
        c.Check("different fix is a separate action", actions.Count(a => a.Title == "Plain high") == 2);
        c.Check("action CVEs are distinct", actions[0].Cves.Count == 1);
    }

    private static void PlanExports(CheckContext c)
    {
        var s = PlanSession();
        string md = RemediationPlan.Markdown(s, false, "Prepared by <team>");
        c.Check("plan Markdown has tiers in order", md.IndexOf("## Fix now", StringComparison.Ordinal) is int now and >= 0
            && md.IndexOf("## Fix next", StringComparison.Ordinal) > now);
        c.Check("plan Markdown explains score", md.Contains("ordering aid", StringComparison.Ordinal) && md.Contains("CISA KEV", StringComparison.Ordinal));
        c.Check("plan Markdown lists affected endpoints", md.Contains("192.0.2.11:443/tcp", StringComparison.Ordinal));
        c.Check("plan Markdown escapes footer", md.Contains("&lt;team&gt;", StringComparison.Ordinal));
        c.Check("plan Markdown omits closed findings", !md.Contains("Accepted risk", StringComparison.Ordinal));
        c.Check("plan Markdown includes closed when asked", RemediationPlan.Markdown(s, true, "").Contains("Accepted risk", StringComparison.Ordinal));

        string csv = RemediationPlan.Csv(s, false);
        var lines = csv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries);
        c.Equal("plan CSV has a row per open finding", 5, lines.Length);
        c.Check("plan CSV first row is top rank", lines[1].StartsWith("1,1,\"Fix now\",", StringComparison.Ordinal));
        c.Check("plan CSV records KEV and EPSS", lines[1].Contains(",Yes,0.2,", StringComparison.Ordinal));
        c.Check("plan CSV neutralises formulas", csv.Contains("\"'=cmd\"", StringComparison.Ordinal));

        var shell = new TestShell();
        foreach (var f in s.Findings.Items) shell.Session.Findings.Add(f);
        using var view = new RemediationView(shell);
        view.SyncData();
        string mdPath = Path.Combine(c.TempDir, "plan.md"), csvPath = Path.Combine(c.TempDir, "plan.CSV");
        c.Check("view exports Markdown", view.ExportPlanTo(mdPath) && File.ReadAllText(mdPath).StartsWith("# Remediation Plan", StringComparison.Ordinal));
        c.Check("view picks CSV by extension", view.ExportPlanTo(csvPath) && File.ReadAllText(csvPath).Contains("Rank,Action,Priority", StringComparison.Ordinal));
        c.Equal("view logs each export", 2, shell.Logs);
        c.Check("view reports write failure", !view.ExportPlanTo(Path.Combine(c.TempDir, "missing-folder", "plan.md")) && shell.Notices == 1);
    }

    private static Session PlanSession()
    {
        var s = new Session { Target = "example.test", Profile = "Full Audit" };
        var exploited = F(1, "cve.check", "Exploited medium", Severity.Medium);
        exploited.Threat = new ThreatInfo { Kev = true, KevCve = "CVE-2024-0001", Epss = 0.2 };
        s.Apply(new FindingFound(exploited));
        s.Apply(new FindingFound(F(2, "tls.weak", "Plain high", Severity.High)));
        s.Apply(new FindingFound(F(3, "tls.weak", "Plain high", Severity.High, host: "192.0.2.11")));
        s.Apply(new FindingFound(F(4, "tls.weak", "Plain high", Severity.High, remediation: "=cmd")));
        var accepted = F(5, "info.rule", "Accepted risk", Severity.Critical);
        accepted.Status = FindingStatus.Accepted;
        s.Apply(new FindingFound(accepted));
        return s;
    }

    private static Finding F(int id, string rule, string title, Severity severity, string host = "192.0.2.10", string evidence = "Example", string remediation = "Fix it.") => new()
    {
        Id = id, RuleId = rule, Severity = severity, Title = title, Host = host, Port = 443, Proto = "tcp", Cwe = 200,
        Description = "Example", Evidence = evidence, Remediation = remediation, Cves = ["CVE-2024-0001"],
    };

    private sealed class TestShell : IShell
    {
        public int Notices { get; private set; }
        public int Logs { get; private set; }
        public Session Session { get; } = new();
        public AppSettings Settings { get; } = new();
        public void ExportReport(ExportFormat format) { }
        public void UseCustomProfile() { }
        public void Notify(string title, string text, IconId icon = IconId.InfoMark) => Notices++;
        public void NavigateTo(int module) { }
        public void OpenInWorkbench(string method, string url) { }
        public void SelectHostInPortAudit(string ip) { }
        public void LogUser(string source, string text) => Logs++;
    }
}
#endif
