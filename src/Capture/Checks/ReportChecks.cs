#if DEBUG
using System.Text.Json;
using PdfSharp.Pdf.IO;
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Capture.Checks;

/// <summary>Remediation plan grouping and dates, and report templates carried through to every export format.</summary>
internal sealed class ReportChecks : ICheckSuite
{
    public string Name => "reports";

    private static readonly DateTime ScanDay = new(2026, 3, 2, 9, 30, 0);

    public Task RunAsync(CheckContext c)
    {
        PlanChecks(c);
        TemplateChecks(c);
        PreviewChecks(c);
        return Task.CompletedTask;
    }

    private static void PlanChecks(CheckContext c)
    {
        var s = Sample();
        var plan = RemediationPlan.Build(s, today: new DateOnly(2026, 3, 3));
        c.Equal("base date is the scan day", new DateOnly(2026, 3, 2), plan.BaseDate);

        var telnet = plan.Items.SingleOrDefault(i => i.Title == "Telnet service exposed");
        c.Check("same fix on two hosts is one work item", telnet is { Endpoints.Count: 2, Hosts.Count: 2 }, telnet?.AffectedText);
        c.Equal("closed findings are left out", 1, plan.ClosedFindings);
        c.Check("accepted finding not planned", plan.Items.All(i => i.Findings.All(f => f.Status != FindingStatus.Accepted)));

        var kev = plan.Items.First();
        c.Check("known exploited item ranks first", kev.Kev && kev.Tier == PriorityTier.FixNow, kev.Title);
        c.Equal("earlier KEV due date wins", new DateOnly(2026, 3, 4), kev.Due);
        c.Check("KEV basis is named", kev.DueBasis.Contains("CISA KEV") && kev.DueBasis.Contains("CVE-2024-3400"), kev.DueBasis);
        c.Check("not overdue before the date", !kev.Overdue);
        c.Check("ranks are 1..n", plan.Items.Select(i => i.Rank).SequenceEqual(Enumerable.Range(1, plan.Items.Count)));
        c.Check("tiers never go backwards", plan.Items.Zip(plan.Items.Skip(1)).All(p => p.First.Tier <= p.Second.Tier));

        var cookie = plan.Items.Single(i => i.Title.StartsWith("Cookie", StringComparison.Ordinal));
        c.Equal("planned tier gets 90 days", new DateOnly(2026, 5, 31), cookie.Due);
        var info = plan.Items.Single(i => i.Severity == Severity.Info);
        c.Check("monitor tier has no deadline", info.Due == null && info.DueText == "-");

        var later = RemediationPlan.Build(s, today: new DateOnly(2026, 4, 15));
        c.Equal("past target dates are overdue", 2, later.OverdueCount);
        c.Check("summary mentions overdue work", later.Summary().Contains("past their target date"), later.Summary());

        // Same rule, different advice: version-specific guidance must not be merged into one line.
        var split = new Session();
        split.Findings.Add(F(1, Severity.High, "Outdated product", "192.0.2.1", 443, "Upgrade to 2.4.62."));
        split.Findings.Add(F(2, Severity.High, "Outdated product", "192.0.2.2", 443, "Upgrade to 2.2.34."));
        c.Equal("different advice stays separate", 2, RemediationPlan.Build(split).Items.Count);
        split.Findings.Add(F(3, Severity.High, "Outdated product", "192.0.2.3", 443, "  upgrade   to 2.4.62. "));
        c.Equal("whitespace and case in advice don't split", 2, RemediationPlan.Build(split).Items.Count);

        s.SetImportance("192.0.2.20", AssetImportance.Critical);
        var lifted = RemediationPlan.Build(s, today: new DateOnly(2026, 3, 5));
        c.Check("host importance reorders the plan", lifted.Items.Single(i => i.Title.StartsWith("Cookie", StringComparison.Ordinal)).Tier == PriorityTier.FixNext);

        var empty = RemediationPlan.Build(new Session());
        c.Check("empty plan says so", empty.Items.Count == 0 && empty.Summary().Contains("nothing to plan"));
        c.Check("plan CSV neutralises formulas", RemediationPlan.Build(Formula()).Csv().Contains("\"'=HYPERLINK", StringComparison.Ordinal));
    }

    private static void TemplateChecks(CheckContext c)
    {
        var s = Sample();
        var settings = new AppSettings { ReportAuthorLine = "Prepared for the change board" };
        string Export(ExportFormat format, ReportScope scope)
        {
            string path = Path.Combine(c.TempDir, $"{scope.Template}-{Guid.NewGuid():N}.{ReportExporter.Describe(format).Extension}");
            ReportExporter.Write(path, format, s, settings, scope);
            return path;
        }

        string full = File.ReadAllText(Export(ExportFormat.Html, ReportScope.Complete));
        c.Check("complete HTML keeps its title", full.Contains("<h1>Security Assessment Report</h1>", StringComparison.Ordinal));
        c.Check("complete HTML has every section", full.Contains("<h2>Hosts</h2>") && full.Contains("<h2>Findings</h2>") && full.Contains("<pre>"));
        c.Check("complete HTML has no plan", !full.Contains("Remediation plan", StringComparison.Ordinal));

        var remediation = ReportScope.For(ReportTemplate.Remediation);
        string planHtml = File.ReadAllText(Export(ExportFormat.Html, remediation));
        c.Check("plan HTML has plan", planHtml.Contains("<h2>Remediation plan</h2>") && planHtml.Contains("192.0.2.10:23/tcp<br>192.0.2.20:23/tcp"));
        c.Check("plan HTML shows KEV deadline", planHtml.Contains("CISA KEV due date") && planHtml.Contains("known exploited"));
        c.Check("plan HTML skips host tables", !planHtml.Contains("<h2>Hosts</h2>"));
        c.Check("plan HTML has no evidence", !planHtml.Contains("<pre>"));

        string exec = File.ReadAllText(Export(ExportFormat.Html, ReportScope.For(ReportTemplate.Executive)));
        c.Check("executive HTML has top priorities", exec.Contains("<h2>Top priorities</h2>") && exec.Contains("<h2>Executive summary</h2>"));
        c.Check("executive HTML has no register", !exec.Contains("<h2>Findings</h2>"));
        c.Check("executive HTML caps the list", exec.Contains("more work item(s) are listed in the full remediation plan"));

        string inventoryCsv = File.ReadAllText(Export(ExportFormat.Csv, ReportScope.For(ReportTemplate.Inventory)));
        c.Check("inventory CSV is a service list", inventoryCsv.StartsWith("﻿Host,Hostname,OS guess,Importance,Port", StringComparison.Ordinal) || inventoryCsv.StartsWith("Host,Hostname", StringComparison.Ordinal));
        c.Check("inventory CSV counts findings per service", inventoryCsv.Contains("\"192.0.2.10\",\"web.example.test\",\"Linux\",\"Normal\",443,\"tcp\",\"https\""));
        c.Check("inventory CSV lists idle hosts", inventoryCsv.Contains("\"192.0.2.30\""));

        string planCsv = File.ReadAllText(Export(ExportFormat.Csv, remediation));
        c.Check("plan CSV has plan columns", planCsv.TrimStart('﻿').StartsWith("Rank,Priority,Score", StringComparison.Ordinal));
        c.Equal("plan CSV has one row per work item", RemediationPlan.Build(s).Items.Count + 1, planCsv.Split("\r\n", StringSplitOptions.RemoveEmptyEntries).Length);

        var web = ReportScope.For(ReportTemplate.WebReview);
        string webCsv = File.ReadAllText(Export(ExportFormat.Csv, web));
        c.Check("web review keeps HTTPS findings", webCsv.Contains("Cookie without Secure flag"));
        c.Check("web review keeps crawled vhost port", webCsv.Contains("Directory listing"));
        c.Check("web review keeps DNS takeover", webCsv.Contains("Dangling DNS alias"));
        c.Check("web review drops telnet", !webCsv.Contains("Telnet"));
        string webSarif = File.ReadAllText(Export(ExportFormat.Sarif, web));
        using (var doc = JsonDocument.Parse(webSarif))
            c.Equal("web review SARIF filtered too", ReportScope.For(ReportTemplate.WebReview).SelectFindings(s).Count, doc.RootElement.GetProperty("runs")[0].GetProperty("results").GetArrayLength());
        var vhost = new Session();
        vhost.Apply(new HostFound(new HostRecord { Ip = "192.0.2.50", Hostname = "shop.example.test", OsGuess = "", LatencyMs = 1, Ttl = 64, Role = "" }));
        vhost.Apply(new PortFound(new PortRecord { HostIp = "192.0.2.50", Port = 8081, Proto = "tcp", State = "open", Service = "unknown", Banner = "", Risk = Severity.Info }));
        vhost.Apply(new UrlBatch([new UrlRecord { Host = "shop.example.test:8081", Path = "/", Url = "http://shop.example.test:8081/", Method = "GET", Status = 200, ContentType = "text/html", Size = 1, TimeMs = 1 }]));
        vhost.Apply(new FindingFound(F(1, Severity.Low, "Thing on the shop", "192.0.2.50", 8081, "Fix.")));
        c.Equal("crawled vhost port counts as web", 1, web.SelectFindings(vhost).Count);
        c.Check("RPC over HTTP is not web", !ReportScope.IsWebService("http-rpc-epmap") && ReportScope.IsWebService("ssl/http") && ReportScope.IsWebService("HTTPS"));

        using (var doc = JsonDocument.Parse(File.ReadAllText(Export(ExportFormat.Json, remediation))))
        {
            var root = doc.RootElement;
            c.Check("plan JSON names the template", root.GetProperty("report").GetString() == "Remediation Plan");
            c.Check("plan JSON has plan items", root.GetProperty("plan").GetProperty("items").GetArrayLength() > 0);
            c.Check("plan JSON keeps findings", root.GetProperty("findings").GetArrayLength() == s.FindingCount);
            c.Check("plan JSON omits hosts", !root.TryGetProperty("hosts", out _));
        }
        using (var doc = JsonDocument.Parse(File.ReadAllText(Export(ExportFormat.Json, ReportScope.Complete))))
            c.Check("complete JSON has no plan block", !doc.RootElement.TryGetProperty("plan", out _) && doc.RootElement.TryGetProperty("services", out _));

        string md = File.ReadAllText(Export(ExportFormat.Markdown, remediation));
        c.Check("plan Markdown has table and actions", md.StartsWith("# Remediation Plan", StringComparison.Ordinal) && md.Contains("| # | Priority |") && md.Contains("### Actions"));
        c.Check("Markdown table cells escape pipes", md.Contains("a \\| b", StringComparison.Ordinal));
        string noEvidence = File.ReadAllText(Export(ExportFormat.Markdown, ReportScope.Complete with { Evidence = false }));
        c.Check("evidence switch is honoured", !noEvidence.Contains("**Evidence**") && noEvidence.Contains("**Remediation**"));

        using (var pdf = PdfReader.Open(Export(ExportFormat.Pdf, remediation), PdfDocumentOpenMode.Import))
            c.Check("plan PDF is valid", pdf.PageCount >= 1, $"{pdf.PageCount} pages");

        var described = ReportExporter.Describe(ExportFormat.Csv, remediation);
        c.Check("plan CSV is named for what it is", described.Name == "Remediation plan CSV" && described.FileTag == "remediation-plan");
        c.Equal("SARIF keeps its findings tag", "findings", ReportExporter.Describe(ExportFormat.Sarif, remediation).FileTag);
        c.Equal("technical keeps old names", ReportExporter.Describe(ExportFormat.Html), ReportExporter.Describe(ExportFormat.Html, ReportScope.Complete));
    }

    private static void PreviewChecks(CheckContext c)
    {
        var shell = new CheckShell();
        var sample = Sample();
        shell.Session.LoadFrom(sample.ToFile(), "sample.tzs");
        using var view = new ReportsView(shell);
        view.SyncData();
        var templates = CheckShell.Find<SkinList>(view).First(l => l.Parent is EtchedGroup);
        var export = CheckShell.Find<SkinButton>(view).Single(b => b.Caption == "Export...");
        var preview = CheckShell.Find<ReportPreview>(view).Single();

        templates.SelectedIndex = (int)ReportTemplate.Remediation;
        c.Equal("view applies the template", ReportTemplate.Remediation, view.Scope.Template);
        c.Check("remediation preview has plan pages", preview.PageCount >= 2, $"{preview.PageCount} pages");
        export.PerformClick();
        c.Check("export carries the template", shell.Exports.LastOrDefault().Scope?.Template == ReportTemplate.Remediation);

        templates.SelectedIndex = (int)ReportTemplate.Executive;
        c.Equal("executive preview is one page", 1, preview.PageCount);
        var register = CheckShell.Find<SkinCheck>(view).Single(b => b.Caption == "Findings register");
        register.Checked = true;
        c.Check("sections switched on are exported", view.Scope.Findings && view.Scope.Template == ReportTemplate.Executive);
        c.Check("executive preview grows with the register", preview.PageCount >= 2);
    }

    private static Finding F(int id, Severity severity, string title, string host, int port, string remediation, string proto = "tcp", string rule = "") => new()
    {
        Id = id, Severity = severity, Title = title, Host = host, Port = port, Proto = proto, Cwe = 200,
        Description = "Description of " + title, Evidence = "GET / -> 200\nServer: test", Remediation = remediation,
        RuleId = rule.Length > 0 ? rule : FindingDetails.Slug(title),
    };

    /// <summary>
    /// Two hosts sharing a telnet finding, a KEV-listed firewall bug with a CISA deadline, HTTPS and crawled-only web
    /// findings, a DNS alias, an informational note and one accepted risk.
    /// </summary>
    private static Session Sample()
    {
        var s = new Session { Target = "192.0.2.0/24", Profile = "Full Audit", StartedAt = ScanDay };
        foreach (var (ip, name) in new[] { ("192.0.2.10", "web.example.test"), ("192.0.2.20", "fw.example.test"), ("192.0.2.30", "idle.example.test") })
            s.Apply(new HostFound(new HostRecord { Ip = ip, Hostname = name, OsGuess = "Linux", LatencyMs = 2, Ttl = 64, Role = "server" }));
        void Port(string ip, int port, string service) =>
            s.Apply(new PortFound(new PortRecord { HostIp = ip, Port = port, Proto = "tcp", State = "open", Service = service, Banner = service + " banner", Risk = Severity.Info }));
        Port("192.0.2.10", 23, "telnet");
        Port("192.0.2.10", 443, "https");
        Port("192.0.2.20", 23, "telnet");
        Port("192.0.2.20", 443, "https");
        s.Apply(new UrlBatch(new[] { new UrlRecord { Host = "192.0.2.10", Path = "/files/", Url = "http://192.0.2.10:8081/files/", Method = "GET", Status = 200, ContentType = "text/html", Size = 10, TimeMs = 5 } }));

        var findings = new List<Finding>
        {
            F(1, Severity.High, "Telnet service exposed", "192.0.2.10", 23, "Disable telnet; use SSH."),
            F(2, Severity.High, "Telnet service exposed", "192.0.2.20", 23, "Disable telnet; use SSH."),
            F(3, Severity.Critical, "PAN-OS command injection", "192.0.2.20", 443, "Apply the vendor hotfix.", rule: "cve-2024-3400"),
            F(4, Severity.Medium, "Cookie without Secure flag", "192.0.2.20", 443, "Set the Secure attribute."),
            F(5, Severity.Low, "Directory listing", "192.0.2.10", 8081, "Turn off autoindex."),
            F(6, Severity.Medium, "Dangling DNS alias", "old.example.test", 0, "Remove the stale CNAME.", proto: "dns"),
            F(7, Severity.Info, "Server banner disclosed a | b", "192.0.2.10", 23, "Hide the banner."),
            F(8, Severity.High, "Weak TLS protocol", "192.0.2.10", 443, "Disable TLS 1.0."),
        };
        findings[2].Threat = new ThreatInfo { Kev = true, KevCve = "CVE-2024-3400", KevDueDate = new DateOnly(2026, 3, 4), Epss = 0.94 };
        findings[7].Status = FindingStatus.Accepted;
        foreach (var f in findings) s.Apply(new FindingFound(f));
        return s;
    }

    private static Session Formula()
    {
        var s = new Session();
        s.Findings.Add(F(1, Severity.High, "=HYPERLINK(\"http://x\")", "192.0.2.1", 80, "Fix."));
        return s;
    }
}
#endif
