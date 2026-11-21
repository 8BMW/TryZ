#if DEBUG
using System.Threading.Channels;
using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

/// <summary>Firm versus tentative findings: where they come from, how they rank, and how they survive save and load.</summary>
internal sealed class ConfidenceChecks : ICheckSuite
{
    public string Name => "confidence";

    public Task RunAsync(CheckContext c)
    {
        var firm = F(1, Confidence.Firm);
        var tentative = F(2, Confidence.Tentative);
        c.Equal("firm is the default", Confidence.Firm, new Finding { Id = 0, Severity = Severity.Low, Title = "t", Host = "h", Port = 0, Cwe = 0, Description = "", Evidence = "", Remediation = "" }.Confidence);
        c.Equal("tentative loses 10", Prioritizer.Evaluate(firm).Score - 10, Prioritizer.Evaluate(tentative).Score);
        c.Check("tentative reduction explained", Prioritizer.Evaluate(tentative).Reasons.Any(r => r.StartsWith("Tentative", StringComparison.Ordinal)));
        c.Check("tentative needs verification", tentative.NeedsVerification && tentative.ConfidenceText == "Tentative");

        tentative.Status = FindingStatus.Confirmed;
        c.Equal("confirming removes the reduction", Prioritizer.Evaluate(firm).Score, Prioritizer.Evaluate(tentative).Score);
        c.Check("confirmed tentative reads as verified", !tentative.NeedsVerification && tentative.ConfidenceText == "Verified");
        tentative.Status = FindingStatus.New;

        tentative.Threat = new ThreatInfo { Kev = true };
        c.Equal("KEV keeps a tentative finding at the floor", 85d, Prioritizer.Evaluate(tentative).Score);
        tentative.Threat = null;

        // Engine: details carry confidence into the stored finding.
        var channel = Channel.CreateUnbounded<ScanEvent>();
        using (var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, new ScanOptions { Threads = 1 }), channel.Writer, CancellationToken.None))
        {
            ctx.AddFinding(Severity.High, "Banner says old", "192.0.2.1", 22, 1104, "d", "Version banner indicates OpenSSH 7.4.", "Upgrade.",
                new FindingDetails { Confidence = Confidence.Tentative, Cves = ["CVE-2018-15473"] });
            ctx.AddFinding(Severity.High, "Response proves it", "192.0.2.1", 80, 200, "d", "GET /.git/HEAD -> 200", "Remove.");
            var stored = ctx.FindingsSnapshot();
            c.Check("engine keeps tentative", stored.Single(f => f.Port == 22).Confidence == Confidence.Tentative);
            c.Check("engine defaults to firm", stored.Single(f => f.Port == 80).Confidence == Confidence.Firm);
        }

        // Save and load, including files written before the field existed.
        var s = new Session();
        s.Apply(new FindingFound(tentative));
        s.Apply(new FindingFound(firm));
        var file = s.ToFile();
        c.Check("confidence is saved", file.Findings.Any(f => f.Confidence == Confidence.Tentative));
        var back = new Session();
        back.LoadFrom(file, "c.tzs");
        c.Equal("confidence survives load", Confidence.Tentative, back.Findings.Items.Single(f => f.Id == 2).Confidence);
        var old = new SessionFile
        {
            Findings =
            [
                new FindingDto { Id = 1, Title = "Old CVE match", Cves = ["CVE-2021-41773"] },
                new FindingDto { Id = 2, Title = "Old banner match", Description = "Version banner indicates nginx 1.18." },
                new FindingDto { Id = 3, Title = "Potential dangling DNS alias (x)", RuleId = "potential-dangling-dns-alias" },
                new FindingDto { Id = 4, Title = "Old header check", Description = "The response lacks HSTS." },
                new FindingDto { Id = 5, Title = "Garbage value", Confidence = (Confidence)9 },
            ],
        };
        var legacy = new Session();
        legacy.LoadFrom(old, "old.tzs");
        var byId = legacy.Findings.Items.ToDictionary(f => f.Id);
        c.Check("old CVE match inferred tentative", byId[1].Confidence == Confidence.Tentative);
        c.Check("old banner match inferred tentative", byId[2].Confidence == Confidence.Tentative);
        c.Check("old DNS lead inferred tentative", byId[3].Confidence == Confidence.Tentative);
        c.Check("old direct check inferred firm", byId[4].Confidence == Confidence.Firm);
        c.Check("unknown value falls back to inference", byId[5].Confidence == Confidence.Firm);

        // Reports and plan.
        var plan = RemediationPlan.Build(s);
        c.Check("all-tentative item says verify first", plan.Items.Single(i => i.Findings.Contains(tentative)).NeedsVerification);
        c.Check("firm item doesn't", !plan.Items.Single(i => i.Findings.Contains(firm)).NeedsVerification);
        c.Check("plan CSV has verify column", plan.Csv().StartsWith("Rank,Priority,Score,Severity,Due,Due basis,Overdue,Verify first,", StringComparison.Ordinal));
        string csv = ReportWriter.BuildFindingsCsv(s);
        c.Check("findings CSV has confidence", csv.StartsWith("Id,Severity,Title,Host,Port,CWE,Status,Confidence,", StringComparison.Ordinal) && csv.Contains("\"Tentative\""));
        string html = ReportWriter.BuildHtml(s, string.Empty);
        c.Check("HTML marks tentative findings", html.Contains("confidence Tentative") && html.Contains("Verify before remediation"));
        c.Check("JSON carries confidence", StructuredReport.FindingsJson(s).Contains("\"confidence\": \"Tentative\""));
        c.Check("SARIF carries confidence", StructuredReport.Sarif(s).Contains("\"confidence\": \"Tentative\""));
        c.Check("Markdown carries confidence", StructuredReport.Markdown(s, string.Empty).Contains("**Confidence:** Tentative"));
        return Task.CompletedTask;
    }

    private static Finding F(int id, Confidence confidence) => new()
    {
        Id = id, Severity = Severity.High, Title = confidence == Confidence.Firm ? "Firm thing" : "Tentative thing", Host = "192.0.2.1", Port = 443 + id,
        Cwe = 200, Description = "d", Evidence = "e", Remediation = id == 1 ? "Fix firm." : "Fix tentative.", Confidence = confidence,
    };
}
#endif
