#if DEBUG
using TryZ.Data;
using TryZ.Views;

namespace TryZ.Capture.Checks;

internal sealed class PriorityChecks : ICheckSuite
{
    public string Name => "priority";

    public Task RunAsync(CheckContext c)
    {
        var medium = Finding(Severity.Medium);
        var plain = Prioritizer.Evaluate(medium);
        c.Equal("severity establishes base", 45d, plain.Score);
        c.Check("unavailable data is explicitly unknown", plain.Reasons.Any(r => r.Contains("unavailable", StringComparison.OrdinalIgnoreCase)));
        medium.Threat = new ThreatInfo { Kev = true, KevCve = "CVE-2024-1111", Epss = 0.12 };
        var enriched = Prioritizer.Evaluate(medium);
        c.Equal("KEV floor and EPSS bonus", 95d, enriched.Score);
        c.Equal("known exploitation is fix now", PriorityTier.FixNow, enriched.Tier);
        c.Check("reasons describe KEV and EPSS", enriched.Reasons.Any(r => r.Contains("CVE-2024-1111")) && enriched.Reasons.Any(r => r.Contains("12.0%")));
        medium.Threat = new ThreatInfo { Kev = false, Epss = 0.005 };
        c.Equal("low EPSS does not reduce severity", 45d, Prioritizer.Evaluate(medium).Score);
        medium.Threat = new ThreatInfo { Epss = double.NaN };
        c.Check("invalid EPSS treated as unavailable", Prioritizer.Evaluate(medium).Reasons.Any(r => r.Contains("EPSS unavailable")));
        var critical = Finding(Severity.Critical);
        critical.Threat = new ThreatInfo { Kev = true, KevRansomware = true, Epss = 0.9 };
        var max = Prioritizer.Evaluate(critical);
        c.Equal("score is capped", 100d, max.Score);
        c.Check("cap is explained", max.Reasons.Any(r => r.Contains("capped")));
        var shell = new TestShell();
        var first = Finding(Severity.High); first.Status = FindingStatus.Accepted;
        var second = Finding(Severity.Medium);
        shell.Session.Findings.Add(first);
        shell.Session.Findings.Add(second);
        using var view = new RemediationView(shell);
        view.SyncData();
        var grid = Find<GridView>(view).Single();
        var check = Find<SkinCheck>(view).Single();
        c.Equal("accepted findings hidden by default", 1, grid.Source!.Count);
        check.Checked = true;
        c.Equal("accepted findings can be included", 2, grid.Source!.Count);
        c.Check("higher score ranks first", ReferenceEquals(first, grid.Source.ItemAt(0)));
        second.Threat = new ThreatInfo { Kev = true, Epss = 0.5 };
        shell.Session.Findings.Touch();
        view.SyncData();
        c.Check("enrichment updates ordering", ReferenceEquals(second, grid.Source.ItemAt(0)));
        check.Checked = false;
        second.Status = FindingStatus.FalsePositive;
        shell.Session.Findings.Touch();
        view.SyncData();
        c.Equal("status changes update visible scope", 0, grid.Source.Count);
        return Task.CompletedTask;
    }

    private static Finding Finding(Severity severity) => new()
    {
        Id = 1, Severity = severity, Title = "Example finding", Host = "example.test", Port = 443,
        Cwe = 200, Description = "Example", Evidence = "Example", Remediation = "Fix it.",
    };

    private static IEnumerable<T> Find<T>(Control root) where T : Control
    {
        foreach (Control child in root.Controls)
        {
            if (child is T result) yield return result;
            foreach (var descendant in Find<T>(child)) yield return descendant;
        }
    }

    private sealed class TestShell : IShell
    {
        public Session Session { get; } = new();
        public AppSettings Settings { get; } = new();
        public void ExportReport(ExportFormat format) { }
        public void UseCustomProfile() { }
        public void Notify(string title, string text, IconId icon = IconId.InfoMark) { }
        public void NavigateTo(int module) { }
        public void OpenInWorkbench(string method, string url) { }
        public void SelectHostInPortAudit(string ip) { }
        public void LogUser(string source, string text) { }
    }
}
#endif
