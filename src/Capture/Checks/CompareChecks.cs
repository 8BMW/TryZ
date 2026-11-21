#if DEBUG
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Capture.Checks;

/// <summary>The Scan Compare view end to end: baseline file on disk, live session, filters, warnings and clearing.</summary>
internal sealed class CompareChecks : ICheckSuite
{
    public string Name => "compare-view";

    public Task RunAsync(CheckContext c)
    {
        var shell = new CheckShell();
        var s = shell.Session;
        s.Target = "192.0.2.0/24";
        s.Profile = "Full Audit";

        var baseline = new SessionFile
        {
            Target = "192.0.2.0/24", Profile = "Full Audit",
            Findings =
            [
                new FindingDto { RuleId = "telnet", Title = "Telnet service exposed", Host = "192.0.2.10", Port = 23, Proto = "tcp", Severity = Severity.High },
                new FindingDto { RuleId = "tls10", Title = "TLS 1.0 enabled", Host = "192.0.2.10", Port = 443, Proto = "tcp", Severity = Severity.Medium },
            ],
            Ports = [ new PortDto { HostIp = "192.0.2.10", Port = 23, Proto = "tcp", State = "open", Service = "telnet", Banner = "old" } ],
        };
        string path = Path.Combine(c.TempDir, "baseline.tzs");
        SessionFile.Write(path, baseline);

        using var view = new CompareView(shell);
        var grid = CheckShell.Find<GridView>(view).Single();
        var combos = CheckShell.Find<SkinCombo>(view).ToList();
        var kind = combos[0];
        var change = combos[1];
        var labels = CheckShell.Find<SkinLabel>(view).ToList();
        var clear = CheckShell.Find<SkinButton>(view).Single(b => b.Caption == "Clear");

        view.SyncData();
        c.Equal("no baseline, no rows", 0, grid.Source!.Count);
        c.Check("subtitle asks for a baseline", view.Subtitle.Contains("Choose a baseline"));

        c.Check("baseline loads", view.LoadBaseline(path));
        c.Equal("baseline path remembered", path, shell.Settings.LastCompareBaseline);
        c.Check("load is logged", shell.UserLog.Any(l => l.Contains("baseline.tzs")));
        c.Check("subtitle names the baseline", view.Subtitle.Contains("baseline.tzs"));
        c.Equal("everything not observed before the scan runs", 3, grid.Source.Count);
        c.Check("incomplete scan warning", labels.Any(l => l.Caption.Contains("incomplete or not started")));

        // The scan comes in: telnet is still there with a new banner, TLS 1.0 is gone, a new header finding appears.
        s.Apply(new HostFound(new HostRecord { Ip = "192.0.2.10", Hostname = "", OsGuess = "", LatencyMs = 1, Ttl = 64, Role = "" }));
        s.Apply(new PortFound(new PortRecord { HostIp = "192.0.2.10", Port = 23, Proto = "tcp", State = "open", Service = "telnet", Banner = "new", Risk = Severity.High }));
        s.Apply(new FindingFound(F(1, "telnet", "Telnet service exposed", 23, Severity.High)));
        s.Apply(new FindingFound(F(2, "hsts", "HSTS header missing", 443, Severity.Low)));
        view.SyncData();
        var rows = Rows(grid);
        c.Equal("four observations", 4, rows.Count);
        c.Check("still-present finding unchanged", rows.Any(r => r.Kind == "Finding" && r.Name == "Telnet service exposed" && r.Change == "Unchanged"));
        c.Check("gone finding is not observed", rows.Any(r => r.Name == "TLS 1.0 enabled" && r.Change == "Not observed"));
        c.Check("new finding flagged", rows.Any(r => r.Name == "HSTS header missing" && r.Change == "New"));
        c.Check("banner change flagged", rows.Any(r => r.Kind == "Service" && r.Change == "Changed" && r.After.Contains("new")));

        change.Value = "New";
        c.Equal("change filter", 1, grid.Source.Count);
        change.Value = "All changes";
        kind.Value = "Service";
        c.Equal("type filter", 1, grid.Source.Count);
        kind.Value = "All types";
        s.FilterText = "HSTS";
        view.SyncData();
        c.Equal("global filter applies", 1, grid.Source.Count);
        s.FilterText = string.Empty;
        view.SyncData();
        c.Equal("filter cleared", 4, grid.Source.Count);

        int count = grid.Source.Count;
        s.Findings.Items[0].Status = FindingStatus.FalsePositive;
        s.Findings.Touch();
        view.SyncData();
        c.Equal("status edits don't change observations", count, grid.Source.Count);

        s.Target = "198.51.100.0/24";
        view.SyncData();
        c.Check("different target warning", labels.Any(l => l.Caption.Contains("Target or profile differs")));

        clear.PerformClick();
        c.Equal("clear empties the grid", 0, grid.Source.Count);
        c.Check("clear resets the subtitle", view.Subtitle.Contains("Choose a baseline"));
        view.SyncData();
        c.Equal("cleared view ignores new data", 0, grid.Source.Count);

        string broken = Path.Combine(c.TempDir, "broken.tzs");
        File.WriteAllText(broken, "{ this is not a session");
        c.Check("broken baseline refused", !view.LoadBaseline(broken));
        c.Check("broken baseline explained", shell.Notices.Any(n => n.StartsWith("Compare:", StringComparison.Ordinal)));
        File.WriteAllText(broken, "{\"Format\": 99}");
        c.Check("future format refused", !view.LoadBaseline(broken) && shell.Notices.Last().Contains("99"));
        c.Check("missing file refused", !view.LoadBaseline(Path.Combine(c.TempDir, "missing.tzs")));
        c.Equal("failed loads keep the last good path", path, shell.Settings.LastCompareBaseline);
        return Task.CompletedTask;
    }

    private static List<ComparisonRow> Rows(GridView grid) =>
        Enumerable.Range(0, grid.Source!.Count).Select(i => (ComparisonRow)grid.Source.ItemAt(i)).ToList();

    private static Finding F(int id, string rule, string title, int port, Severity severity) => new()
    {
        Id = id, RuleId = rule, Severity = severity, Title = title, Host = "192.0.2.10", Port = port, Proto = "tcp", Cwe = 0,
        Description = string.Empty, Evidence = string.Empty, Remediation = string.Empty,
    };
}
#endif
