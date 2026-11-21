#if DEBUG
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Capture.Checks;

/// <summary>Session file round trips and the Scan Compare view wired to a baseline on disk.</summary>
internal sealed class CompareChecks : ICheckSuite
{
    public string Name => "compare";

    public Task RunAsync(CheckContext c)
    {
        RoundTrip(c);
        LegacyAndInvalidFiles(c);
        View(c);
        return Task.CompletedTask;
    }

    private static void RoundTrip(CheckContext c)
    {
        var s = Build(("ssh.weak", "Weak SSH configuration", 22, Severity.Medium));
        s.Findings.Items[0].Threat = new ThreatInfo { Kev = true, KevCve = "CVE-2023-0001", KevDueDate = new DateOnly(2026, 1, 2), Epss = 0.25, EpssPercentile = 0.9 };
        string path = Path.Combine(c.TempDir, "roundtrip.tzs");
        SessionFile.Write(path, s.ToFile());
        var file = SessionFile.Read(path);
        c.Equal("current format written", SessionFile.CurrentFormat, file.Format);
        var loaded = new Session();
        loaded.LoadFrom(file, "roundtrip.tzs");
        var f = loaded.Findings.Items.Single();
        c.Equal("rule id preserved", "ssh.weak", f.RuleId);
        c.Equal("protocol preserved", "tcp", f.Proto);
        c.Equal("product preserved", "OpenSSH 7.4", f.Product);
        c.Check("CVEs preserved", f.Cves.SequenceEqual(new[] { "CVE-2023-0001" }));
        c.Equal("CVSS preserved", (double?)5.3, f.Cvss);
        c.Check("threat intel preserved", f.Threat is { Kev: true, KevCve: "CVE-2023-0001", Epss: 0.25 } && f.Threat.KevDueDate == new DateOnly(2026, 1, 2));
        c.Equal("fingerprint stable across save", s.Findings.Items[0].Fingerprint, f.Fingerprint);
        c.Check("no temp file left behind", !File.Exists(path + ".tmp"));
    }

    private static void LegacyAndInvalidFiles(CheckContext c)
    {
        string legacy = Path.Combine(c.TempDir, "legacy.tzs");
        File.WriteAllText(legacy, """
            { "Format": 1, "Target": "example.test", "Profile": "Quick Audit",
              "Findings": [ { "Id": 1, "Severity": "Low", "Title": "Old finding", "Host": "192.0.2.10", "Port": 80,
                              "Description": "d", "Evidence": "e", "Remediation": "r", "Status": "Confirmed" } ] }
            """);
        var file = SessionFile.Read(legacy);
        c.Equal("format 1 accepted", 1, file.Format);
        var s = new Session();
        s.LoadFrom(file, "legacy.tzs");
        var f = s.Findings.Items.Single();
        c.Check("format 1 defaults new fields", f.RuleId == "" && f.Proto == "tcp" && f.Cves.Count == 0 && f.Threat == null && f.Cvss == null);
        c.Check("format 1 has no nulls in lists", file.Ports != null && file.Hosts != null && file.Urls != null && file.Log != null);

        Throws(c, "future format rejected", """{ "Format": 99 }""");
        Throws(c, "format 0 rejected", """{ "Format": 0 }""");
        Throws(c, "malformed JSON rejected", "{ not json");
        Throws(c, "JSON null rejected", "null");

        void Throws(CheckContext ctx, string name, string json)
        {
            string p = Path.Combine(ctx.TempDir, Guid.NewGuid().ToString("N") + ".tzs");
            File.WriteAllText(p, json);
            try { SessionFile.Read(p); ctx.Check(name, false, "no exception"); }
            catch (InvalidDataException) { ctx.Check(name, true); }
        }
    }

    private static void View(CheckContext c)
    {
        var baseline = Build(("old.rule", "Fixed elsewhere", 80, Severity.High), ("same.rule", "Still present", 443, Severity.Low));
        baseline.Apply(new PortFound(new PortRecord { HostIp = "192.0.2.10", Port = 22, Proto = "tcp", State = "open", Service = "ssh", Banner = "OpenSSH_7.4", Risk = Severity.Low }));
        string path = Path.Combine(c.TempDir, "baseline.tzs");
        SessionFile.Write(path, baseline.ToFile());

        var shell = new TestShell();
        var current = Build(("same.rule", "Still present", 443, Severity.Low), ("new.rule", "Newly seen", 8080, Severity.Medium));
        foreach (var f in current.Findings.Items) shell.Session.Findings.Add(f);
        shell.Session.Ports.Add(new PortRecord { HostIp = "192.0.2.10", Port = 22, Proto = "tcp", State = "open", Service = "ssh", Banner = "OpenSSH_9.6", Risk = Severity.Low });

        using var view = new CompareView(shell);
        var grid = Find<GridView>(view).Single();
        c.Equal("no rows without baseline", 0, grid.Source!.Count);
        c.Check("missing baseline file reported", !view.LoadBaseline(Path.Combine(c.TempDir, "missing.tzs")) && shell.Notices == 1);
        string bad = Path.Combine(c.TempDir, "bad.tzs");
        File.WriteAllText(bad, "{ not json");
        c.Check("invalid baseline reported", !view.LoadBaseline(bad) && shell.Notices == 2);
        c.Equal("failed load keeps no baseline", 0, grid.Source.Count);

        c.Check("baseline loads", view.LoadBaseline(path));
        c.Equal("baseline path remembered", path, shell.Settings.LastCompareBaseline);
        c.Equal("all observations listed", 4, grid.Source.Count);
        var rows = Enumerable.Range(0, grid.Source.Count).Select(i => (ComparisonRow)grid.Source.ItemAt(i)).ToList();
        c.Check("new finding shown", rows.Any(r => r.Name == "Newly seen" && r.Change == "New"));
        c.Check("absent finding not claimed fixed", rows.Any(r => r.Name == "Fixed elsewhere" && r.Change == "Not observed"));
        c.Check("unchanged finding shown", rows.Any(r => r.Name == "Still present" && r.Change == "Unchanged"));
        c.Check("banner change shown", rows.Any(r => r.Kind == "Service" && r.Change == "Changed"));

        var combos = Find<SkinCombo>(view).ToList();
        combos[1].SelectedIndex = combos[1].Items.IndexOf("New");
        c.Equal("change filter applies", 1, grid.Source.Count);
        combos[0].SelectedIndex = combos[0].Items.IndexOf("Service");
        c.Equal("type and change filters combine", 0, grid.Source.Count);
        combos[1].SelectedIndex = 0;
        c.Equal("type filter alone", 1, grid.Source.Count);
        combos[0].SelectedIndex = 0;

        shell.Session.Findings.Add(F(99, "late.rule", "Found later", 9000, Severity.Low));
        view.SyncData();
        c.Equal("current scan changes refresh comparison", 5, grid.Source.Count);

        Find<SkinButton>(view).Single(b => b.Caption == "Clear").PerformClick();
        c.Equal("clear removes rows", 0, grid.Source.Count);
        view.SyncData();
        c.Equal("cleared view stays empty after sync", 0, grid.Source.Count);
    }

    private static Session Build(params (string rule, string title, int port, Severity severity)[] findings)
    {
        var s = new Session { Target = "example.test", Profile = "Quick Audit" };
        int id = 1;
        foreach (var (rule, title, port, severity) in findings) s.Apply(new FindingFound(F(id++, rule, title, port, severity)));
        return s;
    }

    private static Finding F(int id, string rule, string title, int port, Severity severity) => new()
    {
        Id = id, RuleId = rule, Severity = severity, Title = title, Host = "192.0.2.10", Port = port, Proto = "tcp", Cwe = 200,
        Description = "Example", Evidence = "Example", Remediation = "Fix it.", Product = "OpenSSH 7.4", Cves = ["CVE-2023-0001"], Cvss = 5.3,
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
        public int Notices { get; private set; }
        public Session Session { get; } = new();
        public AppSettings Settings { get; } = new();
        public void ExportReport(ExportFormat format) { }
        public void UseCustomProfile() { }
        public void Notify(string title, string text, IconId icon = IconId.InfoMark) => Notices++;
        public void NavigateTo(int module) { }
        public void OpenInWorkbench(string method, string url) { }
        public void SelectHostInPortAudit(string ip) { }
        public void LogUser(string source, string text) { }
    }
}
#endif
