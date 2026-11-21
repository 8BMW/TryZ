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
        var shell = new CheckShell();
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
        ImportanceChecks(c);
        return Task.CompletedTask;
    }

    private static void ImportanceChecks(CheckContext c)
    {
        var high = Finding(Severity.High);
        c.Equal("normal importance changes nothing", Prioritizer.Evaluate(high).Score, Prioritizer.Evaluate(high, AssetImportance.Normal).Score);
        c.Equal("high importance adds 8", 78d, Prioritizer.Evaluate(high, AssetImportance.High).Score);
        var critical = Prioritizer.Evaluate(high, AssetImportance.Critical);
        c.Equal("critical host lifts high to fix now", PriorityTier.FixNow, critical.Tier);
        c.Check("critical host is explained", critical.Reasons.Any(r => r.Contains("business critical")));
        c.Equal("low importance takes 10", 60d, Prioritizer.Evaluate(high, AssetImportance.Low).Score);
        var info = Finding(Severity.Info);
        c.Equal("low importance never goes below zero", 0d, Prioritizer.Evaluate(info, AssetImportance.Low).Score);
        high.Threat = new ThreatInfo { Kev = true };
        var kevLow = Prioritizer.Evaluate(high, AssetImportance.Low);
        c.Equal("low importance does not bury KEV", 85d, kevLow.Score);
        c.Check("KEV exception is explained", kevLow.Reasons.Any(r => r.Contains("foothold")));

        var s = new Session();
        s.SetImportance(" 192.0.2.5 ", AssetImportance.Critical);
        c.Equal("importance lookup trims and ignores case", AssetImportance.Critical, s.ImportanceOf("192.0.2.5"));
        int before = s.Findings.MutationVersion;
        s.SetImportance("WEB.example.test", AssetImportance.Low);
        c.Check("importance change touches findings", s.Findings.MutationVersion > before);
        c.Equal("hostnames are case-insensitive", AssetImportance.Low, s.ImportanceOf("web.EXAMPLE.test"));
        s.SetImportance("web.example.test", AssetImportance.Normal);
        c.Equal("normal is not stored", 1, s.Importance.Count);
        s.ResetResults();
        c.Equal("rescan keeps importance", AssetImportance.Critical, s.ImportanceOf("192.0.2.5"));

        var file = s.ToFile();
        file.Assets.Add(new AssetDto { Host = "", Importance = AssetImportance.High });
        file.Assets.Add(new AssetDto { Host = "x", Importance = (AssetImportance)42 });
        var loaded = new Session();
        loaded.LoadFrom(file, "copy.tzs");
        c.Equal("importance survives save and load", AssetImportance.Critical, loaded.ImportanceOf("192.0.2.5"));
        c.Equal("blank and unknown entries are ignored", 1, loaded.Importance.Count);
        loaded.Clear();
        c.Equal("new session forgets importance", 0, loaded.Importance.Count);

        string path = Path.Combine(c.TempDir, "importance.tzs");
        SessionFile.Write(path, s.ToFile());
        c.Check("importance written to session file", File.ReadAllText(path).Contains("\"Critical\"", StringComparison.Ordinal));
        c.Equal("session file reads importance back", AssetImportance.Critical, SessionFile.Read(path).Assets.Single().Importance);

        // The view: pick a host, raise it, watch it move up.
        var shell = new CheckShell();
        shell.Session.Findings.Add(new Finding { Id = 10, Severity = Severity.Medium, Title = "Alpha", Host = "192.0.2.10", Port = 80, Cwe = 0, Description = "", Evidence = "", Remediation = "Fix alpha." });
        shell.Session.Findings.Add(new Finding { Id = 11, Severity = Severity.Medium, Title = "Bravo", Host = "192.0.2.11", Port = 80, Cwe = 0, Description = "", Evidence = "", Remediation = "Fix bravo." });
        using var view = new RemediationView(shell);
        view.SyncData();
        var grid = Find<GridView>(view).Single();
        var combo = Find<SkinCombo>(view).Single();
        grid.SelectRow(1);
        var picked = (Finding)grid.SelectedItem!;
        c.Equal("combo shows current importance", (int)AssetImportance.Normal, combo.SelectedIndex);
        combo.SelectedIndex = (int)AssetImportance.Critical;
        c.Equal("combo sets host importance", AssetImportance.Critical, shell.Session.ImportanceOf(picked.Host));
        c.Check("raised host ranks first", ReferenceEquals(picked, grid.Source!.ItemAt(0)));
        c.Check("importance change is logged", shell.UserLog.Any(l => l.Contains(picked.Host) && l.Contains("critical")));
        grid.SelectRow(grid.Source.Count - 1);
        c.Equal("combo follows the selection", (int)AssetImportance.Normal, combo.SelectedIndex);
    }

    private static Finding Finding(Severity severity) => new()
    {
        Id = 1, Severity = severity, Title = "Example finding", Host = "example.test", Port = 443,
        Cwe = 200, Description = "Example", Evidence = "Example", Remediation = "Fix it.",
    };

    private static IEnumerable<T> Find<T>(Control root) where T : Control => CheckShell.Find<T>(root);
}
#endif
