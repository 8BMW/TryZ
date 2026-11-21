#if DEBUG
using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

/// <summary>Finding history across scans: first sighting, triage carried over, careful resolution, reopen, MTTR.</summary>
internal sealed class HistoryChecks : ICheckSuite
{
    public string Name => "history";

    private static readonly DateTime Mar1 = new(2026, 3, 1, 10, 0, 0), Mar15 = new(2026, 3, 15, 10, 0, 0),
        Apr1 = new(2026, 4, 1, 10, 0, 0), Apr20 = new(2026, 4, 20, 10, 0, 0);

    public Task RunAsync(CheckContext c)
    {
        var s = new Session { Target = "192.0.2.0/24" };

        // Scan 1: three issues.
        Scan(s, Mar1, ports: [("192.0.2.1", 22), ("192.0.2.1", 443), ("192.0.2.2", 80)],
            F(1, "ssh-weak-kex", "192.0.2.1", 22, Severity.Medium), F(2, "hsts-missing", "192.0.2.1", 443, Severity.Low), F(3, "dir-listing", "192.0.2.2", 80, Severity.Low));
        var d1 = s.RecordScan(completed: true);
        c.Check("first scan: everything is new", d1 is { New: 3, Recurring: 0, Resolved: 0 });
        c.Equal("one scan known", 1, s.History.ScanCount);

        // Analyst triage between scans.
        s.Findings.Items.Single(f => f.RuleId == "hsts-missing").Status = FindingStatus.FalsePositive;

        // Scan 2: dir listing gone from a service that is still up; the rest remain.
        Scan(s, Mar15, ports: [("192.0.2.1", 22), ("192.0.2.1", 443), ("192.0.2.2", 80)],
            F(1, "ssh-weak-kex", "192.0.2.1", 22, Severity.Medium), F(2, "HSTS-Missing", "192.0.2.1", 443, Severity.Low));
        c.Equal("triage carries into the rescan", FindingStatus.FalsePositive, s.Findings.Items.Single(f => f.Port == 443).Status);
        var d2 = s.RecordScan(completed: true);
        c.Check("second scan: two recurring, one resolved", d2 is { New: 0, Recurring: 2, Resolved: 1 }, d2.ToString());
        var dir = s.History.Entries.Single(e => e.Key.StartsWith("dir-listing", StringComparison.Ordinal));
        c.Equal("resolution dated to the scan that re-checked it", Mar15, dir.ResolvedAt);
        var ssh = s.History.Entries.Single(e => e.Key.StartsWith("ssh-weak-kex", StringComparison.Ordinal));
        c.Check("recurring keeps its first sighting", ssh.FirstSeen == Mar1 && ssh.LastSeen == Mar15 && ssh.TimesSeen == 2);

        // Plan dates come from the first sighting, not the latest scan.
        var plan = RemediationPlan.Build(s, today: new DateOnly(2026, 3, 16));
        var sshItem = plan.Items.Single(i => i.Title == "ssh-weak-kex");
        c.Equal("due counts from first seen", new DateOnly(2026, 3, 1).AddDays(90), sshItem.Due);
        c.Equal("item knows when it was first seen", new DateOnly(2026, 3, 1), sshItem.FirstSeen);
        var stats = s.History.Stats(Mar15.AddDays(1));
        c.Check("MTTR from the resolved issue", stats.MeanDaysToResolve is double m && Math.Abs(m - 14) < 0.01, $"{stats.MeanDaysToResolve}");
        c.Check("false positive doesn't count as open", stats.Open == 1, $"{stats.Open}");
        c.Check("plan summary shows the trend", plan.Summary().Contains("Across 2 scans") && plan.Summary().Contains("mean time to resolve 14"), plan.Summary());

        // Scan 3, stopped early: the fixed issue is back, ssh wasn't reached.
        Scan(s, Apr1, ports: [("192.0.2.2", 80)], F(3, "dir-listing", "192.0.2.2", 80, Severity.Low));
        var d3 = s.RecordScan(completed: false);
        c.Check("stopped scan resolves nothing", d3 is { Resolved: 0, Reopened: 1 }, d3.ToString());
        c.Check("ssh still open after a partial scan", ssh.ResolvedAt == null);
        c.Check("reopen is counted", dir.ResolvedAt == null && dir.Reopened == 1);
        c.Check("reopened shows on the plan", RemediationPlan.Build(s).Items.Single(i => i.Title == "dir-listing").Reopened);

        // Scan 4, completed but port 22 wasn't open this time (closed, filtered or outside the profile).
        Scan(s, Apr20, ports: [("192.0.2.1", 443)]);
        var d4 = s.RecordScan(completed: true);
        c.Check("unreached service is not claimed fixed", ssh.ResolvedAt == null && d4.NotObserved >= 1, d4.ToString());
        c.Check("dir listing on a down host is not claimed fixed", dir.ResolvedAt == null);

        // Save and load.
        var file = s.ToFile();
        c.Equal("history saved", s.History.Entries.Count, file.History.Count);
        c.Equal("scan times saved", 4, file.Scans.Count);
        var back = new Session();
        back.LoadFrom(file, "h.tzs");
        c.Equal("history loaded", s.History.Entries.Count, back.History.Entries.Count);
        c.Check("load keeps dates and counts", back.History.Entries.Single(e => e.Key.StartsWith("ssh", StringComparison.Ordinal)) is { FirstSeen: var fs, TimesSeen: 2 } && fs == Mar1);
        back.Clear();
        c.Equal("new session forgets history", 0, back.History.Entries.Count);

        // Sessions from before history: the findings become one past scan.
        var legacy = new SessionFile { StartedAt = Mar1, Findings = [new FindingDto { Id = 9, RuleId = "old-issue", Title = "Old", Host = "192.0.2.9", Port = 21, Proto = "tcp" }] };
        var loaded = new Session();
        loaded.LoadFrom(legacy, "old.tzs");
        c.Check("old file seeds history", loaded.History.Entries.Single().FirstSeen == Mar1);

        // Import into a fresh session.
        var fresh = new Session();
        Scan(fresh, Apr20, ports: [], F(1, "ssh-weak-kex", "192.0.2.1", 22, Severity.Medium));
        fresh.ImportHistory(file);
        c.Equal("import brings the first sighting", Mar1, fresh.History.Get(fresh.Findings.Items[0])!.FirstSeen);
        fresh.ImportHistory(legacy);
        c.Check("import of an old file adds its findings", fresh.History.Entries.Any(e => e.Key.StartsWith("old-issue", StringComparison.Ordinal)));
        c.Equal("history keys ignore case", FindingHistory.KeyOf("ABC", "t", "Host.EXAMPLE", "TCP", 1), FindingHistory.KeyOf("abc", "x", "host.example", "tcp", 1));
        return Task.CompletedTask;
    }

    private static void Scan(Session s, DateTime when, (string Ip, int Port)[] ports, params Finding[] findings)
    {
        s.ResetResults();
        s.StartedAt = when;
        foreach (var ip in ports.Select(p => p.Ip).Concat(findings.Select(f => f.Host)).Distinct())
            s.Apply(new HostFound(new HostRecord { Ip = ip, Hostname = string.Empty, OsGuess = string.Empty, LatencyMs = 1, Ttl = 64, Role = string.Empty }));
        foreach (var (ip, port) in ports)
            s.Apply(new PortFound(new PortRecord { HostIp = ip, Port = port, Proto = "tcp", State = "open", Service = "svc", Banner = string.Empty, Risk = Severity.Info }));
        foreach (var f in findings) s.Apply(new FindingFound(f));
    }

    private static Finding F(int id, string rule, string host, int port, Severity severity) => new()
    {
        Id = id, RuleId = rule, Title = rule.ToLowerInvariant(), Host = host, Port = port, Severity = severity, Cwe = 0,
        Description = string.Empty, Evidence = string.Empty, Remediation = "Fix " + rule.ToLowerInvariant() + ".",
    };
}
#endif
