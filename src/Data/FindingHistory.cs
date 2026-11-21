using TryZ.Engine;

namespace TryZ.Data;

/// <summary>What TryZ remembers about one issue across scans of the same estate.</summary>
internal sealed class HistoryEntry
{
    public required string Key { get; init; }
    public string Title { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public string Proto { get; set; } = "tcp";
    public int Port { get; set; }
    public Severity Severity { get; set; }
    public DateTime FirstSeen { get; set; }
    public DateTime LastSeen { get; set; }
    /// <summary>Set when a completed scan re-checked the same service and the issue was gone.</summary>
    public DateTime? ResolvedAt { get; set; }
    public int TimesSeen { get; set; }
    public int Reopened { get; set; }
    /// <summary>Triage decision from the last time it was seen; carried into the next scan.</summary>
    public FindingStatus Status { get; set; }

    public bool IsOpen => ResolvedAt == null && Status is not (FindingStatus.Accepted or FindingStatus.FalsePositive);
}

/// <summary>Outcome of folding one scan into the history.</summary>
internal readonly record struct ScanDelta(int New, int Recurring, int Reopened, int Resolved, int NotObserved);

internal readonly record struct HistoryStats(int Open, int Resolved, int Reopened, double? MeanDaysToResolve, int? OldestOpenDays, int Scans)
{
    public string Text()
    {
        var parts = new List<string> { $"{Open} open", $"{Resolved} resolved" };
        if (MeanDaysToResolve is double mttr) parts.Add($"mean time to resolve {mttr:0.#} day(s)");
        if (OldestOpenDays is int oldest && oldest > 0) parts.Add($"oldest open {oldest} day(s)");
        if (Reopened > 0) parts.Add($"{Reopened} reopened");
        return string.Join(", ", parts);
    }
}

/// <summary>
/// Remembers every issue by check, host and endpoint so a recurring finding keeps its original date, a fixed one is
/// counted as fixed only when TryZ could actually look again, and triage decisions survive a rescan.
/// </summary>
internal sealed class FindingHistory
{
    private readonly Dictionary<string, HistoryEntry> _entries = new(StringComparer.OrdinalIgnoreCase);
    private readonly SortedSet<DateTime> _scans = new();

    public IReadOnlyCollection<HistoryEntry> Entries => _entries.Values;
    public int ScanCount => _scans.Count;
    public int Version { get; private set; }

    public static string KeyOf(Finding f) => KeyOf(f.RuleId, f.Title, f.Host, f.Proto, f.Port);

    public static string KeyOf(string? ruleId, string? title, string? host, string? proto, int port)
    {
        string identity = string.IsNullOrWhiteSpace(ruleId) ? FindingDetails.Slug(title ?? string.Empty) : ruleId.Trim();
        string p = string.IsNullOrWhiteSpace(proto) ? "tcp" : proto.Trim();
        return $"{identity}|{(host ?? string.Empty).Trim()}|{p}/{port}".ToLowerInvariant();
    }

    public HistoryEntry? Get(Finding f) => _entries.TryGetValue(KeyOf(f), out var e) ? e : null;

    public void Clear()
    {
        _entries.Clear();
        _scans.Clear();
        Version++;
    }

    /// <summary>
    /// Notes findings as seen at <paramref name="when"/> without judging anything that's missing. Used when results are
    /// about to be replaced and when older sessions are imported.
    /// </summary>
    public void Absorb(IEnumerable<Finding> findings, DateTime when)
    {
        bool any = false;
        foreach (var f in findings)
        {
            any = true;
            Touch(f, when, out _);
        }
        if (any) _scans.Add(when);
        Version++;
    }

    /// <summary>
    /// Folds a finished (or stopped) scan in. Issues not seen again are marked resolved only when the scan completed and
    /// the same service was up and checked; otherwise they stay open as "not observed", because a narrower profile or a
    /// filtered port proves nothing.
    /// </summary>
    public ScanDelta Record(IReadOnlyList<Finding> findings, IEnumerable<PortRecord> ports, IEnumerable<HostRecord> hosts, DateTime when, bool completed)
    {
        int created = 0, recurring = 0, reopened = 0, resolved = 0, missing = 0;
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var f in findings)
        {
            if (!seen.Add(KeyOf(f))) continue;
            switch (Touch(f, when, out bool wasResolved))
            {
                case true when wasResolved: reopened++; break;
                case true: recurring++; break;
                default: created++; break;
            }
        }
        var live = hosts.Where(h => !string.Equals(h.State, "Down", StringComparison.OrdinalIgnoreCase)).Select(h => h.Ip).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var open = ports.Where(p => p.State == "open").Select(p => $"{p.HostIp}|{p.Proto}/{p.Port}".ToLowerInvariant()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var e in _entries.Values)
        {
            if (seen.Contains(e.Key) || e.ResolvedAt != null || e.LastSeen >= when) continue;
            // A false positive or accepted risk going quiet isn't a fix; counting it would flatter MTTR.
            if (e.Status is FindingStatus.Accepted or FindingStatus.FalsePositive) continue;
            bool checkedAgain = completed && live.Contains(e.Host)
                && (e.Port == 0 ? e.Proto == "tcp" : open.Contains($"{e.Host}|{e.Proto}/{e.Port}".ToLowerInvariant()));
            if (checkedAgain)
            {
                e.ResolvedAt = when;
                resolved++;
            }
            else missing++;
        }
        _scans.Add(when);
        Version++;
        return new ScanDelta(created, recurring, reopened, resolved, missing);
    }

    // True when the issue was already known; wasResolved says it had been fixed and came back.
    private bool Touch(Finding f, DateTime when, out bool wasResolved)
    {
        string key = KeyOf(f);
        wasResolved = false;
        if (_entries.TryGetValue(key, out var e))
        {
            if (e.ResolvedAt is DateTime fixedAt && when > fixedAt)
            {
                wasResolved = true;
                e.ResolvedAt = null;
                e.Reopened++;
            }
            if (when > e.LastSeen) { e.LastSeen = when; e.TimesSeen++; }
            if (when < e.FirstSeen) e.FirstSeen = when;
            Update(e, f);
            return true;
        }
        e = new HistoryEntry { Key = key, FirstSeen = when, LastSeen = when, TimesSeen = 1 };
        Update(e, f);
        _entries[key] = e;
        return false;
    }

    private static void Update(HistoryEntry e, Finding f)
    {
        e.Title = f.Title;
        e.Host = f.Host;
        e.Proto = string.IsNullOrWhiteSpace(f.Proto) ? "tcp" : f.Proto;
        e.Port = f.Port;
        e.Severity = f.Severity;
        e.Status = f.Status;
    }

    /// <summary>Keeps triage decisions in step with the current findings without counting a new sighting.</summary>
    public void SyncStatus(IEnumerable<Finding> findings)
    {
        foreach (var f in findings)
            if (_entries.TryGetValue(KeyOf(f), out var e)) e.Status = f.Status;
    }

    public HistoryStats Stats(DateTime now)
    {
        var resolved = _entries.Values.Where(e => e.ResolvedAt != null).ToList();
        var open = _entries.Values.Where(e => e.IsOpen).ToList();
        double? mttr = resolved.Count == 0 ? null : resolved.Average(e => Math.Max(0, (e.ResolvedAt!.Value - e.FirstSeen).TotalDays));
        int? oldest = open.Count == 0 ? null : (int)Math.Floor(open.Max(e => Math.Max(0, (now - e.FirstSeen).TotalDays)));
        return new HistoryStats(open.Count, resolved.Count, _entries.Values.Sum(e => e.Reopened), mttr, oldest, _scans.Count);
    }

    public List<HistoryDto> ToDto() => _entries.Values.OrderBy(e => e.FirstSeen).ThenBy(e => e.Key, StringComparer.Ordinal).Select(e => new HistoryDto
    {
        Key = e.Key, Title = e.Title, Host = e.Host, Proto = e.Proto, Port = e.Port, Severity = e.Severity, FirstSeen = e.FirstSeen,
        LastSeen = e.LastSeen, ResolvedAt = e.ResolvedAt, TimesSeen = e.TimesSeen, Reopened = e.Reopened, Status = e.Status,
    }).ToList();

    public List<DateTime> ScanTimes => _scans.ToList();

    /// <summary>Merges saved history: earliest first sighting, latest last sighting, and the newer verdict on resolution.</summary>
    public void Merge(IEnumerable<HistoryDto> items, IEnumerable<DateTime>? scans = null)
    {
        foreach (var d in items)
        {
            if (d == null || string.IsNullOrWhiteSpace(d.Key) || d.FirstSeen == default) continue;
            var last = d.LastSeen < d.FirstSeen ? d.FirstSeen : d.LastSeen;
            if (!_entries.TryGetValue(d.Key, out var e))
            {
                _entries[d.Key] = new HistoryEntry
                {
                    Key = d.Key, Title = d.Title ?? string.Empty, Host = d.Host ?? string.Empty, Proto = string.IsNullOrWhiteSpace(d.Proto) ? "tcp" : d.Proto,
                    Port = d.Port, Severity = (Severity)Math.Clamp((int)d.Severity, 0, 4), FirstSeen = d.FirstSeen, LastSeen = last,
                    ResolvedAt = d.ResolvedAt is DateTime r && r >= d.FirstSeen ? r : null, TimesSeen = Math.Max(1, d.TimesSeen),
                    Reopened = Math.Max(0, d.Reopened), Status = Enum.IsDefined(d.Status) ? d.Status : FindingStatus.New,
                };
                continue;
            }
            if (d.FirstSeen < e.FirstSeen) e.FirstSeen = d.FirstSeen;
            if (last > e.LastSeen)
            {
                e.LastSeen = last;
                e.ResolvedAt = d.ResolvedAt;
                if (Enum.IsDefined(d.Status)) e.Status = d.Status;
            }
            else if (last == e.LastSeen && d.ResolvedAt is DateTime r2 && e.ResolvedAt == null) e.ResolvedAt = r2;
            e.TimesSeen = Math.Max(e.TimesSeen, d.TimesSeen);
            e.Reopened = Math.Max(e.Reopened, d.Reopened);
        }
        if (scans != null) foreach (var s in scans) if (s != default) _scans.Add(s);
        Version++;
    }
}
