using System.Globalization;
using System.Text;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Data;

/// <summary>
/// One unit of remediation work: the same fix for the same issue, wherever it was seen. Ten hosts with the same
/// outdated OpenSSH are one ticket for whoever patches them, not ten.
/// </summary>
internal sealed class PlanItem
{
    public required int Rank { get; init; }
    public required string Title { get; init; }
    public required string Action { get; init; }
    public required PriorityTier Tier { get; init; }
    public required double Score { get; init; }
    public required Severity Severity { get; init; }
    public required IReadOnlyList<Finding> Findings { get; init; }
    /// <summary>Distinct "host:port/proto" locations, in host order.</summary>
    public required IReadOnlyList<string> Endpoints { get; init; }
    public required IReadOnlyList<string> Hosts { get; init; }
    public required IReadOnlyList<string> Cves { get; init; }
    public DateOnly? Due { get; init; }
    public required string DueBasis { get; init; }
    public bool Overdue { get; init; }
    public bool Kev { get; init; }
    public bool Ransomware { get; init; }
    public double? Epss { get; init; }
    public int Confirmed { get; init; }
    /// <summary>Every finding behind the item is tentative and unconfirmed: check before anyone schedules downtime.</summary>
    public bool NeedsVerification { get; init; }

    public string TierText => RemediationPlan.TierName(Tier);
    public string DueText => Due is DateOnly d ? d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : "-";
    public string AffectedText => Endpoints.Count == 1 ? Endpoints[0] : $"{Endpoints.Count} endpoints on {Hosts.Count} host(s)";
}

/// <summary>
/// Turns the open findings into an ordered work list with target dates. Dates are a starting point for the
/// owner of the systems: they come from a fixed window per priority tier, or from CISA when it set an earlier one.
/// </summary>
internal sealed class RemediationPlan
{
    private RemediationPlan(IReadOnlyList<PlanItem> items, DateOnly baseDate, DateOnly today, int open, int closed)
    {
        Items = items;
        BaseDate = baseDate;
        Today = today;
        OpenFindings = open;
        ClosedFindings = closed;
    }

    public IReadOnlyList<PlanItem> Items { get; }
    /// <summary>Day the clock starts: the scan start, or today when no scan has run.</summary>
    public DateOnly BaseDate { get; }
    public DateOnly Today { get; }
    public int OpenFindings { get; }
    /// <summary>Findings left out because they were accepted or marked false positive.</summary>
    public int ClosedFindings { get; }

    public int Count(PriorityTier tier) => Items.Count(i => i.Tier == tier);
    public int OverdueCount => Items.Count(i => i.Overdue);

    public static string TierName(PriorityTier tier) => tier switch
    {
        PriorityTier.FixNow => "Fix now",
        PriorityTier.FixNext => "Fix next",
        PriorityTier.Planned => "Planned",
        _ => "Monitor",
    };

    /// <summary>Remediation window per tier, in days from the scan. Monitor items get no deadline.</summary>
    public static int? TargetDays(PriorityTier tier) => tier switch
    {
        PriorityTier.FixNow => 7,
        PriorityTier.FixNext => 30,
        PriorityTier.Planned => 90,
        _ => null,
    };

    public static bool IsClosed(Finding f) => f.Status is FindingStatus.Accepted or FindingStatus.FalsePositive;

    /// <summary>Target date for a single finding and the reason for it.</summary>
    public static (DateOnly? Due, string Basis) DueFor(Finding f, PriorityScore priority, DateOnly baseDate)
    {
        DateOnly? due = null;
        string basis;
        if (TargetDays(priority.Tier) is int days)
        {
            due = baseDate.AddDays(days);
            basis = $"{TierName(priority.Tier)}: {days} days from {baseDate:yyyy-MM-dd}";
        }
        else basis = "No deadline; review at the next assessment";
        if (f.Threat is { Kev: true, KevDueDate: DateOnly kevDue } && (due is null || kevDue < due))
        {
            due = kevDue;
            basis = "CISA KEV due date" + (string.IsNullOrWhiteSpace(f.Threat.KevCve) ? string.Empty : $" for {f.Threat.KevCve}");
        }
        return (due, basis);
    }

    public static RemediationPlan Build(Session session, IEnumerable<Finding>? findings = null, DateOnly? today = null)
    {
        ArgumentNullException.ThrowIfNull(session);
        var now = today ?? DateOnly.FromDateTime(DateTime.Now);
        var baseDate = session.StartedAt is DateTime started ? DateOnly.FromDateTime(started) : now;
        var all = (findings ?? session.Findings.Items).ToList();
        var open = all.Where(f => !IsClosed(f)).ToList();

        var groups = open
            .Select(f => (Finding: f, Priority: session.PriorityOf(f)))
            .GroupBy(x => GroupKey(x.Finding), StringComparer.Ordinal)
            .Select(g => Item(g.ToList(), baseDate, now))
            .OrderBy(i => i.Tier)
            .ThenByDescending(i => i.Score)
            .ThenBy(i => i.Due ?? DateOnly.MaxValue)
            .ThenByDescending(i => i.Endpoints.Count)
            .ThenByDescending(i => i.Severity)
            .ThenBy(i => i.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var ranked = new List<PlanItem>(groups.Count);
        for (int i = 0; i < groups.Count; i++)
        {
            var g = groups[i];
            ranked.Add(new PlanItem
            {
                Rank = i + 1, Title = g.Title, Action = g.Action, Tier = g.Tier, Score = g.Score, Severity = g.Severity,
                Findings = g.Findings, Endpoints = g.Endpoints, Hosts = g.Hosts, Cves = g.Cves, Due = g.Due, DueBasis = g.DueBasis,
                Overdue = g.Overdue, Kev = g.Kev, Ransomware = g.Ransomware, Epss = g.Epss, Confirmed = g.Confirmed, NeedsVerification = g.NeedsVerification,
            });
        }
        return new RemediationPlan(ranked, baseDate, now, open.Count, all.Count - open.Count);
    }

    // Same check plus the same advice means the same fix. The advice is part of the key because a rule that
    // gives version-specific guidance should not have two different upgrades folded into one line.
    private static string GroupKey(Finding f)
    {
        string identity = f.RuleId.Trim().Length > 0 ? f.RuleId.Trim().ToLowerInvariant() : FindingDetails.Slug(f.Title);
        return identity + "\n" + Normalize(f.Remediation);
    }

    private static string Normalize(string text) => string.Join(' ', (text ?? string.Empty).Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).ToLowerInvariant();

    private static PlanItem Item(List<(Finding Finding, PriorityScore Priority)> group, DateOnly baseDate, DateOnly today)
    {
        var lead = group.OrderByDescending(x => x.Priority.Score).ThenByDescending(x => x.Finding.Severity).ThenBy(x => x.Finding.Id).First();
        DateOnly? due = null;
        string basis = "No deadline; review at the next assessment";
        foreach (var (f, p) in group)
        {
            var (d, why) = DueFor(f, p, baseDate);
            if (d is DateOnly day && (due is null || day < due)) { due = day; basis = why; }
        }
        var findings = group.Select(x => x.Finding)
            .OrderBy(f => Schemas.IpKey(f.Host)).ThenBy(f => f.Host, StringComparer.OrdinalIgnoreCase).ThenBy(f => f.Port).ToList();
        var endpoints = findings.Select(Endpoint).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var hosts = findings.Select(f => f.Host).Where(h => h.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        var threats = findings.Select(f => f.Threat).OfType<ThreatInfo>().ToList();
        var titles = findings.Select(f => f.Title).Distinct(StringComparer.OrdinalIgnoreCase).Count();
        string action = lead.Finding.Remediation.Trim();
        return new PlanItem
        {
            Rank = 0,
            Title = titles == 1 ? lead.Finding.Title : $"{lead.Finding.Title} (+{titles - 1} related)",
            Action = action.Length > 0 ? action : "Review the finding and apply the vendor's guidance.",
            Tier = lead.Priority.Tier,
            Score = lead.Priority.Score,
            Severity = findings.Max(f => f.Severity),
            Findings = findings,
            Endpoints = endpoints,
            Hosts = hosts,
            Cves = findings.SelectMany(f => f.Cves).Where(c => !string.IsNullOrWhiteSpace(c)).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList(),
            Due = due,
            DueBasis = basis,
            Overdue = due is DateOnly when && when < today,
            Kev = threats.Any(t => t.Kev),
            Ransomware = threats.Any(t => t.Kev && t.KevRansomware),
            Epss = threats.Select(t => t.Epss).Where(e => e is double v && double.IsFinite(v)).Max(),
            Confirmed = findings.Count(f => f.Status == FindingStatus.Confirmed),
            NeedsVerification = findings.All(f => f.NeedsVerification),
        };
    }

    public static string Endpoint(Finding f) =>
        f.Port > 0 ? $"{f.Host}:{f.Port.ToString(CultureInfo.InvariantCulture)}/{f.Proto}" : f.Host;

    /// <summary>One-line summary used at the top of every plan export.</summary>
    public string Summary()
    {
        if (Items.Count == 0)
            return OpenFindings == 0 && ClosedFindings == 0
                ? "No findings recorded, so there is nothing to plan."
                : $"No open work: all {ClosedFindings} finding(s) are accepted or marked false positive.";
        var sb = new StringBuilder();
        sb.Append(CultureInfo.InvariantCulture, $"{OpenFindings} open finding(s) grouped into {Items.Count} work item(s): ");
        sb.Append(CultureInfo.InvariantCulture, $"{Count(PriorityTier.FixNow)} fix now, {Count(PriorityTier.FixNext)} fix next, ");
        sb.Append(CultureInfo.InvariantCulture, $"{Count(PriorityTier.Planned)} planned, {Count(PriorityTier.Monitor)} monitor.");
        if (OverdueCount > 0) sb.Append(CultureInfo.InvariantCulture, $" {OverdueCount} item(s) are past their target date.");
        if (ClosedFindings > 0) sb.Append(CultureInfo.InvariantCulture, $" {ClosedFindings} accepted / false-positive finding(s) are left out.");
        return sb.ToString();
    }

    public const string Disclaimer =
        "Priority is an ordering aid built from severity, detection confidence, CISA KEV, FIRST EPSS and the host importance set in TryZ. "
        + "Target dates start from the scan date; adjust them to your own policy. Verify each issue applies before changing production systems.";

    public string Csv()
    {
        var sb = new StringBuilder();
        sb.Append("Rank,Priority,Score,Severity,Due,Due basis,Overdue,Verify first,Issue,Action,Affected,Endpoints,CVEs,KEV,EPSS,Finding ids\r\n");
        foreach (var i in Items)
        {
            sb.Append(i.Rank).Append(',')
              .Append(ReportWriter.Csv(i.TierText)).Append(',')
              .Append(i.Score.ToString("0", CultureInfo.InvariantCulture)).Append(',')
              .Append(ReportWriter.Csv(i.Severity.ToString())).Append(',')
              .Append(i.Due is DateOnly d ? d.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) : string.Empty).Append(',')
              .Append(ReportWriter.Csv(i.DueBasis)).Append(',')
              .Append(i.Overdue ? "yes" : "no").Append(',')
              .Append(i.NeedsVerification ? "yes" : "no").Append(',')
              .Append(ReportWriter.Csv(i.Title)).Append(',')
              .Append(ReportWriter.Csv(i.Action)).Append(',')
              .Append(i.Endpoints.Count).Append(',')
              .Append(ReportWriter.Csv(string.Join("; ", i.Endpoints))).Append(',')
              .Append(ReportWriter.Csv(string.Join("; ", i.Cves))).Append(',')
              .Append(i.Kev ? "yes" : "no").Append(',')
              .Append(i.Epss is double e ? e.ToString("0.0000", CultureInfo.InvariantCulture) : string.Empty).Append(',')
              .Append(ReportWriter.Csv(string.Join(" ", i.Findings.Select(f => f.Id.ToString(CultureInfo.InvariantCulture))))).Append("\r\n");
        }
        return sb.ToString();
    }

    /// <summary>Plain data for the JSON export.</summary>
    public object ToData() => new
    {
        baseDate = BaseDate.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
        openFindings = OpenFindings,
        closedFindings = ClosedFindings,
        summary = Summary(),
        items = Items.Select(i => new
        {
            rank = i.Rank, priority = i.TierText, score = Math.Round(i.Score), severity = i.Severity.ToString(), title = i.Title,
            action = i.Action, due = i.Due?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture), dueBasis = i.DueBasis, overdue = i.Overdue,
            endpoints = i.Endpoints, cves = i.Cves, kev = i.Kev, verifyFirst = i.NeedsVerification, ransomware = i.Ransomware, epss = i.Epss, confirmed = i.Confirmed,
            findingIds = i.Findings.Select(f => f.Id).ToArray(),
        }).ToArray(),
    };
}
