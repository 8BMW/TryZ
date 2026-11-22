using System.Globalization;
using System.Net;
using System.Text;

namespace TryZ.Data;

/// <summary>
/// One consolidated remediation action: a single fix (identified by its guidance text) that resolves one or more
/// findings, with the hosts it affects and the highest priority among them. De-duplicating by guidance turns a long
/// finding list into a short, ordered worklist — "fix this once, here is everywhere it applies".
/// </summary>
internal sealed record RemediationAction(
    int Rank,
    string Category,
    string Guidance,
    Severity MaxSeverity,
    PriorityTier Tier,
    double MaxScore,
    IReadOnlyList<string> Hosts,
    IReadOnlyList<string> Cwes,
    IReadOnlyList<string> Cves,
    int FindingCount);

/// <summary>
/// Turns the findings of a scan into an ordered, de-duplicated remediation plan grouped by priority tier. Priority
/// reuses <see cref="Prioritizer"/> so the plan agrees with the Remediation view. The plan is an ordering aid, not a
/// guarantee of applicability — the same caveats as the per-finding score apply.
/// </summary>
internal sealed class RemediationPlan
{
    private RemediationPlan(IReadOnlyList<RemediationAction> actions, int findingsCovered, int[] tierFindingCounts)
    {
        Actions = actions;
        FindingsCovered = findingsCovered;
        TierFindingCounts = tierFindingCounts;
    }

    /// <summary>Consolidated actions, highest priority first.</summary>
    public IReadOnlyList<RemediationAction> Actions { get; }

    /// <summary>Number of individual findings the plan accounts for.</summary>
    public int FindingsCovered { get; }

    /// <summary>Finding counts indexed by <see cref="PriorityTier"/>.</summary>
    public int[] TierFindingCounts { get; }

    public IEnumerable<RemediationAction> InTier(PriorityTier tier) => Actions.Where(a => a.Tier == tier);

    /// <summary>
    /// Builds the plan from a set of findings. Accepted and false-positive findings are excluded unless
    /// <paramref name="includeClosed"/> is set. Findings are grouped by their remediation guidance (normalised), so a
    /// fix that appears across many hosts collapses to one action.
    /// </summary>
    public static RemediationPlan Build(IEnumerable<Finding> findings, bool includeClosed = false)
    {
        ArgumentNullException.ThrowIfNull(findings);
        var active = findings
            .Where(f => includeClosed || f.Status is not (FindingStatus.Accepted or FindingStatus.FalsePositive))
            .ToList();

        var groups = new Dictionary<string, Group>(StringComparer.Ordinal);
        foreach (var f in active)
        {
            string guidance = string.IsNullOrWhiteSpace(f.Remediation)
                ? "Review this finding and apply the relevant vendor or framework guidance."
                : f.Remediation.Trim();
            string key = Normalize(guidance);
            if (!groups.TryGetValue(key, out var g)) groups[key] = g = new Group(guidance);
            g.Add(f);
        }

        int[] tierCounts = new int[4];
        foreach (var f in active) tierCounts[(int)Prioritizer.Evaluate(f).Tier]++;

        var actions = groups.Values
            .OrderByDescending(g => g.MaxScore)
            .ThenByDescending(g => g.MaxSeverity)
            .ThenByDescending(g => g.Count)
            .Select((g, i) => g.ToAction(i + 1))
            .ToList();
        return new RemediationPlan(actions, active.Count, tierCounts);
    }

    /// <summary>Renders the plan as Markdown, suitable for appending to a report or exporting on its own.</summary>
    public string ToMarkdown(string? footer = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Remediation Plan").AppendLine();
        if (Actions.Count == 0)
        {
            sb.AppendLine("No active findings to remediate.");
            if (!string.IsNullOrWhiteSpace(footer)) sb.AppendLine().AppendLine(Md(footer!));
            return sb.ToString();
        }
        sb.Append("**").Append(Actions.Count).Append("** consolidated action(s) cover **").Append(FindingsCovered).AppendLine("** finding(s).  ");
        sb.Append("Fix now: ").Append(TierFindingCounts[(int)PriorityTier.FixNow])
          .Append("  |  Fix next: ").Append(TierFindingCounts[(int)PriorityTier.FixNext])
          .Append("  |  Planned: ").Append(TierFindingCounts[(int)PriorityTier.Planned])
          .Append("  |  Monitor: ").Append(TierFindingCounts[(int)PriorityTier.Monitor]).AppendLine();
        sb.AppendLine().AppendLine("Priority is a heuristic ordering aid; confirm each item applies to your environment before acting.").AppendLine();

        foreach (var tier in new[] { PriorityTier.FixNow, PriorityTier.FixNext, PriorityTier.Planned, PriorityTier.Monitor })
        {
            var items = InTier(tier).ToList();
            if (items.Count == 0) continue;
            sb.AppendLine().Append("## ").Append(TierTitle(tier)).Append(" (").Append(items.Count).AppendLine(" action(s))").AppendLine();
            foreach (var a in items)
            {
                sb.Append(a.Rank).Append(". **").Append(Md(a.Category)).Append("** — priority ").Append(a.MaxScore.ToString("0", CultureInfo.InvariantCulture))
                  .Append("/100, max severity ").Append(a.MaxSeverity).Append(", ").Append(a.FindingCount).AppendLine(a.FindingCount == 1 ? " finding" : " findings");
                sb.Append("   - Action: ").AppendLine(Md(a.Guidance));
                sb.Append("   - Affects: ").AppendLine(Md(a.Hosts.Count <= 8 ? string.Join(", ", a.Hosts) : string.Join(", ", a.Hosts.Take(8)) + $" +{a.Hosts.Count - 8} more"));
                if (a.Cwes.Count > 0) sb.Append("   - CWE: ").AppendLine(Md(string.Join(", ", a.Cwes)));
                if (a.Cves.Count > 0) sb.Append("   - CVE: ").AppendLine(Md(a.Cves.Count <= 10 ? string.Join(", ", a.Cves) : string.Join(", ", a.Cves.Take(10)) + $" +{a.Cves.Count - 10} more"));
            }
        }
        if (!string.IsNullOrWhiteSpace(footer)) sb.AppendLine().AppendLine(Md(footer!));
        return sb.ToString();
    }

    private static string TierTitle(PriorityTier tier) => tier switch
    {
        PriorityTier.FixNow => "Fix now",
        PriorityTier.FixNext => "Fix next",
        PriorityTier.Planned => "Planned",
        _ => "Monitor",
    };

    private static string Normalize(string guidance) =>
        string.Join(' ', guidance.ToLowerInvariant().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

    // Same conservative Markdown escaping as the structured report: external text is never passed through as markup.
    private static string Md(string value) => WebUtility.HtmlEncode(value ?? string.Empty)
        .Replace("\\", "\\\\", StringComparison.Ordinal).Replace("*", "\\*", StringComparison.Ordinal)
        .Replace("_", "\\_", StringComparison.Ordinal).Replace("[", "\\[", StringComparison.Ordinal)
        .Replace("]", "\\]", StringComparison.Ordinal).Replace("`", "\\`", StringComparison.Ordinal)
        .Replace("\r", "", StringComparison.Ordinal).Replace("\n", " ", StringComparison.Ordinal);

    private sealed class Group
    {
        private readonly List<string> _hosts = new();
        private readonly HashSet<string> _hostSet = new(StringComparer.OrdinalIgnoreCase);
        private readonly SortedSet<int> _cwes = new();
        private readonly HashSet<string> _cves = new(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, int> _categories = new(StringComparer.OrdinalIgnoreCase);

        public Group(string guidance) => Guidance = guidance;

        public string Guidance { get; }
        public Severity MaxSeverity { get; private set; } = Severity.Info;
        public double MaxScore { get; private set; }
        public int Count { get; private set; }

        public void Add(Finding f)
        {
            Count++;
            if (f.Severity > MaxSeverity) MaxSeverity = f.Severity;
            double score = Prioritizer.Evaluate(f).Score;
            if (score > MaxScore) MaxScore = score;
            if (f.Host.Length > 0 && _hostSet.Add(f.Host)) _hosts.Add(f.Host);
            if (f.Cwe > 0) _cwes.Add(f.Cwe);
            foreach (var c in f.Cves) _cves.Add(c);
            string cat = Category(f.Title);
            _categories[cat] = _categories.GetValueOrDefault(cat) + 1;
        }

        public RemediationAction ToAction(int rank) => new(
            rank,
            _categories.OrderByDescending(kv => kv.Value).ThenBy(kv => kv.Key, StringComparer.Ordinal).First().Key,
            Guidance,
            MaxSeverity,
            TierForScore(MaxScore),
            MaxScore,
            _hosts.Count == 0 ? new[] { "(not host-specific)" } : _hosts.ToArray(),
            _cwes.Select(c => $"CWE-{c}").ToArray(),
            _cves.OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToArray(),
            Count);

        /// <summary>The category shown for an action: the finding title up to the first ": " (drops the path/parameter suffix active checks add).</summary>
        private static string Category(string title)
        {
            if (string.IsNullOrWhiteSpace(title)) return "Finding";
            int at = title.IndexOf(": ", StringComparison.Ordinal);
            return (at > 0 ? title[..at] : title).Trim();
        }
    }

    // The plan's tier follows the group's worst priority score, consistent with Prioritizer's own thresholds.
    private static PriorityTier TierForScore(double score) =>
        score >= 85 ? PriorityTier.FixNow : score >= 60 ? PriorityTier.FixNext : score >= 30 ? PriorityTier.Planned : PriorityTier.Monitor;
}
