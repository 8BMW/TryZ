using System.Globalization;
using System.Text;
using TryZ.Engine;

namespace TryZ.Data;

/// <summary>One finding in the plan with its computed priority and 1-based rank.</summary>
internal sealed record PlanEntry(int Rank, Finding Finding, PriorityScore Priority);

/// <summary>Findings that share a check and a remediation, so one fix covers every affected endpoint.</summary>
internal sealed record PlanAction(PriorityTier Tier, double Score, string Title, string Remediation, IReadOnlyList<PlanEntry> Entries)
{
    public string TierText => Entries[0].Priority.TierText;
    public Severity Severity => Entries.Max(e => e.Finding.Severity);
    public IReadOnlyList<string> Cves => Entries.SelectMany(e => e.Finding.Cves).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase).ToList();
}

/// <summary>
/// Orders findings for remediation using <see cref="Prioritizer"/>. The plan is an ordering aid: it does not know asset
/// importance or local exposure, and accepted / false-positive findings are excluded unless asked for.
/// </summary>
internal static class RemediationPlan
{
    public static bool IsOpen(Finding f) => f.Status is not (FindingStatus.Accepted or FindingStatus.FalsePositive);

    /// <summary>Highest score first; ties by severity, then by discovery order, so the ranking is stable.</summary>
    public static List<PlanEntry> Rank(IEnumerable<Finding> findings, bool includeClosed)
    {
        ArgumentNullException.ThrowIfNull(findings);
        return findings.Where(f => f != null && (includeClosed || IsOpen(f)))
            .Select(f => (f, p: Prioritizer.Evaluate(f)))
            .OrderByDescending(x => x.p.Score).ThenByDescending(x => x.f.Severity).ThenBy(x => x.f.Id)
            .Select((x, i) => new PlanEntry(i + 1, x.f, x.p))
            .ToList();
    }

    /// <summary>Groups ranked entries by check identity and remediation text; each action takes its best entry's priority.</summary>
    public static List<PlanAction> Group(IReadOnlyList<PlanEntry> ranked)
    {
        ArgumentNullException.ThrowIfNull(ranked);
        return ranked
            .GroupBy(e => (Identity(e.Finding), Norm(e.Finding.Remediation)))
            .Select(g =>
            {
                var entries = g.OrderBy(e => e.Rank).ToList();
                var best = entries[0];
                return new PlanAction(best.Priority.Tier, best.Priority.Score, best.Finding.Title, best.Finding.Remediation, entries);
            })
            .OrderBy(a => a.Entries[0].Rank)
            .ToList();
    }

    public static List<PlanAction> Build(Session session, bool includeClosed) => Group(Rank(session.Findings.Items, includeClosed));

    public static string Markdown(Session session, bool includeClosed, string footer)
    {
        ArgumentNullException.ThrowIfNull(session);
        var actions = Build(session, includeClosed);
        static string Md(string? v) => StructuredReport.Md(v ?? string.Empty);
        var sb = new StringBuilder();
        sb.AppendLine("# Remediation Plan").AppendLine();
        sb.Append("**Target:** ").AppendLine(Md(session.Target)).Append("  \n**Profile:** ").AppendLine(Md(session.Profile));
        sb.Append("  \n**Generated:** ").AppendLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture));
        int findings = actions.Sum(a => a.Entries.Count);
        sb.Append("  \n**Scope:** ").Append(findings).Append(" finding(s) in ").Append(actions.Count).Append(" action(s)")
          .AppendLine(includeClosed ? ", including accepted and false-positive findings." : "; accepted and false-positive findings are excluded.");
        sb.AppendLine().AppendLine("> Scores are a 0-100 ordering aid built from reported severity, CISA KEV and FIRST EPSS. They are not CVSS scores or probabilities, and they do not account for asset importance or local exposure. Verify applicability before remediation.").AppendLine();
        if (actions.Count == 0)
        {
            sb.AppendLine("No findings to remediate.");
        }
        foreach (var tier in Enum.GetValues<PriorityTier>())
        {
            var inTier = actions.Where(a => a.Tier == tier).ToList();
            if (inTier.Count == 0) continue;
            sb.Append("## ").Append(inTier[0].TierText).Append(" (").Append(inTier.Count).AppendLine(")").AppendLine();
            foreach (var a in inTier)
            {
                int n = actions.IndexOf(a) + 1;
                sb.Append("### ").Append(n).Append(". ").AppendLine(Md(a.Title)).AppendLine();
                sb.Append("**Score:** ").Append(a.Score.ToString("0", CultureInfo.InvariantCulture)).Append("/100  \n**Severity:** ").Append(a.Severity).AppendLine("  ");
                if (a.Cves.Count > 0) sb.Append("**CVEs:** ").Append(Md(string.Join(", ", a.Cves))).AppendLine("  ");
                sb.AppendLine("**Affected:**").AppendLine();
                foreach (var e in a.Entries)
                    sb.Append("- ").Append(Md(Endpoint(e.Finding))).Append(" (").Append(Md(e.Finding.StatusText)).Append(", score ")
                      .Append(e.Priority.Score.ToString("0", CultureInfo.InvariantCulture)).AppendLine(")");
                sb.AppendLine().AppendLine("**Why this priority**").AppendLine();
                foreach (var reason in a.Entries[0].Priority.Reasons) sb.Append("- ").AppendLine(Md(reason));
                sb.AppendLine().AppendLine("**Recommended action**").AppendLine().AppendLine(Md(a.Remediation)).AppendLine();
            }
        }
        if (!string.IsNullOrEmpty(footer)) sb.AppendLine(Md(footer));
        return sb.ToString();
    }

    /// <summary>One row per finding, in rank order, with the action number that groups it.</summary>
    public static string Csv(Session session, bool includeClosed)
    {
        ArgumentNullException.ThrowIfNull(session);
        var actions = Build(session, includeClosed);
        var sb = new StringBuilder();
        sb.Append("Rank,Action,Priority,Score,Severity,Title,Host,Port,Protocol,Status,CVEs,KEV,EPSS,Remediation\r\n");
        var rows = actions.SelectMany((a, i) => a.Entries.Select(e => (action: i + 1, e))).OrderBy(x => x.e.Rank);
        foreach (var (action, e) in rows)
        {
            var f = e.Finding;
            sb.Append(e.Rank).Append(',').Append(action).Append(',')
              .Append(ReportWriter.Csv(e.Priority.TierText)).Append(',')
              .Append(e.Priority.Score.ToString("0", CultureInfo.InvariantCulture)).Append(',')
              .Append(ReportWriter.Csv(f.Severity.ToString())).Append(',')
              .Append(ReportWriter.Csv(f.Title)).Append(',')
              .Append(ReportWriter.Csv(f.Host)).Append(',')
              .Append(f.Port).Append(',')
              .Append(ReportWriter.Csv(f.Proto)).Append(',')
              .Append(ReportWriter.Csv(f.StatusText)).Append(',')
              .Append(ReportWriter.Csv(string.Join(" ", f.Cves))).Append(',')
              .Append(f.Threat == null ? "" : f.Threat.Kev ? "Yes" : "No").Append(',')
              .Append(f.Threat?.Epss is double epss && double.IsFinite(epss) ? epss.ToString("0.#####", CultureInfo.InvariantCulture) : "").Append(',')
              .Append(ReportWriter.Csv(f.Remediation)).Append("\r\n");
        }
        return sb.ToString();
    }

    private static string Endpoint(Finding f) =>
        f.Port > 0 ? $"{f.Host}:{f.Port}/{(string.IsNullOrWhiteSpace(f.Proto) ? "tcp" : f.Proto)}" : f.Host;

    private static string Identity(Finding f) => Norm(f.RuleId.Length > 0 ? f.RuleId : FindingDetails.Slug(f.Title));
    private static string Norm(string? text) => (text ?? string.Empty).Trim().ToUpperInvariant();
}
