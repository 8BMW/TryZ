using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;

namespace TryZ.Data;

internal static class StructuredReport
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private static IEnumerable<Finding> Findings(Session s) => s.Findings.Items.OrderByDescending(f => f.Severity).ThenBy(f => f.Id);
    private static object FindingData(Finding f) => new
    {
        id = f.Id, ruleId = f.RuleId, severity = f.Severity.ToString(), title = f.Title, host = f.Host,
        port = f.Port, protocol = f.Proto, cwe = f.Cwe > 0 ? f.CweText : null, status = f.StatusText,
        f.Description, f.Evidence, f.Remediation, f.Product, cves = f.Cves, f.Cvss, f.CvssVector,
        threat = f.Threat == null ? null : new { f.Threat.Kev, f.Threat.KevCve, f.Threat.KevDateAdded, f.Threat.KevDueDate, f.Threat.KevRansomware, f.Threat.KevAction, f.Threat.Epss, f.Threat.EpssPercentile },
        fingerprint = f.Fingerprint,
    };

    public static string FindingsJson(Session s) => JsonSerializer.Serialize(new
    {
        format = "TryZ findings", version = 1, generatedAt = DateTimeOffset.UtcNow, target = s.Target, profile = s.Profile,
        findings = Findings(s).Select(FindingData).ToArray(),
    }, JsonOptions);

    public static string Sarif(Session s)
    {
        var findings = Findings(s).ToArray();
        string RuleId(Finding f) => string.IsNullOrWhiteSpace(f.RuleId) ? "tryz-" + f.Id.ToString(CultureInfo.InvariantCulture) : f.RuleId;
        var rules = findings.GroupBy(RuleId, StringComparer.Ordinal).Select(g =>
        {
            var f = g.First();
            return new
            {
                id = g.Key, shortDescription = new { text = f.Title }, fullDescription = new { text = f.Description.Length == 0 ? f.Title : f.Description },
                help = new { text = f.Remediation.Length == 0 ? "Review this finding." : f.Remediation },
                properties = new { tags = (f.Cwe > 0 ? new[] { f.CweText } : Array.Empty<string>()).Concat(f.Cves).Distinct().ToArray() },
            };
        }).ToArray();
        var results = findings.Select(f => new
        {
            ruleId = RuleId(f),
            level = f.Severity switch { Severity.High or Severity.Critical => "error", Severity.Medium => "warning", _ => "note" },
            message = new { text = f.Title },
            locations = string.IsNullOrWhiteSpace(f.Host) ? Array.Empty<object>() : new object[] { new { logicalLocations = new[] { new { name = f.Host, fullyQualifiedName = $"{f.Host}:{f.Port}/{f.Proto}", kind = "resource" } } } },
            partialFingerprints = new Dictionary<string, string> { ["tryz/v1"] = f.Fingerprint },
            properties = new { tryzStatus = f.StatusText, severity = f.Severity.ToString(), f.Evidence, f.Remediation, f.Product, f.Cves, f.Cvss, f.CvssVector, f.Threat, f.Port, protocol = f.Proto },
        }).ToArray();
        return JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["$schema"] = "https://json.schemastore.org/sarif-2.1.0.json",
            ["version"] = "2.1.0",
            ["runs"] = new[] { new { tool = new { driver = new { name = "TryZ Security Suite", rules } }, results } },
        }, JsonOptions);
    }

    // Treat external content as text; never pass HTML through to a rendered report.
    private static string Md(string value) => WebUtility.HtmlEncode(value ?? string.Empty)
        .Replace("\\", "\\\\", StringComparison.Ordinal).Replace("*", "\\*", StringComparison.Ordinal)
        .Replace("_", "\\_", StringComparison.Ordinal).Replace("[", "\\[", StringComparison.Ordinal)
        .Replace("]", "\\]", StringComparison.Ordinal).Replace("`", "\\`", StringComparison.Ordinal)
        .Replace("\r", "", StringComparison.Ordinal).Replace("\n", "  \n", StringComparison.Ordinal);

    public static string Markdown(Session s, string footer)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Security Assessment Report").AppendLine();
        sb.Append("**Target:** ").AppendLine(Md(s.Target)).Append("**Profile:** ").AppendLine(Md(s.Profile));
        sb.Append("**Started:** ").AppendLine(s.StartedAt?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "Unknown");
        sb.Append("**Summary:** ").Append(s.Hosts.Items.Count).Append(" hosts, ").Append(s.Ports.Items.Count(p => p.State == "open")).Append(" open services, ").Append(s.FindingCount).AppendLine(" findings.");
        sb.AppendLine().AppendLine("Results cover only the checks performed; absence of a finding does not prove absence of a vulnerability.");
        sb.AppendLine().AppendLine("## Hosts and open services").AppendLine();
        foreach (var h in s.Hosts.Items) sb.Append("- ").Append(Md(h.Ip)).Append(" — ").Append(Md(h.Hostname)).Append(" — ").AppendLine(Md(h.OsGuess));
        foreach (var p in s.Ports.Items.Where(p => p.State == "open")) sb.Append("- ").Append(Md(p.HostIp)).Append(':').Append(p.Port).Append('/').Append(Md(p.Proto)).Append(" — ").Append(Md(p.Service)).Append(" — ").AppendLine(Md(p.Banner));
        sb.AppendLine().AppendLine("## Findings").AppendLine();
        foreach (var f in Findings(s))
        {
            sb.Append("### ").Append(Md(f.Title)).AppendLine();
            sb.Append("**Severity:** ").Append(f.Severity).Append("  \n**Host:** ").Append(Md(f.Host)).Append(':').Append(f.Port).Append('/').Append(Md(f.Proto)).Append("  \n**Status:** ").Append(Md(f.StatusText)).AppendLine();
            if (f.Cwe > 0) sb.Append("**CWE:** ").Append(f.CweText).AppendLine();
            if (f.Cves.Count > 0) sb.Append("**CVEs:** ").AppendLine(Md(string.Join(", ", f.Cves)));
            if (f.Cvss is double score) sb.Append("**CVSS:** ").AppendLine(score.ToString("0.0", CultureInfo.InvariantCulture));
            if (f.Threat != null) sb.Append("**KEV:** ").Append(f.Threat.Kev ? "Yes" : "No").Append(f.Threat.Epss is double epss ? $"; EPSS: {epss.ToString("P2", CultureInfo.InvariantCulture)}" : "").AppendLine();
            sb.AppendLine().AppendLine("**Description**").AppendLine().AppendLine(Md(f.Description));
            sb.AppendLine().AppendLine("**Evidence**").AppendLine().AppendLine(Md(f.Evidence));
            sb.AppendLine().AppendLine("**Remediation**").AppendLine().AppendLine(Md(f.Remediation)).AppendLine();
        }
        if (s.FindingCount == 0) sb.AppendLine("No findings recorded.");
        if (footer.Length > 0) sb.AppendLine().AppendLine(Md(footer));
        return sb.ToString();
    }
}
