namespace TryZ.Data;

internal enum PriorityTier { FixNow, FixNext, Planned, Monitor }

/// <summary>How much a host matters to the organisation. Set by the user per host; Normal means nothing was said.</summary>
internal enum AssetImportance { Low, Normal, High, Critical }

/// <summary>Remediation priority of one finding: an explanatory 0..100 heuristic, not a probability or CVSS score.</summary>
internal readonly record struct PriorityScore(double Score, PriorityTier Tier, IReadOnlyList<string> Reasons)
{
    public string TierText => Tier switch
    {
        PriorityTier.FixNow => "Fix now",
        PriorityTier.FixNext => "Fix next",
        PriorityTier.Planned => "Planned",
        _ => "Monitor",
    };
}

internal static class Prioritizer
{
    public static readonly string[] ImportanceNames = { "Low", "Normal", "High", "Critical" };

    /// <summary>
    /// Combines the finding's reported severity with observed threat intelligence and, when the user has said so,
    /// how important the host is. Missing intelligence is unknown, not a negative result. The score is an ordering
    /// aid; it cannot establish applicability or local risk.
    /// </summary>
    public static PriorityScore Evaluate(Finding f, AssetImportance importance = AssetImportance.Normal)
    {
        ArgumentNullException.ThrowIfNull(f);
        double score = f.Severity switch
        {
            Severity.Critical => 90,
            Severity.High => 70,
            Severity.Medium => 45,
            Severity.Low => 20,
            _ => 5,
        };
        var reasons = new List<string> { $"Reported severity: {f.Severity} (base {score:0}/100)." };
        if (f.Cvss is double cvss && double.IsFinite(cvss) && cvss is >= 0 and <= 10)
            reasons.Add($"CVSS {cvss:0.0}/10 is shown for context; it is not added again to severity.");

        var threat = f.Threat;
        if (threat?.Kev == true)
        {
            double before = score;
            score = Math.Max(score, 85);
            string id = string.IsNullOrWhiteSpace(threat.KevCve) ? "CVE" : threat.KevCve;
            reasons.Add($"{id} appears in CISA KEV; priority floor 85/100{(score > before ? $" (+{score - before:0})" : string.Empty)}. Verify that this finding is affected.");
            if (threat.KevRansomware)
            {
                score += 5;
                reasons.Add("CISA reports known ransomware use (+5).");
            }
            if (threat.KevDueDate is DateOnly due)
                reasons.Add($"CISA KEV due date: {due:yyyy-MM-dd} (context only).");
        }
        else if (threat is null)
            reasons.Add("KEV and EPSS data unavailable; no reduction was applied.");
        else
            reasons.Add("No related CVE was found in the available KEV catalog.");

        if (threat?.Epss is double epss && double.IsFinite(epss) && epss is >= 0 and <= 1)
        {
            int bonus = epss >= 0.5 ? 15 : epss >= 0.1 ? 10 : epss >= 0.01 ? 5 : 0;
            score += bonus;
            reasons.Add($"EPSS: {epss * 100:0.0}% estimated global exploitation activity within 30 days (+{bonus}).");
        }
        else if (threat is not null)
            reasons.Add("EPSS unavailable; no reduction was applied.");

        switch (importance)
        {
            case AssetImportance.Critical:
                score += 15;
                reasons.Add("Host is marked business critical (+15).");
                break;
            case AssetImportance.High:
                score += 8;
                reasons.Add("Host is marked high importance (+8).");
                break;
            case AssetImportance.Low when threat?.Kev == true:
                // A low-value box with a known-exploited flaw is still a way in; don't let the label bury it.
                reasons.Add("Host is marked low importance, but known-exploited issues are a common foothold; no reduction applied.");
                break;
            case AssetImportance.Low:
                score -= 10;
                reasons.Add("Host is marked low importance (-10).");
                break;
        }

        if (score > 100) reasons.Add("Score capped at 100.");
        score = Math.Clamp(score, 0, 100);
        var tier = score >= 85 ? PriorityTier.FixNow : score >= 60 ? PriorityTier.FixNext : score >= 30 ? PriorityTier.Planned : PriorityTier.Monitor;
        return new PriorityScore(score, tier, reasons);
    }
}
