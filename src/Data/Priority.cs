namespace TryZ.Data;

internal enum PriorityTier { FixNow, FixNext, Planned, Monitor }

/// <summary>Remediation priority of one finding: a 0..100 score, its tier and the reasons that drove it.</summary>
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
    public static PriorityScore Evaluate(Finding f)
    {
        double score = f.Severity switch
        {
            Severity.Critical => 90,
            Severity.High => 70,
            Severity.Medium => 45,
            Severity.Low => 20,
            _ => 5,
        };
        var tier = score >= 85 ? PriorityTier.FixNow : score >= 60 ? PriorityTier.FixNext : score >= 30 ? PriorityTier.Planned : PriorityTier.Monitor;
        return new PriorityScore(score, tier, Array.Empty<string>());
    }
}
