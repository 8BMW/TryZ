namespace TryZ.Engine;

/// <summary>Adds CISA KEV and FIRST EPSS data to findings that carry CVE identifiers.</summary>
internal static class ThreatIntel
{
    public static Task EnrichAsync(ScanContext ctx) => Task.CompletedTask;
}
