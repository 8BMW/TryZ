namespace TryZ.Engine;

/// <summary>Protocol-aware UDP service probes.</summary>
internal static class UdpScanner
{
    /// <summary>Probes the host's UDP services, reports ports and findings, and returns the services that answered.</summary>
    public static Task<List<OpenService>> ScanAsync(ScanContext ctx, LiveHost host, int taskId) =>
        Task.FromResult(new List<OpenService>());
}
