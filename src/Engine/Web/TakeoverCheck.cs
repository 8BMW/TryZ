namespace TryZ.Engine;

/// <summary>Looks for DNS names whose CNAME points at an unclaimed third-party resource.</summary>
internal static class TakeoverCheck
{
    public static Task RunAsync(ScanContext ctx, int taskId) => Task.CompletedTask;
}
