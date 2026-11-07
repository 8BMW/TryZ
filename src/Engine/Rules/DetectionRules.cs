namespace TryZ.Engine;

/// <summary>Built-in and user-supplied detection rules.</summary>
internal static class DetectionRules
{
    /// <summary>Loads the rule set for this scan. Called once before discovery.</summary>
    public static Task LoadAsync(ScanContext ctx) => Task.CompletedTask;

    /// <summary>Runs request-based (HTTP) rules against one web service. Called after the built-in HTTP audit.</summary>
    public static Task RunHttpRulesAsync(ScanContext ctx, OpenService svc) => Task.CompletedTask;
}
