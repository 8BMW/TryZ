#if DEBUG
using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

internal sealed class ScanLifecycleChecks : ICheckSuite
{
    public string Name => "scan-lifecycle";

    public async Task RunAsync(CheckContext c)
    {
        using var engine = new ScanEngine();
        var options = new ScanOptions { ProfileIndex = int.MaxValue, Threads = 1 };
        var reader = engine.Start(new ScanRequest("127.0.0.1", 0, 1, options));
        var events = new List<ScanEvent>();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await foreach (var item in reader.ReadAllAsync(timeout.Token)) events.Add(item);
        c.Check("internal failure reported as failure", events.Any(e => e is ScanFailed));
        c.Check("internal failure not reported as completion", !events.Any(e => e is ScanCompleted));
        c.Check("failure does not force full progress", events.OfType<ScanMetrics>().Last().Progress < 1);
        engine.MarkFailed();
        c.Equal("failure state visible", ScanState.Failed, engine.State);
    }
}
#endif
