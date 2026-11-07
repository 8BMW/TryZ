using System.Threading.Channels;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Owns the lifetime of one real scan at a time and exposes its state to the UI.</summary>
internal sealed class ScanEngine : IDisposable
{
    private CancellationTokenSource? _cts;
    private ScanContext? _context;

    public event EventHandler? StateChanged;

    public ScanState State { get; private set; } = ScanState.Idle;

    public ChannelReader<ScanEvent> Start(ScanRequest request)
    {
        Cancel();
        var channel = Channel.CreateUnbounded<ScanEvent>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = false });
        _cts = new CancellationTokenSource();
        var context = new ScanContext(request, channel.Writer, _cts.Token);
        _context = context;
        var token = _cts.Token;
        _ = Task.Run(() => RunAsync(context, channel.Writer, token));
        SetState(ScanState.Running);
        return channel.Reader;
    }

    public void Pause()
    {
        if (State != ScanState.Running) return;
        _context?.Pause();
        SetState(ScanState.Paused);
    }

    public void Resume()
    {
        if (State != ScanState.Paused) return;
        _context?.Resume();
        SetState(ScanState.Running);
    }

    public void Stop()
    {
        if (State is not (ScanState.Running or ScanState.Paused)) return;
        Cancel();
        SetState(ScanState.Stopped);
    }

    public void MarkCompleted()
    {
        Cancel();
        SetState(ScanState.Completed);
    }

    public void Reset()
    {
        Cancel();
        SetState(ScanState.Idle);
    }

    private void Cancel()
    {
        _context?.Resume();
        _cts?.Cancel();
        _cts?.Dispose();
        _cts = null;
        _context = null;
    }

    private void SetState(ScanState state)
    {
        if (State == state) return;
        State = state;
        StateChanged?.Invoke(this, EventArgs.Empty);
    }

    private static async Task RunAsync(ScanContext ctx, ChannelWriter<ScanEvent> writer, CancellationToken token)
    {
        using var metricsCts = CancellationTokenSource.CreateLinkedTokenSource(token);
        var metrics = MetricsLoopAsync(ctx, metricsCts.Token);
        try
        {
            await ScanPipeline.RunAsync(ctx).ConfigureAwait(false);
            metricsCts.Cancel();
            await metrics.ConfigureAwait(false);
            writer.TryWrite(ctx.SampleMetrics(0.25, completed: true));
            writer.TryWrite(new ScanCompleted());
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // Stopped by the user: the UI already knows.
        }
        catch (Exception ex)
        {
            ctx.Log(LogLevel.Alert, "engine", $"Scan aborted by an internal error: {ex.GetType().Name}: {ex.Message}");
            writer.TryWrite(ctx.SampleMetrics(0.25, completed: true));
            writer.TryWrite(new ScanCompleted());
        }
        finally
        {
            metricsCts.Cancel();
            try { await metrics.ConfigureAwait(false); } catch (OperationCanceledException) { }
            writer.TryComplete();
            ctx.Dispose();
        }
    }

    private static async Task MetricsLoopAsync(ScanContext ctx, CancellationToken token)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(250));
        try
        {
            while (await timer.WaitForNextTickAsync(token).ConfigureAwait(false))
                if (!ctx.IsPaused) ctx.Emit(ctx.SampleMetrics(0.25, completed: false));
        }
        catch (OperationCanceledException)
        {
        }
    }

    public void Dispose() => Cancel();
}
