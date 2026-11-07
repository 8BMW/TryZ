using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using TryZ.Data;

namespace TryZ.Engine;

internal enum PortState { Open, Closed, Filtered, Unreachable }

internal static class PortScanner
{
    /// <summary>TCP connect scan; returns open ports in ascending order and updates task progress.</summary>
    public static async Task<List<int>> ScanAsync(ScanContext ctx, LiveHost host, IReadOnlyList<int> ports, int taskId)
    {
        var open = new List<int>();
        var openLock = new object();
        int done = 0, closed = 0, filtered = 0, unreachable = 0;
        int total = ports.Count;
        int step = Math.Max(1, total / 50); // ~2 % granularity
        var sw = Stopwatch.StartNew();

        await Parallel.ForEachAsync(ports,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Max(1, ctx.Options.Threads), CancellationToken = ctx.Token },
            async (port, _) =>
            {
                var state = await ProbePortAsync(ctx, host.Address, port).ConfigureAwait(false);
                switch (state)
                {
                    case PortState.Open:
                        lock (openLock) open.Add(port);
                        ctx.Log(LogLevel.Debug, "portaudit", $"{host.Ip}:{port}/tcp open (connect accepted)");
                        break;
                    case PortState.Closed: Interlocked.Increment(ref closed); break;
                    case PortState.Filtered: Interlocked.Increment(ref filtered); break;
                    default: Interlocked.Increment(ref unreachable); break;
                }
                int d = Interlocked.Increment(ref done);
                if (d % step == 0 && d < total) ctx.UpdateTask(taskId, TaskState.Running, (int)(d * 100L / total));
            }).ConfigureAwait(false);

        ctx.UpdateTask(taskId, TaskState.Running, 100);
        open.Sort();
        ctx.Log(LogLevel.Info, "portaudit",
            $"{host.Ip}: {open.Count} open, {closed} closed, {filtered} filtered (no response){(unreachable > 0 ? $", {unreachable} unreachable" : string.Empty)} in {sw.Elapsed.TotalSeconds:0.0} s");
        return open;
    }

    /// <summary>Connect probe with retries on timeout only. RST = closed, silence = filtered.</summary>
    private static async Task<PortState> ProbePortAsync(ScanContext ctx, IPAddress address, int port)
    {
        int attempts = 1 + Math.Max(0, ctx.Options.Retries);
        var state = PortState.Filtered;
        for (int attempt = 0; attempt < attempts; attempt++)
        {
            await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
            try
            {
                await ctx.GateAsync().ConfigureAwait(false);
                using var work = ctx.BeginWork();
                (state, _) = await TcpConnector.ProbeAsync(ctx, new IPEndPoint(address, port), ctx.Options.ConnectTimeoutMs).ConfigureAwait(false);
            }
            finally
            {
                ctx.Concurrency.Release();
            }
            if (state != PortState.Filtered) break;
        }
        return state;
    }
}

/// <summary>Low-level TCP connect helpers shared by discovery, the port sweep and service identification.</summary>
internal static class TcpConnector
{
    // SIO_TCP_INITIAL_RTO = _WSAIOW(IOC_VENDOR, 17). Payload: USHORT Rtt (0xFFFF = unspecified), UCHAR MaxSynRetransmissions (0xFE = none).
    private const int SioTcpInitialRto = unchecked((int)0x98000011);
    private static readonly byte[] NoSynRetransmissions = { 0xFF, 0xFF, 0xFE, 0x00 };
    // TCP_FAIL_CONNECT_ON_ICMP_ERROR (IPPROTO_TCP level option 18): fail connect() immediately on ICMP unreachable.
    private const SocketOptionName FailConnectOnIcmpError = (SocketOptionName)18;
    private static int _tuningUnsupported;

    /// <summary>Creates a TCP socket tuned for scanning: no Nagle, RST on close (no TIME_WAIT pile-up), fast failure on RST/ICMP.</summary>
    public static Socket CreateSocket(AddressFamily family, bool scanTuning)
    {
        var socket = new Socket(family, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            socket.LingerState = new LingerOption(true, 0);
        }
        catch (SocketException)
        {
        }
        if (scanTuning && Volatile.Read(ref _tuningUnsupported) == 0 && OperatingSystem.IsWindows())
        {
            try
            {
                // Without this Windows re-sends the SYN after a RST and a closed port takes ~1 s instead of one RTT.
                socket.IOControl(SioTcpInitialRto, NoSynRetransmissions, null);
                socket.SetSocketOption(SocketOptionLevel.Tcp, FailConnectOnIcmpError, 1);
            }
            catch (SocketException)
            {
                Volatile.Write(ref _tuningUnsupported, 1);
            }
        }
        return socket;
    }

    /// <summary>One connect attempt. Never throws except <see cref="OperationCanceledException"/> when the scan is stopped.</summary>
    public static async Task<(PortState State, double LatencyMs)> ProbeAsync(ScanContext ctx, IPEndPoint endpoint, int timeoutMs, CancellationToken abort = default)
    {
        var sw = Stopwatch.StartNew();
        using var socket = CreateSocket(endpoint.AddressFamily, scanTuning: true);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token, abort);
        cts.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(endpoint, cts.Token).ConfigureAwait(false);
            double ms = sw.Elapsed.TotalMilliseconds;
            ctx.CountRequest(ms);
            return (PortState.Open, ms);
        }
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            ctx.CountRequest(-1);
            return (PortState.Filtered, -1);
        }
        catch (SocketException ex)
        {
            ctx.Token.ThrowIfCancellationRequested();
            double ms = sw.Elapsed.TotalMilliseconds;
            switch (ex.SocketErrorCode)
            {
                case SocketError.ConnectionRefused:
                case SocketError.ConnectionReset:
                    ctx.CountRequest(ms);
                    return (PortState.Closed, ms);
                case SocketError.TimedOut:
                case SocketError.OperationAborted:
                    ctx.CountRequest(-1);
                    return (PortState.Filtered, -1);
                case SocketError.HostUnreachable:
                case SocketError.NetworkUnreachable:
                case SocketError.HostDown:
                case SocketError.NetworkDown:
                    ctx.CountRequest(-1);
                    return (PortState.Unreachable, -1);
                default:
                    // Local resource problems (ephemeral ports, buffers) are real errors: let auto-backoff see them.
                    ctx.CountRequest(-1, error: true);
                    ctx.Log(LogLevel.Debug, "net", $"connect {endpoint}: {ex.SocketErrorCode}");
                    return (PortState.Filtered, -1);
            }
        }
        catch (ObjectDisposedException)
        {
            ctx.Token.ThrowIfCancellationRequested();
            ctx.CountRequest(-1);
            return (PortState.Filtered, -1);
        }
    }

    /// <summary>Opens a connected socket or throws (<see cref="SocketException"/> / <see cref="TimeoutException"/>).</summary>
    public static async Task<Socket> ConnectAsync(ScanContext ctx, IPEndPoint endpoint, int timeoutMs)
    {
        var socket = CreateSocket(endpoint.AddressFamily, scanTuning: false);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        cts.CancelAfter(timeoutMs);
        try
        {
            await socket.ConnectAsync(endpoint, cts.Token).ConfigureAwait(false);
            return socket;
        }
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            socket.Dispose();
            throw new TimeoutException($"connect to {endpoint} timed out");
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }
}
