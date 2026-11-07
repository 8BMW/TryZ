using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using TryZ.Data;

namespace TryZ.Engine;

internal static class HostDiscovery
{
    /// <summary>TCP ports used as liveness probes when ICMP gets no answer (a RST proves the host is up as well).</summary>
    private static readonly int[] ProbePorts = { 80, 443, 22, 445, 3389, 135, 139, 8080 };

    private sealed record Probe(bool Up, int LatencyMs, int Ttl, string Reason);

    /// <summary>Finds live hosts, emits HostFound for each, updates PhaseDiscovery progress.</summary>
    public static async Task<List<LiveHost>> RunAsync(ScanContext ctx, IReadOnlyList<ScanTarget> targets)
    {
        var live = new List<LiveHost>();
        var liveLock = new object();
        int total = targets.Count, done = 0;
        int step = Math.Max(1, total / 50);
        bool single = total == 1;
        var sw = Stopwatch.StartNew();

        int task = ctx.AddTask($"Host discovery ({total:N0} address{(total == 1 ? string.Empty : "es")})", "Discovery");
        ctx.UpdateTask(task, TaskState.Running, 0);
        ctx.Log(LogLevel.Info, "discover", ctx.Options.AssumeUp
            ? "Liveness checks skipped (assume hosts up); probing for latency and TTL only"
            : $"Probing {total:N0} address(es) with ICMP echo and TCP connect to {string.Join(",", ProbePorts)}");

        await Parallel.ForEachAsync(targets,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(ctx.Options.Threads, 1, 256), CancellationToken = ctx.Token },
            async (target, _) =>
            {
                var host = await ProbeHostAsync(ctx, target, single).ConfigureAwait(false);
                if (host != null)
                    lock (liveLock) live.Add(host);
                int d = Interlocked.Increment(ref done);
                ctx.SetPhase(ScanContext.PhaseDiscovery, d / (double)total * 0.999);
                if (d % step == 0 && d < total) ctx.UpdateTask(task, TaskState.Running, (int)(d * 100L / total));
            }).ConfigureAwait(false);

        ctx.UpdateTask(task, TaskState.Done, 100);
        ctx.Log(LogLevel.Info, "discover", $"Discovery took {sw.Elapsed.TotalSeconds:0.0} s");
        live.Sort((a, b) => CompareAddresses(a.Address, b.Address));
        return live;
    }

    private static async Task<LiveHost?> ProbeHostAsync(ScanContext ctx, ScanTarget target, bool single)
    {
        var address = target.Address;
        var probe = await PingAsync(ctx, address).ConfigureAwait(false);
        if (!probe.Up)
        {
            var tcp = await TcpProbeAsync(ctx, address).ConfigureAwait(false);
            if (tcp.Up) probe = tcp;
        }

        if (!probe.Up)
        {
            if (ctx.Options.AssumeUp)
            {
                probe = probe with { Up = true, Reason = "assumed up" };
            }
            else if (single)
            {
                ctx.Log(LogLevel.Notice, "discover", $"{address} did not answer ICMP or TCP liveness probes; scanning it anyway because it is the only target");
                probe = probe with { Up = true, Reason = "single target, no probe response" };
            }
            else
            {
                ctx.Log(LogLevel.Debug, "discover", $"{address} appears down (no ICMP reply, no TCP response on {ProbePorts.Length} ports)");
                return null;
            }
        }

        string name = target.Hostname;
        string rdns = string.Empty;
        if (name.Length == 0)
        {
            rdns = await ReverseLookupAsync(ctx, address).ConfigureAwait(false);
            name = rdns;
        }

        // HTTP requests built with this name must reach this address, not whatever DNS says later.
        // User-supplied names were pinned before discovery started, so a reverse name can never take one of them;
        // a reverse name shared by several scanned addresses (e.g. "localhost") is only used for display.
        string urlName = name;
        if (name.Length > 0 && !ctx.PinHost(name, address))
        {
            ctx.Log(LogLevel.Debug, "discover", $"{name} already names another scanned address; using {address} in URLs");
            urlName = string.Empty;
        }

        string os = GuessOs(probe.Ttl);
        var host = new LiveHost
        {
            Address = address,
            Hostname = urlName.Length > 0 ? urlName : address.ToString(),
            SeedUrl = target.SeedUrl,
            Aliases = target.Aliases,
            LatencyMs = Math.Max(0, probe.LatencyMs),
            Ttl = probe.Ttl,
            OsGuess = os,
        };
        ctx.Emit(new HostFound(new HostRecord
        {
            Ip = host.Ip,
            Hostname = name.Length > 0 ? name : "-",
            OsGuess = os,
            LatencyMs = host.LatencyMs,
            Ttl = host.Ttl,
            Role = "Host",
        }));
        string latency = probe.LatencyMs >= 0 ? $", {probe.LatencyMs} ms" : string.Empty;
        string ttl = probe.Ttl > 0 ? $", TTL {probe.Ttl}" : string.Empty;
        string label = name.Length > 0 ? $"{address} ({name})" : address.ToString();
        ctx.Log(LogLevel.Ok, "discover", $"Host {label} is up ({probe.Reason}{latency}{ttl}); OS: {os}");
        return host;
    }

    // ---------------------------------------------------------------- ICMP

    private static async Task<Probe> PingAsync(ScanContext ctx, IPAddress address)
    {
        var none = new Probe(false, -1, 0, "no ICMP reply");
        await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
        try
        {
            await ctx.GateAsync().ConfigureAwait(false);
            using var work = ctx.BeginWork();
            using var ping = new Ping();
            var sw = Stopwatch.StartNew();
            try
            {
                var reply = await ping.SendPingAsync(address, TimeSpan.FromMilliseconds(ctx.Options.ConnectTimeoutMs),
                    new byte[32], new PingOptions(128, dontFragment: false), ctx.Token).ConfigureAwait(false);
                if (reply.Status != IPStatus.Success)
                {
                    ctx.CountRequest(-1);
                    if (reply.Status is not IPStatus.TimedOut)
                        ctx.Log(LogLevel.Debug, "discover", $"ICMP {address}: {reply.Status}");
                    return none;
                }
                long rtt = reply.RoundtripTime > 0 ? reply.RoundtripTime : (long)sw.Elapsed.TotalMilliseconds;
                ctx.CountRequest(rtt);
                int ttl = reply.Options?.Ttl ?? 0;
                return new Probe(true, (int)Math.Min(int.MaxValue, rtt), ttl, "ICMP echo reply");
            }
            catch (Exception ex) when (ex is PingException or InvalidOperationException or NotSupportedException or SocketException
                                       || (ex is OperationCanceledException && !ctx.Token.IsCancellationRequested))
            {
                ctx.Token.ThrowIfCancellationRequested();
                ctx.CountRequest(-1, error: ex is not OperationCanceledException);
                ctx.Log(LogLevel.Debug, "discover", $"ICMP {address} failed: {(ex.InnerException ?? ex).Message}");
                return none;
            }
        }
        finally
        {
            ctx.Concurrency.Release();
        }
    }

    // ---------------------------------------------------------------- TCP

    private static async Task<Probe> TcpProbeAsync(ScanContext ctx, IPAddress address)
    {
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        var probes = ProbePorts.Select(port => TcpProbeOneAsync(ctx, address, port, stop)).ToArray();
        var results = await Task.WhenAll(probes).ConfigureAwait(false);
        ctx.Token.ThrowIfCancellationRequested();

        var best = results.Where(r => r.State == PortState.Open).OrderBy(r => r.Ms).FirstOrDefault()
                   ?? results.Where(r => r.State == PortState.Closed).OrderBy(r => r.Ms).FirstOrDefault();
        if (best == null) return new Probe(false, -1, 0, "no TCP response");
        string reason = best.State == PortState.Open ? $"TCP {best.Port} open" : $"TCP RST from port {best.Port}";
        return new Probe(true, (int)Math.Round(Math.Max(0, best.Ms)), 0, reason);
    }

    private sealed record TcpResult(int Port, PortState State, double Ms);

    private static async Task<TcpResult> TcpProbeOneAsync(ScanContext ctx, IPAddress address, int port, CancellationTokenSource stop)
    {
        try
        {
            await ctx.Concurrency.WaitAsync(stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            return new TcpResult(port, PortState.Filtered, -1);
        }
        try
        {
            if (stop.IsCancellationRequested) return new TcpResult(port, PortState.Filtered, -1);
            await ctx.GateAsync().ConfigureAwait(false);
            using var work = ctx.BeginWork();
            var (state, ms) = await TcpConnector.ProbeAsync(ctx, new IPEndPoint(address, port), ctx.Options.ConnectTimeoutMs, stop.Token).ConfigureAwait(false);
            if (state is PortState.Open or PortState.Closed)
            {
                try
                {
                    stop.Cancel();
                }
                catch (ObjectDisposedException)
                {
                }
            }
            return new TcpResult(port, state, ms);
        }
        finally
        {
            ctx.Concurrency.Release();
        }
    }

    // ---------------------------------------------------------------- naming

    private static async Task<string> ReverseLookupAsync(ScanContext ctx, IPAddress address)
    {
        await ctx.GateAsync().ConfigureAwait(false);
        using var work = ctx.BeginWork();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        cts.CancelAfter(Math.Clamp(ctx.Options.ConnectTimeoutMs, 500, 2000));
        var sw = Stopwatch.StartNew();
        try
        {
            var entry = await Dns.GetHostEntryAsync(address.ToString(), cts.Token).ConfigureAwait(false);
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
            string name = entry.HostName?.TrimEnd('.') ?? string.Empty;
            if (name.Length == 0 || IPAddress.TryParse(name, out _)) return string.Empty;
            return name.ToLowerInvariant();
        }
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            ctx.CountRequest(-1);
            return string.Empty;
        }
        catch (SocketException)
        {
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
            return string.Empty;
        }
        catch (ArgumentException)
        {
            return string.Empty;
        }
    }

    /// <summary>Guess from the observed TTL rounded up to the nearest common initial value (64, 128, 255).</summary>
    internal static string GuessOs(int ttl)
    {
        if (ttl <= 0) return "Unknown";
        (int initial, string family) = ttl switch
        {
            <= 64 => (64, "Linux/Unix/macOS"),
            <= 128 => (128, "Windows"),
            _ => (255, "Network device / Solaris"),
        };
        int hops = initial - ttl;
        return $"{family} (TTL guess, ~{hops} hop{(hops == 1 ? string.Empty : "s")})";
    }

    internal static int CompareAddresses(IPAddress a, IPAddress b)
    {
        int fam = (a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1).CompareTo(b.AddressFamily == AddressFamily.InterNetwork ? 0 : 1);
        return fam != 0 ? fam : IpRange.ToBig(a).CompareTo(IpRange.ToBig(b));
    }
}
