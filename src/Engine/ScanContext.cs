using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Channels;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Shared state for one scan run. Every module talks to the UI only through this object:
/// it emits events, logs, tasks and findings, and it enforces pause, cancellation, rate limit and exclusions.
/// All members are thread-safe.
/// </summary>
internal sealed class ScanContext : IDisposable
{
    // Indexes follow the run order: discovery, port audit, vulnerability audit, web crawl, report (see Session.PhaseNames).
    public static readonly double[] PhaseWeights = { 0.15, 0.35, 0.25, 0.20, 0.05 };
    public const int PhaseDiscovery = 0, PhasePorts = 1, PhaseAudit = 2, PhaseCrawl = 3, PhaseReport = 4;

    private readonly ChannelWriter<ScanEvent> _writer;
    private readonly Stopwatch _clock = Stopwatch.StartNew();
    private readonly object _rateLock = new();
    private readonly object _pauseLock = new();
    private readonly HashSet<string> _findingKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<Finding> _findings = new();
    private readonly ConcurrentDictionary<string, byte> _hostnames = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<IpRange> _exclusions = new();
    private readonly ConcurrentDictionary<string, IPAddress> _pins = new(StringComparer.OrdinalIgnoreCase);
    private readonly double[] _phase = new double[5];
    private readonly HttpClient _http;
    private readonly HttpClient _httpFollow;
    private TaskCompletionSource _resume = CreateResumed();
    // Completed while paused; replaced by a fresh (pending) source on resume.
    private TaskCompletionSource _pauseStarted = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private double _pausedSeconds;
    private long _pausedAt = -1;
    private double _nextSlot;
    private double _rateFactor = 1;
    private int _taskId, _findingId, _active, _currentPhase;
    private long _totalRequests, _errors, _windowRequests;
    private double _latencySum;
    private long _latencyCount;

    public ScanContext(ScanRequest request, ChannelWriter<ScanEvent> writer, CancellationToken token)
    {
        Request = request;
        Options = request.Options;
        _writer = writer;
        Token = token;
        Concurrency = new SemaphoreSlim(Options.Threads, Options.Threads);
        foreach (var ex in Options.Exclusions)
            if (IpRange.TryParse(ex, out var range)) _exclusions.Add(range);
        _http = CreateClient(followRedirects: false, Options.Auth);
        _httpFollow = CreateClient(followRedirects: true);
    }

    public ScanRequest Request { get; }
    public ScanOptions Options { get; }
    public CancellationToken Token { get; }

    /// <summary>Limits concurrent network operations to the configured worker count.</summary>
    public SemaphoreSlim Concurrency { get; }

    /// <summary>Shared client that does NOT follow redirects and accepts any certificate (TLS is audited separately).</summary>
    public HttpClient Http => _http;

    /// <summary>Shared client that follows up to 5 redirects.</summary>
    public HttpClient HttpFollow => _httpFollow;

    public double ElapsedSeconds
    {
        get
        {
            lock (_pauseLock)
            {
                double paused = _pausedSeconds + (_pausedAt >= 0 ? (_clock.ElapsedTicks - _pausedAt) / (double)Stopwatch.Frequency : 0);
                return _clock.Elapsed.TotalSeconds - paused;
            }
        }
    }

    public bool IsPaused
    {
        get
        {
            lock (_pauseLock) return _pausedAt >= 0;
        }
    }

    // ---------------------------------------------------------------- pacing

    /// <summary>
    /// Call before every network request: waits while paused, enforces the requests-per-second limit,
    /// and throws <see cref="OperationCanceledException"/> when the scan is stopped.
    /// </summary>
    public async Task GateAsync()
    {
        while (true)
        {
            Token.ThrowIfCancellationRequested();
            Task resume, pauseStarted;
            lock (_pauseLock)
            {
                resume = _resume.Task;
                pauseStarted = _pauseStarted.Task;
            }
            if (!resume.IsCompleted)
            {
                await resume.WaitAsync(Token).ConfigureAwait(false);
                continue;
            }

            double delay;
            lock (_rateLock)
            {
                double now = _clock.Elapsed.TotalSeconds;
                double interval = 1.0 / Math.Max(1, Options.MaxRequestsPerSecond * _rateFactor);
                _nextSlot = Math.Max(_nextSlot, now) + interval;
                delay = _nextSlot - interval - now;
            }
            if (delay > 0.001)
            {
                // Wake up as soon as a pause begins, so a request already queued for a future slot is not sent while paused.
                var slot = Task.Delay(TimeSpan.FromSeconds(delay), Token);
                await Task.WhenAny(slot, pauseStarted).ConfigureAwait(false);
                Token.ThrowIfCancellationRequested();
            }
            // Paused while waiting for the slot: wait for resume, then take a fresh slot.
            if (pauseStarted.IsCompleted) continue;
            break;
        }
        Interlocked.Increment(ref _totalRequests);
        Interlocked.Increment(ref _windowRequests);
    }

    /// <summary>Records the outcome of one request for throughput, latency and automatic back-off.</summary>
    public void CountRequest(double latencyMs, bool error = false)
    {
        lock (_rateLock)
        {
            if (latencyMs >= 0)
            {
                _latencySum += latencyMs;
                _latencyCount++;
            }
            if (error) _errors++;
        }
    }

    /// <summary>Marks a unit of in-flight work for the "active threads" gauge. Dispose when done.</summary>
    public IDisposable BeginWork()
    {
        Interlocked.Increment(ref _active);
        return new WorkToken(this);
    }

    private sealed class WorkToken(ScanContext owner) : IDisposable
    {
        private int _done;
        public void Dispose()
        {
            if (Interlocked.Exchange(ref _done, 1) == 0) Interlocked.Decrement(ref owner._active);
        }
    }

    public void Pause()
    {
        lock (_pauseLock)
        {
            if (_pausedAt >= 0) return;
            _pausedAt = _clock.ElapsedTicks;
            _resume = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _pauseStarted.TrySetResult();
        }
    }

    public void Resume()
    {
        lock (_pauseLock)
        {
            if (_pausedAt < 0) return;
            _pausedSeconds += (_clock.ElapsedTicks - _pausedAt) / (double)Stopwatch.Frequency;
            _pausedAt = -1;
            _pauseStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            _resume.TrySetResult();
        }
    }

    private static TaskCompletionSource CreateResumed()
    {
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        tcs.SetResult();
        return tcs;
    }

    // ---------------------------------------------------------------- scope

    public bool IsExcluded(IPAddress address)
    {
        foreach (var r in _exclusions)
            if (r.Contains(address)) return true;
        return false;
    }

    /// <summary>
    /// Binds a host name to the scanned address so every HTTP request made with that name in the URL connects to the
    /// address that was actually discovered and authorised, never to whatever DNS returns later.
    /// Returns false when the name is already bound to a different address.
    /// </summary>
    public bool PinHost(string name, IPAddress address)
    {
        name = name.Trim().TrimEnd('.');
        if (name.Length == 0 || IPAddress.TryParse(name, out _)) return true;
        return _pins.GetOrAdd(name, address).Equals(address);
    }

    /// <summary>The scanned address for a URL host (pinned name or literal IP), or null for an unknown name.</summary>
    public IPAddress? PinnedAddress(string host)
    {
        host = host.Trim('[', ']').TrimEnd('.');
        if (IPAddress.TryParse(host, out var ip)) return ip;
        return _pins.TryGetValue(host, out var pinned) ? pinned : null;
    }

    /// <summary>The IP text to attribute findings to for a URL host.</summary>
    public string IpFor(string host) => PinnedAddress(host)?.ToString() ?? host;

    // ---------------------------------------------------------------- output

    public void Emit(ScanEvent ev) => _writer.TryWrite(ev);

    public void Log(LogLevel level, string source, string text) => Emit(new ScanLog(level, source, text));

    public int AddTask(string title, string module)
    {
        int id = Interlocked.Increment(ref _taskId);
        Emit(new TaskAdded(new TaskItem { Id = id, Title = title, Module = module }));
        return id;
    }

    public void UpdateTask(int id, TaskState state, int progress) => Emit(new TaskChanged(id, state, Math.Clamp(progress, 0, 100)));

    /// <summary>Adds a finding unless an identical (title, host, port) finding was already reported. Returns false for duplicates.</summary>
    public bool AddFinding(Severity severity, string title, string host, int port, int cwe,
        string description, string evidence, string remediation, FindingDetails? details = null)
    {
        string proto = details?.Proto is { Length: > 0 } p ? p : "tcp";
        lock (_findingKeys)
            if (!_findingKeys.Add($"{title}|{host}|{proto}/{port}")) return false;
        // A page seen with the user's session can echo the cookie or token back; never store it.
        evidence = AuthHandler.Redact(evidence, Options.Auth);
        description = AuthHandler.Redact(description, Options.Auth);
        var f = new Finding
        {
            Id = Interlocked.Increment(ref _findingId),
            Severity = severity,
            Title = title,
            Host = host,
            Port = port,
            Cwe = cwe,
            Description = description,
            Evidence = evidence.Length > 4000 ? evidence[..4000] + " ..." : evidence,
            Remediation = remediation,
            RuleId = details?.RuleId is { Length: > 0 } id ? id : FindingDetails.Slug(title),
            Proto = proto,
            Product = details?.Product ?? string.Empty,
            Cves = details?.Cves ?? Array.Empty<string>(),
            Cvss = details?.Cvss,
            CvssVector = details?.CvssVector ?? string.Empty,
        };
        _findings.Enqueue(f);
        Emit(new FindingFound(f));
        var level = severity >= Severity.High ? LogLevel.Alert : severity == Severity.Medium ? LogLevel.Warn : LogLevel.Notice;
        Log(level, "audit", $"[{severity}] {title} on {host}{(port > 0 ? ":" + port : string.Empty)} (CWE-{cwe})");
        return true;
    }

    public int FindingCount => Volatile.Read(ref _findingId);

    /// <summary>
    /// Findings reported so far, in report order. The objects are shared with the UI thread: treat them as read-only here
    /// and publish changes through a <see cref="FindingEnriched"/> event.
    /// </summary>
    public IReadOnlyList<Finding> FindingsSnapshot() => _findings.ToArray();

    /// <summary>Records a DNS name seen during the scan (typed by the user, from certificates or from crawled links).</summary>
    public void NoteHostname(string name)
    {
        name = name.Trim().TrimEnd('.').ToLowerInvariant();
        if (name.Length is > 0 and <= 253 && !IPAddress.TryParse(name, out _)) _hostnames.TryAdd(name, 0);
    }

    public IReadOnlyCollection<string> ObservedHostnames => _hostnames.Keys.ToArray();

    /// <summary>
    /// Reports progress for a phase. Progress only moves forward: parallel workers can report out of order,
    /// so a value below the recorded one is ignored. Use <see cref="ResetPhase"/> to start a phase over.
    /// </summary>
    public void SetPhase(int index, double progress)
    {
        lock (_phase)
        {
            _phase[index] = Math.Max(_phase[index], Math.Clamp(progress, 0, 1));
            if (progress < 1) _currentPhase = index;
        }
    }

    /// <summary>Sets a phase back to 0 and makes it the current phase.</summary>
    public void ResetPhase(int index)
    {
        lock (_phase)
        {
            _phase[index] = 0;
            _currentPhase = index;
        }
    }

    public void SetCurrentPhase(int index)
    {
        lock (_phase) _currentPhase = index;
    }

    /// <summary>Builds a metrics sample; called by the engine every 250 ms.</summary>
    public ScanMetrics SampleMetrics(double windowSeconds, bool completed)
    {
        double[] phases;
        int current;
        lock (_phase)
        {
            phases = (double[])_phase.Clone();
            current = _currentPhase;
        }
        double progress = 0;
        for (int i = 0; i < phases.Length; i++) progress += phases[i] * PhaseWeights[i];
        long window = Interlocked.Exchange(ref _windowRequests, 0);
        double latency;
        lock (_rateLock)
        {
            latency = _latencyCount > 0 ? _latencySum / _latencyCount : 0;
            _latencySum = 0;
            _latencyCount = 0;
            ApplyBackoff(window);
        }
        double rps = windowSeconds > 0 ? window / windowSeconds : 0;
        string text = completed ? "Completed" : IsPaused ? "Paused" : Session.PhaseNames[current];
        return new ScanMetrics(ElapsedSeconds, rps, latency, completed ? 0 : Volatile.Read(ref _active),
            completed ? 1 : Math.Min(0.999, progress), text, Interlocked.Read(ref _totalRequests), phases);
    }

    private void ApplyBackoff(long window)
    {
        long errors = _errors;
        _errors = 0;
        if (!Options.AutoBackoff || window < 20) return;
        double rate = errors / (double)window;
        if (rate > 0.35 && _rateFactor > 0.1)
        {
            _rateFactor = Math.Max(0.1, _rateFactor * 0.6);
            Log(LogLevel.Warn, "engine", $"Error rate {rate:P0}; backing off to {Options.MaxRequestsPerSecond * _rateFactor:0} req/s");
        }
        else if (rate < 0.05 && _rateFactor < 1)
        {
            _rateFactor = Math.Min(1, _rateFactor * 1.25);
        }
    }

    // ---------------------------------------------------------------- http

    private HttpClient CreateClient(bool followRedirects, IReadOnlyList<AuthHeader>? auth = null)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = followRedirects,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromMilliseconds(Options.ConnectTimeoutMs),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxConnectionsPerServer = Math.Max(2, Math.Min(Options.Threads, 32)),
            UseCookies = false,
            // Scanned host names connect to the discovered address (see PinHost); excluded addresses are refused.
            ConnectCallback = ConnectPinnedAsync,
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                // Certificate problems are reported by TlsAudit; HTTP checks must still reach the content.
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            },
        };
        // Credentials only ride on the non-redirecting client: a redirect to another host must not take them along.
        HttpMessageHandler pipeline = handler;
        if (!followRedirects && auth is { Count: > 0 })
            pipeline = new AuthHandler(handler, auth, text => Log(LogLevel.Warn, "auth", text));
        var client = new HttpClient(pipeline, disposeHandler: true)
        {
            Timeout = TimeSpan.FromMilliseconds(Options.ConnectTimeoutMs + Options.ReadTimeoutMs),
            MaxResponseContentBufferSize = 8 * 1024 * 1024,
        };
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", Options.UserAgent);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "*/*");
        return client;
    }

    private async ValueTask<Stream> ConnectPinnedAsync(SocketsHttpConnectionContext context, CancellationToken token)
    {
        var target = context.DnsEndPoint;
        var address = PinnedAddress(target.Host);
        if (address != null)
        {
            if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
            if (IsExcluded(address)) throw new HttpRequestException($"{address} is on the exclusion list");
        }
        else
        {
            // A name that was not scanned (e.g. the target of a redirect): resolve it here, so the exclusion list is
            // checked against the address that is actually contacted, and connect to that checked address.
            var resolved = await Dns.GetHostAddressesAsync(target.Host, token).ConfigureAwait(false);
            var usable = resolved.Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .ToList();
            if (usable.Count == 0) throw new HttpRequestException($"{target.Host} resolved to no usable address");
            var excluded = usable.FirstOrDefault(IsExcluded);
            if (excluded != null) throw new HttpRequestException($"{target.Host} resolves to {excluded}, which is on the exclusion list");
            address = usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? usable[0];
        }
        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, target.Port), token).ConfigureAwait(false);
            return new NetworkStream(socket, ownsSocket: true);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    public void Dispose()
    {
        _http.Dispose();
        _httpFollow.Dispose();
        Concurrency.Dispose();
        lock (_pauseLock) _resume.TrySetResult();
    }
}
