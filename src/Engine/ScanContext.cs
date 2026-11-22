using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Text;
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
    // Form login: a shared cookie jar the handlers read/write, the login endpoint, and single-flight re-login state.
    private readonly CookieContainer? _cookies;
    private readonly Uri? _loginUri;
    private readonly SemaphoreSlim _loginGate = new(1, 1);
    private long _lastLoginTicks = long.MinValue;
    private volatile bool _loggedIn;
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
        if (Options.FormLogin && Uri.TryCreate(Options.LoginUrl, UriKind.Absolute, out var lu)
            && lu.Scheme is "http" or "https")
        {
            _cookies = new CookieContainer();
            _loginUri = lu;
        }
        _http = CreateClient(followRedirects: false);
        _httpFollow = CreateClient(followRedirects: true);
    }

    /// <summary>True when form login is configured and a login endpoint was parsed.</summary>
    public bool FormLoginEnabled => _loginUri != null;

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

    private HttpClient CreateClient(bool followRedirects)
    {
        var handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = followRedirects,
            MaxAutomaticRedirections = 5,
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromMilliseconds(Options.ConnectTimeoutMs),
            PooledConnectionLifetime = TimeSpan.FromMinutes(2),
            MaxConnectionsPerServer = Math.Max(2, Math.Min(Options.Threads, 32)),
            // With form login, a shared cookie jar keeps the session across requests and survives re-authentication;
            // otherwise cookies are stateless and only a fixed Cookie header (below) is sent.
            UseCookies = _cookies != null,
            CookieContainer = _cookies ?? new CookieContainer(),
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                // Certificate problems are reported by TlsAudit; HTTP checks must still reach the content.
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            },
        };
        // An upstream proxy (Burp/ZAP) terminates the connection itself, so host pinning and the exclusion list are
        // enforced by the proxy operator, not here. Without a proxy, every connection is pinned to the discovered address.
        var proxy = BuildProxy();
        if (proxy != null)
        {
            handler.Proxy = proxy;
            handler.UseProxy = true;
        }
        else
        {
            // Scanned host names connect to the discovered address (see PinHost); excluded addresses are refused.
            handler.ConnectCallback = ConnectPinnedAsync;
        }
        var client = new HttpClient(handler, disposeHandler: true)
        {
            Timeout = TimeSpan.FromMilliseconds(Options.ConnectTimeoutMs + Options.ReadTimeoutMs),
            MaxResponseContentBufferSize = 8 * 1024 * 1024,
        };
        var h = client.DefaultRequestHeaders;
        h.TryAddWithoutValidation("User-Agent", Options.UserAgent);
        h.TryAddWithoutValidation("Accept", "*/*");
        // Authenticated scanning: a session cookie, custom headers and/or an Authorization header reach every request.
        // When a cookie jar is active (form login), seed the jar with the static cookie instead of a fixed header so it
        // can be replaced by the Set-Cookie of a (re-)login; otherwise send it as a fixed header on every request.
        if (Options.SessionCookie.Length > 0)
        {
            if (_cookies != null && _loginUri != null) SeedCookies(_cookies, _loginUri, Options.SessionCookie);
            else h.TryAddWithoutValidation("Cookie", Options.SessionCookie);
        }
        string auth = Options.AuthorizationHeader;
        if (auth.Length == 0 && Options.BasicUser.Length > 0)
            auth = "Basic " + Convert.ToBase64String(Encoding.UTF8.GetBytes($"{Options.BasicUser}:{Options.BasicPassword}"));
        if (auth.Length > 0) h.TryAddWithoutValidation("Authorization", auth);
        foreach (var line in Options.ExtraHeaders)
        {
            int c = line.IndexOf(':');
            if (c <= 0) continue;
            string name = line[..c].Trim();
            string value = line[(c + 1)..].Trim();
            if (name.Length > 0) h.TryAddWithoutValidation(name, value);
        }
        return client;
    }

    private IWebProxy? BuildProxy()
    {
        string p = Options.HttpProxy;
        if (string.IsNullOrWhiteSpace(p)) return null;
        if (!p.Contains("://", StringComparison.Ordinal)) p = "http://" + p;
        return Uri.TryCreate(p, UriKind.Absolute, out var u) ? new WebProxy(u) { BypassProxyOnLocal = false } : null;
    }

    // ---------------------------------------------------------------- form login & session refresh

    /// <summary>
    /// Posts the configured credentials to the login endpoint, storing the session cookie in the shared jar. Called once
    /// before the web phase and again, under a single-flight lock, whenever a response looks logged out. Returns whether
    /// the login appears to have succeeded.
    /// </summary>
    public async Task<bool> LoginAsync()
    {
        if (_loginUri == null) return false;
        var fields = new List<KeyValuePair<string, string>>
        {
            new(Options.LoginUserField, Options.LoginUser),
            new(Options.LoginPassField, Options.LoginPassword),
        };
        foreach (var kv in ParsePairs(Options.LoginExtraData)) fields.Add(kv);
        try
        {
            await GateAsync().ConfigureAwait(false);
            using var work = BeginWork();
            using var content = new FormUrlEncodedContent(fields);
            using var req = new HttpRequestMessage(HttpMethod.Post, _loginUri) { Content = content };
            using var resp = await _httpFollow.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, Token).ConfigureAwait(false);
            int status = (int)resp.StatusCode;
            byte[] body = await ReadLimitedAsync(resp.Content, 64 * 1024).ConfigureAwait(false);
            string text = Encoding.UTF8.GetString(body);
            bool marker = Options.LoginLoggedOutMarker.Length > 0 && text.Contains(Options.LoginLoggedOutMarker, StringComparison.OrdinalIgnoreCase);
            bool ok = status < 400 && !marker;
            _loggedIn = ok;
            _lastLoginTicks = _clock.ElapsedTicks;
            Log(ok ? LogLevel.Ok : LogLevel.Warn, "login",
                ok ? $"Form login as '{Options.LoginUser}' at {_loginUri.AbsolutePath} succeeded (HTTP {status})"
                   : $"Form login at {_loginUri.AbsolutePath} did not look successful (HTTP {status}{(marker ? ", logged-out marker present" : "")})");
            return ok;
        }
        catch (OperationCanceledException) when (Token.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidOperationException or OperationCanceledException)
        {
            Log(LogLevel.Warn, "login", $"Form login request failed: {ex.GetType().Name}");
            return false;
        }
    }

    /// <summary>Re-authenticates if the given response looks logged out. Single-flight with a short cooldown so parallel
    /// workers that all hit an expired session trigger only one re-login. Returns true when the session is (now) valid.</summary>
    public async Task<bool> EnsureSessionAsync(int status, string location, string body)
    {
        if (_loginUri == null || !LooksLoggedOut(status, location, body)) return false;
        await _loginGate.WaitAsync(Token).ConfigureAwait(false);
        try
        {
            // Another worker may have just re-authenticated; treat a very recent login as still valid.
            if (_loggedIn && _lastLoginTicks != long.MinValue
                && (_clock.ElapsedTicks - _lastLoginTicks) / (double)Stopwatch.Frequency < 8)
                return true;
            Log(LogLevel.Notice, "login", "Session looks expired; re-authenticating");
            return await LoginAsync().ConfigureAwait(false);
        }
        finally
        {
            _loginGate.Release();
        }
    }

    /// <summary>Heuristic: does this response indicate the session is not authenticated?</summary>
    public bool LooksLoggedOut(int status, string location, string body)
    {
        if (_loginUri == null) return false;
        if (status is 401 or 403) return true;
        if (Options.LoginLoggedOutMarker.Length > 0 && body.Contains(Options.LoginLoggedOutMarker, StringComparison.OrdinalIgnoreCase)) return true;
        if (status is >= 300 and < 400 && location.Length > 0
            && location.Contains(_loginUri.AbsolutePath, StringComparison.OrdinalIgnoreCase)) return true;
        return false;
    }

    private static void SeedCookies(CookieContainer jar, Uri origin, string cookieHeader)
    {
        foreach (var part in cookieHeader.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=');
            if (eq <= 0) continue;
            string name = part[..eq].Trim();
            string value = part[(eq + 1)..].Trim();
            if (name.Length == 0) continue;
            try { jar.Add(new Cookie(name, value, "/", origin.Host)); }
            catch (CookieException) { }
            catch (ArgumentException) { }
        }
    }

    private static IEnumerable<KeyValuePair<string, string>> ParsePairs(string data)
    {
        foreach (var part in data.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            string name = Uri.UnescapeDataString((eq >= 0 ? part[..eq] : part).Trim());
            string value = eq >= 0 ? Uri.UnescapeDataString(part[(eq + 1)..].Trim()) : string.Empty;
            if (name.Length > 0) yield return new KeyValuePair<string, string>(name, value);
        }
    }

    // ---------------------------------------------------------------- shared probe (active + discovery modules)

    /// <summary>Result of a <see cref="ProbeAsync"/> request: a thin, allocation-light view used by the active checks.</summary>
    public sealed class Probe
    {
        public required Uri Uri { get; init; }
        public required int Status { get; init; }
        public required string Body { get; init; }
        public required IReadOnlyDictionary<string, string> Headers { get; init; }
        public double LatencyMs { get; init; }
        public string Header(string name) => Headers.TryGetValue(name, out var v) ? v : string.Empty;
        public string ContentType => Header("Content-Type");
        public bool IsHtml => ContentType.Contains("html", StringComparison.OrdinalIgnoreCase)
                              || (ContentType.Length == 0 && Body.TrimStart().StartsWith('<'));
    }

    /// <summary>
    /// Issues one rate-limited, cancellation-aware HTTP request through the shared pinned client and returns the
    /// decoded response (body capped), or null on transport failure. Used by the active-audit and discovery modules so
    /// they share pacing, pinning, auth and proxy settings with the passive checks.
    /// </summary>
    public Task<Probe?> ProbeAsync(HttpMethod method, Uri uri, bool follow = false,
        HttpContent? content = null, int maxBody = 256 * 1024, IReadOnlyList<(string Name, string Value)>? extraHeaders = null) =>
        ProbeAsync(method, uri, follow, content, maxBody, extraHeaders, canRelogin: true);

    private async Task<Probe?> ProbeAsync(HttpMethod method, Uri uri, bool follow,
        HttpContent? content, int maxBody, IReadOnlyList<(string Name, string Value)>? extraHeaders, bool canRelogin)
    {
        await GateAsync().ConfigureAwait(false);
        using var work = BeginWork();
        var sw = Stopwatch.StartNew();
        try
        {
            using var req = new HttpRequestMessage(method, uri) { Content = content };
            if (extraHeaders != null)
                foreach (var (name, value) in extraHeaders)
                    req.Headers.TryAddWithoutValidation(name, value);
            var client = follow ? _httpFollow : _http;
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, Token).ConfigureAwait(false);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var hh in resp.Headers.NonValidated) headers[hh.Key] = string.Join(", ", hh.Value);
            foreach (var hh in resp.Content.Headers.NonValidated) headers[hh.Key] = string.Join(", ", hh.Value);
            byte[] body = method == HttpMethod.Head ? Array.Empty<byte>() : await ReadLimitedAsync(resp.Content, maxBody).ConfigureAwait(false);
            double ms = sw.Elapsed.TotalMilliseconds;
            CountRequest(ms, (int)resp.StatusCode >= 500);
            var probe = new Probe { Uri = uri, Status = (int)resp.StatusCode, Body = Encoding.UTF8.GetString(body), Headers = headers, LatencyMs = ms };
            // Form login: if the session has expired, re-authenticate and (for a body-less GET) retry once so the check
            // sees the authenticated response. Content-bearing requests cannot be replayed, so they only trigger re-login.
            if (_loginUri != null && LooksLoggedOut(probe.Status, probe.Header("Location"), probe.Body))
            {
                bool valid = await EnsureSessionAsync(probe.Status, probe.Header("Location"), probe.Body).ConfigureAwait(false);
                if (valid && canRelogin && content == null)
                    return await ProbeAsync(method, uri, follow, null, maxBody, extraHeaders, canRelogin: false).ConfigureAwait(false) ?? probe;
            }
            return probe;
        }
        catch (OperationCanceledException) when (Token.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or SocketException or InvalidOperationException)
        {
            CountRequest(sw.Elapsed.TotalMilliseconds, true);
            return null;
        }
    }

    private async Task<byte[]> ReadLimitedAsync(HttpContent content, int max)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(Token);
        cts.CancelAfter(Options.ReadTimeoutMs);
        using var ms = new MemoryStream();
        try
        {
            await using var s = await content.ReadAsStreamAsync(cts.Token).ConfigureAwait(false);
            byte[] buf = new byte[16 * 1024];
            while (ms.Length < max)
            {
                int n = await s.ReadAsync(buf.AsMemory(0, (int)Math.Min(buf.Length, max - ms.Length)), cts.Token).ConfigureAwait(false);
                if (n == 0) break;
                ms.Write(buf, 0, n);
            }
        }
        catch (OperationCanceledException) when (!Token.IsCancellationRequested) { }
        catch (Exception ex) when (ex is IOException or HttpRequestException) { }
        return ms.ToArray();
    }

    // ---------------------------------------------------------------- injection points (fed by the crawler)

    private readonly ConcurrentDictionary<string, InjectionPoint> _injectionPoints = new(StringComparer.Ordinal);

    /// <summary>
    /// Records a parameterised request the crawler found (a URL with a query string, or an HTML form) as a candidate
    /// for the active audit. De-duplicated by method, path and the set of parameter names so value-only variants collapse.
    /// </summary>
    public void NoteInjectionPoint(InjectionPoint point)
    {
        if (point.Parameters.Count == 0 || _injectionPoints.Count >= 20_000) return;
        _injectionPoints.TryAdd(point.Signature, point);
    }

    public IReadOnlyCollection<InjectionPoint> InjectionPoints => _injectionPoints.Values.ToArray();

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
        _loginGate.Dispose();
        lock (_pauseLock) _resume.TrySetResult();
    }
}
