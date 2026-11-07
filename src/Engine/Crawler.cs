using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Same-origin, breadth-first web crawler. Only issues GET requests, honours robots.txt (when enabled), reads sitemaps,
/// records every fetched URL and raises passive findings (forms, mixed content, error disclosure, exposed files).
/// </summary>
internal static partial class Crawler
{
    private const int MaxBodyBytes = 5 * 1024 * 1024;
    private const int MaxFrontier = 50_000;
    private const int MaxSitemapFiles = 25;
    private const int MaxSitemapUrls = 20_000;

    /// <summary>Same-origin breadth-first crawl of each root; emits UrlBatch events and crawl findings.</summary>
    public static async Task RunAsync(ScanContext ctx, IReadOnlyList<Uri> roots)
    {
        var o = ctx.Options;
        var unique = new List<Uri>();
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in roots)
        {
            var n = Normalize(r);
            if (n != null && origins.Add(n.GetLeftPart(UriPartial.Authority))) unique.Add(n);
        }
        if (unique.Count == 0)
        {
            ctx.Log(LogLevel.Info, "crawler", "No crawlable web roots");
            return;
        }

        var shared = new SharedState(ctx, o.CrawlMaxPages, unique.Count);
        using var batcher = new UrlBatcher(ctx);
        var pump = batcher.RunAsync();
        ctx.Log(LogLevel.Info, "crawler", $"Crawling {unique.Count} web root(s): max {o.CrawlMaxPages} page(s), depth {o.CrawlMaxDepth}, robots.txt {(o.RespectRobots ? "honoured" : "ignored")}");
        try
        {
            await Parallel.ForEachAsync(Enumerable.Range(0, unique.Count),
                new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(unique.Count, 1, 4), CancellationToken = ctx.Token },
                async (i, _) => await new RootCrawl(ctx, unique[i], i, shared, batcher).RunAsync().ConfigureAwait(false)).ConfigureAwait(false);
        }
        finally
        {
            batcher.Stop();
            await pump.ConfigureAwait(false);
            batcher.Flush();
        }
        ctx.Log(LogLevel.Ok, "crawler", $"Crawl finished: {shared.TotalFetched} URL(s) fetched across {unique.Count} root(s)");
    }

    // ================================================================ URL helpers

    /// <summary>Absolute http(s) URL without fragment or user-info, lowercase scheme/host, default port removed, dot segments collapsed.</summary>
    internal static Uri? Normalize(Uri u)
    {
        if (!u.IsAbsoluteUri) return null;
        if (u.Scheme != Uri.UriSchemeHttp && u.Scheme != Uri.UriSchemeHttps) return null;
        if (string.IsNullOrEmpty(u.Host)) return null;
        string s = u.GetComponents(UriComponents.HttpRequestUrl, UriFormat.UriEscaped);
        return Uri.TryCreate(s, UriKind.Absolute, out var n) ? n : null;
    }

    private static Uri? Resolve(Uri baseUri, string raw)
    {
        if (raw.Length == 0 || raw.Length > 2048) return null;
        // browsers strip ASCII tab/newline inside URLs
        if (raw.IndexOfAny(new[] { '\t', '\n', '\r' }) >= 0) raw = raw.Replace("\t", "").Replace("\n", "").Replace("\r", "");
        raw = raw.Trim();
        if (raw.Length == 0 || raw[0] == '#') return null;
        if (raw.Contains("{{", StringComparison.Ordinal) || raw.Contains("${", StringComparison.Ordinal) || raw.Contains('<')) return null;
        int colon = raw.IndexOf(':');
        if (colon > 0 && Uri.CheckSchemeName(raw[..colon]))
        {
            string scheme = raw[..colon].ToLowerInvariant();
            if (scheme is not ("http" or "https")) return null; // mailto:, javascript:, tel:, data:, ...
        }
        return Uri.TryCreate(baseUri, raw, out var u) ? Normalize(u) : null;
    }

    private static bool SameOrigin(Uri a, Uri b) =>
        a.Scheme == b.Scheme && a.Port == b.Port && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase);

    [GeneratedRegex(@"log[-_]?out|log[-_]?off|sign[-_]?out|sign[-_]?off|delete|destroy|/remove\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex UnsafeLinkRegex();

    [GeneratedRegex(@"\.(?:bak|old|orig|backup|sql|zip|tar\.gz|tgz|tar|7z|rar|log|env)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex InterestingFileRegex();

    [GeneratedRegex(@"(?:^|/)\.env(?:\.[a-z]+)?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DotEnvRegex();

    [GeneratedRegex(@"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63})*\.[A-Za-z]{2,24}\b", RegexOptions.CultureInvariant, 2000)]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])", RegexOptions.CultureInvariant, 2000)]
    private static partial Regex InternalIpRegex();

    [GeneratedRegex(@"[#@]\s*sourceMappingURL\s*=\s*(?<u>[^\s'""*]+)", RegexOptions.CultureInvariant, 2000)]
    private static partial Regex SourceMapRegex();

    [GeneratedRegex(@"<meta\b[^>]*name\s*=\s*[""']?[^""'>]*(?:csrf|xsrf)[^>]*>", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 2000)]
    private static partial Regex CsrfMetaRegex();

    private static readonly (string Pattern, string Label)[] ErrorPatterns =
    {
        ("Traceback (most recent call last)", "Python traceback"),
        ("at System.", ".NET stack trace"),
        ("java.lang.", "Java exception"),
        ("Fatal error:</b>", "PHP fatal error"),
        ("Warning</b>: ", "PHP warning"),
        ("SQLSTATE[", "PDO/SQL error"),
        ("You have an error in your SQL syntax", "MySQL syntax error"),
        ("ORA-0", "Oracle error"),
        ("Microsoft OLE DB", "OLE DB error"),
    };

    private static readonly HashSet<string> ImageTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "png", "jpg", "jpeg", "gif", "svg", "webp", "css", "js", "ico", "bmp", "avif",
    };

    private static bool IsParseable(string media) =>
        media.Length == 0 || media.StartsWith("text/", StringComparison.Ordinal) || media.Contains("html", StringComparison.Ordinal)
        || media.Contains("xml", StringComparison.Ordinal) || media.Contains("javascript", StringComparison.Ordinal)
        || media.Contains("ecmascript", StringComparison.Ordinal) || media.Contains("json", StringComparison.Ordinal);

    // ================================================================ shared state

    private sealed class SharedState
    {
        private readonly ScanContext _ctx;
        private readonly int _total, _roots;
        private readonly double[] _fraction;
        private int _spare, _fetched;

        public SharedState(ScanContext ctx, int total, int roots)
        {
            _ctx = ctx;
            _total = Math.Max(1, total);
            _roots = roots;
            _fraction = new double[roots];
        }

        public int TotalFetched => Volatile.Read(ref _fetched);

        /// <summary>Fair initial share of the global page cap for root <paramref name="index"/>.</summary>
        public int Quota(int index) => _total / _roots + (index < _total % _roots ? 1 : 0);

        /// <summary>Takes one page of budget left unused by roots that already finished.</summary>
        public bool TakeSpare()
        {
            while (true)
            {
                int s = Volatile.Read(ref _spare);
                if (s <= 0) return false;
                if (Interlocked.CompareExchange(ref _spare, s - 1, s) == s) return true;
            }
        }

        public void GiveBack(int pages)
        {
            if (pages > 0) Interlocked.Add(ref _spare, pages);
        }

        public void Fetched() => Interlocked.Increment(ref _fetched);

        public void Progress(int index, double fraction)
        {
            double sum = 0;
            lock (_fraction)
            {
                _fraction[index] = Math.Clamp(fraction, 0, 1);
                foreach (var f in _fraction) sum += f;
            }
            _ctx.SetPhase(ScanContext.PhaseCrawl, Math.Min(0.999, sum / _roots));
        }
    }

    /// <summary>Collects UrlRecords and emits them every ~100 ms or 200 records.</summary>
    private sealed class UrlBatcher : IDisposable
    {
        private readonly ScanContext _ctx;
        private readonly List<UrlRecord> _pending = new();
        private readonly CancellationTokenSource _stop = new();
        private long _lastFlush = Environment.TickCount64;

        public UrlBatcher(ScanContext ctx) => _ctx = ctx;

        public void Add(UrlRecord r)
        {
            UrlRecord[]? batch = null;
            lock (_pending)
            {
                _pending.Add(r);
                if (_pending.Count >= 200 || Environment.TickCount64 - _lastFlush >= 100) batch = TakeLocked();
            }
            if (batch != null) _ctx.Emit(new UrlBatch(batch));
        }

        public void Flush()
        {
            UrlRecord[]? batch;
            lock (_pending) batch = TakeLocked();
            if (batch != null) _ctx.Emit(new UrlBatch(batch));
        }

        private UrlRecord[]? TakeLocked()
        {
            _lastFlush = Environment.TickCount64;
            if (_pending.Count == 0) return null;
            var a = _pending.ToArray();
            _pending.Clear();
            return a;
        }

        public async Task RunAsync()
        {
            using var timer = new PeriodicTimer(TimeSpan.FromMilliseconds(100));
            try
            {
                while (await timer.WaitForNextTickAsync(_stop.Token).ConfigureAwait(false)) Flush();
            }
            catch (OperationCanceledException)
            {
                // stopped by Stop()
            }
        }

        public void Stop() => _stop.Cancel();

        public void Dispose() => _stop.Dispose();
    }

    // ================================================================ fetch result

    private sealed class FetchResult
    {
        public required Uri Url { get; init; }
        public int Status { get; init; }
        public string MediaType { get; init; } = string.Empty;
        public string? Body { get; init; }
        public Uri? Location { get; init; }
        public long Size { get; init; }
        public int TimeMs { get; init; }
    }

    private enum Kind { CleartextPassword, PasswordAutocomplete, MissingCsrf, MixedContent, ErrorDisclosure, Emails, InternalIp, InterestingFile, SourceMap }

    private sealed class Collected
    {
        public int Count;
        public readonly List<string> Examples = new();
        public readonly HashSet<string> Distinct = new(StringComparer.OrdinalIgnoreCase);
    }

    // ================================================================ per-root crawl

    private sealed class RootCrawl
    {
        private readonly ScanContext _ctx;
        private readonly Uri _root;
        private readonly int _index;
        private readonly SharedState _shared;
        private readonly UrlBatcher _batcher;
        private readonly object _lock = new();
        private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
        private readonly Dictionary<string, HashSet<string>> _variants = new(StringComparer.Ordinal);
        private readonly Dictionary<Kind, Collected> _found = new();
        private readonly Dictionary<int, int> _statusCounts = new();
        private readonly List<string> _disallow = new(), _allow = new();
        private readonly string _rootIp;
        private int _quota, _used, _fetched, _errors, _robotsSkipped, _unsafeSkipped, _taskId;
        private long _bytes;

        public RootCrawl(ScanContext ctx, Uri root, int index, SharedState shared, UrlBatcher batcher)
        {
            _ctx = ctx;
            _root = root;
            _index = index;
            _shared = shared;
            _batcher = batcher;
            _quota = shared.Quota(index);
            _rootIp = ctx.IpFor(root.Host);
        }

        private string Label => _root.GetLeftPart(UriPartial.Authority);

        public async Task RunAsync()
        {
            var o = _ctx.Options;
            _taskId = _ctx.AddTask($"Crawl {_root.Authority}", "Web Crawler");
            _ctx.UpdateTask(_taskId, TaskState.Running, 0);
            _ctx.Log(LogLevel.Info, "crawler", $"Crawl started on {Label} (budget {_quota} page(s))");
            int workers = Math.Clamp(Math.Min(o.Threads, 8), 1, 8);
            bool cancelled = false;
            var sw = Stopwatch.StartNew();
            try
            {
                var current = new List<(Uri Url, int Depth)>();
                var next = new List<(Uri Url, int Depth)>();
                if (TryAccept(_root, ignoreRobots: true)) current.Add((_root, 0));
                var rootPage = new Uri(_root, "/");
                if (TryAccept(rootPage, ignoreRobots: true)) current.Add((rootPage, 0));

                foreach (var u in await DiscoverSeedsAsync().ConfigureAwait(false))
                    if (TryAccept(u, ignoreRobots: false)) next.Add((u, 1));

                for (int depth = 0; depth <= o.CrawlMaxDepth && (current.Count > 0 || next.Count > 0); depth++)
                {
                    if (current.Count == 0)
                    {
                        current = next;
                        next = new List<(Uri, int)>();
                        continue;
                    }
                    var level = current;
                    var nextLevel = next;
                    await Parallel.ForEachAsync(level, new ParallelOptions { MaxDegreeOfParallelism = workers, CancellationToken = _ctx.Token },
                        async (item, _) =>
                        {
                            if (!Reserve()) return;
                            var res = await FetchAsync(item.Url).ConfigureAwait(false);
                            var links = Process(item.Url, res);
                            if (item.Depth + 1 > o.CrawlMaxDepth) return;
                            foreach (var l in links)
                            {
                                if (!TryAccept(l, ignoreRobots: false)) continue;
                                lock (nextLevel)
                                {
                                    if (nextLevel.Count < MaxFrontier) nextLevel.Add((l, item.Depth + 1));
                                }
                            }
                        }).ConfigureAwait(false);
                    _ctx.Log(LogLevel.Debug, "crawler", $"{Label}: depth {depth} done, {Volatile.Read(ref _fetched)} fetched, {nextLevel.Count} queued for depth {depth + 1}");
                    if (OutOfBudget()) break;
                    current = nextLevel;
                    next = new List<(Uri, int)>();
                }
            }
            catch (OperationCanceledException) when (_ctx.Token.IsCancellationRequested)
            {
                cancelled = true;
                throw;
            }
            finally
            {
                ReportFindings();
                int unused;
                lock (_lock) unused = _quota - _used;
                _shared.GiveBack(unused);
                _shared.Progress(_index, 1);
                _ctx.UpdateTask(_taskId, cancelled ? TaskState.Cancelled : TaskState.Done, cancelled ? Progress() : 100);
            }

            string statuses;
            lock (_statusCounts) statuses = string.Join(", ", _statusCounts.OrderBy(k => k.Key).Select(k => $"{k.Key}x{k.Value}"));
            _ctx.Log(LogLevel.Ok, "crawler",
                $"Crawl finished on {Label}: {_fetched} URL(s) in {sw.Elapsed.TotalSeconds:0.0}s, {FormatBytes(Interlocked.Read(ref _bytes))}, " +
                $"{_errors} error(s), {_robotsSkipped} robots-excluded, {_unsafeSkipped} unsafe link(s) skipped" + (statuses.Length > 0 ? $" [{statuses}]" : string.Empty));
        }

        private static string FormatBytes(long b) => b >= 1024 * 1024 ? $"{b / 1048576.0:0.0} MB" : b >= 1024 ? $"{b / 1024.0:0.0} KB" : $"{b} B";

        private int Progress()
        {
            lock (_lock) return _quota == 0 ? 100 : (int)(100.0 * _used / _quota);
        }

        private bool OutOfBudget()
        {
            lock (_lock)
            {
                if (_used < _quota) return false;
            }
            return !HasSpare(_shared);
        }

        private static bool HasSpare(SharedState s)
        {
            if (!s.TakeSpare()) return false;
            s.GiveBack(1);
            return true;
        }

        private bool Reserve()
        {
            lock (_lock)
            {
                if (_used < _quota)
                {
                    _used++;
                    return true;
                }
            }
            if (!_shared.TakeSpare()) return false;
            lock (_lock)
            {
                _quota++;
                _used++;
            }
            return true;
        }

        // ------------------------------------------------------------ scope

        private bool TryAccept(Uri u, bool ignoreRobots)
        {
            if (!SameOrigin(u, _root)) return false;
            string pq = u.PathAndQuery;
            if (UnsafeLinkRegex().IsMatch(pq))
            {
                Interlocked.Increment(ref _unsafeSkipped);
                return false;
            }
            string key = u.AbsoluteUri;
            lock (_lock)
            {
                if (_seen.Contains(key)) return false;
                if (!ignoreRobots && _ctx.Options.RespectRobots && IsDisallowed(pq))
                {
                    _seen.Add(key);
                    _robotsSkipped++;
                    return false;
                }
                if (u.Query.Length > 1)
                {
                    // at most 3 variants per path; variants differing only in parameter values count as one
                    string shape = QueryShape(u.Query);
                    if (!_variants.TryGetValue(u.AbsolutePath, out var shapes)) _variants[u.AbsolutePath] = shapes = new HashSet<string>(StringComparer.Ordinal);
                    if (shapes.Contains(shape) || shapes.Count >= 3) return false;
                    shapes.Add(shape);
                }
                if (_seen.Count > MaxFrontier * 4) return false;
                _seen.Add(key);
                return true;
            }
        }

        /// <summary>Parameter names in order, values ignored: "?a=1&amp;b=2" becomes "a&amp;b".</summary>
        private static string QueryShape(string query)
        {
            var sb = new StringBuilder();
            foreach (var part in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int eq = part.IndexOf('=');
                if (sb.Length > 0) sb.Append('&');
                sb.Append(eq >= 0 ? part[..eq] : part);
            }
            return sb.ToString();
        }

        private bool IsDisallowed(string pathAndQuery)
        {
            // longest match wins; Allow wins ties (RFC 9309)
            int bestDis = -1, bestAllow = -1;
            foreach (var r in _disallow)
                if (r.Length > bestDis && HtmlLinks.RobotsMatch(r, pathAndQuery)) bestDis = r.Length;
            if (bestDis < 0) return false;
            foreach (var r in _allow)
                if (r.Length > bestAllow && HtmlLinks.RobotsMatch(r, pathAndQuery)) bestAllow = r.Length;
            return bestDis > bestAllow;
        }

        // ------------------------------------------------------------ robots + sitemaps

        private async Task<List<Uri>> DiscoverSeedsAsync()
        {
            var seeds = new List<Uri>();
            var sitemapQueue = new List<(Uri Url, int Level)>();
            var robotsUri = new Uri(_root, "/robots.txt");
            var robots = await FetchAsync(robotsUri).ConfigureAwait(false);
            if (robots != null) Record(robots);
            if (robots is { Status: 200, Body: { } text } && !robots.MediaType.Contains("html", StringComparison.Ordinal))
            {
                var (dis, allow, maps) = HtmlLinks.ParseRobots(text);
                lock (_lock)
                {
                    _disallow.AddRange(dis);
                    _allow.AddRange(allow);
                }
                foreach (var m in maps)
                    if (Uri.TryCreate(m, UriKind.Absolute, out var mu) && Normalize(mu) is { } nm && SameOrigin(nm, _root))
                        sitemapQueue.Add((nm, 1));
                // Disallowed paths are themselves interesting: queue them for discovery only when robots is not honoured.
                if (!_ctx.Options.RespectRobots)
                    foreach (var d in dis)
                        if (!d.Contains('*') && Resolve(_root, d.TrimEnd('$')) is { } du) seeds.Add(du);
                _ctx.Log(LogLevel.Debug, "crawler", $"{Label}: robots.txt has {dis.Count} Disallow / {allow.Count} Allow rule(s) for *, {maps.Count} sitemap(s)");
            }
            if (sitemapQueue.Count == 0) sitemapQueue.Add((new Uri(_root, "/sitemap.xml"), 1));

            var done = new HashSet<string>(StringComparer.Ordinal);
            int files = 0;
            for (int i = 0; i < sitemapQueue.Count && files < MaxSitemapFiles && seeds.Count < MaxSitemapUrls; i++)
            {
                var (url, lvl) = sitemapQueue[i];
                if (!done.Add(url.AbsoluteUri)) continue;
                files++;
                var res = await FetchAsync(url).ConfigureAwait(false);
                if (res == null) continue;
                Record(res);
                if (res.Status != 200 || res.Body == null || res.MediaType.Contains("html", StringComparison.Ordinal)) continue;
                var (pages, indexes) = HtmlLinks.ParseSitemap(res.Body, MaxSitemapUrls - seeds.Count);
                foreach (var p in pages)
                    if (Uri.TryCreate(p.Trim(), UriKind.Absolute, out var pu) && Normalize(pu) is { } np && SameOrigin(np, _root)) seeds.Add(np);
                if (lvl < 2)
                    foreach (var ix in indexes)
                        if (Uri.TryCreate(ix.Trim(), UriKind.Absolute, out var iu) && Normalize(iu) is { } ni && SameOrigin(ni, _root))
                            sitemapQueue.Add((ni, lvl + 1));
                _ctx.Log(LogLevel.Debug, "crawler", $"{Label}: sitemap {url.AbsolutePath} listed {pages.Count} page(s), {indexes.Count} child sitemap(s)");
            }
            return seeds;
        }

        // ------------------------------------------------------------ network

        private async Task<FetchResult?> FetchAsync(Uri url)
        {
            var o = _ctx.Options;
            await _ctx.Concurrency.WaitAsync(_ctx.Token).ConfigureAwait(false);
            var sw = new Stopwatch();
            try
            {
                await _ctx.GateAsync().ConfigureAwait(false);
                using var _ = _ctx.BeginWork();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(_ctx.Token);
                cts.CancelAfter(TimeSpan.FromMilliseconds(o.ConnectTimeoutMs + o.ReadTimeoutMs * 3));
                sw.Start();
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                using var resp = await _ctx.Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false);
                double headerMs = sw.Elapsed.TotalMilliseconds;
                int status = (int)resp.StatusCode;
                string media = resp.Content.Headers.ContentType?.MediaType?.ToLowerInvariant() ?? string.Empty;
                string? charset = resp.Content.Headers.ContentType?.CharSet;
                long? declared = resp.Content.Headers.ContentLength;

                Uri? location = null;
                if (status is >= 300 and < 400 && resp.Headers.Location is { } loc)
                    location = loc.IsAbsoluteUri ? Normalize(loc) : Uri.TryCreate(url, loc, out var abs) ? Normalize(abs) : null;

                string? body = null;
                long read = 0;
                if (IsParseable(media) && (declared is null || declared < MaxBodyBytes))
                {
                    try
                    {
                        (body, read) = await ReadBodyAsync(resp, charset, media.Length == 0, cts.Token).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) when (_ctx.Token.IsCancellationRequested)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _ctx.Log(LogLevel.Debug, "crawler", $"Body read failed for {url}: {ex.GetType().Name}: {ex.Message}");
                    }
                }
                sw.Stop();
                _ctx.CountRequest(headerMs, status >= 500);
                Interlocked.Add(ref _bytes, read);
                return new FetchResult
                {
                    Url = url,
                    Status = status,
                    MediaType = media,
                    Body = body,
                    Location = location,
                    Size = Math.Max(read, declared ?? 0),
                    TimeMs = (int)sw.Elapsed.TotalMilliseconds,
                };
            }
            catch (OperationCanceledException) when (_ctx.Token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex)
            {
                _ctx.CountRequest(sw.IsRunning ? sw.Elapsed.TotalMilliseconds : -1, error: true);
                Interlocked.Increment(ref _errors);
                _ctx.Log(LogLevel.Debug, "crawler", $"GET {url} failed: {ex.GetType().Name}: {ex.Message}");
                return null;
            }
            finally
            {
                _ctx.Concurrency.Release();
            }
        }

        private static async Task<(string? Body, long Read)> ReadBodyAsync(HttpResponseMessage resp, string? charset, bool sniff, CancellationToken token)
        {
            var stream = await resp.Content.ReadAsStreamAsync(token).ConfigureAwait(false);
            await using (stream.ConfigureAwait(false))
            {
                using var ms = new MemoryStream();
                var buf = new byte[64 * 1024];
                int total = 0;
                while (total < MaxBodyBytes)
                {
                    int n = await stream.ReadAsync(buf.AsMemory(0, Math.Min(buf.Length, MaxBodyBytes - total)), token).ConfigureAwait(false);
                    if (n == 0) break;
                    ms.Write(buf, 0, n);
                    total += n;
                }
                return (Decode(ms, charset, sniff), total);
            }
        }

        private static string? Decode(MemoryStream ms, string? charset, bool sniff)
        {
            var bytes = ms.GetBuffer().AsSpan(0, (int)ms.Length);
            if (sniff && bytes[..Math.Min(bytes.Length, 1024)].IndexOf((byte)0) >= 0) return null; // binary without a content type
            Encoding enc = Encoding.UTF8;
            if (!string.IsNullOrWhiteSpace(charset))
            {
                try
                {
                    enc = Encoding.GetEncoding(charset.Trim('"', '\'', ' '));
                }
                catch (ArgumentException)
                {
                    enc = Encoding.UTF8;
                }
            }
            return enc.GetString(bytes);
        }

        // ------------------------------------------------------------ analysis

        private void Record(FetchResult r)
        {
            _batcher.Add(new UrlRecord
            {
                Host = r.Url.Authority,
                Path = r.Url.PathAndQuery,
                Url = r.Url.AbsoluteUri,
                Method = "GET",
                Status = r.Status,
                ContentType = r.MediaType,
                Size = r.Size,
                TimeMs = r.TimeMs,
            });
            lock (_statusCounts) _statusCounts[r.Status] = _statusCounts.GetValueOrDefault(r.Status) + 1;
        }

        private List<Uri> Process(Uri url, FetchResult? r)
        {
            int n = Interlocked.Increment(ref _fetched);
            _shared.Fetched();
            int quota;
            lock (_lock) quota = _quota;
            _shared.Progress(_index, n / (double)Math.Max(1, quota));
            if (n % 25 == 0) _ctx.UpdateTask(_taskId, TaskState.Running, Progress());
            if (n % 100 == 0) _ctx.Log(LogLevel.Debug, "crawler", $"{Label}: {n} URL(s) fetched");

            var links = new List<Uri>();
            if (r == null) return links;
            Record(r);
            if (r.Location != null) links.Add(r.Location);

            string path = url.AbsolutePath;
            bool isHtml = r.MediaType.Contains("html", StringComparison.Ordinal);
            if (r.Status == 200 && !isHtml)
            {
                if (InterestingFileRegex().IsMatch(path) || DotEnvRegex().IsMatch(path))
                    Collect(Kind.InterestingFile, $"{url.AbsoluteUri} (HTTP 200, {r.MediaType.DefaultIfEmpty("no content-type")}, {(r.Size > 0 ? r.Size + " bytes" : "size not declared")})");
                else if (path.EndsWith(".map", StringComparison.OrdinalIgnoreCase))
                    Collect(Kind.SourceMap, url.AbsoluteUri);
            }

            if (r.Body is not { Length: > 0 } body) return links;
            try
            {
                Analyze(url, r, body, isHtml, links);
            }
            catch (RegexMatchTimeoutException)
            {
                _ctx.Log(LogLevel.Debug, "crawler", $"Parsing timed out on {url} ({body.Length} chars); partial results kept");
            }
            return links;
        }

        private void Analyze(Uri url, FetchResult r, string body, bool isHtml, List<Uri> links)
        {
            string media = r.MediaType;
            bool isJs = media.Contains("javascript", StringComparison.Ordinal) || media.Contains("ecmascript", StringComparison.Ordinal)
                || url.AbsolutePath.EndsWith(".js", StringComparison.OrdinalIgnoreCase);
            bool isJson = media.Contains("json", StringComparison.Ordinal);
            bool isXml = !isHtml && media.Contains("xml", StringComparison.Ordinal);

            // ---- links
            var raw = new List<string>();
            Uri baseUri = url;
            List<ActiveRef>? active = isHtml && url.Scheme == Uri.UriSchemeHttps ? new List<ActiveRef>() : null;
            if (isHtml || isXml)
            {
                raw.AddRange(HtmlLinks.FromHtml(body, out var baseHref, active));
                if (baseHref != null && Uri.TryCreate(url, baseHref, out var b) && Normalize(b) is { } nb) baseUri = nb;
            }
            else if (isJs || isJson)
            {
                raw.AddRange(HtmlLinks.FromScript(body));
            }
            else if (media == "text/css")
            {
                raw.AddRange(HtmlLinks.FromCss(body));
            }
            if (isJs || isHtml)
                foreach (Match m in SourceMapRegex().Matches(body))
                    raw.Add(m.Groups["u"].Value);
            foreach (var s in raw)
                if (Resolve(baseUri, s) is { } u) links.Add(u);

            // ---- error disclosure (not in JS/CSS where these strings occur legitimately)
            if (!isJs && media != "text/css")
            {
                foreach (var (pattern, label) in ErrorPatterns)
                {
                    int at = body.IndexOf(pattern, StringComparison.Ordinal);
                    if (at < 0) continue;
                    if (pattern == "at System." && !LooksLikeDotNetTrace(body, at)) continue;
                    Collect(Kind.ErrorDisclosure, $"{url.AbsoluteUri} [HTTP {r.Status}] {label}: \"{Snippet(body, at)}\"");
                    break;
                }
            }

            // ---- e-mail addresses
            if (!isJs)
            {
                foreach (Match m in EmailRegex().Matches(body))
                {
                    string addr = m.Value.TrimEnd('.');
                    string tld = addr[(addr.LastIndexOf('.') + 1)..];
                    if (ImageTlds.Contains(tld)) continue;
                    if (addr.Contains("example.", StringComparison.OrdinalIgnoreCase)) continue;
                    CollectDistinct(Kind.Emails, addr.ToLowerInvariant(), url.AbsoluteUri);
                }
            }

            // ---- internal IP addresses
            foreach (Match m in InternalIpRegex().Matches(body))
            {
                if (!IPAddress.TryParse(m.Value, out var ip) || ip.ToString() != m.Value) continue; // rejects octets > 255
                if (string.Equals(m.Value, _rootIp, StringComparison.Ordinal)) continue;
                CollectDistinct(Kind.InternalIp, m.Value, url.AbsoluteUri);
            }

            if (!isHtml) return;

            // ---- mixed content
            if (active != null)
            {
                foreach (var a in active)
                {
                    if (!Uri.TryCreate(baseUri, a.Url, out var au) || au.Scheme != Uri.UriSchemeHttp) continue;
                    Collect(Kind.MixedContent, $"{url.AbsoluteUri} loads <{a.Tag}> {au.AbsoluteUri}");
                }
            }

            // ---- forms
            bool metaToken = CsrfMetaRegex().IsMatch(body);
            foreach (var f in HtmlLinks.Forms(body))
            {
                Uri target = url;
                if (f.Action.Length > 0 && Uri.TryCreate(baseUri, f.Action, out var fa)) target = fa;
                if (f.Action.Length > 0 && !f.Action.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase)
                    && Normalize(target) is { } nt && f.Method == "get" && !f.HasPassword)
                    links.Add(nt); // GET forms are plain navigations; their action is a link
                if (f.HasPassword && target.Scheme == Uri.UriSchemeHttp)
                    Collect(Kind.CleartextPassword, $"{url.AbsoluteUri} -> {f.Method.ToUpperInvariant()} {target.AbsoluteUri}");
                if (f.HasPassword && f.PasswordAutocomplete)
                    Collect(Kind.PasswordAutocomplete, url.AbsoluteUri);
                if (f.Method == "post" && !f.HasCsrfToken && !metaToken)
                    Collect(Kind.MissingCsrf, $"{url.AbsoluteUri} -> POST {target.AbsoluteUri}");
            }
        }

        private static bool LooksLikeDotNetTrace(string body, int at)
        {
            // require a typical frame shape such as "at System.Foo.Bar(...)" and a second frame or exception name nearby
            int end = Math.Min(body.Length, at + 2000);
            string window = body[at..end];
            return window.Contains('(') && (window.IndexOf(" at ", 10, StringComparison.Ordinal) > 0 || window.Contains("Exception", StringComparison.Ordinal));
        }

        private static string Snippet(string body, int at)
        {
            int start = Math.Max(0, at - 20);
            int len = Math.Min(body.Length - start, 160);
            var s = body.Substring(start, len);
            var sb = new StringBuilder(s.Length);
            bool space = false;
            foreach (char c in s)
            {
                if (char.IsWhiteSpace(c) || char.IsControl(c))
                {
                    if (!space) sb.Append(' ');
                    space = true;
                }
                else
                {
                    sb.Append(c);
                    space = false;
                }
            }
            return sb.ToString().Trim();
        }

        private void Collect(Kind kind, string example)
        {
            lock (_found)
            {
                if (!_found.TryGetValue(kind, out var c)) _found[kind] = c = new Collected();
                if (!c.Distinct.Add(example)) return;
                c.Count++;
                if (c.Examples.Count < 5) c.Examples.Add(example);
            }
        }

        private void CollectDistinct(Kind kind, string value, string where)
        {
            lock (_found)
            {
                if (!_found.TryGetValue(kind, out var c)) _found[kind] = c = new Collected();
                if (c.Distinct.Count >= 1000 || !c.Distinct.Add(value)) return;
                c.Count++;
                if (c.Examples.Count < 5) c.Examples.Add($"{value} (in {where})");
            }
        }

        // ------------------------------------------------------------ findings

        private void ReportFindings()
        {
            Dictionary<Kind, Collected> found;
            lock (_found) found = new Dictionary<Kind, Collected>(_found);
            string host = _rootIp;
            int port = _root.Port;
            foreach (var (kind, c) in found)
            {
                if (c.Count == 0) continue;
                string ev = $"{c.Count} occurrence(s) found while crawling {Label}. Examples:\n" + string.Join("\n", c.Examples);
                switch (kind)
                {
                    case Kind.CleartextPassword:
                        _ctx.AddFinding(Severity.Medium, "Password form submitted over cleartext HTTP", host, port, 319,
                            "A form containing a password field is served or submitted over unencrypted HTTP, so credentials can be read or modified by anyone on the network path.",
                            ev, "Serve the login page and its form action exclusively over HTTPS and redirect HTTP to HTTPS; add HSTS.");
                        break;
                    case Kind.PasswordAutocomplete:
                        _ctx.AddFinding(Severity.Info, "Password field with autocomplete enabled", host, port, 525,
                            "Password inputs do not set autocomplete=\"off\"/\"new-password\". Browsers may store the credential; this is often acceptable for modern password managers.",
                            ev, "Set autocomplete=\"current-password\" or \"new-password\" deliberately, or autocomplete=\"off\" for sensitive back-office forms.");
                        break;
                    case Kind.MissingCsrf:
                        _ctx.AddFinding(Severity.Low, "POST form without apparent anti-CSRF token", host, port, 352,
                            "POST forms were found without a hidden field whose name looks like a CSRF token (csrf, xsrf, token, nonce, authenticity...) and without a csrf meta tag. " +
                            "Heuristic: protection may still exist via SameSite cookies, custom headers or a differently named field; verify manually.",
                            ev, "Protect state-changing requests with a per-session or per-request anti-CSRF token and SameSite=Lax/Strict cookies.");
                        break;
                    case Kind.MixedContent:
                        _ctx.AddFinding(Severity.Low, "Mixed content: HTTPS page loads active content over HTTP", host, port, 311,
                            "HTTPS pages reference scripts, frames, objects or stylesheets over plain HTTP. An on-path attacker can replace that content and take over the page; modern browsers block it, breaking the page.",
                            ev, "Load every sub-resource over HTTPS (or protocol-relative/relative URLs) and consider Content-Security-Policy: upgrade-insecure-requests.");
                        break;
                    case Kind.ErrorDisclosure:
                        _ctx.AddFinding(Severity.Medium, "Error page discloses stack trace or database error", host, port, 209,
                            "Responses contain framework stack traces or raw database error messages, revealing internal paths, technologies, queries or code structure.",
                            ev, "Disable debug/detailed errors in production, return generic error pages and log details server-side only.");
                        break;
                    case Kind.Emails:
                        _ctx.AddFinding(Severity.Info, "E-mail addresses disclosed", host, port, 200,
                            $"{c.Count} distinct e-mail address(es) appear in crawled content. They can be harvested for spam or phishing.",
                            ev, "Review whether these addresses need to be published; prefer contact forms or role addresses.");
                        break;
                    case Kind.InternalIp:
                        _ctx.AddFinding(Severity.Low, "Internal IP address disclosed", host, port, 200,
                            $"{c.Count} private (RFC 1918) IP address(es) appear in responses, revealing internal network layout.",
                            ev, "Remove internal addresses from pages, headers, scripts and error messages; check proxy and load balancer configuration.");
                        break;
                    case Kind.InterestingFile:
                        _ctx.AddFinding(Severity.Medium, "Backup, archive, log or environment file exposed", host, port, 530,
                            "Files such as backups, archives, SQL dumps, logs or .env files are reachable over HTTP (status 200, non-HTML). They often contain source code, credentials or personal data.",
                            ev, "Remove these files from the web root and block such extensions at the web server.");
                        break;
                    case Kind.SourceMap:
                        _ctx.AddFinding(Severity.Info, "JavaScript source map exposed", host, port, 540,
                            "Source map files are publicly reachable and allow reconstruction of the original front-end source code, including comments.",
                            ev, "Do not deploy .map files to production, or restrict access to them.");
                        break;
                }
            }
        }
    }
}

internal static class CrawlerStringExtensions
{
    public static string DefaultIfEmpty(this string s, string fallback) => s.Length == 0 ? fallback : s;
}
