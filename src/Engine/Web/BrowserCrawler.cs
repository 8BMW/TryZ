using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Http;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Optional headless-browser crawl for JavaScript-driven applications. It drives an installed Chromium browser
/// (Microsoft Edge or Google Chrome) over the Chrome DevTools Protocol — the same protocol Playwright uses — to render
/// each web root, run its scripts, and read the links and forms that only exist after the page's JavaScript executes.
/// Those become GET injection points and form injection points for the active audit, so single-page apps are covered.
///
/// No browser is bundled and no package is required: the feature uses a browser already on the machine and degrades
/// gracefully — if none is found, or anything fails, it logs and the normal scan continues. All navigations are
/// same-origin with the discovered web roots and honour the configured upstream proxy.
/// </summary>
internal static class BrowserCrawler
{
    public static async Task RunAsync(ScanContext ctx, IReadOnlyList<Uri> roots)
    {
        if (roots.Count == 0) return;
        string? exe = FindBrowser(ctx.Options.BrowserPath);
        if (exe == null)
        {
            ctx.Log(LogLevel.Warn, "browser", "No Chromium browser (Edge/Chrome) found; headless browser crawl skipped. Set an explicit path in Options → Active Testing.");
            return;
        }

        string profileDir = Path.Combine(Path.GetTempPath(), "tryz-cdp-" + Guid.NewGuid().ToString("N")[..12]);
        Process? browser = null;
        try
        {
            ctx.Log(LogLevel.Info, "browser", $"Launching headless browser: {Path.GetFileName(exe)}");
            browser = LaunchHeadless(exe, profileDir, ctx.Options.HttpProxy);
            if (browser == null)
            {
                ctx.Log(LogLevel.Warn, "browser", "Browser process could not be started; browser crawl skipped");
                return;
            }
            int port = await ReadDevToolsPortAsync(profileDir, ctx.Token).ConfigureAwait(false);
            if (port <= 0)
            {
                ctx.Log(LogLevel.Warn, "browser", "Browser did not expose a DevTools endpoint in time; browser crawl skipped");
                return;
            }
            string? wsUrl = await GetBrowserWebSocketAsync(port, ctx.Token).ConfigureAwait(false);
            if (wsUrl == null)
            {
                ctx.Log(LogLevel.Warn, "browser", "Could not read the DevTools WebSocket endpoint; browser crawl skipped");
                return;
            }

            await using var cdp = await Cdp.ConnectAsync(wsUrl, ctx.Token).ConfigureAwait(false);
            await CrawlAsync(ctx, cdp, roots).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
        catch (Exception ex)
        {
            ctx.Log(LogLevel.Warn, "browser", $"Browser crawl error: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            try { if (browser is { HasExited: false }) browser.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
            browser?.Dispose();
            TryDeleteDir(profileDir);
        }
    }

    // ------------------------------------------------------------------ crawl loop

    private static async Task CrawlAsync(ScanContext ctx, Cdp cdp, IReadOnlyList<Uri> roots)
    {
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var frontier = new Queue<Uri>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in roots)
        {
            origins.Add(r.GetLeftPart(UriPartial.Authority));
            if (seen.Add(r.AbsoluteUri)) frontier.Enqueue(r);
        }

        int budget = ctx.Options.BrowserMaxPages;
        int rendered = 0, forms = 0, links = 0;
        ctx.Log(LogLevel.Notice, "browser", $"Browser crawl started on {roots.Count} root(s); up to {budget} page(s) rendered");

        while (frontier.Count > 0 && rendered < budget)
        {
            ctx.Token.ThrowIfCancellationRequested();
            var url = frontier.Dequeue();
            var page = await RenderAsync(ctx, cdp, url).ConfigureAwait(false);
            if (page == null) continue;
            rendered++;
            EmitRendered(ctx, url, page.Value);

            foreach (var form in page.Value.Forms)
            {
                if (NoteForm(ctx, url, form, origins)) forms++;
            }
            foreach (var href in page.Value.Links)
            {
                if (!Uri.TryCreate(href, UriKind.Absolute, out var lu)) continue;
                if (lu.Scheme is not ("http" or "https")) continue;
                ctx.NoteHostname(lu.Host);
                if (!origins.Contains(lu.GetLeftPart(UriPartial.Authority))) continue;
                links++;
                NoteQueryPoint(ctx, lu);
                // Enqueue unseen same-origin pages for shallow in-app discovery, within the page budget.
                var norm = Crawler.Normalize(lu);
                if (norm != null && seen.Count < budget * 4 && seen.Add(norm.AbsoluteUri) && frontier.Count + rendered < budget)
                    frontier.Enqueue(norm);
            }
        }
        ctx.Log(LogLevel.Ok, "browser", $"Browser crawl finished: {rendered} page(s) rendered, {forms} form(s) and {links} link(s) discovered for active testing");
    }

    private readonly record struct PageData(string Url, IReadOnlyList<string> Links, IReadOnlyList<RenderedForm> Forms);
    private sealed record RenderedForm(string Action, string Method, List<KeyValuePair<string, string>> Fields, bool HasPassword);

    private static async Task<PageData?> RenderAsync(ScanContext ctx, Cdp cdp, Uri url)
    {
        string? sessionId = null;
        string? targetId = null;
        try
        {
            await ctx.GateAsync().ConfigureAwait(false);
            using var work = ctx.BeginWork();
            var create = await cdp.SendAsync("Target.createTarget", new { url = "about:blank" }, null, ctx.Token).ConfigureAwait(false);
            targetId = create.TryGetProperty("result", out var cr) && cr.TryGetProperty("targetId", out var t) ? t.GetString() : null;
            if (targetId == null) return null;
            var attach = await cdp.SendAsync("Target.attachToTarget", new { targetId, flatten = true }, null, ctx.Token).ConfigureAwait(false);
            sessionId = attach.TryGetProperty("result", out var ar) && ar.TryGetProperty("sessionId", out var s) ? s.GetString() : null;
            if (sessionId == null) return null;

            await cdp.SendAsync("Page.enable", null, sessionId, ctx.Token).ConfigureAwait(false);
            // Register the load waiter before navigating so the event is not missed.
            int budgetMs = ctx.Options.ConnectTimeoutMs + ctx.Options.ReadTimeoutMs * 2;
            var load = cdp.WaitForEventAsync("Page.loadEventFired", sessionId, ctx.Token);
            await cdp.SendAsync("Page.navigate", new { url = url.AbsoluteUri }, sessionId, ctx.Token).ConfigureAwait(false);
            await AwaitOrTimeout(load, budgetMs, ctx.Token).ConfigureAwait(false);
            // Give client-side rendering / XHR a moment to settle.
            await Task.Delay(Math.Clamp(ctx.Options.ReadTimeoutMs / 4, 300, 1500), ctx.Token).ConfigureAwait(false);

            var eval = await cdp.SendAsync("Runtime.evaluate",
                new { expression = CollectScript, returnByValue = true, awaitPromise = false }, sessionId, ctx.Token).ConfigureAwait(false);
            string? json = eval.TryGetProperty("result", out var er) && er.TryGetProperty("result", out var rr)
                && rr.TryGetProperty("value", out var vv) && vv.ValueKind == JsonValueKind.String ? vv.GetString() : null;
            ctx.CountRequest(-1);
            return json == null ? null : Parse(json);
        }
        catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
        catch (Exception ex) when (ex is JsonException or WebSocketException or InvalidOperationException or TimeoutException)
        {
            ctx.Log(LogLevel.Debug, "browser", $"Render failed for {url}: {ex.GetType().Name}");
            return null;
        }
        finally
        {
            if (targetId != null)
                try { await cdp.SendAsync("Target.closeTarget", new { targetId }, null, ctx.Token).ConfigureAwait(false); }
                catch (Exception ex) when (ex is WebSocketException or InvalidOperationException or OperationCanceledException) { }
        }
    }

    private static PageData? Parse(string json)
    {
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;
        string pageUrl = root.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
        var links = new List<string>();
        if (root.TryGetProperty("links", out var la) && la.ValueKind == JsonValueKind.Array)
            foreach (var l in la.EnumerateArray())
                if (l.GetString() is { Length: > 0 } s) links.Add(s);
        var forms = new List<RenderedForm>();
        if (root.TryGetProperty("forms", out var fa) && fa.ValueKind == JsonValueKind.Array)
        {
            foreach (var f in fa.EnumerateArray())
            {
                string action = f.TryGetProperty("action", out var a) ? a.GetString() ?? "" : "";
                string method = (f.TryGetProperty("method", out var m) ? m.GetString() ?? "get" : "get").ToLowerInvariant();
                bool pwd = false;
                var fields = new List<KeyValuePair<string, string>>();
                if (f.TryGetProperty("fields", out var fl) && fl.ValueKind == JsonValueKind.Array)
                {
                    foreach (var fe in fl.EnumerateArray())
                    {
                        string name = fe.TryGetProperty("name", out var n) ? n.GetString() ?? "" : "";
                        string val = fe.TryGetProperty("value", out var v) ? v.GetString() ?? "" : "";
                        string type = fe.TryGetProperty("type", out var ty) ? ty.GetString() ?? "" : "";
                        if (name.Length == 0) continue;
                        if (type.Equals("password", StringComparison.OrdinalIgnoreCase)) pwd = true;
                        fields.Add(new KeyValuePair<string, string>(name, val));
                    }
                }
                if (action.Length > 0) forms.Add(new RenderedForm(action, method, fields, pwd));
            }
        }
        return new PageData(pageUrl, links, forms);
    }

    // A single expression (string result) collecting the rendered DOM's links and forms.
    private const string CollectScript = """
        (function(){try{
          var links=[];var seen={};
          document.querySelectorAll('a[href]').forEach(function(a){var h=a.href;if(h&&!seen[h]){seen[h]=1;links.push(h);}});
          var forms=[];
          Array.prototype.forEach.call(document.forms,function(f){
            var fields=[];
            Array.prototype.forEach.call(f.elements,function(e){if(e.name){fields.push({name:e.name,value:(e.value||'').toString().slice(0,64),type:(e.type||'')});}});
            forms.push({action:f.action||location.href,method:(f.method||'get').toLowerCase(),fields:fields});
          });
          return JSON.stringify({url:location.href,links:links.slice(0,500),forms:forms});
        }catch(e){return JSON.stringify({url:location.href,links:[],forms:[]});}})()
        """;

    // ------------------------------------------------------------------ feed the active audit

    private static bool NoteForm(ScanContext ctx, Uri pageUrl, RenderedForm form, HashSet<string> origins)
    {
        if (form.Fields.Count == 0) return false;
        if (!Uri.TryCreate(pageUrl, form.Action, out var action)) return false;
        if (action.Scheme is not ("http" or "https")) return false;
        if (!origins.Contains(action.GetLeftPart(UriPartial.Authority))) return false;
        ctx.NoteInjectionPoint(new InjectionPoint
        {
            Method = form.Method == "post" ? "POST" : "GET",
            Url = new Uri(action.GetLeftPart(UriPartial.Path)),
            HostIp = ctx.IpFor(action.Host),
            Port = action.Port,
            Parameters = form.Fields,
            Origin = form.HasPassword ? "login form (rendered)" : "HTML form (rendered)",
        });
        return true;
    }

    private static void NoteQueryPoint(ScanContext ctx, Uri url)
    {
        if (url.Query.Length <= 1) return;
        var pars = new List<KeyValuePair<string, string>>();
        foreach (var part in url.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            string name = Uri.UnescapeDataString((eq >= 0 ? part[..eq] : part).Replace('+', ' '));
            string val = eq >= 0 ? Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' ')) : string.Empty;
            if (name.Length > 0) pars.Add(new KeyValuePair<string, string>(name, val));
        }
        if (pars.Count == 0) return;
        ctx.NoteInjectionPoint(new InjectionPoint
        {
            Method = "GET",
            Url = new Uri(url.GetLeftPart(UriPartial.Path)),
            HostIp = ctx.IpFor(url.Host),
            Port = url.Port,
            Parameters = pars,
            Origin = "query string (rendered)",
        });
    }

    private static void EmitRendered(ScanContext ctx, Uri url, PageData page) =>
        ctx.Emit(new UrlBatch(new[]
        {
            new UrlRecord
            {
                Host = url.Authority, Path = url.PathAndQuery, Url = url.AbsoluteUri, Method = "RENDER",
                Status = 200, ContentType = "text/html (rendered)", Size = 0, TimeMs = 0,
            },
        }));

    // ------------------------------------------------------------------ browser discovery & launch

    private static string? FindBrowser(string configured)
    {
        if (configured.Length > 0 && File.Exists(configured)) return configured;
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string pfx86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var candidate in new[]
                 {
                     Path.Combine(pfx86, @"Microsoft\Edge\Application\msedge.exe"),
                     Path.Combine(pf, @"Microsoft\Edge\Application\msedge.exe"),
                     Path.Combine(pf, @"Google\Chrome\Application\chrome.exe"),
                     Path.Combine(pfx86, @"Google\Chrome\Application\chrome.exe"),
                     Path.Combine(local, @"Google\Chrome\Application\chrome.exe"),
                 })
            if (File.Exists(candidate)) return candidate;
        return null;
    }

    private static Process? LaunchHeadless(string exe, string profileDir, string proxy)
    {
        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var a in new[]
                 {
                     "--headless=new", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run",
                     "--no-default-browser-check", "--disable-extensions", "--disable-background-networking",
                     "--disable-sync", "--mute-audio", "--remote-debugging-port=0", $"--user-data-dir={profileDir}",
                     "about:blank",
                 })
            psi.ArgumentList.Add(a);
        if (proxy.Length > 0) psi.ArgumentList.Insert(psi.ArgumentList.Count - 1, $"--proxy-server={proxy}");
        try { return Process.Start(psi); }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { return null; }
    }

    private static async Task<int> ReadDevToolsPortAsync(string profileDir, CancellationToken token)
    {
        string path = Path.Combine(profileDir, "DevToolsActivePort");
        for (int i = 0; i < 80; i++) // up to ~8s
        {
            token.ThrowIfCancellationRequested();
            try
            {
                if (File.Exists(path))
                {
                    var lines = await File.ReadAllLinesAsync(path, token).ConfigureAwait(false);
                    if (lines.Length >= 1 && int.TryParse(lines[0].Trim(), out int port) && port > 0) return port;
                }
            }
            catch (IOException) { }
            await Task.Delay(100, token).ConfigureAwait(false);
        }
        return -1;
    }

    private static async Task<string?> GetBrowserWebSocketAsync(int port, CancellationToken token)
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        try
        {
            string body = await http.GetStringAsync($"http://127.0.0.1:{port}/json/version", token).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.TryGetProperty("webSocketDebuggerUrl", out var w) ? w.GetString() : null;
        }
        catch (Exception ex) when (ex is HttpRequestException or JsonException or TaskCanceledException) { return null; }
    }

    private static async Task AwaitOrTimeout(Task task, int timeoutMs, CancellationToken token)
    {
        try { await task.WaitAsync(TimeSpan.FromMilliseconds(timeoutMs), token).ConfigureAwait(false); }
        catch (TimeoutException) { /* proceed with whatever rendered so far */ }
    }

    private static void TryDeleteDir(string dir)
    {
        try { if (Directory.Exists(dir)) Directory.Delete(dir, recursive: true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    // ------------------------------------------------------------------ minimal CDP client

    private sealed class Cdp : IAsyncDisposable
    {
        private readonly ClientWebSocket _ws = new();
        private readonly ConcurrentDictionary<int, TaskCompletionSource<JsonElement>> _pending = new();
        private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonElement>> _events = new();
        private readonly SemaphoreSlim _sendLock = new(1, 1);
        private readonly CancellationTokenSource _cts = new();
        private int _nextId;
        private Task? _pump;

        public static async Task<Cdp> ConnectAsync(string wsUrl, CancellationToken token)
        {
            var c = new Cdp();
            await c._ws.ConnectAsync(new Uri(wsUrl), token).ConfigureAwait(false);
            c._pump = Task.Run(() => c.PumpAsync(c._cts.Token));
            return c;
        }

        public async Task<JsonElement> SendAsync(string method, object? @params, string? sessionId, CancellationToken token)
        {
            int id = Interlocked.Increment(ref _nextId);
            var tcs = new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously);
            _pending[id] = tcs;
            var msg = new Dictionary<string, object?> { ["id"] = id, ["method"] = method };
            if (@params != null) msg["params"] = @params;
            if (sessionId != null) msg["sessionId"] = sessionId;
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(msg);
            await _sendLock.WaitAsync(token).ConfigureAwait(false);
            try { await _ws.SendAsync(bytes, WebSocketMessageType.Text, true, token).ConfigureAwait(false); }
            finally { _sendLock.Release(); }
            await using var reg = token.Register(static s => ((TaskCompletionSource<JsonElement>)s!).TrySetCanceled(), tcs).ConfigureAwait(false);
            // Bound each command so a lost reply cannot hang the crawl.
            return await tcs.Task.WaitAsync(TimeSpan.FromSeconds(20), token).ConfigureAwait(false);
        }

        public Task<JsonElement> WaitForEventAsync(string method, string sessionId, CancellationToken token)
        {
            var tcs = _events.GetOrAdd(method + "|" + sessionId, _ => new TaskCompletionSource<JsonElement>(TaskCreationOptions.RunContinuationsAsynchronously));
            return tcs.Task.WaitAsync(token);
        }

        private async Task PumpAsync(CancellationToken token)
        {
            var buffer = new byte[64 * 1024];
            try
            {
                while (_ws.State == WebSocketState.Open && !token.IsCancellationRequested)
                {
                    using var ms = new MemoryStream();
                    WebSocketReceiveResult result;
                    do
                    {
                        result = await _ws.ReceiveAsync(buffer, token).ConfigureAwait(false);
                        if (result.MessageType == WebSocketMessageType.Close) return;
                        ms.Write(buffer, 0, result.Count);
                    } while (!result.EndOfMessage);
                    Dispatch(ms.ToArray());
                }
            }
            catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or ObjectDisposedException or InvalidOperationException)
            {
                // socket closed; outstanding waiters are cancelled on dispose
            }
        }

        private void Dispatch(byte[] bytes)
        {
            try
            {
                using var doc = JsonDocument.Parse(bytes);
                var root = doc.RootElement;
                if (root.TryGetProperty("id", out var idEl) && idEl.TryGetInt32(out int id) && _pending.TryRemove(id, out var tcs))
                {
                    tcs.TrySetResult(root.Clone());
                }
                else if (root.TryGetProperty("method", out var mEl))
                {
                    string sid = root.TryGetProperty("sessionId", out var s) ? s.GetString() ?? "" : "";
                    string key = (mEl.GetString() ?? "") + "|" + sid;
                    if (_events.TryRemove(key, out var ev)) ev.TrySetResult(root.Clone());
                }
            }
            catch (JsonException) { }
        }

        public async ValueTask DisposeAsync()
        {
            try { _cts.Cancel(); } catch (ObjectDisposedException) { }
            foreach (var p in _pending.Values) p.TrySetCanceled();
            foreach (var e in _events.Values) e.TrySetCanceled();
            try
            {
                if (_ws.State == WebSocketState.Open)
                    await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "done", CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is WebSocketException or ObjectDisposedException or OperationCanceledException) { }
            if (_pump != null) try { await _pump.ConfigureAwait(false); } catch (Exception) { }
            _ws.Dispose();
            _sendLock.Dispose();
            _cts.Dispose();
        }
    }
}
