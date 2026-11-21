#if DEBUG
using System.Net;
using System.Text;
using System.Threading.Channels;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

/// <summary>
/// Drives the real <see cref="ActiveAudit"/> against a local, deliberately vulnerable HTTP server and asserts that each
/// injection class is detected on the vulnerable endpoint and NOT reported on the safe (output-encoded) one. This guards
/// the active checks against regressions in both directions: missed findings and false positives.
/// </summary>
internal sealed class ActiveAuditChecks : ICheckSuite
{
    public string Name => "active";

    public async Task RunAsync(CheckContext c)
    {
        using var site = VulnSite.TryStart();
        if (!c.Check("local vulnerable test server available", site != null)) return;
        int port = site!.Port;

        var opts = new ScanOptions { Threads = 4, RunActiveChecks = true, MaxRequestsPerSecond = 2000, MaxActiveTargets = 100 };
        var channel = Channel.CreateUnbounded<ScanEvent>();
        using var ctx = new ScanContext(new ScanRequest("127.0.0.1", 1, 4, opts), channel.Writer, CancellationToken.None);

        void Point(string path, string param, string method = "GET") => ctx.NoteInjectionPoint(new InjectionPoint
        {
            Method = method,
            Url = new Uri($"http://127.0.0.1:{port}{path}"),
            HostIp = "127.0.0.1",
            Port = port,
            Parameters = new[] { new KeyValuePair<string, string>(param, "1") },
        });
        Point("/xss", "q");
        Point("/safe", "q");
        Point("/sql", "id");
        Point("/clean", "id");
        Point("/lfi", "file");
        Point("/redir", "url");
        Point("/post", "name", "POST");

        await ActiveAudit.RunAsync(ctx, 1);
        var f = ctx.FindingsSnapshot();

        bool Hit(string titlePart, string pathPart) => f.Any(x => x.Title.Contains(titlePart, StringComparison.OrdinalIgnoreCase) && x.Title.Contains(pathPart, StringComparison.Ordinal));

        c.Check("reflected XSS detected on /xss", Hit("XSS", "/xss"));
        c.Check("reflected XSS detected via POST on /post", Hit("XSS", "/post"));
        c.Check("no XSS false positive on output-encoded /safe", !Hit("XSS", "/safe"));
        c.Check("error-based SQL injection detected on /sql", Hit("SQL injection", "/sql"));
        c.Check("no SQL injection false positive on /clean", !Hit("SQL injection", "/clean"));
        c.Check("path traversal detected on /lfi", Hit("traversal", "/lfi"));
        c.Check("open redirect detected on /redir", Hit("Open redirect", "/redir"));
    }

    /// <summary>A tiny HttpListener-based server with one endpoint per vulnerability class (and safe counterparts).</summary>
    private sealed class VulnSite : IDisposable
    {
        private readonly HttpListener _listener;
        private readonly CancellationTokenSource _cts = new();
        private readonly Task _loop;
        public int Port { get; }

        private VulnSite(HttpListener listener, int port) { _listener = listener; Port = port; _loop = LoopAsync(); }

        public static VulnSite? TryStart()
        {
            foreach (int port in new[] { 18080, 18081, 18082, 18083, 18084 })
            {
                var l = new HttpListener();
                l.Prefixes.Add($"http://127.0.0.1:{port}/");
                try { l.Start(); return new VulnSite(l, port); }
                catch (HttpListenerException) { }
                catch (System.Net.Sockets.SocketException) { }
            }
            return null;
        }

        private async Task LoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try { ctx = await _listener.GetContextAsync().WaitAsync(_cts.Token); }
                catch { return; }
                _ = Task.Run(() => HandleAsync(ctx));
            }
        }

        private static async Task HandleAsync(HttpListenerContext ctx)
        {
            var req = ctx.Request;
            string path = req.Url!.AbsolutePath;
            string v = req.QueryString["q"] ?? req.QueryString["id"] ?? req.QueryString["file"] ?? req.QueryString["url"] ?? "";
            if (req.HttpMethod == "POST")
            {
                using var sr = new StreamReader(req.InputStream);
                foreach (var kv in (await sr.ReadToEndAsync()).Split('&'))
                {
                    var p = kv.Split('=', 2);
                    if (p.Length == 2 && p[0] == "name") v = Uri.UnescapeDataString(p[1].Replace('+', ' '));
                }
            }
            int status = 200; string? location = null; string type = "text/html";
            string body = path switch
            {
                "/xss" or "/post" => $"<html><body>Hello {v}</body></html>",                    // raw reflection
                "/safe" => $"<html><body>Hello {WebUtility.HtmlEncode(v)}</body></html>",        // encoded
                "/sql" => v.Contains('\'') || v.Contains('"')
                    ? "<html>You have an error in your SQL syntax near '' at line 1</html>"
                    : $"<html>Item {WebUtility.HtmlEncode(v)}</html>",
                "/clean" => $"<html>Item {WebUtility.HtmlEncode(v)}</html>",
                "/lfi" => v.Contains("etc/passwd")
                    ? "root:x:0:0:root:/root:/bin/bash\n"
                    : $"<html>File {WebUtility.HtmlEncode(v)}</html>",
                "/redir" => v.Length > 0 ? MarkRedirect(ref status, ref location, v) : "<html>no</html>",
                _ => "nope",
            };
            if (path == "/redir" && v.Length == 0) status = 200;
            if (body == "nope") status = 404;
            byte[] bytes = Encoding.UTF8.GetBytes(body);
            ctx.Response.StatusCode = status;
            ctx.Response.ContentType = type;
            if (location != null) ctx.Response.Headers["Location"] = location;
            ctx.Response.ContentLength64 = bytes.Length;
            try { await ctx.Response.OutputStream.WriteAsync(bytes); ctx.Response.Close(); } catch { }
        }

        private static string MarkRedirect(ref int status, ref string? location, string v)
        {
            status = 302;
            location = v;
            return "redirecting";
        }

        public void Dispose()
        {
            _cts.Cancel();
            try { _listener.Stop(); } catch { }
            try { _loop.Wait(1000); } catch { }
            _cts.Dispose();
        }
    }
}
#endif
