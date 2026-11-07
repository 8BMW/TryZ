#if DEBUG
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace TryZ.Capture;

/// <summary>
/// Minimal HTTP/1.1 server on 127.0.0.1 used by the self test and screenshot runner, so a real scan of the loopback
/// address has a web service to identify, crawl and audit. It deliberately sends no security headers and exposes
/// /.git/HEAD so the HTTP checks have something to report.
/// </summary>
internal sealed class TestSite : IDisposable
{
    private readonly TcpListener _listener;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _loop;

    private TestSite(TcpListener listener)
    {
        _listener = listener;
        _loop = AcceptLoopAsync();
    }

    public int Port => ((IPEndPoint)_listener.LocalEndpoint).Port;
    public int Requests;

    /// <summary>Web ports from the top-100 list, in order of preference, so every scan profile probes the site.</summary>
    public static readonly int[] CandidatePorts = { 8080, 8000, 8008, 8081, 8888, 3000, 5000, 9999 };

    /// <summary>Starts the site on the first free candidate port, or returns null when all are taken.</summary>
    public static TestSite? TryStartAny()
    {
        foreach (int port in CandidatePorts)
        {
            var site = TryStart(port);
            if (site != null) return site;
        }
        return null;
    }

    /// <summary>Starts the site on 127.0.0.1:<paramref name="port"/>, or returns null when the port is already in use.</summary>
    public static TestSite? TryStart(int port)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Server.ExclusiveAddressUse = true;
        try
        {
            listener.Start(64);
        }
        catch (SocketException)
        {
            return null;
        }
        return new TestSite(listener);
    }

    private async Task AcceptLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (SocketException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            _ = ServeAsync(client);
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        using (client)
        {
            try
            {
                client.ReceiveTimeout = 5000;
                var stream = client.GetStream();
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_cts.Token);
                timeout.CancelAfter(5000);
                var head = new StringBuilder();
                var buffer = new byte[4096];
                while (!head.ToString().Contains("\r\n\r\n", StringComparison.Ordinal) && head.Length < 32768)
                {
                    int n = await stream.ReadAsync(buffer, timeout.Token);
                    if (n == 0) return;
                    head.Append(Encoding.Latin1.GetString(buffer, 0, n));
                }
                Interlocked.Increment(ref Requests);
                var first = head.ToString().Split("\r\n")[0].Split(' ');
                string method = first.Length > 0 ? first[0] : "GET";
                string path = first.Length > 1 ? first[1] : "/";
                int q = path.IndexOf('?');
                if (q >= 0) path = path[..q];
                var (status, type, body) = Route(path);
                byte[] payload = Encoding.UTF8.GetBytes(body);
                string reason = status switch { 200 => "OK", 404 => "Not Found", _ => "Error" };
                string headers =
                    $"HTTP/1.1 {status} {reason}\r\n" +
                    "Server: TryZ-SelfTest/1.0\r\n" +
                    $"Date: {DateTime.UtcNow:R}\r\n" +
                    $"Content-Type: {type}\r\n" +
                    $"Content-Length: {payload.Length}\r\n" +
                    "Connection: close\r\n\r\n";
                await stream.WriteAsync(Encoding.ASCII.GetBytes(headers), timeout.Token);
                if (method != "HEAD") await stream.WriteAsync(payload, timeout.Token);
            }
            catch (OperationCanceledException)
            {
            }
            catch (IOException)
            {
            }
            catch (SocketException)
            {
            }
        }
    }

    private static (int Status, string Type, string Body) Route(string path)
    {
        const string html = "text/html; charset=utf-8";
        return path switch
        {
            "/" or "/index.html" => (200, html, Page("Test site home",
                "<a href=\"/about.html\">About</a> <a href=\"/docs/index.html\">Docs</a> <a href=\"/contact.html\">Contact</a> " +
                "<form method=\"get\" action=\"/search\"><input name=\"q\"><input type=\"submit\" value=\"Search\"></form>")),
            "/about.html" => (200, html, Page("About", "<a href=\"/\">Home</a> <a href=\"/docs/index.html\">Docs</a>")),
            "/contact.html" => (200, html, Page("Contact", "<a href=\"/\">Home</a> <a href=\"mailto:admin@localhost\">Mail</a>")),
            "/docs/index.html" => (200, html, Page("Docs", "<a href=\"/docs/page2.html\">Page 2</a> <a href=\"../about.html\">About</a>")),
            "/docs/page2.html" => (200, html, Page("Docs page 2", "<a href=\"/docs/index.html\">Back</a> <script src=\"/static/app.js\"></script>")),
            "/static/app.js" => (200, "application/javascript", "console.log('tryz self test');\n"),
            "/search" => (200, html, Page("Search", "<p>No results.</p>")),
            "/robots.txt" => (200, "text/plain", "User-agent: *\nDisallow: /private/\n"),
            "/.git/HEAD" => (200, "text/plain", "ref: refs/heads/main\n"),
            _ => (404, html, Page("Not found", "<p>The page does not exist.</p>")),
        };
    }

    private static string Page(string title, string content) =>
        $"<!DOCTYPE html>\n<html><head><title>{title}</title></head><body><h1>{title}</h1>{content}</body></html>\n";

    public void Dispose()
    {
        _cts.Cancel();
        _listener.Stop();
        try
        {
            _loop.Wait(1000);
        }
        catch (AggregateException)
        {
        }
        _cts.Dispose();
    }
}
#endif
