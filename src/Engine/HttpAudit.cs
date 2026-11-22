using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Read-only HTTP assessment of one web service: security headers, cookies, information disclosure, HTTP methods,
/// CORS, default pages, directory listing and exposed sensitive files. Only GET/HEAD/OPTIONS/TRACE requests are sent;
/// every positive file result is validated against the file's real format and a soft-404 baseline.
/// </summary>
internal static class HttpAudit
{
    private const string Src = "web";
    private const int MaxBody = 512 * 1024;
    private const string CorsProbeOrigin = "https://tryz-cors-check.invalid";

    private sealed class Resp
    {
        public required Uri Uri { get; init; }
        public required int Status { get; init; }
        public required Dictionary<string, List<string>> Headers { get; init; }
        public required byte[] Body { get; init; }
        public required double LatencyMs { get; init; }

        public string? Header(string name) => Headers.TryGetValue(name, out var v) && v.Count > 0 ? string.Join(", ", v) : null;
        public IReadOnlyList<string> All(string name) => Headers.TryGetValue(name, out var v) ? v : Array.Empty<string>();
        public string ContentType => Header("Content-Type") ?? string.Empty;
        public bool IsHtml => ContentType.Contains("html", StringComparison.OrdinalIgnoreCase)
                              || (ContentType.Length == 0 && Text.TrimStart().StartsWith('<'));
        private string? _text;
        public string Text => _text ??= Encoding.UTF8.GetString(Body);
        public bool Ok => Status is >= 200 and < 300;
        public string StatusLine => $"HTTP {Status} {ContentType}".TrimEnd() + $", {Body.Length} bytes";
    }

    private sealed record Baseline(int Status, int Length, string Hash);

    private sealed class Run
    {
        public required ScanContext Ctx { get; init; }
        public required OpenService Svc { get; init; }
        public required Uri Base { get; init; }
        public Baseline? Soft404 { get; set; }
        public string BaseText => Base.GetLeftPart(UriPartial.Authority);
    }

    /// <summary>Header, cookie, disclosure and exposed-file checks. Returns the base URI to crawl, or null.</summary>
    public static async Task<Uri?> AuditAsync(ScanContext ctx, OpenService svc)
    {
        string hostPart = HostForUrl(svc.Host);
        string path = "/";
        var seed = svc.Host.SeedUrl;
        if (seed != null && seed.Port == svc.Port
            && (seed.Host.Equals(svc.Host.Hostname, StringComparison.OrdinalIgnoreCase) || seed.Host.Trim('[', ']').Equals(svc.Host.Ip, StringComparison.OrdinalIgnoreCase)))
        {
            path = seed.AbsolutePath.Length > 0 ? seed.AbsolutePath : "/";
        }
        Uri baseUri;
        try
        {
            baseUri = new UriBuilder(svc.Scheme, hostPart, svc.Port, path).Uri;
        }
        catch (UriFormatException ex)
        {
            ctx.Log(LogLevel.Warn, Src, $"{svc.Host.Ip}:{svc.Port}: cannot build URL ({ex.Message}); web checks skipped");
            return null;
        }

        var run = new Run { Ctx = ctx, Svc = svc, Base = baseUri };
        ctx.Log(LogLevel.Info, Src, $"Web audit started on {baseUri}");

        var root = await GetAsync(run, baseUri).ConfigureAwait(false);
        if (root == null)
        {
            ctx.Log(LogLevel.Warn, Src, $"{baseUri} did not answer an HTTP request; web checks skipped");
            return null;
        }
        ctx.Log(LogLevel.Info, Src, $"{baseUri} -> {root.StatusLine}" + (root.Header("Server") is { } srv ? $", Server: {srv}" : string.Empty));

        // Follow one redirect within the same origin to find the canonical application root.
        var page = root;
        Uri crawlRoot = baseUri;
        Uri? redirect = Location(root);
        if (redirect != null && SameOrigin(redirect, baseUri) && redirect != baseUri)
        {
            var followed = await GetAsync(run, redirect).ConfigureAwait(false);
            if (followed != null)
            {
                page = followed;
                crawlRoot = new UriBuilder(redirect) { Fragment = string.Empty }.Uri;
                ctx.Log(LogLevel.Info, Src, $"{baseUri} redirects to {redirect} -> {followed.StatusLine}");
            }
        }

        HeaderChecks(run, root, page);
        CookieChecks(run, root, page);
        DefaultPageChecks(run, page);
        DirectoryListingCheck(run, page);
        if (!svc.Tls) await PlainHttpCheckAsync(run, root, page).ConfigureAwait(false);

        run.Soft404 = await BaselineAsync(run).ConfigureAwait(false);
        await MethodChecksAsync(run).ConfigureAwait(false);
        await CorsChecksAsync(run).ConfigureAwait(false);
        await SensitiveFileChecksAsync(run).ConfigureAwait(false);

        ctx.Log(LogLevel.Ok, Src, $"Web audit finished on {baseUri}");
        return crawlRoot;
    }

    // ------------------------------------------------------------------ headers

    private static void HeaderChecks(Run run, Resp root, Resp page)
    {
        var svc = run.Svc;
        string ev(Resp r) => $"GET {r.Uri} -> HTTP {r.Status}\n" + string.Join("\n", r.Headers.OrderBy(h => h.Key, StringComparer.OrdinalIgnoreCase)
            .Where(h => !h.Key.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
            .Select(h => $"{h.Key}: {string.Join(", ", h.Value)}"));

        if (svc.Tls)
        {
            string? hsts = root.Header("Strict-Transport-Security") ?? page.Header("Strict-Transport-Security");
            if (hsts == null)
                Add(run, Severity.Low, "Missing HTTP Strict-Transport-Security header", 319,
                    "The HTTPS site does not send Strict-Transport-Security. Browsers will still try plain HTTP first when users type the address or follow http:// links, which allows SSL-stripping man-in-the-middle attacks.",
                    ev(page), "Send 'Strict-Transport-Security: max-age=31536000; includeSubDomains' on all HTTPS responses (add 'preload' once every subdomain supports HTTPS).");
            else
            {
                var m = Regex.Match(hsts, @"max-age\s*=\s*""?(\d+)", RegexOptions.IgnoreCase);
                if (m.Success && long.TryParse(m.Groups[1].Value, out long age) && age < 15_552_000)
                    Add(run, Severity.Low, "Short HSTS max-age", 319,
                        $"Strict-Transport-Security is set with max-age={age} seconds ({age / 86400} days). Values under 180 days give little protection between visits; max-age=0 disables HSTS.",
                        $"Strict-Transport-Security: {hsts}", "Use max-age of at least 31536000 (one year).");
            }
        }

        bool htmlPage = page.Ok && page.IsHtml;
        string? csp = page.Header("Content-Security-Policy");
        if (htmlPage)
        {
            if (csp == null)
                Add(run, Severity.Low, "Missing Content-Security-Policy header", 693,
                    "HTML responses carry no Content-Security-Policy. CSP is the main browser-side defence that limits the impact of cross-site scripting and content injection.",
                    ev(page) + (page.Header("Content-Security-Policy-Report-Only") != null ? "\n(Only a Report-Only policy is present; it is not enforced.)" : string.Empty),
                    "Define a Content-Security-Policy (start with default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self') and tighten it iteratively.");
            else if (Regex.IsMatch(csp, @"script-src[^;]*'unsafe-inline'", RegexOptions.IgnoreCase) && !Regex.IsMatch(csp, @"script-src[^;]*'(nonce-|sha256-|sha384-|sha512-|strict-dynamic)", RegexOptions.IgnoreCase)
                     || (!csp.Contains("script-src", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(csp, @"default-src[^;]*'unsafe-inline'", RegexOptions.IgnoreCase)))
                Add(run, Severity.Low, "Content-Security-Policy allows 'unsafe-inline' scripts", 693,
                    "The CSP permits inline script without nonces or hashes, which removes most of its protection against cross-site scripting.",
                    $"Content-Security-Policy: {csp}", "Remove 'unsafe-inline' from script-src and use nonces or hashes for required inline scripts.");

            bool frameAncestors = csp != null && csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase);
            if (page.Header("X-Frame-Options") == null && !frameAncestors)
                Add(run, Severity.Low, "Clickjacking protection missing (no X-Frame-Options / frame-ancestors)", 1021,
                    "The page can be embedded in a frame on any other site, allowing clickjacking (UI redressing) attacks against logged-in users.",
                    ev(page), "Send 'X-Frame-Options: DENY' (or SAMEORIGIN) and/or a CSP 'frame-ancestors' directive.");

            if (!string.Equals(page.Header("X-Content-Type-Options")?.Trim(), "nosniff", StringComparison.OrdinalIgnoreCase))
                Add(run, Severity.Low, "Missing X-Content-Type-Options: nosniff", 693,
                    "Without 'X-Content-Type-Options: nosniff' browsers may MIME-sniff responses and execute user-uploaded or mislabelled content as script or HTML.",
                    ev(page), "Send 'X-Content-Type-Options: nosniff' on all responses.");
        }

        // Version / technology disclosure (any response)
        foreach (var r in new[] { root, page }.Distinct())
        {
            if (r.Header("Server") is { } server && Regex.IsMatch(server, @"\d+\.\d+"))
                Add(run, Severity.Low, "Server version disclosed in Server header", 200,
                    "The Server header reveals the exact software version, helping attackers select known exploits for that release.",
                    $"Server: {server}", "Suppress version details (nginx: server_tokens off; Apache: ServerTokens Prod + ServerSignature Off; IIS: removeServerHeader=\"true\").");
            if (r.Header("X-Powered-By") is { } powered)
                Add(run, Severity.Low, "Technology disclosed in X-Powered-By header", 200,
                    "The X-Powered-By header reveals the application framework" + (Regex.IsMatch(powered, @"\d") ? " and its version" : string.Empty) + ".",
                    $"X-Powered-By: {powered}", "Remove the header (PHP: expose_php = Off; Express: app.disable('x-powered-by'); IIS: remove from customHeaders).");
            foreach (var h in new[] { "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache", "X-Runtime-Version" })
                if (r.Header(h) is { } val && Regex.IsMatch(val, @"\d"))
                    Add(run, Severity.Low, $"Version disclosed in {h} header", 200,
                        $"The {h} header reveals framework version information.",
                        $"{h}: {val}", h.StartsWith("X-AspNet", StringComparison.OrdinalIgnoreCase)
                            ? "Set <httpRuntime enableVersionHeader=\"false\" /> and MvcHandler.DisableMvcResponseHeader = true."
                            : $"Remove the {h} header in the server configuration.");
        }
    }

    // ------------------------------------------------------------------ cookies

    private static readonly Regex SessionName = new(@"sess|sid|auth|token|jwt|login|remember|identity|connect\.|laravel|asp\.net|phpsessid|jsessionid", RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static void CookieChecks(Run run, Resp root, Resp page)
    {
        var noSecure = new List<string>();
        var noHttpOnly = new List<string>();
        var noSameSite = new List<string>();
        bool sessionNoSecure = false, sessionNoHttpOnly = false;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var r in new[] { root, page }.Distinct())
            foreach (var raw in r.All("Set-Cookie"))
            {
                var parts = raw.Split(';');
                int eq = parts[0].IndexOf('=');
                if (eq <= 0) continue;
                string name = parts[0][..eq].Trim();
                if (!seen.Add(name)) continue;
                var attrs = parts.Skip(1).Select(p => p.Trim()).ToList();
                bool secure = attrs.Any(a => a.Equals("secure", StringComparison.OrdinalIgnoreCase));
                bool httpOnly = attrs.Any(a => a.Equals("httponly", StringComparison.OrdinalIgnoreCase));
                bool sameSite = attrs.Any(a => a.StartsWith("samesite", StringComparison.OrdinalIgnoreCase));
                bool deleting = attrs.Any(a => a.StartsWith("max-age=0", StringComparison.OrdinalIgnoreCase))
                                || attrs.Any(a => a.StartsWith("expires=", StringComparison.OrdinalIgnoreCase) && a.Contains("1970", StringComparison.Ordinal));
                if (deleting) continue;
                bool session = SessionName.IsMatch(name);
                bool csrf = name.Contains("csrf", StringComparison.OrdinalIgnoreCase) || name.Contains("xsrf", StringComparison.OrdinalIgnoreCase);
                if (run.Svc.Tls && !secure) { noSecure.Add(name); sessionNoSecure |= session; }
                if (!httpOnly && !csrf) { noHttpOnly.Add(name); sessionNoHttpOnly |= session; }
                if (!sameSite) noSameSite.Add(name);
            }

        string list(List<string> l) => string.Join(", ", l.Take(20)) + (l.Count > 20 ? $" (+{l.Count - 20} more)" : string.Empty);
        if (noSecure.Count > 0)
            Add(run, sessionNoSecure ? Severity.Medium : Severity.Low, "Cookie without Secure flag on HTTPS site", 614,
                "Cookies set over HTTPS lack the Secure attribute, so the browser will also send them over plain HTTP where they can be intercepted.",
                $"Cookies without Secure: {list(noSecure)}", "Add the Secure attribute to every cookie set by an HTTPS application.");
        if (noHttpOnly.Count > 0)
            Add(run, sessionNoHttpOnly ? Severity.Medium : Severity.Low, "Cookie without HttpOnly flag", 1004,
                "Cookies lack the HttpOnly attribute, so any script running in the page (including injected XSS payloads) can read them" + (sessionNoHttpOnly ? "; at least one looks like a session/authentication cookie." : "."),
                $"Cookies without HttpOnly: {list(noHttpOnly)}", "Set HttpOnly on session and authentication cookies.");
        if (noSameSite.Count > 0)
            Add(run, Severity.Low, "Cookie without SameSite attribute", 1275,
                "Cookies have no explicit SameSite attribute. Browsers that do not default to Lax will attach them to cross-site requests, which helps cross-site request forgery.",
                $"Cookies without SameSite: {list(noSameSite)}", "Set SameSite=Lax (or Strict) on session cookies; use SameSite=None only together with Secure where cross-site use is required.");
    }

    // ------------------------------------------------------------------ default pages / listing

    private static readonly (string Marker, string Product)[] DefaultPages =
    {
        ("<title>IIS Windows Server</title>", "Microsoft IIS"),
        ("<title>IIS Windows</title>", "Microsoft IIS"),
        ("<title>IIS7</title>", "Microsoft IIS 7"),
        ("<title>IIS8</title>", "Microsoft IIS 8"),
        ("iisstart.png", "Microsoft IIS"),
        ("<title>Internet Information Services</title>", "Microsoft IIS"),
        ("<h1>It works!</h1>", "Apache httpd"),
        ("Apache2 Ubuntu Default Page", "Apache httpd (Ubuntu)"),
        ("Apache2 Debian Default Page", "Apache httpd (Debian)"),
        ("Test Page for the Apache HTTP Server", "Apache httpd (RHEL/CentOS/Fedora)"),
        ("<title>HTTP Server Test Page", "Apache httpd (RHEL/Rocky/Alma)"),
        ("<title>Welcome to nginx!</title>", "nginx"),
        ("<title>Welcome to nginx on", "nginx (distribution package)"),
        ("If you're seeing this, you've successfully installed Tomcat", "Apache Tomcat"),
        ("<title>Welcome to OpenResty!</title>", "OpenResty"),
        ("<title>Welcome to CentOS</title>", "Apache httpd (CentOS)"),
        ("Congratulations! Your Caddy web server is running", "Caddy"),
        ("<title>Test Page for the Nginx HTTP Server", "nginx (RHEL/Fedora)"),
    };

    private static void DefaultPageChecks(Run run, Resp page)
    {
        if (!page.Ok) return;
        foreach (var (marker, product) in DefaultPages)
        {
            if (!page.Text.Contains(marker, StringComparison.OrdinalIgnoreCase)) continue;
            Add(run, Severity.Info, $"Default {product.Split(' ')[0] switch { "Microsoft" => "IIS", var p => p }} welcome page", 200,
                $"The server shows the default installation page of {product}. This usually indicates an unused or unconfigured server and discloses the software in use.",
                $"GET {page.Uri} -> HTTP {page.Status}; page contains \"{marker}\"",
                "Remove the default content or disable the site if it is not needed; reduce exposed services.");
            return;
        }
    }

    private static readonly Regex Listing = new(@"<title>\s*Index of /|<h1>\s*Index of /|\[To Parent Directory\]|<title>\s*Directory listing for /|<title>[^<]*- /</title>\s*</head>.*\[To Parent Directory\]",
        RegexOptions.IgnoreCase | RegexOptions.Singleline | RegexOptions.Compiled);

    private static bool DirectoryListingCheck(Run run, Resp r)
    {
        if (!r.Ok || !r.IsHtml || !Listing.IsMatch(r.Text)) return false;
        var entries = Regex.Matches(r.Text, @"href=""([^""?#]+)""", RegexOptions.IgnoreCase)
            .Select(m => m.Groups[1].Value).Where(h => !h.StartsWith("..", StringComparison.Ordinal) && !h.StartsWith("/", StringComparison.Ordinal) && !h.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            .Distinct().Take(15).ToList();
        Add(run, Severity.Medium, $"Directory listing enabled ({r.Uri.AbsolutePath})", 548,
            "The web server generates an index of files for a directory without a default document. Attackers can browse and download files that were never meant to be linked (backups, configuration, uploads).",
            $"GET {r.Uri} -> HTTP {r.Status}, auto-index page detected.\nEntries: {(entries.Count > 0 ? string.Join(", ", entries) : "(none parsed)")}",
            "Disable automatic indexes (Apache: Options -Indexes; nginx: autoindex off; IIS: directoryBrowse enabled=\"false\").");
        return true;
    }

    // ------------------------------------------------------------------ http -> https

    private static async Task PlainHttpCheckAsync(Run run, Resp root, Resp page)
    {
        Uri? loc = Location(root) ?? Location(page);
        if (loc != null && loc.Scheme == Uri.UriSchemeHttps) return;
        if (run.Svc.Port == 443) return;
        var https = new UriBuilder(Uri.UriSchemeHttps, run.Base.Host, 443, "/").Uri;
        var r = await SendAsync(run, HttpMethod.Get, https, maxBody: 1024).ConfigureAwait(false);
        if (r == null) return;
        Add(run, Severity.Low, "HTTP site does not redirect to HTTPS", 319,
            "The plain-HTTP service serves content directly although an HTTPS service is available on the same host. Users and links that use http:// send cookies and form data unencrypted.",
            $"GET {root.Uri} -> HTTP {root.Status} (no redirect to https)\nGET {https} -> HTTP {r.Status} (HTTPS available)",
            "Redirect all plain-HTTP requests permanently (301/308) to HTTPS and enable HSTS.");
    }

    // ------------------------------------------------------------------ methods / CORS

    private static async Task MethodChecksAsync(Run run)
    {
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(8));
        var trace = await SendAsync(run, new HttpMethod("TRACE"), run.Base, configure: m => m.Headers.TryAddWithoutValidation("X-TryZ-Trace", token), maxBody: 64 * 1024).ConfigureAwait(false);
        if (trace != null && trace.Ok && (trace.Text.Contains(token, StringComparison.Ordinal) || trace.ContentType.Contains("message/http", StringComparison.OrdinalIgnoreCase)))
            Add(run, Severity.Medium, "HTTP TRACE method enabled", 693,
                "The server echoes TRACE requests back to the client. Combined with other flaws this enables cross-site tracing (XST) to read HttpOnly cookies or authentication headers, and it reveals headers added by proxies.",
                $"TRACE {run.Base} with header X-TryZ-Trace: {token} -> HTTP {trace.Status} {trace.ContentType}; request header echoed in response body.",
                "Disable TRACE (Apache: TraceEnable off; IIS: request filtering verb TRACE deny; nginx returns 405 by default).");

        var options = await SendAsync(run, HttpMethod.Options, run.Base, maxBody: 16 * 1024).ConfigureAwait(false);
        if (options == null) return;
        string allow = string.Join(", ", new[] { options.Header("Allow"), options.Header("Public"), options.Header("Access-Control-Allow-Methods") }.Where(s => s != null));
        var methods = allow.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(m => m.ToUpperInvariant()).Distinct().ToList();
        var dav = new[] { "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "SEARCH" };
        var risky = methods.Where(m => m is "PUT" or "DELETE" || dav.Contains(m)).ToList();
        string? davHeader = options.Header("DAV");
        if (risky.Count > 0 || davHeader != null)
        {
            bool isDav = davHeader != null || risky.Any(dav.Contains);
            Add(run, Severity.Medium, isDav ? "WebDAV enabled (OPTIONS advertises DAV methods)" : "Dangerous HTTP methods advertised (PUT/DELETE)", 749,
                (isDav ? "The server advertises WebDAV support. WebDAV allows remote file management and has a history of severe vulnerabilities (e.g. IIS 6.0 CVE-2017-7269); misconfigured write access leads to web shell upload. "
                       : "The server advertises PUT/DELETE on the web root. If they are actually permitted without authentication, attackers can upload or delete files. ") +
                "TryZ only reads the advertised methods and does not attempt writes; verify whether the methods are authorised.",
                $"OPTIONS {run.Base} -> HTTP {options.Status}\nAllow/Public: {(allow.Length > 0 ? allow : "(none)")}" + (davHeader != null ? $"\nDAV: {davHeader}" : string.Empty),
                "Disable WebDAV and unneeded methods; allow only GET, HEAD, POST (and the methods the application really needs) and require authentication for write methods.");
        }
    }

    private static async Task CorsChecksAsync(Run run)
    {
        foreach (var origin in new[] { CorsProbeOrigin, "null" })
        {
            var r = await SendAsync(run, HttpMethod.Get, run.Base, configure: m => m.Headers.TryAddWithoutValidation("Origin", origin), maxBody: 16 * 1024).ConfigureAwait(false);
            if (r == null) return;
            string? acao = r.Header("Access-Control-Allow-Origin")?.Trim();
            if (acao == null) continue;
            bool creds = string.Equals(r.Header("Access-Control-Allow-Credentials")?.Trim(), "true", StringComparison.OrdinalIgnoreCase);
            string ev = $"GET {run.Base} with Origin: {origin} -> HTTP {r.Status}\nAccess-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {r.Header("Access-Control-Allow-Credentials") ?? "(absent)"}";
            if (acao == origin)
            {
                string label = origin == "null" ? "the 'null' origin" : "arbitrary origins";
                Add(run, creds ? Severity.High : Severity.Low,
                    creds ? $"CORS trusts {label} with credentials" : $"CORS reflects {label}", 942,
                    creds
                        ? $"The server reflects {(origin == "null" ? "Origin: null (sent by sandboxed iframes and file: pages)" : "an attacker-chosen Origin")} in Access-Control-Allow-Origin and allows credentials. Any website can make authenticated requests on behalf of a logged-in user and read the responses."
                        : "The server reflects the requesting Origin in Access-Control-Allow-Origin (without credentials). Unauthenticated data is readable cross-origin; this is risky if the service relies on network location for access control.",
                    ev, "Validate Origin against an explicit allow-list; never reflect arbitrary origins or 'null', especially with Access-Control-Allow-Credentials: true.");
                return;
            }
            if (acao == "*" && origin == CorsProbeOrigin)
            {
                Add(run, Severity.Low, "CORS allows any origin (Access-Control-Allow-Origin: *)", 942,
                    "Responses are readable by scripts on any website. Browsers do not send credentials with a wildcard, but content reachable only from the internal network or by IP-based trust becomes readable cross-origin." + (creds ? " (Allow-Credentials: true is also set but is ignored by browsers with a wildcard.)" : string.Empty),
                    ev, "Restrict Access-Control-Allow-Origin to the origins that need access unless the content is truly public.");
                return;
            }
        }
    }

    // ------------------------------------------------------------------ sensitive files

    private sealed record FileCheck(string Path, Severity Severity, int Cwe, string Title, string Description, string Remediation, Func<Resp, string?> Validate);

    private static readonly Regex EnvLine = new(@"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=", RegexOptions.Compiled);

    private static string? NotHtml(Resp r) => r.Ok && !r.IsHtml && !r.Text.TrimStart().StartsWith("<", StringComparison.Ordinal) ? r.Text : null;

    private static bool StartsWith(byte[] body, params byte[] magic) => body.Length >= magic.Length && body.AsSpan(0, magic.Length).SequenceEqual(magic);

    private static string FirstLines(string text, int lines = 3, int max = 200)
    {
        var l = text.Replace("\r", string.Empty).Split('\n').Where(s => s.Trim().Length > 0).Take(lines);
        string s = string.Join(" | ", l);
        return s.Length > max ? s[..max] + "..." : s;
    }

    private static string Mask(string value) => value.Length <= 4 ? "****" : value[..Math.Min(4, value.Length / 4)] + new string('*', Math.Min(12, value.Length - Math.Min(4, value.Length / 4)));

    private static readonly FileCheck[] Files = BuildFileChecks();

    private static FileCheck[] BuildFileChecks()
    {
        const string gitRem = "Block access to version-control metadata (nginx: location ~ /\\.(git|svn|hg) { deny all; }; Apache: RedirectMatch 404 /\\.git) and deploy without the .git directory. Rotate any secrets that were ever committed.";
        const string backupRem = "Remove backup/dump files from the web root, store them outside served directories, and rotate any credentials they contain.";
        var list = new List<FileCheck>
        {
            new("/.git/HEAD", Severity.High, 527, "Git repository exposed (/.git/HEAD)",
                "The .git directory is served. Attackers can reconstruct the full source code and history, including hard-coded credentials.",
                gitRem, r =>
                {
                    var t = NotHtml(r)?.Trim();
                    if (t == null) return null;
                    return t.StartsWith("ref: refs/", StringComparison.Ordinal) || Regex.IsMatch(t, @"^[0-9a-f]{40}([0-9a-f]{24})?$") ? $"Content: {FirstLines(t, 1)}" : null;
                }),
            new("/.git/config", Severity.High, 527, "Git repository configuration exposed (/.git/config)",
                "The repository configuration is served, confirming source code exposure and possibly revealing remote URLs with embedded credentials.",
                gitRem, r =>
                {
                    var t = NotHtml(r);
                    if (t == null || !t.Contains("[core]", StringComparison.Ordinal) || !t.Contains("repositoryformatversion", StringComparison.Ordinal)) return null;
                    var remotes = Regex.Matches(t, @"url\s*=\s*(\S+)").Select(m => Regex.Replace(m.Groups[1].Value, @"//[^/@\s]+@", "//***@")).ToList();
                    return "Sections: " + string.Join(" ", Regex.Matches(t, @"^\[[^\]]+\]", RegexOptions.Multiline).Select(m => m.Value).Distinct()) +
                           (remotes.Count > 0 ? $"\nRemote URLs (credentials masked): {string.Join(", ", remotes)}" : string.Empty);
                }),
            new("/.svn/entries", Severity.High, 527, "Subversion metadata exposed (/.svn/entries)",
                "Subversion working-copy metadata is served, which can disclose file names and source code.",
                gitRem, r =>
                {
                    var t = NotHtml(r);
                    if (t == null) return null;
                    string first = t.Replace("\r", string.Empty).Split('\n')[0].Trim();
                    return (int.TryParse(first, out int fmt) && fmt is >= 7 and <= 12) || t.Contains("<wc-entries", StringComparison.Ordinal) ? $"Working-copy format: {FirstLines(t, 1)}" : null;
                }),
            new("/.svn/wc.db", Severity.High, 527, "Subversion working-copy database exposed (/.svn/wc.db)",
                "The SVN wc.db SQLite database is served; it lists every file and allows downloading pristine copies of the source.",
                gitRem, r => r.Ok && StartsWith(r.Body, Encoding.ASCII.GetBytes("SQLite format 3\0")) ? $"SQLite database header found, {r.Body.Length} bytes read" : null),
            new("/.env", Severity.High, 538, "Environment file exposed (/.env)",
                "The application's .env file is served. These files typically contain database passwords, API keys and application secrets.",
                "Remove .env from the web root (or deny dotfiles in the web server) and rotate every secret it contains.", r =>
                {
                    var t = NotHtml(r);
                    if (t == null) return null;
                    var lines = t.Replace("\r", string.Empty).Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToList();
                    var keys = lines.Select(l => EnvLine.Match(l)).Where(m => m.Success).Select(m => m.Groups[1].Value).ToList();
                    if (keys.Count < 2 || keys.Count < lines.Count * 0.6) return null;
                    return $"{keys.Count} variable(s) (values withheld): {string.Join(", ", keys.Take(25))}";
                }),
            new("/.DS_Store", Severity.Medium, 538, "macOS .DS_Store file exposed",
                "A Finder .DS_Store file is served. It lists the names of files and folders in the directory, revealing hidden content.",
                "Delete .DS_Store files from the web root and deny dotfiles in the web server.", r =>
                    r.Ok && StartsWith(r.Body, 0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31) ? $"Bud1 magic found, {r.Body.Length} bytes" : null),
            new("/server-status", Severity.Medium, 497, "Apache server-status page exposed",
                "mod_status is reachable. It shows client IP addresses, requested URLs (including tokens in query strings) and server internals in real time.",
                "Restrict /server-status to localhost or an admin network (Require local / Require ip ...).", r =>
                    r.Ok && r.Text.Contains("Apache Server Status for", StringComparison.Ordinal) ? $"Page title: {Regex.Match(r.Text, "<title>([^<]*)</title>").Groups[1].Value.Trim()}; {Regex.Match(r.Text, @"Server Version:\s*([^<\n]+)").Groups[1].Value.Trim()}" : null),
            new("/server-info", Severity.Medium, 497, "Apache server-info page exposed",
                "mod_info is reachable and discloses the complete server configuration and loaded modules.",
                "Disable mod_info or restrict /server-info to localhost.", r =>
                    r.Ok && r.Text.Contains("Apache Server Information", StringComparison.Ordinal) ? "Page contains 'Apache Server Information'" : null),
            new("/phpinfo.php", Severity.Medium, 497, "phpinfo() page exposed (/phpinfo.php)",
                "A phpinfo() page is reachable. It discloses PHP version, modules, file paths, environment variables and sometimes secrets passed via the environment.",
                "Delete phpinfo test pages from production servers.", PhpInfo),
            new("/info.php", Severity.Medium, 497, "phpinfo() page exposed (/info.php)",
                "A phpinfo() page is reachable. It discloses PHP version, modules, file paths, environment variables and sometimes secrets passed via the environment.",
                "Delete phpinfo test pages from production servers.", PhpInfo),
            new("/web.config", Severity.High, 538, "ASP.NET web.config exposed",
                "The web.config file is served as content. It can contain connection strings, machine keys and other secrets.",
                "Ensure .config files are blocked by request filtering and are not served by any static handler; rotate exposed secrets (especially machineKey).", r =>
                    r.Ok && r.Text.Contains("<configuration", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(r.Text, "<(system\\.web|system\\.webServer|appSettings|connectionStrings)", RegexOptions.IgnoreCase)
                        ? "Sections: " + string.Join(", ", Regex.Matches(r.Text, "<(system\\.web|system\\.webServer|appSettings|connectionStrings|machineKey)\\b", RegexOptions.IgnoreCase).Select(m => m.Groups[1].Value).Distinct(StringComparer.OrdinalIgnoreCase))
                        : null),
            new("/WEB-INF/web.xml", Severity.High, 538, "Java WEB-INF/web.xml exposed",
                "The deployment descriptor of a Java web application is served, disclosing servlet mappings, filters and security constraints; it indicates WEB-INF protection is broken.",
                "Make sure WEB-INF is never served directly (fix the front-end proxy / static file mapping).", r =>
                    r.Ok && r.Text.Contains("<web-app", StringComparison.Ordinal) ? $"Servlets: {string.Join(", ", Regex.Matches(r.Text, "<servlet-name>([^<]+)</servlet-name>").Select(m => m.Groups[1].Value).Distinct().Take(10))}" : null),
            new("/backup.zip", Severity.High, 530, "Backup archive exposed (/backup.zip)",
                "A ZIP archive named backup.zip is downloadable. Backups typically contain source code, configuration and data.", backupRem,
                r => r.Ok && (StartsWith(r.Body, 0x50, 0x4B, 0x03, 0x04) || StartsWith(r.Body, 0x50, 0x4B, 0x05, 0x06)) ? $"ZIP signature PK\\x03\\x04, Content-Length: {r.Header("Content-Length") ?? "?"}" : null),
            new("/backup.tar.gz", Severity.High, 530, "Backup archive exposed (/backup.tar.gz)",
                "A gzip archive named backup.tar.gz is downloadable. Backups typically contain source code, configuration and data.", backupRem,
                r => r.Ok && StartsWith(r.Body, 0x1F, 0x8B, 0x08) && !r.ContentType.Contains("html", StringComparison.OrdinalIgnoreCase) && r.Header("Content-Encoding") == null ? $"gzip signature 1F 8B 08, Content-Length: {r.Header("Content-Length") ?? "?"}" : null),
            new("/db.sql", Severity.High, 530, "Database dump exposed (/db.sql)",
                "An SQL dump is downloadable; it can contain all application data including user records and password hashes.", backupRem, SqlDump),
            new("/dump.sql", Severity.High, 530, "Database dump exposed (/dump.sql)",
                "An SQL dump is downloadable; it can contain all application data including user records and password hashes.", backupRem, SqlDump),
            new("/backup.sql", Severity.High, 530, "Database dump exposed (/backup.sql)",
                "An SQL dump is downloadable; it can contain all application data including user records and password hashes.", backupRem, SqlDump),
            new("/.htpasswd", Severity.High, 522, "Password file exposed (/.htpasswd)",
                "The Apache .htpasswd file is served. It contains user names and password hashes that can be cracked offline.",
                "Store .htpasswd outside the document root, deny dotfiles, and change the affected passwords.", r =>
                {
                    var t = NotHtml(r);
                    if (t == null) return null;
                    var lines = t.Replace("\r", string.Empty).Split('\n').Where(l => l.Trim().Length > 0).ToList();
                    var rx = new Regex(@"^([^:\s]+):(\$apr1\$|\$2[abxy]\$|\{SHA\}|\$[156]\$|[A-Za-z0-9./]{13}$)");
                    if (lines.Count == 0 || !lines.All(l => rx.IsMatch(l))) return null;
                    return "Users (hashes withheld): " + string.Join(", ", lines.Take(15).Select(l => rx.Match(l).Groups[1].Value + " [" + HashKind(rx.Match(l).Groups[2].Value) + "]"));
                }),
            new("/config.php.bak", Severity.High, 530, "PHP configuration backup exposed (/config.php.bak)",
                "A backup of a PHP configuration file is served as plain text, disclosing source and credentials.", backupRem, PhpSource),
            new("/wp-config.php.bak", Severity.High, 530, "WordPress configuration backup exposed (/wp-config.php.bak)",
                "A backup of wp-config.php is served as plain text, disclosing database credentials and authentication salts.", backupRem, PhpSource),
            new("/wp-config.php~", Severity.High, 530, "WordPress configuration backup exposed (/wp-config.php~)",
                "An editor backup of wp-config.php is served as plain text, disclosing database credentials and authentication salts.", backupRem, PhpSource),
            new("/wp-config.php.save", Severity.High, 530, "WordPress configuration backup exposed (/wp-config.php.save)",
                "An editor backup of wp-config.php is served as plain text, disclosing database credentials and authentication salts.", backupRem, PhpSource),
            new("/actuator/env", Severity.High, 497, "Spring Boot Actuator /env endpoint exposed",
                "The Actuator environment endpoint is reachable without authentication. It reveals configuration properties, environment variables and (depending on version) unmasked secrets.",
                "Expose only health/info over HTTP (management.endpoints.web.exposure.include=health,info) and protect actuator endpoints with authentication.", r =>
                {
                    if (!r.Ok || !(r.Text.Contains("\"propertySources\"", StringComparison.Ordinal) || r.Text.Contains("\"activeProfiles\"", StringComparison.Ordinal))) return null;
                    var sources = Regex.Matches(r.Text, "\"name\"\\s*:\\s*\"([^\"]+)\"").Select(m => m.Groups[1].Value).Distinct().Take(10);
                    return $"Property sources: {string.Join(", ", sources)}";
                }),
            new("/elmah.axd", Severity.High, 215, "ELMAH error log exposed (/elmah.axd)",
                "The ELMAH error log is publicly readable. Logged errors include stack traces, server variables and often session cookies of other users.",
                "Restrict elmah.axd (allowRemoteAccess=\"false\" and authorization rules) or remove ELMAH from production.", r =>
                    r.Ok && r.Text.Contains("Error Log for", StringComparison.Ordinal) && r.Text.Contains("ELMAH", StringComparison.OrdinalIgnoreCase) ? $"Title: {Regex.Match(r.Text, "<title>([^<]*)</title>").Groups[1].Value.Trim()}" : null),
            new("/trace.axd", Severity.Medium, 215, "ASP.NET trace viewer exposed (/trace.axd)",
                "ASP.NET tracing is enabled and readable remotely, disclosing request details, headers, cookies and server variables.",
                "Set <trace enabled=\"false\" localOnly=\"true\"/> in web.config.", r =>
                    r.Ok && (r.Text.Contains("Application Trace", StringComparison.Ordinal) || r.Text.Contains("Requests to this Application", StringComparison.Ordinal)) ? "Page contains 'Application Trace'" : null),
            new("/.aws/credentials", Severity.High, 522, "AWS credentials file exposed (/.aws/credentials)",
                "An AWS shared credentials file is served. It contains access keys that grant access to the AWS account.",
                "Remove the file from the web root immediately, deactivate the exposed access keys in IAM and review CloudTrail for misuse.", r =>
                {
                    var t = NotHtml(r);
                    if (t == null || !t.Contains("aws_access_key_id", StringComparison.OrdinalIgnoreCase)) return null;
                    var profiles = Regex.Matches(t, @"^\s*\[([^\]]+)\]", RegexOptions.Multiline).Select(m => m.Groups[1].Value);
                    var ids = Regex.Matches(t, @"aws_access_key_id\s*=\s*(\S+)", RegexOptions.IgnoreCase).Select(m => Mask(m.Groups[1].Value));
                    return $"Profiles: {string.Join(", ", profiles)}; access key ids (masked): {string.Join(", ", ids)}";
                }),
            new("/docker-compose.yml", Severity.Medium, 538, "docker-compose.yml exposed",
                "The Docker Compose file is served, disclosing the service architecture, images, internal ports and often environment secrets.",
                "Remove deployment files from the web root and rotate any secrets they contain.", r =>
                {
                    var t = NotHtml(r);
                    if (t == null || !Regex.IsMatch(t, @"^services:\s*$", RegexOptions.Multiline) || !Regex.IsMatch(t, @"^\s+(image|build):", RegexOptions.Multiline)) return null;
                    var services = Regex.Matches(t, @"^  ([A-Za-z0-9_.-]+):\s*$", RegexOptions.Multiline).Select(m => m.Groups[1].Value).Take(15);
                    bool secrets = Regex.IsMatch(t, @"(PASSWORD|SECRET|TOKEN|API_KEY)", RegexOptions.IgnoreCase);
                    return $"Services: {string.Join(", ", services)}" + (secrets ? "\nFile contains secret-looking variables (values withheld)." : string.Empty);
                }),
            new("/crossdomain.xml", Severity.Medium, 942, "Permissive crossdomain.xml (allow-access-from domain=\"*\")",
                "The Flash/Silverlight cross-domain policy allows any domain to read content from this site with the user's cookies.",
                "Remove crossdomain.xml or restrict allow-access-from to trusted domains.", r =>
                    r.Ok && r.Text.Contains("<cross-domain-policy", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(r.Text, "<allow-access-from[^>]*domain\\s*=\\s*[\"']\\*[\"']", RegexOptions.IgnoreCase)
                        ? Regex.Match(r.Text, "<allow-access-from[^>]*>", RegexOptions.IgnoreCase).Value : null),
            new("/clientaccesspolicy.xml", Severity.Medium, 942, "Permissive clientaccesspolicy.xml (any domain)",
                "The Silverlight client access policy allows any domain to access this site.",
                "Remove clientaccesspolicy.xml or restrict it to trusted domains.", r =>
                    r.Ok && r.Text.Contains("<access-policy", StringComparison.OrdinalIgnoreCase) && Regex.IsMatch(r.Text, "<domain\\s+uri\\s*=\\s*[\"']\\*[\"']", RegexOptions.IgnoreCase)
                        ? Regex.Match(r.Text, "<domain[^>]*>", RegexOptions.IgnoreCase).Value : null),
        };

        foreach (var p in new[] { "/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/swagger/v1/swagger.json" })
            list.Add(new(p, Severity.Info, 200, $"API documentation exposed ({p})",
                "A machine-readable OpenAPI/Swagger description is publicly available. It maps every endpoint and parameter of the API, which speeds up attacks against it.",
                "Publish API documentation only where intended; require authentication for internal APIs.", r =>
                {
                    if (!r.Ok || r.IsHtml) return null;
                    var m = Regex.Match(r.Text, "\"(swagger|openapi)\"\\s*:\\s*\"([^\"]+)\"");
                    if (!m.Success || !r.Text.Contains("\"paths\"", StringComparison.Ordinal)) return null;
                    string title = Regex.Match(r.Text, "\"title\"\\s*:\\s*\"([^\"]+)\"").Groups[1].Value;
                    int paths = Regex.Matches(r.Text, "\"/[^\"]*\"\\s*:\\s*\\{").Count;
                    return $"{m.Groups[1].Value} {m.Groups[2].Value}; title \"{title}\"; ~{paths} path entries";
                }));

        list.Add(new("/robots.txt", Severity.Info, 200, "robots.txt lists disallowed paths",
            "robots.txt is public and lists paths the owner does not want indexed; these often point to administrative or sensitive areas. (Informational: robots.txt is not an access control.)",
            "Do not rely on robots.txt to hide sensitive locations; protect them with authentication.", r =>
            {
                var t = NotHtml(r);
                if (t == null || !Regex.IsMatch(t, @"^\s*user-agent\s*:", RegexOptions.IgnoreCase | RegexOptions.Multiline)) return null;
                var dis = Regex.Matches(t, @"^\s*disallow\s*:\s*(\S+)", RegexOptions.IgnoreCase | RegexOptions.Multiline).Select(m => m.Groups[1].Value).Where(p => p != "/").Distinct().ToList();
                return dis.Count == 0 ? null : $"Disallowed ({dis.Count}): {string.Join(" ", dis.Take(40))}";
            }));
        return list.ToArray();
    }

    private static string HashKind(string prefix) => prefix switch
    {
        "$apr1$" => "MD5-APR",
        "{SHA}" => "SHA-1",
        "$1$" => "MD5-crypt",
        "$5$" => "SHA-256-crypt",
        "$6$" => "SHA-512-crypt",
        _ when prefix.StartsWith("$2", StringComparison.Ordinal) => "bcrypt",
        _ => "DES-crypt",
    };

    private static string? PhpInfo(Resp r)
    {
        if (!r.Ok) return null;
        bool ok = r.Text.Contains("<title>phpinfo()</title>", StringComparison.OrdinalIgnoreCase)
                  || (r.Text.Contains("PHP Version", StringComparison.Ordinal) && r.Text.Contains("Configuration File (php.ini) Path", StringComparison.Ordinal));
        if (!ok) return null;
        var v = Regex.Match(r.Text, @"PHP Version\s*(?:</[^>]+>\s*<[^>]+>\s*)?([0-9][0-9.]+[^<\s]*)");
        var sys = Regex.Match(r.Text, @"System\s*</td>\s*<td[^>]*>\s*([^<]+)");
        return $"PHP Version: {(v.Success ? v.Groups[1].Value : "?")}" + (sys.Success ? $"; System: {sys.Groups[1].Value.Trim()}" : string.Empty);
    }

    private static string? SqlDump(Resp r)
    {
        var t = NotHtml(r);
        if (t == null) return null;
        string head = t.Length > 4096 ? t[..4096] : t;
        bool marker = Regex.IsMatch(head, @"^-- (MySQL dump|MariaDB dump|PostgreSQL database dump|Dumping data for table)", RegexOptions.Multiline)
                      || (Regex.IsMatch(t, @"\bCREATE TABLE\b", RegexOptions.IgnoreCase) && Regex.IsMatch(t, @"\bINSERT INTO\b", RegexOptions.IgnoreCase));
        if (!marker) return null;
        var tables = Regex.Matches(t, @"CREATE TABLE (?:IF NOT EXISTS )?[`""]?([A-Za-z0-9_.]+)", RegexOptions.IgnoreCase).Select(m => m.Groups[1].Value).Distinct().Take(15);
        return $"Header: {FirstLines(head, 1)}\nTables: {string.Join(", ", tables)}";
    }

    private static string? PhpSource(Resp r)
    {
        var t = NotHtml(r) ?? (r.Ok && r.Text.TrimStart().StartsWith("<?php", StringComparison.Ordinal) ? r.Text : null);
        if (t == null || !t.Contains("<?php", StringComparison.Ordinal)) return null;
        var keys = Regex.Matches(t, @"define\(\s*['""](DB_[A-Z_]+|AUTH_KEY|SECURE_AUTH_KEY|[A-Z_]*PASSWORD[A-Z_]*)['""]").Select(m => m.Groups[1].Value).Distinct().ToList();
        bool vars = Regex.IsMatch(t, @"\$(db|database|dbpass|password|pass|db_password)\w*\s*=", RegexOptions.IgnoreCase);
        if (keys.Count == 0 && !vars) return null;
        return "PHP source served as text; " + (keys.Count > 0 ? $"constants (values withheld): {string.Join(", ", keys.Take(15))}" : "credential variables present (values withheld)");
    }

    private static async Task SensitiveFileChecksAsync(Run run)
    {
        var ctx = run.Ctx;
        await Parallel.ForEachAsync(Files, new ParallelOptions { MaxDegreeOfParallelism = 4, CancellationToken = ctx.Token }, async (check, _) =>
        {
            var uri = new Uri(run.Base, check.Path);
            var r = await GetAsync(run, uri).ConfigureAwait(false);
            if (r == null || !r.Ok || IsSoft404(run, r, check.Path)) return;
            string? detail;
            try { detail = check.Validate(r); }
            catch (RegexMatchTimeoutException) { detail = null; }
            if (detail == null)
            {
                ctx.Log(LogLevel.Debug, Src, $"{uri} -> HTTP {r.Status}, content does not match the expected format (ignored)");
                return;
            }
            Add(run, check.Severity, check.Title, check.Cwe, check.Description,
                $"GET {uri} -> {r.StatusLine}\n{detail}", check.Remediation);
        }).ConfigureAwait(false);

        // Directories commonly left browsable.
        foreach (var dir in new[] { "/backup/", "/backups/", "/uploads/", "/files/", "/images/", "/.git/" })
        {
            var r = await GetAsync(run, new Uri(run.Base, dir)).ConfigureAwait(false);
            if (r != null && !IsSoft404(run, r, dir)) DirectoryListingCheck(run, r);
        }

        // Spring Boot actuator index: lists endpoints without triggering them (a heap dump is never downloaded).
        var act = await GetAsync(run, new Uri(run.Base, "/actuator")).ConfigureAwait(false);
        if (act != null && act.Ok && act.Text.Contains("\"_links\"", StringComparison.Ordinal) && !IsSoft404(run, act, "/actuator"))
        {
            var endpoints = Regex.Matches(act.Text, "\"([A-Za-z0-9_-]+)\"\\s*:\\s*\\{\\s*\"href\"").Select(m => m.Groups[1].Value).Where(e => e != "self").Distinct().ToList();
            Add(run, Severity.Info, "Spring Boot Actuator endpoints exposed", 200,
                "The Actuator discovery page is reachable and lists management endpoints.",
                $"GET {act.Uri} -> HTTP {act.Status}\nEndpoints: {string.Join(", ", endpoints)}",
                "Expose only health/info and secure the management port.");
            if (endpoints.Contains("heapdump"))
                Add(run, Severity.High, "Spring Boot Actuator heapdump endpoint exposed", 528,
                    "The Actuator 'heapdump' endpoint is published. Downloading it yields a full JVM memory dump containing credentials, session tokens and personal data. (TryZ does not download the dump; the endpoint was identified from the Actuator index.)",
                    $"GET {act.Uri} -> HTTP {act.Status}; _links contains \"heapdump\" ({new Uri(run.Base, "/actuator/heapdump")})",
                    "Remove heapdump from management.endpoints.web.exposure.include and require authentication on all actuator endpoints.");
        }

        // Tomcat manager: only observe the authentication challenge, no login attempts.
        var mgr = await GetAsync(run, new Uri(run.Base, "/manager/html")).ConfigureAwait(false);
        if (mgr != null)
        {
            string? auth = mgr.Header("WWW-Authenticate");
            if (mgr.Status == 401 && auth != null && auth.Contains("Tomcat Manager", StringComparison.OrdinalIgnoreCase))
                Add(run, Severity.Info, "Tomcat Manager application exposed (/manager/html)", 200,
                    "The Tomcat Manager login is reachable. It allows WAR deployment (code execution) for anyone who obtains valid credentials and is a frequent password-guessing target.",
                    $"GET {mgr.Uri} -> HTTP 401\nWWW-Authenticate: {auth}",
                    "Restrict the manager application to localhost/admin networks (RemoteAddrValve) or remove it in production.");
            else if (mgr.Ok && mgr.Text.Contains("Tomcat Web Application Manager", StringComparison.Ordinal))
                Add(run, Severity.Critical, "Tomcat Manager accessible without authentication", 306,
                    "The Tomcat Web Application Manager is accessible without credentials; anyone can deploy a WAR file and execute code on the server.",
                    $"GET {mgr.Uri} -> {mgr.StatusLine}; page contains 'Tomcat Web Application Manager'",
                    "Remove the manager application or protect it with strong authentication and an IP allow-list immediately.");
        }
    }

    // ------------------------------------------------------------------ soft-404 baseline

    private static async Task<Baseline?> BaselineAsync(Run run)
    {
        string probe = "/tryz-" + Convert.ToHexString(RandomNumberGenerator.GetBytes(6)).ToLowerInvariant() + ".txt";
        var r = await GetAsync(run, new Uri(run.Base, probe)).ConfigureAwait(false);
        if (r == null) return null;
        var b = new Baseline(r.Status, r.Body.Length, NormalizedHash(r, probe));
        if (r.Ok)
            run.Ctx.Log(LogLevel.Info, Src, $"{run.BaseText} answers non-existent paths with HTTP {r.Status} ({r.Body.Length} bytes); soft-404 filtering active");
        return b;
    }

    private static bool IsSoft404(Run run, Resp r, string path)
    {
        var b = run.Soft404;
        if (b == null || r.Status != b.Status) return false;
        if (NormalizedHash(r, path) == b.Hash) return true;
        if (!r.Ok) return false;
        int tolerance = Math.Max(48, b.Length / 50);
        return Math.Abs(r.Body.Length - b.Length) <= tolerance && r.IsHtml;
    }

    private static string NormalizedHash(Resp r, string path)
    {
        string t = r.Text.Replace(path, string.Empty, StringComparison.OrdinalIgnoreCase)
                         .Replace(Uri.EscapeDataString(path), string.Empty, StringComparison.OrdinalIgnoreCase);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(t)));
    }

    // ------------------------------------------------------------------ transport

    private static Task<Resp?> GetAsync(Run run, Uri uri) => SendAsync(run, HttpMethod.Get, uri);

    private static async Task<Resp?> SendAsync(Run run, HttpMethod method, Uri uri, Action<HttpRequestMessage>? configure = null, int maxBody = MaxBody)
    {
        var ctx = run.Ctx;
        await ctx.GateAsync().ConfigureAwait(false);
        using var work = ctx.BeginWork();
        var sw = Stopwatch.StartNew();
        try
        {
            using var req = new HttpRequestMessage(method, uri);
            configure?.Invoke(req);
            using var resp = await ctx.Http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ctx.Token).ConfigureAwait(false);
            var headers = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in resp.Headers.NonValidated) headers[h.Key] = h.Value.ToList();
            foreach (var h in resp.Content.Headers.NonValidated) headers[h.Key] = h.Value.ToList();
            byte[] body = method == HttpMethod.Head ? Array.Empty<byte>() : await ReadLimitedAsync(ctx, resp.Content, maxBody).ConfigureAwait(false);
            double ms = sw.Elapsed.TotalMilliseconds;
            ctx.CountRequest(ms, (int)resp.StatusCode >= 500);
            return new Resp { Uri = uri, Status = (int)resp.StatusCode, Headers = headers, Body = body, LatencyMs = ms };
        }
        catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or SocketException or InvalidOperationException)
        {
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds, true);
            ctx.Log(LogLevel.Debug, Src, $"{method} {uri} failed: {(ex is OperationCanceledException ? "timeout" : ex.Message)}");
            return null;
        }
    }

    private static async Task<byte[]> ReadLimitedAsync(ScanContext ctx, HttpContent content, int max)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        cts.CancelAfter(ctx.Options.ReadTimeoutMs);
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
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            // body read timed out: keep what arrived
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException)
        {
            ctx.Log(LogLevel.Debug, Src, $"body read interrupted: {ex.Message}");
        }
        return ms.ToArray();
    }

    // ------------------------------------------------------------------ helpers

    private static void Add(Run run, Severity sev, string title, int cwe, string description, string evidence, string remediation) =>
        run.Ctx.AddFinding(sev, title, run.Svc.Host.Ip, run.Svc.Port, cwe, description, evidence, remediation);

    private static string HostForUrl(LiveHost host) => host.UrlHost;

    private static Uri? Location(Resp r)
    {
        if (r.Status is < 300 or >= 400) return null;
        string? loc = r.Header("Location");
        if (string.IsNullOrWhiteSpace(loc)) return null;
        return Uri.TryCreate(r.Uri, loc.Trim(), out var u) && (u.Scheme == Uri.UriSchemeHttp || u.Scheme == Uri.UriSchemeHttps) ? u : null;
    }

    private static bool SameOrigin(Uri a, Uri b) =>
        a.Scheme == b.Scheme && a.Port == b.Port && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase);
}
