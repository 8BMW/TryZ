using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Dictionary-based discovery of resources that are present but not linked from any page: admin panels, API roots,
/// backup and configuration files, version-control and CI metadata. Each web root is probed against a built-in word
/// list (optionally extended by the user) with a per-root soft-404 baseline so that catch-all 200 pages do not create
/// noise. Also performs DNS-only enumeration of common sub-domains of in-scope names, reporting the ones that resolve
/// (so the dangling-alias check and the operator can act on them) without scanning hosts that were never authorised.
/// </summary>
internal static class ContentDiscovery
{
    private const string Src = "discovery";

    // A compact, high-signal built-in list: sensitive files, metadata, admin and API surfaces. Extended by WordlistPath.
    private static readonly string[] BuiltIn =
    {
        "admin", "administrator", "admin/login", "login", "wp-admin/", "wp-login.php", "user/login", "dashboard",
        "phpmyadmin/", "adminer.php", "manager/html", "console", "cpanel", "webmail/",
        "api", "api/", "api/v1", "api/v2", "graphql", "swagger", "swagger-ui.html", "swagger/index.html",
        "openapi.json", "api-docs", "v2/api-docs", "actuator", "actuator/health", "actuator/env",
        ".git/", ".git/HEAD", ".git/config", ".svn/entries", ".hg/", ".bzr/",
        ".env", ".env.local", ".env.production", "config.php", "config.php.bak", "configuration.php",
        "web.config", "appsettings.json", "settings.py", "wp-config.php.bak", "database.yml", "credentials",
        "backup/", "backups/", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql", "dump.sql", "site.zip",
        "old/", "test/", "tmp/", "temp/", "dev/", "staging/", "uploads/", "files/", "logs/", "log/",
        "server-status", "server-info", "phpinfo.php", "info.php", "status", "metrics", "health", "healthz",
        ".well-known/security.txt", "robots.txt", "sitemap.xml", "crossdomain.xml", ".DS_Store",
        "readme.md", "CHANGELOG.md", "composer.json", "package.json", "Dockerfile", "docker-compose.yml",
        ".aws/credentials", ".ssh/id_rsa", "id_rsa", ".htpasswd", ".htaccess",
    };

    // Common sub-domain labels for DNS enumeration (resolve only; no port scanning of newly found hosts).
    private static readonly string[] SubLabels =
    {
        "www", "mail", "webmail", "smtp", "imap", "pop", "ftp", "sftp", "ns1", "ns2", "dns",
        "dev", "staging", "stage", "test", "qa", "uat", "sandbox", "demo", "preview", "beta",
        "api", "api-dev", "apis", "gateway", "app", "apps", "portal", "admin", "manage", "cpanel", "whm",
        "git", "gitlab", "jenkins", "ci", "build", "nexus", "registry", "docker", "harbor", "argocd",
        "vpn", "remote", "citrix", "rdp", "gateway", "proxy", "cache", "cdn", "static", "assets", "media", "img",
        "db", "database", "mysql", "postgres", "redis", "mongo", "elastic", "kibana", "grafana", "prometheus",
        "internal", "intranet", "corp", "office", "ad", "ldap", "sso", "auth", "login", "id", "accounts",
        "status", "monitor", "metrics", "logs", "support", "help", "docs", "wiki", "blog", "shop", "store",
        "m", "mobile", "secure", "payment", "pay", "billing", "crm", "erp", "hr", "jira", "confluence", "s3",
    };

    // ------------------------------------------------------------------ content discovery

    public static async Task RunContentAsync(ScanContext ctx, IReadOnlyList<Uri> roots, int taskId)
    {
        if (roots.Count == 0)
        {
            ctx.Log(LogLevel.Info, Src, "No web root available; content discovery skipped");
            return;
        }
        var words = LoadWords(ctx);
        ctx.Log(LogLevel.Notice, Src, $"Content discovery started: {words.Count} path(s) across {roots.Count} web root(s)");
        int done = 0, total = roots.Count * words.Count, hits = 0;

        foreach (var root in roots)
        {
            ctx.Token.ThrowIfCancellationRequested();
            var soft = await SoftBaselineAsync(ctx, root).ConfigureAwait(false);
            await Parallel.ForEachAsync(words,
                new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(ctx.Options.Threads / 4, 1, 12), CancellationToken = ctx.Token },
                async (word, _) =>
                {
                    try
                    {
                        if (await ProbePathAsync(ctx, root, word, soft).ConfigureAwait(false)) Interlocked.Increment(ref hits);
                    }
                    catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
                    catch (Exception ex) { ctx.Log(LogLevel.Debug, Src, $"discovery error on {word}: {ex.GetType().Name}"); }
                    int n = Interlocked.Increment(ref done);
                    if (n % 25 == 0) ctx.UpdateTask(taskId, TaskState.Running, (int)(100.0 * n / Math.Max(1, total)));
                }).ConfigureAwait(false);
        }
        ctx.Log(LogLevel.Ok, Src, $"Content discovery finished: {hits} notable path(s) found");
    }

    private static List<string> LoadWords(ScanContext ctx)
    {
        var set = new HashSet<string>(BuiltIn, StringComparer.OrdinalIgnoreCase);
        string path = ctx.Options.WordlistPath;
        if (path.Length > 0 && File.Exists(path))
        {
            try
            {
                foreach (var raw in File.ReadLines(path).Take(50_000))
                {
                    string w = raw.Trim().TrimStart('/');
                    if (w.Length is > 0 and <= 128 && !w.StartsWith('#')) set.Add(w);
                }
                ctx.Log(LogLevel.Info, Src, $"Loaded extra word list from {path}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                ctx.Log(LogLevel.Warn, Src, $"Could not read word list {path}: {ex.Message}");
            }
        }
        return set.ToList();
    }

    private sealed record Soft(int Status, string Hash, int Length);

    private static async Task<Soft?> SoftBaselineAsync(ScanContext ctx, Uri root)
    {
        string probe = "tzc" + Guid.NewGuid().ToString("N")[..10];
        if (!Uri.TryCreate(root, probe, out var uri)) return null;
        var r = await ctx.ProbeAsync(HttpMethod.Get, uri, follow: false).ConfigureAwait(false);
        if (r == null) return null;
        if (r.Status is >= 200 and < 300)
            ctx.Log(LogLevel.Info, Src, $"{root.GetLeftPart(UriPartial.Authority)} serves HTTP {r.Status} for non-existent paths; soft-404 filtering active");
        return new Soft(r.Status, HashBody(r.Body), r.Body.Length);
    }

    private static async Task<bool> ProbePathAsync(ScanContext ctx, Uri root, string word, Soft? soft)
    {
        if (!Uri.TryCreate(root, word, out var uri) || !SameOrigin(uri, root)) return false;
        var r = await ctx.ProbeAsync(HttpMethod.Get, uri, follow: false).ConfigureAwait(false);
        if (r == null) return false;
        int status = r.Status;
        if (status is not (200 or 201 or 204 or 301 or 302 or 401 or 403 or 500)) return false;

        // Filter catch-all soft-404s: same status and near-identical body as the random-path baseline.
        if (soft != null && status == soft.Status && status is >= 200 and < 300)
        {
            if (HashBody(r.Body) == soft.Hash) return false;
            if (Math.Abs(r.Body.Length - soft.Length) <= Math.Max(48, soft.Length / 40)) return false;
        }

        bool sensitive = IsSensitive(word);
        Severity sev = status switch
        {
            401 or 403 => Severity.Info,
            >= 200 and < 300 when sensitive => Severity.Medium,
            >= 200 and < 300 => Severity.Low,
            500 => Severity.Low,
            _ => Severity.Info, // redirects
        };
        string kind = status switch
        {
            401 or 403 => "protected resource present (authentication/authorisation required)",
            301 or 302 => "redirecting resource present",
            500 => "resource present but erroring",
            _ => "unlinked resource reachable",
        };
        string host = ctx.IpFor(root.Host);
        ctx.AddFinding(sev, $"Content discovery: /{word.TrimStart('/')}", host, root.Port, 538,
            $"A dictionary probe found a resource that is not linked from the crawled pages: {kind}. " +
            (sensitive ? "The name suggests sensitive functionality or data (administrative, backup, configuration or version-control). " : "") +
            "Unlinked resources are often forgotten and left unprotected.",
            $"{r.Status} {r.ContentType}".TrimEnd() + $" at {uri.AbsoluteUri} ({r.Body.Length} bytes)",
            "Remove resources that should not be public; require authentication and authorisation on administrative and internal endpoints; keep backups, dumps and VCS metadata off the web root.",
            new FindingDetails { RuleId = "content-discovery" });
        return true;
    }

    private static bool IsSensitive(string word)
    {
        string w = word.ToLowerInvariant();
        return w.Contains("admin") || w.Contains("backup") || w.Contains(".git") || w.Contains(".svn") || w.Contains(".env")
            || w.Contains("config") || w.Contains("password") || w.Contains("secret") || w.Contains("credential")
            || w.Contains(".sql") || w.Contains("dump") || w.Contains("phpmyadmin") || w.Contains("id_rsa")
            || w.Contains("actuator") || w.Contains(".htpasswd") || w.Contains(".aws") || w.Contains(".ssh");
    }

    // ------------------------------------------------------------------ subdomain enumeration (DNS only)

    public static async Task RunSubdomainsAsync(ScanContext ctx, int taskId)
    {
        var bases = BaseDomains(ctx.ObservedHostnames);
        if (bases.Count == 0)
        {
            ctx.Log(LogLevel.Info, Src, "No registrable host name observed; sub-domain enumeration skipped");
            return;
        }
        var candidates = bases.SelectMany(b => SubLabels.Select(l => $"{l}.{b}"))
            .Where(n => !ctx.ObservedHostnames.Contains(n))
            .Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        ctx.Log(LogLevel.Notice, Src, $"Sub-domain enumeration started: {candidates.Count} name(s) across {bases.Count} base domain(s) (DNS only)");
        int done = 0, found = 0;

        await Parallel.ForEachAsync(candidates,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(ctx.Options.Threads / 2, 2, 24), CancellationToken = ctx.Token },
            async (name, _) =>
            {
                try
                {
                    await ctx.GateAsync().ConfigureAwait(false);
                    using var work = ctx.BeginWork();
                    using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
                    cts.CancelAfter(Math.Clamp(ctx.Options.ReadTimeoutMs, 500, 5000));
                    IPAddress[] addrs;
                    try { addrs = await Dns.GetHostAddressesAsync(name, cts.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested) { return; }
                    catch (SocketException) { return; }
                    if (addrs.Length == 0) return;
                    ctx.NoteHostname(name); // feeds the dangling-alias check
                    Interlocked.Increment(ref found);
                    string ips = string.Join(", ", addrs.Take(4).Select(a => a.ToString()));
                    ctx.AddFinding(Severity.Info, $"Sub-domain discovered: {name}", name, 0, 0,
                        "A common sub-domain name resolves in DNS. Enumerating sub-domains enlarges the known attack surface; each resolving name may expose an additional application or service. " +
                        "It was resolved only — it was not scanned unless it is in the authorised scope.",
                        $"{name} resolves to {ips}",
                        "Review whether this sub-domain should be publicly resolvable. Decommission unused DNS records and ensure every exposed host is inventoried and hardened.",
                        new FindingDetails { RuleId = "subdomain-discovered", Proto = "dns" });
                }
                catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
                catch (Exception ex) { ctx.Log(LogLevel.Debug, Src, $"sub-domain error on {name}: {ex.GetType().Name}"); }
                int n = Interlocked.Increment(ref done);
                if (n % 20 == 0) ctx.UpdateTask(taskId, TaskState.Running, (int)(100.0 * n / Math.Max(1, candidates.Count)));
            }).ConfigureAwait(false);

        ctx.Log(LogLevel.Ok, Src, $"Sub-domain enumeration finished: {found} name(s) resolved");
    }

    /// <summary>Registrable-ish base domains from observed names: the last two labels (last three for known 2-level TLDs).</summary>
    private static List<string> BaseDomains(IEnumerable<string> names)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in names)
        {
            if (IPAddress.TryParse(name, out _)) continue;
            var parts = name.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            int take = 2;
            if (parts.Length >= 3 && TwoLevelTlds.Contains($"{parts[^2]}.{parts[^1]}")) take = 3;
            set.Add(string.Join('.', parts[^take..]));
        }
        return set.ToList();
    }

    private static readonly HashSet<string> TwoLevelTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au", "org.au",
        "co.nz", "com.br", "com.cn", "com.sa", "com.eg", "co.in", "co.za", "com.tr", "com.mx", "com.ar",
    };

    private static string HashBody(string body) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(body)));

    private static bool SameOrigin(Uri a, Uri b) =>
        a.Scheme == b.Scheme && a.Port == b.Port && string.Equals(a.Host, b.Host, StringComparison.OrdinalIgnoreCase);
}
