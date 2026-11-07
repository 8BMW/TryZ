using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Looks up CVEs for identified product versions in the NVD CVE API 2.0.
/// Known products are queried by CPE (virtualMatchString=cpe:2.3:a:vendor:product), unknown ones by keyword; every CVE is then
/// matched locally against its configuration cpeMatch entries (vendor/product + exact version or version range) so that only CVEs
/// whose affected-version data covers the observed version are reported.
/// </summary>
internal static class NvdClient
{
    private const string Src = "nvd";
    private const string Endpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private const int MaxLookups = 15;
    private const int PageSize = 2000;
    private const int MaxPagesPerQuery = 3;
    private const int MaxFindingsPerVersion = 60;

    /// <summary>Product name pattern -> NVD CPE vendor:product pairs. Order matters (more specific first).</summary>
    private static readonly (Regex Match, string Display, string[] Cpes)[] Products =
    {
        (Rx(@"openssh"), "OpenSSH", ["openbsd:openssh"]),
        (Rx(@"dropbear"), "Dropbear SSH", ["dropbear_ssh_project:dropbear_ssh"]),
        (Rx(@"tomcat|coyote"), "Apache Tomcat", ["apache:tomcat"]),
        (Rx(@"couchdb"), "Apache CouchDB", ["apache:couchdb"]),
        (Rx(@"cassandra"), "Apache Cassandra", ["apache:cassandra"]),
        (Rx(@"^apache(\s*httpd|\s+http server)?$|^apache/|^httpd$"), "Apache httpd", ["apache:http_server"]),
        (Rx(@"openresty"), "OpenResty", ["openresty:openresty"]),
        (Rx(@"nginx"), "nginx", ["f5:nginx", "nginx:nginx"]),
        (Rx(@"(microsoft[- ]?)?iis|internet information services"), "Microsoft IIS", ["microsoft:internet_information_services"]),
        (Rx(@"lighttpd"), "lighttpd", ["lighttpd:lighttpd"]),
        (Rx(@"caddy"), "Caddy", ["caddyserver:caddy"]),
        (Rx(@"jetty"), "Eclipse Jetty", ["eclipse:jetty"]),
        (Rx(@"haproxy"), "HAProxy", ["haproxy:haproxy"]),
        (Rx(@"squid"), "Squid", ["squid-cache:squid"]),
        (Rx(@"vsftpd"), "vsftpd", ["vsftpd_project:vsftpd", "beasts:vsftpd"]),
        (Rx(@"proftpd"), "ProFTPD", ["proftpd:proftpd"]),
        (Rx(@"pure-?ftpd"), "Pure-FTPd", ["pureftpd:pure-ftpd"]),
        (Rx(@"filezilla"), "FileZilla Server", ["filezilla-project:filezilla_server"]),
        (Rx(@"exim"), "Exim", ["exim:exim"]),
        (Rx(@"postfix"), "Postfix", ["postfix:postfix"]),
        (Rx(@"dovecot"), "Dovecot", ["dovecot:dovecot"]),
        (Rx(@"samba"), "Samba", ["samba:samba"]),
        (Rx(@"mariadb"), "MariaDB", ["mariadb:mariadb"]),
        (Rx(@"mysql"), "MySQL", ["oracle:mysql"]),
        (Rx(@"postgres"), "PostgreSQL", ["postgresql:postgresql"]),
        (Rx(@"mongodb"), "MongoDB", ["mongodb:mongodb"]),
        (Rx(@"redis"), "Redis", ["redis:redis"]),
        (Rx(@"elasticsearch"), "Elasticsearch", ["elastic:elasticsearch"]),
        (Rx(@"memcached"), "Memcached", ["memcached:memcached"]),
        (Rx(@"openssl"), "OpenSSL", ["openssl:openssl"]),
        (Rx(@"^php$"), "PHP", ["php:php"]),
        (Rx(@"\bbind\b|^named$"), "ISC BIND", ["isc:bind"]),
    };

    private static Regex Rx(string p) => new(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private sealed record Target(string Display, string[] Cpes, string Keyword);

    private sealed record Match(string Id, double Score, string ScoreSource, Severity Severity, int Cwe, string Description, string Criteria, string Range, string Vector);

    /// <summary>Looks up CVEs for identified product/version pairs in the NVD 2.0 API and reports them as findings.</summary>
    public static async Task LookupAsync(ScanContext ctx, IReadOnlyList<OpenService> services)
    {
        // product -> version -> services
        var byProduct = new Dictionary<Target, Dictionary<string, List<OpenService>>>();
        foreach (var svc in services)
            foreach (var (product, version) in Observed(svc))
            {
                var target = Resolve(product);
                if (!byProduct.TryGetValue(target, out var versions))
                    byProduct[target] = versions = new Dictionary<string, List<OpenService>>(StringComparer.OrdinalIgnoreCase);
                if (!versions.TryGetValue(version, out var list)) versions[version] = list = new List<OpenService>();
                if (!list.Contains(svc)) list.Add(svc);
            }

        if (byProduct.Count == 0)
        {
            ctx.Log(LogLevel.Info, Src, "NVD lookup: no services with both a product and a version were identified");
            return;
        }

        bool hasKey = ctx.Options.NvdApiKey.Trim().Length > 0;
        var delay = TimeSpan.FromMilliseconds(hasKey ? 700 : 6500);
        var queue = byProduct.OrderByDescending(p => p.Value.Values.Sum(l => l.Count)).ToList();
        int queries = 0, reported = 0, done = 0;
        var skipped = new List<string>();
        ctx.Log(LogLevel.Info, Src, $"NVD lookup for {queue.Count} product(s) {(hasKey ? "with API key" : "without API key (6.5 s between requests)")}");

        // NVD responses for large products are several MB and slow to start: use a dedicated client with a long timeout.
        using var http = CreateClient(ctx);
        DateTime last = DateTime.MinValue;

        foreach (var (target, versions) in queue)
        {
            ctx.Token.ThrowIfCancellationRequested();
            string versionText = string.Join(", ", versions.Keys);
            var queryList = target.Cpes.Length > 0
                ? target.Cpes.Select(c => $"virtualMatchString={Uri.EscapeDataString("cpe:2.3:a:" + c)}").ToList()
                : new List<string> { $"keywordSearch={Uri.EscapeDataString(target.Keyword)}" };
            if (queries + queryList.Count > MaxLookups)
            {
                skipped.Add($"{target.Display} {versionText}");
                continue;
            }

            var cves = new Dictionary<string, JsonElement>(StringComparer.OrdinalIgnoreCase);
            var docs = new List<JsonDocument>();
            bool failed = false;
            try
            {
                foreach (var q in queryList)
                {
                    int start = 0;
                    for (int page = 0; page < MaxPagesPerQuery; page++)
                    {
                        var wait = last + delay - DateTime.UtcNow;
                        if (wait > TimeSpan.Zero) await Task.Delay(wait, ctx.Token).ConfigureAwait(false);
                        var url = $"{Endpoint}?{q}&resultsPerPage={PageSize}&startIndex={start}";
                        var doc = await FetchAsync(ctx, http, url, hasKey).ConfigureAwait(false);
                        last = DateTime.UtcNow;
                        queries++;
                        if (doc == null) { failed = true; break; }
                        docs.Add(doc);
                        var root = doc.RootElement;
                        if (root.TryGetProperty("vulnerabilities", out var vulns) && vulns.ValueKind == JsonValueKind.Array)
                            foreach (var v in vulns.EnumerateArray())
                                if (v.TryGetProperty("cve", out var cve) && Str(cve, "id") is { } id)
                                    cves[id] = cve;
                        int total = Int(root, "totalResults"), per = Int(root, "resultsPerPage");
                        start += Math.Max(per, 1);
                        if (start >= total || per == 0) break;
                        if (page == MaxPagesPerQuery - 1)
                            ctx.Log(LogLevel.Warn, Src, $"{target.Display}: {total} CVE records in NVD, only the first {start} were evaluated");
                    }
                    if (failed) break;
                }

                if (failed && cves.Count == 0) continue;

                foreach (var (version, svcs) in versions)
                {
                    var matches = new List<Match>();
                    foreach (var cve in cves.Values)
                        if (Evaluate(cve, target, version) is { } m) matches.Add(m);
                    matches = matches.OrderByDescending(m => m.Score).ThenByDescending(m => m.Id, StringComparer.Ordinal).ToList();

                    int crit = matches.Count(m => m.Severity == Severity.Critical), high = matches.Count(m => m.Severity == Severity.High),
                        med = matches.Count(m => m.Severity == Severity.Medium);
                    ctx.Log(matches.Count > 0 ? LogLevel.Notice : LogLevel.Info, Src,
                        $"{target.Display} {version}: {matches.Count} CVE(s) apply out of {cves.Count} NVD record(s) checked ({crit} critical, {high} high, {med} medium)");
                    if (matches.Count > MaxFindingsPerVersion)
                        ctx.Log(LogLevel.Info, Src, $"{target.Display} {version}: reporting the {MaxFindingsPerVersion} highest-scored CVEs; {matches.Count - MaxFindingsPerVersion} lower-scored omitted ({string.Join(", ", matches.Skip(MaxFindingsPerVersion).Take(20).Select(m => m.Id))}{(matches.Count - MaxFindingsPerVersion > 20 ? ", ..." : string.Empty)})");

                    foreach (var m in matches.Take(MaxFindingsPerVersion))
                        foreach (var svc in svcs)
                        {
                            string title = $"{m.Id}: {Short(m.Description)} ({target.Display} {version})";
                            string evidence =
                                $"Observed: {svc.Host.Ip}:{svc.Port}/tcp {svc.Service}, {target.Display} {version}" + (svc.Banner.Length > 0 ? $" (banner: {svc.Banner})" : string.Empty) + "\n" +
                                $"NVD applicability: {m.Criteria}{(m.Range.Length > 0 ? " " + m.Range : string.Empty)}\n" +
                                $"{m.ScoreSource} base score {m.Score.ToString("0.0", CultureInfo.InvariantCulture)}{(m.Vector.Length > 0 ? " " + m.Vector : string.Empty)}\n" +
                                $"https://nvd.nist.gov/vuln/detail/{m.Id}";
                            if (ctx.AddFinding(m.Severity, title, svc.Host.Ip, svc.Port, m.Cwe,
                                    $"{m.Description}\n\nMatched by NVD configuration data for {target.Display} {version}. The version was taken from the service banner; distributions often backport fixes without changing the version string, and some CVEs only apply to specific modules or configurations, so verify before remediating.",
                                    evidence,
                                    $"Upgrade {target.Display} to a release that fixes {m.Id} (see vendor advisory and NVD references), or apply the distribution's security update."))
                                reported++;
                        }
                }
            }
            finally
            {
                foreach (var d in docs) d.Dispose();
            }

            done++;
        }

        if (skipped.Count > 0)
            ctx.Log(LogLevel.Warn, Src, $"NVD lookup limit ({MaxLookups} requests per scan) reached; not checked: {string.Join("; ", skipped)}");
        ctx.Log(LogLevel.Ok, Src, $"NVD lookup finished: {done} product(s) checked with {queries} API request(s), {reported} CVE finding(s) reported");
    }

    // ------------------------------------------------------------------ observed product versions

    private static IEnumerable<(string Product, string Version)> Observed(OpenService svc)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (svc.Product.Trim().Length > 0 && VersionComparer.Extract(svc.Version) is { } v && seen.Add(svc.Product.Trim()))
            yield return (svc.Product.Trim(), v);

        // Components disclosed in HTTP headers, e.g. "Apache/2.4.41 (Ubuntu) OpenSSL/1.1.1f PHP/7.4.3"
        foreach (var key in new[] { "http.server", "http.powered_by" })
        {
            if (!svc.Facts.TryGetValue(key, out var header)) continue;
            foreach (System.Text.RegularExpressions.Match m in Regex.Matches(header, @"([A-Za-z][A-Za-z0-9_\-]*)/(\d+(?:\.\d+)+[a-z]?(?:p\d+)?)"))
            {
                string name = m.Groups[1].Value;
                if (name.Equals("Microsoft-IIS", StringComparison.OrdinalIgnoreCase)) name = "Microsoft IIS";
                var t = Resolve(name);
                if (t.Cpes.Length == 0) continue; // only well-known components from headers
                if (seen.Add(t.Display) && (svc.Product.Length == 0 || !Resolve(svc.Product).Equals(t)))
                    yield return (name, m.Groups[2].Value);
            }
        }
    }

    private static Target Resolve(string product)
    {
        string p = product.Trim();
        foreach (var (rx, display, cpes) in Products)
            if (rx.IsMatch(p)) return new Target(display, cpes, display);
        return new Target(p, Array.Empty<string>(), p);
    }

    // ------------------------------------------------------------------ CVE evaluation

    private static Match? Evaluate(JsonElement cve, Target target, string version)
    {
        string id = Str(cve, "id") ?? string.Empty;
        string status = Str(cve, "vulnStatus") ?? string.Empty;
        if (status.Equals("Rejected", StringComparison.OrdinalIgnoreCase)) return null;

        string? criteria = null, range = null;
        if (cve.TryGetProperty("configurations", out var configs) && configs.ValueKind == JsonValueKind.Array)
            foreach (var cfg in configs.EnumerateArray())
            {
                if (!cfg.TryGetProperty("nodes", out var nodes) || nodes.ValueKind != JsonValueKind.Array) continue;
                foreach (var node in nodes.EnumerateArray())
                {
                    if (node.TryGetProperty("negate", out var neg) && neg.ValueKind == JsonValueKind.True) continue;
                    if (!node.TryGetProperty("cpeMatch", out var cms) || cms.ValueKind != JsonValueKind.Array) continue;
                    foreach (var cm in cms.EnumerateArray())
                    {
                        if (!cm.TryGetProperty("vulnerable", out var vul) || vul.ValueKind != JsonValueKind.True) continue;
                        string? c = Str(cm, "criteria");
                        if (c == null || !CpeMatches(c, cm, target, version, out string r)) continue;
                        criteria = c;
                        range = r;
                        break;
                    }
                    if (criteria != null) break;
                }
                if (criteria != null) break;
            }
        if (criteria == null) return null;

        var (score, source, vector) = Score(cve);
        Severity sev = score >= 9 ? Severity.Critical : score >= 7 ? Severity.High : score >= 4 ? Severity.Medium : score > 0 ? Severity.Low : Severity.Info;
        string desc = string.Empty;
        if (cve.TryGetProperty("descriptions", out var ds) && ds.ValueKind == JsonValueKind.Array)
            foreach (var d in ds.EnumerateArray())
                if (Str(d, "lang") == "en") { desc = Str(d, "value") ?? string.Empty; break; }
        return new Match(id, score, source, sev, Cwe(cve), desc.Trim(), criteria, range ?? string.Empty, vector);
    }

    private static bool CpeMatches(string criteria, JsonElement cm, Target target, string version, out string range)
    {
        range = string.Empty;
        var f = SplitCpe(criteria);
        if (f.Count < 7 || f[0] != "cpe" || f[1] != "2.3") return false;
        string vendor = f[3], product = f[4], cver = f[5], update = f[6];

        if (target.Cpes.Length > 0)
        {
            bool known = false;
            foreach (var c in target.Cpes)
            {
                int i = c.IndexOf(':');
                if ((vendor == "*" || vendor.Equals(c[..i], StringComparison.OrdinalIgnoreCase)) && product.Equals(c[(i + 1)..], StringComparison.OrdinalIgnoreCase)) { known = true; break; }
            }
            if (!known) return false;
        }
        else
        {
            // keyword search fallback: the CPE product must be the observed product name itself
            string norm = Regex.Replace(target.Display.ToLowerInvariant(), @"[\s\-]+", "_");
            string last = norm.Split('_').Last();
            if (!(product.Equals(norm, StringComparison.OrdinalIgnoreCase) || (last.Length >= 4 && product.Equals(last, StringComparison.OrdinalIgnoreCase)))) return false;
        }

        string? si = Str(cm, "versionStartIncluding"), se = Str(cm, "versionStartExcluding"),
                ei = Str(cm, "versionEndIncluding"), ee = Str(cm, "versionEndExcluding");
        bool hasRange = si != null || se != null || ei != null || ee != null;

        if (cver is "*" or "-" or "")
        {
            if (!hasRange) return false; // "all versions" entries are too broad to attribute
            if (!VersionComparer.InRange(version, si, se, ei, ee)) return false;
            var parts = new List<string>();
            if (si != null) parts.Add($">= {si}");
            if (se != null) parts.Add($"> {se}");
            if (ei != null) parts.Add($"<= {ei}");
            if (ee != null) parts.Add($"< {ee}");
            range = "(" + string.Join(", ", parts) + ")";
            return true;
        }

        string exact = update is "*" or "-" or "" ? cver : cver + update;
        if (VersionComparer.Compare(version, exact) == 0) { range = "(exact version)"; return true; }
        if (update == "*" && version.StartsWith(cver, StringComparison.OrdinalIgnoreCase) && version.Length > cver.Length && char.IsLetter(version[cver.Length]))
        {
            range = "(version, any update)";
            return true;
        }
        return false;
    }

    /// <summary>Splits a CPE 2.3 formatted string on unescaped colons.</summary>
    private static List<string> SplitCpe(string cpe)
    {
        var parts = new List<string>();
        var sb = new StringBuilder();
        for (int i = 0; i < cpe.Length; i++)
        {
            char c = cpe[i];
            if (c == '\\' && i + 1 < cpe.Length) { sb.Append(cpe[++i]); continue; }
            if (c == ':') { parts.Add(sb.ToString()); sb.Clear(); continue; }
            sb.Append(c);
        }
        parts.Add(sb.ToString());
        return parts;
    }

    private static (double Score, string Source, string Vector) Score(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics) || metrics.ValueKind != JsonValueKind.Object) return (0, "No CVSS", string.Empty);
        foreach (var (key, label) in new[] { ("cvssMetricV31", "CVSS v3.1"), ("cvssMetricV30", "CVSS v3.0"), ("cvssMetricV40", "CVSS v4.0"), ("cvssMetricV2", "CVSS v2") })
        {
            if (!metrics.TryGetProperty(key, out var arr) || arr.ValueKind != JsonValueKind.Array) continue;
            JsonElement? chosen = null;
            foreach (var m in arr.EnumerateArray())
            {
                if (chosen == null) chosen = m;
                if (Str(m, "type") == "Primary") { chosen = m; break; }
            }
            if (chosen is { } c && c.TryGetProperty("cvssData", out var data) && data.TryGetProperty("baseScore", out var bs) && bs.TryGetDouble(out double score))
                return (score, label, Str(data, "vectorString") ?? string.Empty);
        }
        return (0, "No CVSS", string.Empty);
    }

    private static int Cwe(JsonElement cve)
    {
        if (cve.TryGetProperty("weaknesses", out var ws) && ws.ValueKind == JsonValueKind.Array)
        {
            int fallback = 0;
            foreach (var w in ws.EnumerateArray())
            {
                if (!w.TryGetProperty("description", out var ds) || ds.ValueKind != JsonValueKind.Array) continue;
                foreach (var d in ds.EnumerateArray())
                {
                    var m = Regex.Match(Str(d, "value") ?? string.Empty, @"^CWE-(\d+)$");
                    if (!m.Success) continue;
                    int id = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
                    if (Str(w, "type") == "Primary") return id;
                    if (fallback == 0) fallback = id;
                }
            }
            if (fallback != 0) return fallback;
        }
        return 937; // OWASP Top 10 2013 A9: Using Components with Known Vulnerabilities
    }

    private static string Short(string description)
    {
        if (description.Length == 0) return "vulnerability";
        string s = description.Replace('\n', ' ').Trim();
        int dot = s.IndexOf(". ", StringComparison.Ordinal);
        if (dot > 20) s = s[..dot];
        return s.Length > 90 ? s[..87].TrimEnd() + "..." : s.TrimEnd('.');
    }

    // ------------------------------------------------------------------ transport

    private static HttpClient CreateClient(ScanContext ctx)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.All,
            ConnectTimeout = TimeSpan.FromMilliseconds(Math.Max(ctx.Options.ConnectTimeoutMs, 5000)),
            AllowAutoRedirect = true,
            MaxAutomaticRedirections = 3,
        };
        var client = new HttpClient(handler, disposeHandler: true) { Timeout = TimeSpan.FromSeconds(90) };
        client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", ctx.Options.UserAgent);
        client.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "application/json");
        return client;
    }

    private static async Task<JsonDocument?> FetchAsync(ScanContext ctx, HttpClient http, string url, bool hasKey)
    {
        for (int attempt = 0; attempt < 2; attempt++)
        {
            await ctx.GateAsync().ConfigureAwait(false);
            using var work = ctx.BeginWork();
            var sw = Stopwatch.StartNew();
            try
            {
                using var req = new HttpRequestMessage(HttpMethod.Get, url);
                if (hasKey) req.Headers.TryAddWithoutValidation("apiKey", ctx.Options.NvdApiKey.Trim());
                using var resp = await http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ctx.Token).ConfigureAwait(false);
                if (resp.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests or HttpStatusCode.ServiceUnavailable)
                {
                    ctx.CountRequest(sw.Elapsed.TotalMilliseconds, true);
                    string msg = resp.Headers.TryGetValues("message", out var vals) ? string.Join(" ", vals) : resp.ReasonPhrase ?? string.Empty;
                    ctx.Log(LogLevel.Warn, Src, $"NVD returned HTTP {(int)resp.StatusCode} {msg}".TrimEnd() + (attempt == 0 ? "; retrying in 30 s" : string.Empty));
                    if (attempt == 0) { await Task.Delay(TimeSpan.FromSeconds(30), ctx.Token).ConfigureAwait(false); continue; }
                    return null;
                }
                if (!resp.IsSuccessStatusCode)
                {
                    ctx.CountRequest(sw.Elapsed.TotalMilliseconds, true);
                    ctx.Log(LogLevel.Warn, Src, $"NVD request failed: HTTP {(int)resp.StatusCode} {resp.ReasonPhrase} ({url})");
                    return null;
                }
                await using var stream = await resp.Content.ReadAsStreamAsync(ctx.Token).ConfigureAwait(false);
                var doc = await JsonDocument.ParseAsync(stream, default, ctx.Token).ConfigureAwait(false);
                ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
                return doc;
            }
            catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or IOException or JsonException)
            {
                ctx.CountRequest(sw.Elapsed.TotalMilliseconds, true);
                ctx.Log(LogLevel.Warn, Src, $"NVD request failed: {(ex is OperationCanceledException ? "timeout" : ex.Message)}");
                return null;
            }
        }
        return null;
    }

    private static string? Str(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static int Int(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int i) ? i : 0;
}
