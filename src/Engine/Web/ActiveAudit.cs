using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Active (intrusive) web testing of the parameterised requests the crawler collected: reflected XSS, error- and
/// boolean-based SQL injection, path traversal / local file inclusion, open redirect, server-side template injection,
/// OS command injection (time-based), server-side request forgery, and the per-URL CORS and XXE checks. Each parameter
/// is tested against every class against a per-request baseline so only a change caused by the injected payload is
/// reported, which keeps false positives low. All requests are same-origin (except the deliberate out-of-scope canary
/// hosts used by the redirect/SSRF/CORS probes), rate-limited, pinned and cancellation-aware; command-injection payloads
/// use only benign delays (sleep/ping), and every finding records the exact parameter and payload.
/// </summary>
internal static partial class ActiveAudit
{
    private const string Src = "active";
    // A unique run marker keeps reflected payloads and findings attributable to this scan and avoids clashing with page text.
    private static readonly string Marker = "tz" + Guid.NewGuid().ToString("N")[..8];

    public static async Task RunAsync(ScanContext ctx, int taskId)
    {
        var points = ctx.InjectionPoints
            .OrderBy(p => p.Url.AbsolutePath.Length) // shallow paths first: usually the more interesting entry points
            .Take(ctx.Options.MaxActiveTargets)
            .ToList();
        if (points.Count == 0)
        {
            ctx.Log(LogLevel.Info, Src, "No parameters were discovered to test actively");
            return;
        }
        int paramCount = points.Sum(p => p.Parameters.Count);
        ctx.Log(LogLevel.Notice, Src,
            $"Active testing started on {points.Count} request(s), {paramCount} parameter(s): reflected XSS, SQL injection, path traversal, open redirect, template injection, command injection, SSRF, CORS and XXE");

        int done = 0;
        await Parallel.ForEachAsync(points,
            new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(ctx.Options.Threads / 4, 1, 12), CancellationToken = ctx.Token },
            async (point, _) =>
            {
                try
                {
                    await TestPointAsync(ctx, point).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
                catch (Exception ex)
                {
                    ctx.Log(LogLevel.Debug, Src, $"Active test error on {point.Url}: {ex.GetType().Name}");
                }
                ctx.UpdateTask(taskId, TaskState.Running, (int)(100.0 * Interlocked.Increment(ref done) / points.Count));
            }).ConfigureAwait(false);

        ctx.Log(LogLevel.Ok, Src, $"Active testing finished on {points.Count} request(s)");
    }

    private static async Task TestPointAsync(ScanContext ctx, InjectionPoint point)
    {
        var baseline = await SendAsync(ctx, point, point.Parameters).ConfigureAwait(false);
        if (baseline == null) return;

        // URL-level checks that do not depend on a single parameter run once per injection point.
        await CorsAsync(ctx, point).ConfigureAwait(false);
        await XxeAsync(ctx, point).ConfigureAwait(false);

        foreach (var param in point.Parameters)
        {
            ctx.Token.ThrowIfCancellationRequested();
            string name = param.Key;
            // Every parameter is tested against every vulnerability class; a class that confirms a hit does not stop the
            // others, so a parameter that is both reflected and injectable is reported for each. Each class still
            // short-circuits internally on its own first confirmed payload to bound request volume.
            await ReflectedXssAsync(ctx, point, name).ConfigureAwait(false);
            await SqlInjectionAsync(ctx, point, name, param.Value, baseline).ConfigureAwait(false);
            await PathTraversalAsync(ctx, point, name).ConfigureAwait(false);
            await OpenRedirectAsync(ctx, point, name, param.Value).ConfigureAwait(false);
            await TemplateInjectionAsync(ctx, point, name).ConfigureAwait(false);
            await CommandInjectionAsync(ctx, point, name, param.Value, baseline).ConfigureAwait(false);
            await SsrfAsync(ctx, point, name, param.Value).ConfigureAwait(false);
        }
    }

    // ------------------------------------------------------------------ reflected XSS

    private static async Task<bool> ReflectedXssAsync(ScanContext ctx, InjectionPoint point, string name)
    {
        // A context-breaking probe: if it comes back with its angle brackets and quotes intact, the value is reflected
        // into HTML without encoding and script injection is possible. Encoded reflection (&lt;) will not match.
        string tag = Marker + "x";
        string payload = $"'\"></title></textarea></script><{tag}>";
        var resp = await SendMutatedAsync(ctx, point, name, payload).ConfigureAwait(false);
        if (resp == null || !resp.IsHtml) return false;
        if (!resp.Body.Contains($"<{tag}>", StringComparison.Ordinal)) return false;

        Report(ctx, point, Severity.High, "Reflected cross-site scripting (XSS)", 79,
            $"The parameter '{name}' of {point.Method} {point.Url.AbsolutePath} ({point.Origin}) is reflected into the HTML response without output encoding. " +
            "An attacker can craft a link that runs arbitrary JavaScript in the victim's session (session theft, account takeover, defacement).",
            $"Payload in '{name}': {payload}\nThe markup <{tag}> was returned verbatim (angle brackets not encoded) in an HTML response.",
            "Context-sensitively encode all user input on output (HTML entity, attribute, JS and URL encoding); prefer a template engine that auto-escapes. Add a strict Content-Security-Policy as defence in depth.",
            name);
        return true;
    }

    // ------------------------------------------------------------------ SQL injection

    private static async Task<bool> SqlInjectionAsync(ScanContext ctx, InjectionPoint point, string name, string value, ScanContext.Probe baseline)
    {
        bool baselineHasError = SqlErrorRegex().IsMatch(baseline.Body);

        // 1) Error-based: a bare quote that is not already present in the baseline response.
        foreach (string breaker in new[] { "'", "\"", "')", "';" })
        {
            var resp = await SendMutatedAsync(ctx, point, name, value + breaker).ConfigureAwait(false);
            if (resp == null) continue;
            var m = SqlErrorRegex().Match(resp.Body);
            if (m.Success && !baselineHasError)
            {
                Report(ctx, point, Severity.Critical, "SQL injection (error-based)", 89,
                    $"Injecting the SQL meta-character sequence \"{breaker}\" into parameter '{name}' of {point.Method} {point.Url.AbsolutePath} produced a database error that the baseline request did not. " +
                    "This indicates the input is concatenated into an SQL statement, allowing data theft, authentication bypass or, depending on privileges, full database compromise.",
                    $"Payload in '{name}': {value}{breaker}\nDatabase error surfaced: \"{Trim(m.Value)}\"",
                    "Use parameterised queries / prepared statements for every database call; never build SQL by string concatenation. Apply least-privilege database accounts and disable detailed SQL errors in production.",
                    name);
                return true;
            }
        }

        // 2) Boolean-based: a TRUE condition should look like the baseline, a FALSE condition should differ markedly.
        if (!baselineHasError)
        {
            var tru = await SendMutatedAsync(ctx, point, name, value + "' AND '" + Marker + "'='" + Marker).ConfigureAwait(false);
            var fls = await SendMutatedAsync(ctx, point, name, value + "' AND '" + Marker + "'='" + Marker + "z").ConfigureAwait(false);
            if (tru != null && fls != null && tru.Status == baseline.Status
                && Similar(tru.Body, baseline.Body) && !Similar(fls.Body, baseline.Body)
                && Math.Abs(fls.Body.Length - baseline.Body.Length) > Math.Max(64, baseline.Body.Length / 20))
            {
                Report(ctx, point, Severity.Critical, "SQL injection (boolean-based)", 89,
                    $"Parameter '{name}' of {point.Method} {point.Url.AbsolutePath} changed the response in step with an injected boolean SQL condition: a TRUE condition reproduced the normal page while a FALSE condition changed it. " +
                    "This confirms the value is interpreted as SQL and data can be extracted one condition at a time (blind SQL injection).",
                    $"TRUE  payload ('...'='...'): {baseline.Body.Length} vs {tru.Body.Length} bytes (matches baseline)\n" +
                    $"FALSE payload ('...'='...z'): {fls.Body.Length} bytes (differs from baseline)",
                    "Use parameterised queries / prepared statements for every database call; never build SQL by string concatenation. Apply least-privilege database accounts.",
                    name);
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ path traversal / LFI

    private static async Task<bool> PathTraversalAsync(ScanContext ctx, InjectionPoint point, string name)
    {
        foreach (string payload in new[]
                 {
                     "../../../../../../../../etc/passwd",
                     "....//....//....//....//....//etc/passwd",
                     "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
                     "../../../../../../../../windows/win.ini",
                 })
        {
            var resp = await SendMutatedAsync(ctx, point, name, payload).ConfigureAwait(false);
            if (resp == null) continue;
            if (UnixPasswdRegex().IsMatch(resp.Body))
            {
                Report(ctx, point, Severity.Critical, "Path traversal / local file inclusion", 22,
                    $"Parameter '{name}' of {point.Method} {point.Url.AbsolutePath} returned the contents of /etc/passwd when given a directory-traversal path. " +
                    "The application builds a file path from user input without containment, so arbitrary files (source, configuration, credentials) can be read and, in some stacks, code executed.",
                    $"Payload in '{name}': {payload}\nResponse contained a Unix passwd file (root:...:0:0:).",
                    "Never use user input in filesystem paths. Map inputs to a fixed allow-list of identifiers, resolve the final path and verify it stays within an intended base directory (canonicalisation check).",
                    name);
                return true;
            }
            if (resp.Body.Contains("[extensions]", StringComparison.OrdinalIgnoreCase) && resp.Body.Contains("[fonts]", StringComparison.OrdinalIgnoreCase))
            {
                Report(ctx, point, Severity.Critical, "Path traversal / local file inclusion", 22,
                    $"Parameter '{name}' of {point.Method} {point.Url.AbsolutePath} returned the contents of C:\\Windows\\win.ini when given a traversal path, confirming arbitrary file read on Windows.",
                    $"Payload in '{name}': {payload}\nResponse contained win.ini sections ([extensions], [fonts]).",
                    "Never use user input in filesystem paths. Map inputs to a fixed allow-list and verify the resolved path stays within an intended base directory.",
                    name);
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ open redirect

    private static async Task<bool> OpenRedirectAsync(ScanContext ctx, InjectionPoint point, string name, string value)
    {
        // Only parameters that already carry a URL/path, or whose name suggests a redirect target, are worth testing.
        bool candidate = RedirectNameRegex().IsMatch(name)
            || value.StartsWith("http", StringComparison.OrdinalIgnoreCase) || value.StartsWith('/');
        if (!candidate) return false;

        const string canary = "tryz-openredirect-canary.example";
        foreach (string payload in new[] { $"https://{canary}/", $"//{canary}/", $"https:/{canary}/" })
        {
            var resp = await SendMutatedAsync(ctx, point, name, payload, follow: false).ConfigureAwait(false);
            if (resp == null || resp.Status is < 300 or >= 400) continue;
            string loc = resp.Header("Location");
            if (loc.Length == 0) continue;
            if (!Uri.TryCreate(loc, UriKind.Absolute, out var dest))
                Uri.TryCreate(new Uri("http://placeholder.invalid/"), loc, out dest);
            if (dest != null && dest.Host.Equals(canary, StringComparison.OrdinalIgnoreCase))
            {
                Report(ctx, point, Severity.Medium, "Open redirect", 601,
                    $"Parameter '{name}' of {point.Method} {point.Url.AbsolutePath} controls the Location of an HTTP redirect, sending the browser to an attacker-chosen external host. " +
                    "This is used in phishing (a trusted link that lands on a hostile site) and to bypass redirect-based allow-lists in OAuth / SSO flows.",
                    $"Payload in '{name}': {payload}\nServer responded HTTP {resp.Status} with Location: {loc}",
                    "Do not redirect to URLs taken from the request. Redirect only to a server-side allow-list of paths, or map an opaque token to the destination; if an absolute URL is unavoidable, verify its host is in-scope.",
                    name);
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ request building

    private static Task<ScanContext.Probe?> SendMutatedAsync(ScanContext ctx, InjectionPoint point, string name, string payload, bool follow = false)
    {
        var mutated = point.Parameters
            .Select(p => string.Equals(p.Key, name, StringComparison.Ordinal) ? new KeyValuePair<string, string>(p.Key, payload) : p)
            .ToList();
        return SendAsync(ctx, point, mutated, follow);
    }

    private static Task<ScanContext.Probe?> SendAsync(ScanContext ctx, InjectionPoint point, IReadOnlyList<KeyValuePair<string, string>> values, bool follow = false)
    {
        if (point.Method == "POST")
        {
            var content = new FormUrlEncodedContent(values);
            return ctx.ProbeAsync(HttpMethod.Post, point.Url, follow, content);
        }
        var sb = new StringBuilder(point.Url.GetLeftPart(UriPartial.Path));
        sb.Append('?');
        for (int i = 0; i < values.Count; i++)
        {
            if (i > 0) sb.Append('&');
            sb.Append(Uri.EscapeDataString(values[i].Key)).Append('=').Append(Uri.EscapeDataString(values[i].Value));
        }
        return Uri.TryCreate(sb.ToString(), UriKind.Absolute, out var uri)
            ? ctx.ProbeAsync(HttpMethod.Get, uri, follow)
            : Task.FromResult<ScanContext.Probe?>(null);
    }

    private static void Report(ScanContext ctx, InjectionPoint point, Severity sev, string title, int cwe,
        string description, string evidence, string remediation, string param) =>
        ctx.AddFinding(sev, $"{title}: {point.Url.AbsolutePath} ({param})", point.HostIp, point.Port, cwe,
            description, evidence, remediation,
            new FindingDetails { RuleId = $"active-{FindingDetails.Slug(title)}" });

    // ------------------------------------------------------------------ helpers

    /// <summary>Rough similarity: equal within a small length tolerance. Good enough for boolean-based differentials.</summary>
    private static bool Similar(string a, string b)
    {
        int max = Math.Max(a.Length, b.Length);
        if (max == 0) return true;
        return Math.Abs(a.Length - b.Length) <= Math.Max(32, max / 40);
    }

    private static string Trim(string s)
    {
        s = s.Replace('\n', ' ').Replace('\r', ' ').Trim();
        return s.Length > 200 ? s[..200] + " ..." : s;
    }

    // Database error signatures across the common engines (reused idea from the crawler's passive error check).
    [GeneratedRegex(
        @"SQL syntax.*MySQL|valid MySQL result|MySqlClient\.|You have an error in your SQL syntax|" +
        @"PostgreSQL.*ERROR|pg_query\(\)|pg_exec\(\)|Npgsql\.|" +
        @"ORA-\d{4,5}|Oracle error|quoted string not properly terminated|" +
        @"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark after the character string|" +
        @"SQLServer JDBC Driver|System\.Data\.SqlClient\.SqlException|" +
        @"SQLite3?::|SQLITE_ERROR|sqlite3\.OperationalError|" +
        @"SQLSTATE\[|java\.sql\.SQLException|org\.hibernate\.",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, 150)]
    private static partial Regex SqlErrorRegex();

    [GeneratedRegex(@"root:.*?:0:0:", RegexOptions.CultureInvariant, 150)]
    private static partial Regex UnixPasswdRegex();

    [GeneratedRegex(@"^(url|uri|link|next|target|dest|destination|redirect|redir|return|returnurl|return_to|goto|continue|forward|out|view|to|r|u)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex RedirectNameRegex();
}
