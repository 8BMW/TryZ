using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Additional active-audit vulnerability classes: server-side template injection, OS command injection (time-based
/// blind), server-side request forgery, cross-origin resource sharing misconfiguration and XML external entity
/// injection. These live in the same partial class as <see cref="ActiveAudit"/> and reuse its request helpers so they
/// share pacing, host pinning, authentication and the proxy setting.
/// </summary>
internal static partial class ActiveAudit
{
    // ------------------------------------------------------------------ server-side template injection (SSTI)

    /// <summary>
    /// Detects server-side template injection by submitting an arithmetic expression in several template syntaxes and
    /// confirming the server evaluated it: the computed product appears in the response while the literal expression
    /// does not. Two different products are required to agree, which rules out a coincidental number in the page.
    /// </summary>
    private static async Task<bool> TemplateInjectionAsync(ScanContext ctx, InjectionPoint point, string name)
    {
        // Operands chosen so their products (7957 and 8030) are distinctive and unlikely to occur together by chance.
        const int a = 73, b = 109, c = 110;
        foreach (var (open, close, engine) in TemplateSyntaxes)
        {
            string probe1 = open + $"{a}*{b}" + close;
            var r1 = await SendMutatedAsync(ctx, point, name, probe1).ConfigureAwait(false);
            if (r1 == null) continue;
            // The engine must have consumed the expression (literal gone) and produced the product.
            if (!r1.Body.Contains((a * b).ToString(), StringComparison.Ordinal)) continue;
            if (r1.Body.Contains($"{a}*{b}", StringComparison.Ordinal)) continue;

            string probe2 = open + $"{a}*{c}" + close;
            var r2 = await SendMutatedAsync(ctx, point, name, probe2).ConfigureAwait(false);
            if (r2 == null || !r2.Body.Contains((a * c).ToString(), StringComparison.Ordinal) || r2.Body.Contains($"{a}*{c}", StringComparison.Ordinal))
                continue;

            Report(ctx, point, Severity.High, "Server-side template injection", 1336,
                $"The parameter '{name}' of {point.Method} {point.Url.AbsolutePath} ({point.Origin}) is evaluated by a server-side template engine ({engine} syntax). " +
                "Two different arithmetic expressions were each replaced by their computed result in the response. Template injection commonly escalates to disclosure of server-side data and, in many engines, to remote code execution.",
                $"Payload in '{name}': {probe1}  →  response contained {a * b}\n" +
                $"Payload in '{name}': {probe2}  →  response contained {a * c}\n" +
                "The literal expressions were not returned, so the engine evaluated them.",
                "Never place untrusted input into a template that is then compiled/evaluated. Pass user data only as rendered values/parameters, use a sandboxed or logic-less template engine, and keep templates server-defined.",
                name);
            return true;
        }
        return false;
    }

    private static readonly (string Open, string Close, string Engine)[] TemplateSyntaxes =
    {
        ("{{", "}}", "Jinja2 / Twig / Angular"),
        ("${", "}", "Freemarker / JSP EL / Thymeleaf"),
        ("#{", "}", "Ruby / JSF EL"),
        ("<%= ", " %>", "ERB / ASP"),
        ("*{", "}", "Thymeleaf"),
    };

    // ------------------------------------------------------------------ OS command injection (time-based blind)

    /// <summary>
    /// Detects OS command injection with a time delay: a benign <c>sleep</c>/<c>ping</c> is appended behind common shell
    /// separators and the response time is compared with the baseline. A candidate delay is confirmed by repeating the
    /// slow payload and by checking that a zero-delay control of the same shape stays fast, so ordinary latency spikes do
    /// not produce a finding. No destructive command is ever sent.
    /// </summary>
    private static async Task<bool> CommandInjectionAsync(ScanContext ctx, InjectionPoint point, string name, string value, ScanContext.Probe baseline)
    {
        int budgetMs = ctx.Options.ConnectTimeoutMs + ctx.Options.ReadTimeoutMs;
        if (budgetMs < 3500) return false; // too little time budget to separate an injected delay from jitter
        int delayMs = Math.Clamp(budgetMs - 1500, 2000, 7000);
        delayMs = Math.Min(delayMs, budgetMs - 1200);
        int delaySec = Math.Max(2, delayMs / 1000);
        delayMs = delaySec * 1000;
        double normal = baseline.LatencyMs > 0 ? baseline.LatencyMs : 150;
        double threshold = normal + delayMs * 0.6;

        foreach (var (payload, shape) in CommandPayloads(value, delaySec))
        {
            var slow = await SendMutatedAsync(ctx, point, name, payload).ConfigureAwait(false);
            if (slow == null || slow.LatencyMs < threshold) continue;

            // Confirm: a matching zero-delay payload must be fast, and the slow payload must delay again.
            string control = shape.Replace("{D}", "0");
            var fast = await SendMutatedAsync(ctx, point, name, value + control).ConfigureAwait(false);
            if (fast == null || fast.LatencyMs >= threshold) continue;
            var slow2 = await SendMutatedAsync(ctx, point, name, payload).ConfigureAwait(false);
            if (slow2 == null || slow2.LatencyMs < threshold) continue;

            Report(ctx, point, Severity.Critical, "OS command injection (time-based)", 78,
                $"The parameter '{name}' of {point.Method} {point.Url.AbsolutePath} ({point.Origin}) injected a shell command: a benign delay command appended behind a shell separator made the server pause for ~{delaySec}s, while a zero-delay control of the same form returned immediately. " +
                "This confirms user input reaches an operating-system command, which allows arbitrary command execution on the server.",
                $"Payload in '{name}': {payload}\n" +
                $"Response times — injected: {slow.LatencyMs:0} ms and {slow2.LatencyMs:0} ms (delay {delaySec}s); zero-delay control: {fast.LatencyMs:0} ms; baseline: {normal:0} ms.",
                "Do not pass user input to a shell or OS command. Call programs with an argument array (no shell), validate against a strict allow-list, and drop shell metacharacters. Run with least privilege.",
                name);
            return true;
        }
        return false;
    }

    /// <summary>Benign time-delay payloads for both Unix (sleep) and Windows (ping -n) behind the usual separators.</summary>
    private static IEnumerable<(string Payload, string Shape)> CommandPayloads(string value, int delaySec)
    {
        // ping -n N waits ~N-1 seconds on Windows, so request delaySec+1 pings.
        string[] shapes =
        {
            ";sleep {D}", "|sleep {D}", "||sleep {D}", "&&sleep {D}", "`sleep {D}`", "$(sleep {D})", "\nsleep {D}",
            $"&ping -n {{D}} 127.0.0.1", $"|ping -n {{D}} 127.0.0.1",
        };
        foreach (var shape in shapes)
        {
            bool isPing = shape.Contains("ping", StringComparison.Ordinal);
            string filled = shape.Replace("{D}", (isPing ? delaySec + 1 : delaySec).ToString());
            // The shape used for the zero-delay control substitutes {D}=0 (sleep 0 / ping -n 1 ≈ instant).
            string controlShape = isPing ? shape.Replace("{D}", "1") : shape;
            yield return (value + filled, controlShape);
        }
    }

    // ------------------------------------------------------------------ server-side request forgery (SSRF)

    /// <summary>
    /// Conservative SSRF detection: for parameters that carry or name a URL, the value is pointed at cloud instance
    /// metadata endpoints and a finding is raised only when a metadata signature appears in the response, which is a
    /// high-confidence indication that the server fetched the attacker-controlled URL. (Blind SSRF without a metadata
    /// service needs an out-of-band collaborator and is out of scope.)
    /// </summary>
    private static async Task<bool> SsrfAsync(ScanContext ctx, InjectionPoint point, string name, string value)
    {
        bool candidate = SsrfNameRegex().IsMatch(name)
            || value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase);
        if (!candidate) return false;

        foreach (string payload in new[]
                 {
                     "http://169.254.169.254/latest/meta-data/",
                     "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                     "http://metadata.google.internal/computeMetadata/v1/instance/",
                     "http://100.100.100.200/latest/meta-data/",
                 })
        {
            var resp = await SendMutatedAsync(ctx, point, name, payload, follow: true).ConfigureAwait(false);
            if (resp == null || resp.Body.Length == 0) continue;
            var m = MetadataRegex().Match(resp.Body);
            if (!m.Success) continue;

            Report(ctx, point, Severity.High, "Server-side request forgery (SSRF)", 918,
                $"The parameter '{name}' of {point.Method} {point.Url.AbsolutePath} ({point.Origin}) caused the server to fetch a URL supplied in the request and returned the response. " +
                "Pointing it at the cloud instance-metadata service returned metadata content, which an attacker can use to read instance metadata and, on many platforms, temporary cloud credentials, and to reach other internal services.",
                $"Payload in '{name}': {payload}\nResponse contained an instance-metadata signature: \"{Trim(m.Value)}\" (HTTP {resp.Status}).",
                "Do not fetch URLs built from user input. Use an allow-list of permitted hosts/schemes, resolve and pin the address, block link-local (169.254.0.0/16) and private ranges, and disable unused metadata endpoints or require IMDSv2.",
                name);
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ CORS misconfiguration (per URL)

    /// <summary>
    /// Sends an arbitrary <c>Origin</c> and checks whether the server reflects it in <c>Access-Control-Allow-Origin</c>,
    /// which lets any site read authenticated responses — most serious when credentials are also allowed.
    /// </summary>
    private static async Task<bool> CorsAsync(ScanContext ctx, InjectionPoint point)
    {
        const string evil = "https://tryz-cors-probe.example";
        var resp = await ctx.ProbeAsync(HttpMethod.Get, point.Url, follow: false,
            extraHeaders: new[] { ("Origin", evil) }).ConfigureAwait(false);
        if (resp == null) return false;
        string acao = resp.Header("Access-Control-Allow-Origin");
        if (acao.Length == 0) return false;
        bool reflectsEvil = acao.Equals(evil, StringComparison.OrdinalIgnoreCase);
        bool nullOrigin = acao.Equals("null", StringComparison.OrdinalIgnoreCase);
        bool wildcard = acao == "*";
        bool creds = resp.Header("Access-Control-Allow-Credentials").Equals("true", StringComparison.OrdinalIgnoreCase);
        if (!reflectsEvil && !nullOrigin && !(wildcard && creds)) return false;

        var sev = (reflectsEvil || nullOrigin) && creds ? Severity.High : Severity.Medium;
        string why = reflectsEvil
            ? "the server reflected an arbitrary Origin into Access-Control-Allow-Origin"
            : nullOrigin ? "the server allows the \"null\" Origin (reachable from sandboxed iframes and local files)"
            : "the server returns Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true (an invalid, over-permissive combination)";
        ReportUrl(ctx, point, sev, "CORS misconfiguration", 942,
            $"The endpoint {point.Url.AbsolutePath} has a permissive cross-origin policy: {why}" +
            (creds ? ", and it also allows credentials, so a malicious site can read this origin's authenticated responses in a logged-in victim's browser." : ". A malicious site can read this origin's responses from a victim's browser."),
            $"Request header Origin: {evil}\nResponse: Access-Control-Allow-Origin: {acao}" + (creds ? "\nAccess-Control-Allow-Credentials: true" : ""),
            "Do not reflect the Origin header. Allow only an explicit allow-list of trusted origins, never combine a wildcard with credentials, and reject the \"null\" origin.");
        return true;
    }

    // ------------------------------------------------------------------ XML external entity (XXE, per URL)

    /// <summary>
    /// Posts an XML document declaring an external entity that references a local file and reports when the file content
    /// is reflected back. Endpoints that do not parse XML simply ignore the body, so this does not produce false
    /// positives. Attempted only where an XML body is plausible (POST points and API/XML/SOAP paths).
    /// </summary>
    private static async Task<bool> XxeAsync(ScanContext ctx, InjectionPoint point)
    {
        string path = point.Url.AbsolutePath.ToLowerInvariant();
        bool plausible = point.Method == "POST"
            || path.Contains("api", StringComparison.Ordinal) || path.Contains("xml", StringComparison.Ordinal)
            || path.Contains("soap", StringComparison.Ordinal) || path.Contains("upload", StringComparison.Ordinal);
        if (!plausible) return false;

        foreach (var (file, windows) in new[]
                 {
                     ("file:///etc/passwd", false),
                     ("file:///c:/windows/win.ini", true),
                 })
        {
            string xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                         $"<!DOCTYPE tz [<!ENTITY xxe SYSTEM \"{file}\">]>\n<tz>&xxe;</tz>";
            using var content = new StringContent(xml, Encoding.UTF8, "application/xml");
            var resp = await ctx.ProbeAsync(HttpMethod.Post, point.Url, follow: false, content: content).ConfigureAwait(false);
            if (resp == null || resp.Body.Length == 0) continue;
            bool hit = windows
                ? resp.Body.Contains("[extensions]", StringComparison.OrdinalIgnoreCase) && resp.Body.Contains("[fonts]", StringComparison.OrdinalIgnoreCase)
                : UnixPasswdRegex().IsMatch(resp.Body);
            if (!hit) continue;

            ReportUrl(ctx, point, Severity.Critical, "XML external entity (XXE) injection", 611,
                $"The endpoint {point.Url.AbsolutePath} parses posted XML and resolves external entities: a document declaring an entity that reads {file} returned the file's contents. " +
                "This allows reading arbitrary server files and can be leveraged for SSRF and denial of service.",
                $"Posted XML with an external entity referencing {file}; the response contained that file's contents.",
                "Disable DTDs and external entity resolution in the XML parser (set it to not process DOCTYPE/external entities). Prefer a parser configured as non-validating with external entities turned off.");
            return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ helpers

    /// <summary>Reports a finding tied to an endpoint rather than a single parameter (CORS, XXE).</summary>
    private static void ReportUrl(ScanContext ctx, InjectionPoint point, Severity sev, string title, int cwe,
        string description, string evidence, string remediation) =>
        ctx.AddFinding(sev, $"{title}: {point.Url.AbsolutePath}", point.HostIp, point.Port, cwe,
            description, evidence, remediation,
            new FindingDetails { RuleId = $"active-{FindingDetails.Slug(title)}" });

    [GeneratedRegex(@"^(url|uri|link|src|source|path|file|page|feed|host|domain|server|site|callback|webhook|hook|proxy|fetch|load|open|image|img|avatar|photo|icon|dest|destination|redirect|redir|target|resource|ref|data|u|q)$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SsrfNameRegex();

    // Signatures returned by the AWS/GCP/Alibaba instance-metadata services.
    [GeneratedRegex(@"ami-id|instance-id|instance-type|security-credentials|iam/|public-keys|computeMetadata|Metadata-Flavor|placement/|local-hostname|reservation-id",
        RegexOptions.CultureInvariant, 150)]
    private static partial Regex MetadataRegex();
}
