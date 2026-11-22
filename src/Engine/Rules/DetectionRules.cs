using System.Diagnostics;
using System.Net.Http;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using TryZ.Data;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace TryZ.Engine;

/// <summary>Optional, read-only HTTP detection rules loaded once per scan.</summary>
internal static class DetectionRules
{
    private const int MaxFiles = 256, MaxFileBytes = 64 * 1024, MaxBodyBytes = 256 * 1024;
    private static readonly ConditionalWeakTable<ScanContext, RuleSet> Sets = new();
    private sealed class RuleSet { public List<Rule> Rules { get; } = new(); }
    private sealed record Rule(Definition Spec, Severity Severity, Regex? BodyRegex, Regex? HeaderRegex);

    // One rule per file. The public setters are required by the YAML and JSON serializers.
    public sealed class Definition
    {
        public string Id { get; set; } = "";
        public string Name { get; set; } = "";
        public string Severity { get; set; } = "Info";
        public int Cwe { get; set; }
        public string Description { get; set; } = "";
        public string Remediation { get; set; } = "";
        public string Method { get; set; } = "GET";
        public string Path { get; set; } = "/";
        public int? Status { get; set; }
        public string BodyContains { get; set; } = "";
        public string BodyRegex { get; set; } = "";
        public string HeaderName { get; set; } = "";
        public string HeaderContains { get; set; } = "";
        public string HeaderRegex { get; set; } = "";
    }

    public static async Task LoadAsync(ScanContext ctx)
    {
        var set = Sets.GetOrCreateValue(ctx);
        if (!ctx.Options.UseCustomRules) return;
        string dir = ctx.Options.RulesDirectory;
        if (string.IsNullOrWhiteSpace(dir)) dir = ScanOptions.DefaultRulesDirectory;
        if (!Directory.Exists(dir))
        {
            ctx.Log(LogLevel.Warn, "rules", $"Custom rules folder does not exist: {dir}");
            return;
        }
        string[] files;
        try
        {
            files = Directory.EnumerateFiles(dir).Where(p => new[] { ".json", ".yaml", ".yml" }.Contains(Path.GetExtension(p), StringComparer.OrdinalIgnoreCase))
                .OrderBy(p => p, StringComparer.OrdinalIgnoreCase).Take(MaxFiles + 1).ToArray();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            ctx.Log(LogLevel.Warn, "rules", $"Cannot read rules folder: {ex.Message}");
            return;
        }
        if (files.Length > MaxFiles) ctx.Log(LogLevel.Warn, "rules", $"Only the first {MaxFiles} rule files will be loaded.");
        var ids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var yaml = new DeserializerBuilder().WithNamingConvention(CamelCaseNamingConvention.Instance).Build();
        var json = new JsonSerializerOptions { PropertyNameCaseInsensitive = true, UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow };
        foreach (string file in files.Take(MaxFiles))
        {
            ctx.Token.ThrowIfCancellationRequested();
            try
            {
                if (new FileInfo(file).Length > MaxFileBytes) throw new InvalidDataException("file exceeds 64 KB");
                string text = await File.ReadAllTextAsync(file, ctx.Token).ConfigureAwait(false);
                var def = Path.GetExtension(file).Equals(".json", StringComparison.OrdinalIgnoreCase)
                    ? JsonSerializer.Deserialize<Definition>(text, json) : yaml.Deserialize<Definition>(text);
                var rule = Validate(def ?? throw new InvalidDataException("empty rule"));
                if (!ids.Add(rule.Spec.Id)) throw new InvalidDataException("duplicate rule id");
                set.Rules.Add(rule);
            }
            catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException or YamlDotNet.Core.YamlException or ArgumentException or InvalidDataException or NotSupportedException)
            {
                ctx.Log(LogLevel.Warn, "rules", $"Skipped {Path.GetFileName(file)}: {ex.Message}");
            }
        }
        ctx.Log(LogLevel.Info, "rules", $"Loaded {set.Rules.Count} custom HTTP rule(s) from {dir}");
    }

    private static Rule Validate(Definition d)
    {
        // Explicitly reject nulls, which can be supplied by either serializer.
        if (d.Id == null || d.Name == null || d.Severity == null || d.Description == null || d.Remediation == null || d.Method == null || d.Path == null || d.BodyContains == null || d.BodyRegex == null || d.HeaderName == null || d.HeaderContains == null || d.HeaderRegex == null)
            throw new InvalidDataException("fields cannot be null");
        if (!Regex.IsMatch(d.Id, @"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")) throw new InvalidDataException("id must be 1–64 letters, digits, dots, underscores or hyphens");
        if (string.IsNullOrWhiteSpace(d.Name) || d.Name.Length > 160 || string.IsNullOrWhiteSpace(d.Description) || string.IsNullOrWhiteSpace(d.Remediation)) throw new InvalidDataException("name, description and remediation are required");
        if (!Enum.TryParse<Severity>(d.Severity, true, out var severity) || !Enum.IsDefined(severity)) throw new InvalidDataException("invalid severity");
        if (d.Cwe is < 0 or > 99999 || d.Status is < 100 or > 599) throw new InvalidDataException("invalid CWE or status");
        d.Method = d.Method.ToUpperInvariant();
        if (d.Method is not ("GET" or "HEAD")) throw new InvalidDataException("only GET and HEAD are supported");
        if (!d.Path.StartsWith('/') || d.Path.StartsWith("//") || d.Path.Contains('\\') || d.Path.Contains('#') || d.Path.Any(char.IsControl) || d.Path.Length > 2048) throw new InvalidDataException("path must be a same-origin absolute path");
        bool body = d.BodyContains.Length > 0 || d.BodyRegex.Length > 0;
        bool header = d.HeaderContains.Length > 0 || d.HeaderRegex.Length > 0;
        if (!body && !header) throw new InvalidDataException("a body or header matcher is required");
        if (body && d.Method == "HEAD") throw new InvalidDataException("HEAD cannot match a body");
        if (header && (string.IsNullOrWhiteSpace(d.HeaderName) || d.HeaderName.Any(c => !(char.IsAsciiLetterOrDigit(c) || c == '-')))) throw new InvalidDataException("headerName is required and must be a valid header name");
        if (!header && d.HeaderName.Length > 0) throw new InvalidDataException("headerName needs a header matcher");
        if (new[] { d.BodyContains, d.BodyRegex, d.HeaderContains, d.HeaderRegex }.Any(s => s.Length > 4096)) throw new InvalidDataException("matcher exceeds 4096 characters");
        Regex? Compile(string pattern) => pattern.Length == 0 ? null : new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
        return new Rule(d, severity, Compile(d.BodyRegex), Compile(d.HeaderRegex));
    }

    public static async Task RunHttpRulesAsync(ScanContext ctx, OpenService svc)
    {
        if (!Sets.TryGetValue(ctx, out var set) || set.Rules.Count == 0) return;
        Uri origin;
        try { origin = new UriBuilder(svc.Scheme, svc.Host.UrlHost, svc.Port).Uri; }
        catch (UriFormatException ex) { ctx.Log(LogLevel.Warn, "rules", $"Invalid target URL: {ex.Message}"); return; }
        foreach (var rule in set.Rules)
        {
            ctx.Token.ThrowIfCancellationRequested();
            Uri uri;
            try { uri = new Uri(origin, rule.Spec.Path); }
            catch (UriFormatException) { continue; }
            if (!uri.Scheme.Equals(origin.Scheme, StringComparison.OrdinalIgnoreCase) || !uri.Host.Equals(origin.Host, StringComparison.OrdinalIgnoreCase) || uri.Port != origin.Port) continue;
            await ctx.GateAsync().ConfigureAwait(false);
            await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
            using var work = ctx.BeginWork();
            var sw = Stopwatch.StartNew();
            bool error = true;
            try
            {
                using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
                timeout.CancelAfter(ctx.Options.ConnectTimeoutMs + ctx.Options.ReadTimeoutMs);
                using var request = new HttpRequestMessage(new HttpMethod(rule.Spec.Method), uri);
                using var response = await ctx.Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
                error = (int)response.StatusCode >= 500;
                if (rule.Spec.Status is int status && (int)response.StatusCode != status) continue;
                string header = "";
                if (rule.Spec.HeaderName.Length > 0)
                {
                    if (!response.Headers.TryGetValues(rule.Spec.HeaderName, out var values) && !response.Content.Headers.TryGetValues(rule.Spec.HeaderName, out values)) continue;
                    header = string.Join(", ", values).Substring(0, Math.Min(string.Join(", ", values).Length, MaxBodyBytes));
                }
                string body = "";
                if (rule.Spec.BodyContains.Length > 0 || rule.BodyRegex != null)
                {
                    using var stream = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
                    using var buffer = new MemoryStream();
                    byte[] chunk = new byte[8192];
                    while (buffer.Length < MaxBodyBytes)
                    {
                        int n = await stream.ReadAsync(chunk.AsMemory(0, (int)Math.Min(chunk.Length, MaxBodyBytes - buffer.Length)), timeout.Token).ConfigureAwait(false);
                        if (n == 0) break;
                        buffer.Write(chunk, 0, n);
                    }
                    body = Encoding.UTF8.GetString(buffer.ToArray());
                }
                bool match = (rule.Spec.BodyContains.Length == 0 || body.Contains(rule.Spec.BodyContains, StringComparison.OrdinalIgnoreCase))
                    && (rule.BodyRegex == null || rule.BodyRegex.IsMatch(body))
                    && (rule.Spec.HeaderContains.Length == 0 || header.Contains(rule.Spec.HeaderContains, StringComparison.OrdinalIgnoreCase))
                    && (rule.HeaderRegex == null || rule.HeaderRegex.IsMatch(header));
                if (match) ctx.AddFinding(rule.Severity, rule.Spec.Name, svc.Host.Ip, svc.Port, rule.Spec.Cwe, rule.Spec.Description,
                    $"{rule.Spec.Method} {uri} -> HTTP {(int)response.StatusCode}; matched custom rule {rule.Spec.Id}." + (rule.Spec.HeaderName.Length > 0 ? $" Header: {rule.Spec.HeaderName}." : ""),
                    rule.Spec.Remediation, new FindingDetails { RuleId = "custom." + rule.Spec.Id, Product = svc.DisplayBanner });
            }
            catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested) { throw; }
            catch (Exception ex) when (ex is HttpRequestException or IOException or OperationCanceledException or RegexMatchTimeoutException)
            {
                error = true;
                ctx.Log(LogLevel.Warn, "rules", $"Rule {rule.Spec.Id} failed on {uri}: {ex.Message}");
            }
            finally { ctx.CountRequest(sw.Elapsed.TotalMilliseconds, error); ctx.Concurrency.Release(); }
        }
    }
}
