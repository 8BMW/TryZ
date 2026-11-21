using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Adds CISA KEV and FIRST EPSS data to findings that carry CVE identifiers.</summary>
internal static class ThreatIntel
{
    private const string KevUrl = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    private const string EpssUrl = "https://api.first.org/data/v1/epss?cve=";
    private const int MaxCves = 1000, MaxResponseBytes = 16 * 1024 * 1024;
    private static readonly Regex CvePattern = new(@"^CVE-\d{4}-\d{4,}$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(100));
    private static readonly object CacheLock = new();
    private static Dictionary<string, KevEntry>? _cachedKev;
    private static DateTimeOffset _cachedAt;
    private sealed record KevEntry(string Id, DateOnly? Added, DateOnly? Due, bool Ransomware, string Action);
    private sealed record Score(double Probability, double? Percentile);

    public static async Task EnrichAsync(ScanContext ctx)
    {
        if (!ctx.Options.EnableThreatIntel) return;
        using var http = new HttpClient(new SocketsHttpHandler { AutomaticDecompression = DecompressionMethods.All, ConnectTimeout = TimeSpan.FromSeconds(15), MaxAutomaticRedirections = 3 })
        { Timeout = TimeSpan.FromSeconds(40) };
        http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "TryZ-Scanner/1.0");
        await EnrichAsync(ctx, http, useCache: true).ConfigureAwait(false);
    }

    internal static async Task EnrichAsync(ScanContext ctx, HttpClient http, bool useCache = false)
    {
        if (!ctx.Options.EnableThreatIntel) return;
        var findings = ctx.FindingsSnapshot();
        var ids = findings.SelectMany(f => f.Cves).Where(id => id is { Length: <= 32 } && CvePattern.IsMatch(id))
            .Select(id => id.ToUpperInvariant()).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(id => id, StringComparer.Ordinal).ToList();
        if (ids.Count == 0) return;
        if (ids.Count > MaxCves)
        {
            ctx.Log(LogLevel.Warn, "intel", $"EPSS lookup limited to {MaxCves} of {ids.Count} CVEs");
        }
        Dictionary<string, KevEntry>? kev = null;
        bool kevAvailable = false;
        try
        {
            if (useCache)
            {
                lock (CacheLock)
                    if (_cachedKev != null && DateTimeOffset.UtcNow >= _cachedAt && DateTimeOffset.UtcNow - _cachedAt < TimeSpan.FromHours(24)) kev = _cachedKev;
            }
            if (kev == null)
            {
                using var doc = await FetchAsync(ctx, http, KevUrl).ConfigureAwait(false);
                if (!doc.RootElement.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array || vulns.GetArrayLength() == 0)
                    throw new InvalidDataException("Invalid CISA KEV catalog");
                kev = new Dictionary<string, KevEntry>(StringComparer.OrdinalIgnoreCase);
                foreach (var item in vulns.EnumerateArray())
                {
                    string id = Str(item, "cveID");
                    if (id.Length > 32 || !CvePattern.IsMatch(id)) continue;
                    kev[id] = new KevEntry(id, Date(Str(item, "dateAdded")), Date(Str(item, "dueDate")),
                        Str(item, "knownRansomwareCampaignUse").Equals("Known", StringComparison.OrdinalIgnoreCase), Str(item, "requiredAction"));
                }
                if (kev.Count == 0) throw new InvalidDataException("CISA KEV catalog contains no valid CVEs");
                if (useCache) lock (CacheLock) { _cachedKev = kev; _cachedAt = DateTimeOffset.UtcNow; }
            }
            kevAvailable = true;
        }
        catch (Exception ex) when (Recoverable(ex, ctx.Token)) { ctx.Log(LogLevel.Warn, "intel", $"CISA KEV unavailable: {ex.Message}"); }

        var scores = new Dictionary<string, Score>(StringComparer.OrdinalIgnoreCase);
        var limited = ids.Take(MaxCves).ToArray();
        int errors = 0;
        // FIRST accepts a maximum of 2000 characters in the comma-separated CVE parameter.
        for (int start = 0; start < limited.Length;)
        {
            var batch = new List<string>();
            int chars = 0;
            while (start < limited.Length && batch.Count < 100 && chars + limited[start].Length + (batch.Count == 0 ? 0 : 1) <= 1900)
            {
                chars += limited[start].Length + (batch.Count == 0 ? 0 : 1);
                batch.Add(limited[start++]);
            }
            if (batch.Count == 0) { start++; continue; }
            try
            {
                using var doc = await FetchAsync(ctx, http, EpssUrl + string.Join(",", batch)).ConfigureAwait(false);
                if (!doc.RootElement.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Array)
                    throw new InvalidDataException("Invalid FIRST EPSS response");
                foreach (var item in data.EnumerateArray())
                {
                    string id = Str(item, "cve");
                    if (!batch.Contains(id, StringComparer.OrdinalIgnoreCase) || !Number(item, "epss", out double probability)) continue;
                    double? percentile = Number(item, "percentile", out double p) ? p : null;
                    scores[id] = new Score(probability, percentile);
                }
            }
            catch (Exception ex) when (Recoverable(ex, ctx.Token))
            {
                errors++;
                ctx.Log(LogLevel.Warn, "intel", $"FIRST EPSS batch failed: {ex.Message}");
            }
        }
        if (!kevAvailable)
        {
            // The model has no unknown KEV state: do not report unavailable data as a negative result.
            ctx.Log(LogLevel.Warn, "intel", "Enrichment was not attached because KEV status is unavailable");
            return;
        }
        int enriched = 0, known = 0;
        foreach (var finding in findings)
        {
            ctx.Token.ThrowIfCancellationRequested();
            var match = finding.Cves.Where(kev!.ContainsKey).Select(id => kev![id]).OrderBy(e => e.Due ?? DateOnly.MaxValue).FirstOrDefault();
            var score = finding.Cves.Where(scores.ContainsKey).Select(id => scores[id]).OrderByDescending(s => s.Probability).FirstOrDefault();
            // Avoid representing CVEs omitted by the EPSS cap as having been checked for EPSS.
            if (match is null && score is null) continue;
            var info = new ThreatInfo { Kev = match != null, KevCve = match?.Id ?? string.Empty, KevDateAdded = match?.Added,
                KevDueDate = match?.Due, KevRansomware = match?.Ransomware ?? false, KevAction = match?.Action ?? string.Empty,
                Epss = score?.Probability, EpssPercentile = score?.Percentile };
            ctx.Emit(new FindingEnriched(finding.Id, null, null, info));
            enriched++;
            if (match != null) known++;
        }
        ctx.Log(errors > 0 ? LogLevel.Warn : LogLevel.Ok, "intel", $"CISA KEV / FIRST EPSS: enriched {enriched} finding(s), {known} in KEV; EPSS returned {scores.Count} score(s){(errors > 0 ? $", {errors} batch(es) failed" : string.Empty)}");
    }

    private static async Task<JsonDocument> FetchAsync(ScanContext ctx, HttpClient http, string url)
    {
        await ctx.GateAsync().ConfigureAwait(false);
        await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
        var sw = Stopwatch.StartNew();
        bool error = false;
        try
        {
            using var work = ctx.BeginWork();
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(40));
            using var response = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            if (response.Content.Headers.ContentLength > MaxResponseBytes) throw new InvalidDataException("Response exceeds size limit");
            await using var input = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[16384];
            while (true)
            {
                int count = await input.ReadAsync(chunk, timeout.Token).ConfigureAwait(false);
                if (count == 0) break;
                if (buffer.Length + count > MaxResponseBytes) throw new InvalidDataException("Response exceeds size limit");
                buffer.Write(chunk, 0, count);
            }
            buffer.Position = 0;
            return await JsonDocument.ParseAsync(buffer, cancellationToken: timeout.Token).ConfigureAwait(false);
        }
        catch { error = true; throw; }
        finally { ctx.CountRequest(sw.Elapsed.TotalMilliseconds, error); ctx.Concurrency.Release(); }
    }

    private static bool Recoverable(Exception ex, CancellationToken token) => !token.IsCancellationRequested &&
        ex is HttpRequestException or IOException or JsonException or OperationCanceledException;
    private static string Str(JsonElement item, string name) => item.ValueKind == JsonValueKind.Object && item.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String ? value.GetString() ?? string.Empty : string.Empty;
    private static DateOnly? Date(string value) => DateOnly.TryParseExact(value, "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date) ? date : null;
    private static bool Number(JsonElement item, string name, out double number)
    {
        number = 0;
        if (item.ValueKind != JsonValueKind.Object || !item.TryGetProperty(name, out var value)) return false;
        bool valid = value.ValueKind == JsonValueKind.Number ? value.TryGetDouble(out number) :
            value.ValueKind == JsonValueKind.String && double.TryParse(value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out number);
        return valid && double.IsFinite(number) && number >= 0 && number <= 1;
    }
}
