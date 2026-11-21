using TryZ.Data;

namespace TryZ.Engine;

internal enum PortSelection { Top100, Top1000, All, Web }

/// <summary>Immutable per-run settings. Built from <see cref="AppSettings"/> plus the toolbar profile and thread count.</summary>
internal sealed class ScanOptions
{
    public static readonly string[] ProfileNames = { "Quick Audit", "Full Audit", "Web Only", "Custom" };

    public int ProfileIndex { get; init; } = 1;
    public int Threads { get; init; } = 32;
    public PortSelection Ports { get; init; } = PortSelection.Top1000;
    public int ConnectTimeoutMs { get; init; } = 1500;
    public int ReadTimeoutMs { get; init; } = 4000;
    public int MaxRequestsPerSecond { get; init; } = 400;
    public int Retries { get; init; } = 1;
    public bool AutoBackoff { get; init; } = true;
    public IReadOnlyList<string> Exclusions { get; init; } = Array.Empty<string>();
    /// <summary>Skip liveness checks and treat every address as up (like nmap -Pn).</summary>
    public bool AssumeUp { get; init; }
    public bool RunCrawler { get; init; } = true;
    public int CrawlMaxPages { get; init; } = 2000;
    public int CrawlMaxDepth { get; init; } = 6;
    public bool RespectRobots { get; init; } = true;
    public bool RunWebChecks { get; init; } = true;
    public bool RunTlsChecks { get; init; } = true;
    public bool EnableNvd { get; init; }
    public string NvdApiKey { get; init; } = string.Empty;
    /// <summary>Probe common UDP services (DNS, SNMP, NTP, SSDP, ...) after the TCP sweep.</summary>
    public bool RunUdpScan { get; init; }
    /// <summary>Annotate CVE findings with CISA KEV and FIRST EPSS data.</summary>
    public bool EnableThreatIntel { get; init; }
    /// <summary>Check DNS names seen during the scan for dangling CNAMEs (subdomain takeover).</summary>
    public bool CheckTakeover { get; init; }
    /// <summary>Load additional rule files (*.json, *.yaml) from <see cref="RulesDirectory"/>.</summary>
    public bool UseCustomRules { get; init; }
    public string RulesDirectory { get; init; } = string.Empty;
    public string UserAgent { get; init; } = "TryZ-Scanner/1.0 (+authorized security assessment)";

    // ---- authenticated scanning -------------------------------------------------------------
    /// <summary>Cookie header sent with every HTTP request (e.g. "session=abc; csrf=def"), for scanning behind a login.</summary>
    public string SessionCookie { get; init; } = string.Empty;
    /// <summary>Extra request headers as "Name: value" lines, sent with every HTTP request.</summary>
    public IReadOnlyList<string> ExtraHeaders { get; init; } = Array.Empty<string>();
    /// <summary>Optional Authorization header value, e.g. "Bearer eyJ..." or "Basic dXNlcjpwYXNz".</summary>
    public string AuthorizationHeader { get; init; } = string.Empty;
    /// <summary>When set with <see cref="BasicPassword"/>, adds an HTTP Basic Authorization header.</summary>
    public string BasicUser { get; init; } = string.Empty;
    public string BasicPassword { get; init; } = string.Empty;

    // ---- upstream proxy (Burp / ZAP / corporate) --------------------------------------------
    /// <summary>Route all HTTP(S) requests through this proxy, e.g. "http://127.0.0.1:8080". Empty = direct.</summary>
    public string HttpProxy { get; init; } = string.Empty;

    // ---- active (intrusive) web testing -----------------------------------------------------
    /// <summary>Run active injection checks (reflected XSS, SQLi, path traversal, open redirect) on discovered parameters.</summary>
    public bool RunActiveChecks { get; init; }
    /// <summary>Hard cap on the number of parameters actively fuzzed, to bound request volume.</summary>
    public int MaxActiveTargets { get; init; } = 400;

    // ---- content & name discovery -----------------------------------------------------------
    /// <summary>Dictionary-based discovery of unlinked paths (admin panels, backups, API roots).</summary>
    public bool RunContentDiscovery { get; init; }
    /// <summary>DNS enumeration of common sub-domains of in-scope names (feeds the crawl and takeover check).</summary>
    public bool RunSubdomainScan { get; init; }
    /// <summary>Optional file of extra wordlist entries for content discovery, one per line.</summary>
    public string WordlistPath { get; init; } = string.Empty;

    public static ScanOptions From(AppSettings s, int profileIndex, int threads)
    {
        var custom = (PortSelection)Math.Clamp(s.CustomPortSelection, 0, 2);
        return profileIndex switch
        {
            0 => Build(s, profileIndex, threads, PortSelection.Top100, crawlPages: Math.Min(200, s.CrawlMaxPages), nvd: false, udp: s.UdpScan),
            2 => Build(s, profileIndex, threads, PortSelection.Web, crawlPages: s.CrawlMaxPages, nvd: s.EnableNvd, udp: false),
            3 => Build(s, profileIndex, threads, custom, crawlPages: s.CrawlMaxPages, nvd: s.EnableNvd, udp: s.UdpScan),
            _ => Build(s, 1, threads, PortSelection.Top1000, crawlPages: s.CrawlMaxPages, nvd: s.EnableNvd, udp: s.UdpScan),
        };
    }

    /// <summary>Folder searched for user rule files when <see cref="AppSettings.RulesDirectory"/> is empty.</summary>
    public static string DefaultRulesDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TryZ", "rules");

    private static ScanOptions Build(AppSettings s, int profile, int threads, PortSelection ports, int crawlPages, bool nvd, bool udp) => new()
    {
        ProfileIndex = profile,
        Threads = Math.Clamp(threads, 1, 512),
        Ports = ports,
        ConnectTimeoutMs = Math.Clamp(s.ConnectTimeoutMs, 100, 30000),
        ReadTimeoutMs = Math.Clamp(s.ReadTimeoutMs, 100, 60000),
        MaxRequestsPerSecond = Math.Clamp(s.MaxRequestsPerSecond, 1, 5000),
        Retries = Math.Clamp(s.Retries, 0, 8),
        AutoBackoff = s.AutoBackoff,
        Exclusions = s.Exclusions.ToArray(),
        AssumeUp = s.AssumeHostsUp,
        RunCrawler = true,
        CrawlMaxPages = Math.Clamp(crawlPages, 1, 100_000),
        CrawlMaxDepth = Math.Clamp(s.CrawlMaxDepth, 1, 50),
        RespectRobots = s.RespectRobots,
        RunWebChecks = true,
        RunTlsChecks = true,
        EnableNvd = nvd,
        NvdApiKey = s.NvdApiKey ?? string.Empty,
        RunUdpScan = udp,
        EnableThreatIntel = s.EnableThreatIntel,
        CheckTakeover = s.CheckTakeover,
        UseCustomRules = s.UseCustomRules,
        RulesDirectory = string.IsNullOrWhiteSpace(s.RulesDirectory) ? DefaultRulesDirectory : s.RulesDirectory.Trim(),
        UserAgent = string.IsNullOrWhiteSpace(s.UserAgent) ? "TryZ-Scanner/1.0 (+authorized security assessment)" : s.UserAgent,
        SessionCookie = s.SessionCookie?.Trim() ?? string.Empty,
        ExtraHeaders = (s.ExtraHeaders ?? new()).Where(h => h.Contains(':')).ToArray(),
        AuthorizationHeader = s.AuthorizationHeader?.Trim() ?? string.Empty,
        BasicUser = s.BasicUser?.Trim() ?? string.Empty,
        BasicPassword = s.BasicPassword ?? string.Empty,
        HttpProxy = s.HttpProxy?.Trim() ?? string.Empty,
        // Active checks are intrusive: only the Full and Custom profiles run them, and only when enabled in settings.
        RunActiveChecks = s.RunActiveChecks && profile is 1 or 3,
        MaxActiveTargets = Math.Clamp(s.MaxActiveTargets, 1, 5000),
        RunContentDiscovery = s.RunContentDiscovery && profile != 0,
        RunSubdomainScan = s.RunSubdomainScan,
        WordlistPath = s.WordlistPath?.Trim() ?? string.Empty,
    };
}
