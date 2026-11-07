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
    public string UserAgent { get; init; } = "TryZ-Scanner/1.0 (+authorized security assessment)";

    public static ScanOptions From(AppSettings s, int profileIndex, int threads)
    {
        var custom = (PortSelection)Math.Clamp(s.CustomPortSelection, 0, 2);
        return profileIndex switch
        {
            0 => Build(s, profileIndex, threads, PortSelection.Top100, crawlPages: Math.Min(200, s.CrawlMaxPages), nvd: false),
            2 => Build(s, profileIndex, threads, PortSelection.Web, crawlPages: s.CrawlMaxPages, nvd: s.EnableNvd),
            3 => Build(s, profileIndex, threads, custom, crawlPages: s.CrawlMaxPages, nvd: s.EnableNvd),
            _ => Build(s, 1, threads, PortSelection.Top1000, crawlPages: s.CrawlMaxPages, nvd: s.EnableNvd),
        };
    }

    private static ScanOptions Build(AppSettings s, int profile, int threads, PortSelection ports, int crawlPages, bool nvd) => new()
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
        UserAgent = string.IsNullOrWhiteSpace(s.UserAgent) ? "TryZ-Scanner/1.0 (+authorized security assessment)" : s.UserAgent,
    };
}
