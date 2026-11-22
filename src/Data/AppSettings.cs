using System.Text.Json;
using System.Text.Json.Serialization;

namespace TryZ.Data;

internal sealed class AppSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public int WindowX { get; set; } = int.MinValue;
    public int WindowY { get; set; } = int.MinValue;
    public int WindowWidth { get; set; }
    public int WindowHeight { get; set; }
    public bool Maximized { get; set; }
    public int LastModule { get; set; }
    public int DockHeight { get; set; } = 196;
    public bool DockVisible { get; set; } = true;
    public int DockTab { get; set; }
    public bool ShowSplash { get; set; } = true;
    public bool ConfirmStop { get; set; } = true;
    public bool LogAutoscroll { get; set; } = true;
    public bool LogDebug { get; set; } = true;
    /// <summary>Append every activity-log line to a dated file under %APPDATA%\TryZ\logs.</summary>
    public bool LogToFile { get; set; }
    public int DefaultThreads { get; set; } = 32;
    public int DefaultProfile { get; set; } = 1;
    public string LastTarget { get; set; } = "127.0.0.1";
    public string ReportAuthorLine { get; set; } = string.Empty;

    // Real scan engine settings
    public int CustomPortSelection { get; set; } = 1; // 0 top100, 1 top1000, 2 all
    public int ConnectTimeoutMs { get; set; } = 1500;
    public int ReadTimeoutMs { get; set; } = 4000;
    public int MaxRequestsPerSecond { get; set; } = 400;
    public int Retries { get; set; } = 1;
    public bool AutoBackoff { get; set; } = true;
    public bool AssumeHostsUp { get; set; }
    public List<string> Exclusions { get; set; } = new();
    public List<string> AuthorizedTargets { get; set; } = new();
    public int CrawlMaxPages { get; set; } = 2000;
    public int CrawlMaxDepth { get; set; } = 6;
    public bool RespectRobots { get; set; } = true;
    public bool EnableNvd { get; set; } = true;
    [JsonConverter(typeof(EncryptedStringConverter))]
    public string NvdApiKey { get; set; } = string.Empty;
    public bool UdpScan { get; set; } = true;
    public bool EnableThreatIntel { get; set; } = true;
    public bool CheckTakeover { get; set; } = true;
    public bool UseCustomRules { get; set; } = true;
    public string RulesDirectory { get; set; } = string.Empty;
    public string LastCompareBaseline { get; set; } = string.Empty;
    public string UserAgent { get; set; } = "TryZ-Scanner/1.0 (+authorized security assessment)";

    // Authenticated scanning. Secrets are encrypted at rest with the Windows DPAPI (see Secret / EncryptedStringConverter).
    [JsonConverter(typeof(EncryptedStringConverter))]
    public string SessionCookie { get; set; } = string.Empty;
    [JsonConverter(typeof(EncryptedStringListConverter))]
    public List<string> ExtraHeaders { get; set; } = new();
    [JsonConverter(typeof(EncryptedStringConverter))]
    public string AuthorizationHeader { get; set; } = string.Empty;
    public string BasicUser { get; set; } = string.Empty;
    [JsonConverter(typeof(EncryptedStringConverter))]
    public string BasicPassword { get; set; } = string.Empty;

    // Form-based login: the engine posts credentials, keeps the session cookie, and re-authenticates when it expires.
    public bool FormLoginEnabled { get; set; }
    public string LoginUrl { get; set; } = string.Empty;
    public string LoginUser { get; set; } = string.Empty;
    [JsonConverter(typeof(EncryptedStringConverter))]
    public string LoginPassword { get; set; } = string.Empty;
    public string LoginUserField { get; set; } = "username";
    public string LoginPassField { get; set; } = "password";
    /// <summary>Extra login form fields as "name=value&amp;name2=value2" (e.g. a fixed hidden field).</summary>
    public string LoginExtraData { get; set; } = string.Empty;
    /// <summary>Optional text whose presence in a response means the session is logged out (triggers re-login).</summary>
    public string LoginLoggedOutMarker { get; set; } = string.Empty;

    // Upstream proxy (Burp / ZAP)
    public string HttpProxy { get; set; } = string.Empty;

    // Active (intrusive) testing
    public bool RunActiveChecks { get; set; }
    public int MaxActiveTargets { get; set; } = 400;

    // Content & subdomain discovery
    public bool RunContentDiscovery { get; set; }
    public bool RunSubdomainScan { get; set; }
    public string WordlistPath { get; set; } = string.Empty;

    // Headless browser crawl (renders JavaScript apps via an installed Chromium browser over the DevTools protocol).
    public bool BrowserCrawl { get; set; }
    /// <summary>Optional explicit path to msedge.exe / chrome.exe; empty = auto-detect.</summary>
    public string BrowserPath { get; set; } = string.Empty;
    public int BrowserMaxPages { get; set; } = 40;

    // Alerting on new findings (used by headless / scheduled scans). Secrets are encrypted at rest.
    public bool AlertOnNewFindings { get; set; }
    /// <summary>Minimum severity (0 Info .. 4 Critical) that triggers an alert.</summary>
    public int AlertMinSeverity { get; set; } = 2; // Medium
    public string AlertWebhookUrl { get; set; } = string.Empty;
    public bool AlertEmailEnabled { get; set; }
    public string AlertEmailTo { get; set; } = string.Empty;
    public string AlertEmailFrom { get; set; } = string.Empty;
    public string AlertSmtpHost { get; set; } = string.Empty;
    public int AlertSmtpPort { get; set; } = 587;
    public bool AlertSmtpStartTls { get; set; } = true;
    public string AlertSmtpUser { get; set; } = string.Empty;
    [JsonConverter(typeof(EncryptedStringConverter))]
    public string AlertSmtpPassword { get; set; } = string.Empty;

    private static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TryZ", "settings.json");

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                var loaded = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
                loaded.LastTarget ??= "127.0.0.1";
                loaded.ReportAuthorLine ??= string.Empty;
                loaded.Exclusions ??= new();
                loaded.AuthorizedTargets ??= new();
                loaded.NvdApiKey ??= string.Empty;
                loaded.UserAgent ??= string.Empty;
                loaded.RulesDirectory ??= string.Empty;
                loaded.LastCompareBaseline ??= string.Empty;
                loaded.SessionCookie ??= string.Empty;
                loaded.ExtraHeaders ??= new();
                loaded.AuthorizationHeader ??= string.Empty;
                loaded.BasicUser ??= string.Empty;
                loaded.BasicPassword ??= string.Empty;
                loaded.HttpProxy ??= string.Empty;
                loaded.WordlistPath ??= string.Empty;
                loaded.LoginUrl ??= string.Empty;
                loaded.LoginUser ??= string.Empty;
                loaded.LoginPassword ??= string.Empty;
                loaded.LoginUserField ??= "username";
                loaded.LoginPassField ??= "password";
                loaded.LoginExtraData ??= string.Empty;
                loaded.LoginLoggedOutMarker ??= string.Empty;
                loaded.BrowserPath ??= string.Empty;
                loaded.AlertWebhookUrl ??= string.Empty;
                loaded.AlertEmailTo ??= string.Empty;
                loaded.AlertEmailFrom ??= string.Empty;
                loaded.AlertSmtpHost ??= string.Empty;
                loaded.AlertSmtpUser ??= string.Empty;
                loaded.AlertSmtpPassword ??= string.Empty;
                return loaded;
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException or NotSupportedException)
        {
        }
        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
            string temp = FilePath + ".tmp";
            File.WriteAllText(temp, JsonSerializer.Serialize(this, JsonOptions));
            File.Move(temp, FilePath, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
