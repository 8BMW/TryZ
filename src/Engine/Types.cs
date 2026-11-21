using System.Net;
using System.Security.Cryptography.X509Certificates;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>One address to scan. Hostname is the name the user typed (or empty); SeedUrl is set when the user typed a URL.</summary>
internal sealed record ScanTarget(IPAddress Address, string Hostname, Uri? SeedUrl)
{
    /// <summary>Further names / URLs the user typed that resolve to this same address (virtual hosts).</summary>
    public IReadOnlyList<HostAlias> Aliases { get; init; } = Array.Empty<HostAlias>();
}

/// <summary>An additional user-supplied name (and optional seed URL) for an address that is already a target.</summary>
internal sealed record HostAlias(string Name, Uri? SeedUrl);

/// <summary>A host that answered discovery (or every target when AssumeUp is set).</summary>
internal sealed class LiveHost
{
    public required IPAddress Address { get; init; }
    public string Ip => Address.ToString();
    /// <summary>Name to use for Host headers, SNI and display: typed name, else reverse DNS, else the IP.</summary>
    public required string Hostname { get; init; }
    public Uri? SeedUrl { get; init; }
    /// <summary>Other user-supplied names / seed URLs for this address; their web content is audited as separate virtual hosts.</summary>
    public IReadOnlyList<HostAlias> Aliases { get; init; } = Array.Empty<HostAlias>();
    public int LatencyMs { get; init; }
    public int Ttl { get; init; }
    public string OsGuess { get; init; } = "Unknown";
}

/// <summary>An open TCP port after service identification.</summary>
internal sealed class OpenService
{
    public required LiveHost Host { get; init; }
    public required int Port { get; init; }
    /// <summary>"tcp" or "udp".</summary>
    public string Proto { get; init; } = "tcp";
    /// <summary>Short service name, e.g. "ssh", "http", "https", "smtp", "mysql", "rdp", "unknown".</summary>
    public string Service { get; set; } = "unknown";
    /// <summary>Product name when identified, e.g. "OpenSSH", "nginx", "Apache httpd", "Microsoft IIS".</summary>
    public string Product { get; set; } = string.Empty;
    /// <summary>Version string when identified, e.g. "8.9p1", "1.18.0".</summary>
    public string Version { get; set; } = string.Empty;
    /// <summary>Raw first line(s) of the banner or response, printable characters only, max ~200 chars.</summary>
    public string Banner { get; set; } = string.Empty;
    /// <summary>True if the port speaks TLS (TLS handshake succeeded).</summary>
    public bool Tls { get; set; }
    /// <summary>True if the port speaks HTTP (plain or over TLS).</summary>
    public bool Http { get; set; }
    /// <summary>Server certificate captured during identification, if TLS.</summary>
    public X509Certificate2? Certificate { get; set; }
    /// <summary>Extra protocol facts collected while probing (e.g. "ftp.anonymous"="true", "http.server"="nginx/1.18.0").</summary>
    public Dictionary<string, string> Facts { get; } = new(StringComparer.OrdinalIgnoreCase);

    public string DisplayBanner => Product.Length > 0
        ? (Version.Length > 0 ? $"{Product} {Version}" : Product)
        : Banner;

    public string Scheme => Tls ? "https" : "http";
}

/// <summary>
/// A parameterised request the crawler found and the active audit can fuzz: either a GET URL carrying a query string,
/// or an HTML form (GET or POST) with its action and field names. Values captured are only samples to echo back.
/// </summary>
internal sealed class InjectionPoint
{
    /// <summary>"GET" or "POST".</summary>
    public required string Method { get; init; }
    /// <summary>Absolute request URL (for GET, without the query; for POST, the form action).</summary>
    public required Uri Url { get; init; }
    /// <summary>Host IP the request is pinned to, for finding attribution.</summary>
    public required string HostIp { get; init; }
    public required int Port { get; init; }
    /// <summary>Parameter name → sample value, in discovery order.</summary>
    public required IReadOnlyList<KeyValuePair<string, string>> Parameters { get; init; }
    /// <summary>Where it came from, e.g. "query string" or "login form", used in evidence text.</summary>
    public string Origin { get; init; } = "query string";

    /// <summary>De-dup key: method + path + sorted parameter names (values ignored).</summary>
    public string Signature
    {
        get
        {
            var names = Parameters.Select(p => p.Key).OrderBy(n => n, StringComparer.Ordinal);
            return $"{Method} {Url.GetComponents(UriComponents.SchemeAndServer | UriComponents.Path, UriFormat.UriEscaped)}?{string.Join('&', names)}";
        }
    }
}
