using System.Net;
using System.Net.Http;

namespace TryZ.Engine;

/// <summary>
/// A header (session cookie, bearer token, API key) sent only to the hosts the user scoped it to.
/// Scope is "host", "host:port", "*.example.com" or "[2001:db8::1]:8443".
/// </summary>
internal sealed record AuthHeader(string Scope, string Name, string Value)
{
    private static readonly HashSet<string> Forbidden = new(StringComparer.OrdinalIgnoreCase)
    {
        "Host", "Content-Length", "Content-Type", "Transfer-Encoding", "Connection", "Upgrade", "Expect", "TE", "Trailer",
        "Keep-Alive", "Proxy-Connection", "User-Agent",
    };

    /// <summary>Reason the entry can't be used, or null when it is fine.</summary>
    public static string? Validate(string scope, string name, string value)
    {
        if (!TryParseScope(scope, out _, out _, out _)) return "Scope must be a host name or address, optionally with :port or a leading *. for subdomains.";
        if (string.IsNullOrWhiteSpace(name) || name.Length > 64 || name.Any(c => !(char.IsAsciiLetterOrDigit(c) || c is '-' or '_')))
            return "Header name may only contain letters, digits, '-' and '_'.";
        if (Forbidden.Contains(name)) return $"{name} is set by the scanner itself and cannot be overridden.";
        if (string.IsNullOrEmpty(value)) return "Header value is empty.";
        if (value.Length > 8192) return "Header value is longer than 8 KB.";
        if (value.Any(c => c is '\r' or '\n' || (char.IsControl(c) && c != '\t'))) return "Header value cannot contain line breaks or control characters.";
        return null;
    }

    public static bool TryParseScope(string scope, out string host, out int? port, out bool wildcard)
    {
        host = string.Empty;
        port = null;
        wildcard = false;
        string s = (scope ?? string.Empty).Trim();
        if (s.Length == 0 || s.Length > 255 || s.Contains('/') || s.Any(char.IsWhiteSpace)) return false;
        if (s.StartsWith('['))
        {
            int close = s.IndexOf(']');
            if (close < 0) return false;
            host = s[1..close];
            string rest = s[(close + 1)..];
            if (rest.Length > 0 && !TryPort(rest, out port)) return false;
            return IPAddress.TryParse(host, out var v6) && v6.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
        }
        if (s.Count(c => c == ':') > 1) // bare IPv6 without a port
        {
            host = s;
            return IPAddress.TryParse(s, out _);
        }
        int colon = s.IndexOf(':');
        if (colon >= 0)
        {
            if (!TryPort(s[colon..], out port)) return false;
            s = s[..colon];
        }
        if (s.StartsWith("*.", StringComparison.Ordinal))
        {
            wildcard = true;
            s = s[2..];
        }
        if (s.Length == 0 || s.Contains('*')) return false;
        if (!IPAddress.TryParse(s, out _) && Uri.CheckHostName(s) != UriHostNameType.Dns) return false;
        if (wildcard && IPAddress.TryParse(s, out _)) return false;
        host = s.TrimEnd('.');
        return true;
    }

    private static bool TryPort(string text, out int? port)
    {
        port = null;
        if (text.Length < 2 || text[0] != ':' || !int.TryParse(text.AsSpan(1), System.Globalization.NumberStyles.None, null, out int p) || p is < 1 or > 65535) return false;
        port = p;
        return true;
    }

    /// <param name="resolve">
    /// Maps a URL host name to the address the scan pinned it to, so an IP scope still applies when the target was
    /// typed as a name. It never consults DNS: an unpinned name can't borrow an IP scope.
    /// </param>
    public bool Matches(Uri uri, Func<string, IPAddress?>? resolve = null)
    {
        if (!TryParseScope(Scope, out string host, out int? port, out bool wildcard)) return false;
        if (port is int p && uri.Port != p) return false;
        string target = uri.Host.Trim('[', ']').TrimEnd('.');
        if (wildcard) return target.EndsWith("." + host, StringComparison.OrdinalIgnoreCase);
        if (IPAddress.TryParse(host, out var a))
        {
            var b = IPAddress.TryParse(target, out var literal) ? literal : resolve?.Invoke(target);
            if (b == null) return false;
            if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
            if (b.IsIPv4MappedToIPv6) b = b.MapToIPv4();
            return a.Equals(b);
        }
        return string.Equals(target, host, StringComparison.OrdinalIgnoreCase);
    }
}

/// <summary>
/// Adds the configured headers to requests for matching hosts. It sits on the client that does not follow
/// redirects, so a 302 to another site can never carry the credential along.
/// </summary>
internal sealed class AuthHandler : DelegatingHandler
{
    private const int ExpiryThreshold = 10;
    private readonly IReadOnlyList<AuthHeader> _headers;
    private readonly Action<string> _warn;
    private readonly Func<string, IPAddress?>? _resolve;
    private readonly bool[] _used;
    private int _rejected, _accepted, _rejectedRun, _warned;

    public AuthHandler(HttpMessageHandler inner, IReadOnlyList<AuthHeader> headers, Action<string> warn, Func<string, IPAddress?>? resolve = null) : base(inner)
    {
        _headers = headers;
        _warn = warn;
        _resolve = resolve;
        _used = new bool[headers.Count];
    }

    public int AuthenticatedRequests => Volatile.Read(ref _accepted) + Volatile.Read(ref _rejected);

    /// <summary>Configured entries that no request matched: usually a scope typo or a target typed differently.</summary>
    public IEnumerable<AuthHeader> Unused => _headers.Where((_, i) => !Volatile.Read(ref _used[i]));

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        bool applied = false;
        if (request.RequestUri is { IsAbsoluteUri: true } uri)
        {
            var matching = new List<AuthHeader>();
            for (int i = 0; i < _headers.Count; i++)
            {
                if (!_headers[i].Matches(uri, _resolve)) continue;
                matching.Add(_headers[i]);
                Volatile.Write(ref _used[i], true);
            }
            foreach (var group in matching.GroupBy(h => h.Name, StringComparer.OrdinalIgnoreCase))
            {
                request.Headers.Remove(group.Key);
                // Several cookie entries for one host belong in one Cookie header; anything else, last one wins.
                string value = group.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase)
                    ? string.Join("; ", group.Select(h => h.Value.Trim().TrimEnd(';')))
                    : group.Last().Value;
                request.Headers.TryAddWithoutValidation(group.Key, value);
                applied = true;
            }
        }
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (applied)
        {
            int run;
            if (response.StatusCode is HttpStatusCode.Unauthorized)
            {
                Interlocked.Increment(ref _rejected);
                run = Interlocked.Increment(ref _rejectedRun);
            }
            else
            {
                Interlocked.Increment(ref _accepted);
                Interlocked.Exchange(ref _rejectedRun, 0);
                run = 0;
            }
            // A run of 401s with the credential attached, however many successes came before: the session expired
            // mid-scan (or was never valid). A single protected page now and then doesn't reset-and-trip this.
            if (run >= ExpiryThreshold && Interlocked.Exchange(ref _warned, 1) == 0)
                _warn($"{run} authenticated requests in a row were answered 401 Unauthorized. The session cookie or token has probably expired; refresh it in Options > Engine > Authentication and scan again.");
        }
        return response;
    }

    /// <summary>Replaces configured secret values in text that will be stored or shown.</summary>
    public static string Redact(string text, IReadOnlyList<AuthHeader> headers)
    {
        if (string.IsNullOrEmpty(text) || headers.Count == 0) return text;
        foreach (var h in headers)
        {
            foreach (string secret in Secrets(h))
                if (secret.Length >= 4) text = text.Replace(secret, "[redacted]", StringComparison.Ordinal);
        }
        return text;
    }

    // The whole value, plus the parts that tend to get echoed on their own: cookie values and the token after "Bearer ".
    private static IEnumerable<string> Secrets(AuthHeader h)
    {
        string v = h.Value.Trim();
        yield return v;
        int space = v.IndexOf(' ');
        if (space > 0 && space < v.Length - 1) yield return v[(space + 1)..].Trim();
        foreach (string part in v.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int eq = part.IndexOf('=');
            if (eq > 0 && eq < part.Length - 1) yield return part[(eq + 1)..];
        }
    }
}
