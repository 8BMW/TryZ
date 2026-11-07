using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Numerics;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Inclusive IPv4/IPv6 address range parsed from "a.b.c.d", "a.b.c.d/nn", "a.b.c.d-e", "a.b.c.d-w.x.y.z" or an IPv6 address/CIDR.</summary>
internal readonly record struct IpRange(IPAddress First, IPAddress Last)
{
    private static readonly Regex Ipv4Strict = new(@"^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>CIDR prefix length when the range was written as a CIDR block, otherwise -1.</summary>
    public int Prefix { get; init; } = -1;

    public static bool TryParse(string text, out IpRange range)
    {
        range = default;
        if (string.IsNullOrWhiteSpace(text)) return false;
        text = text.Trim();

        int slash = text.IndexOf('/');
        if (slash > 0)
        {
            if (!TryParseAddress(text[..slash], out var addr)) return false;
            if (!int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix)) return false;
            int bits = addr.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefix < 0 || prefix > bits) return false;
            BigInteger value = ToBig(addr);
            BigInteger hostMask = (BigInteger.One << (bits - prefix)) - 1;
            BigInteger network = value & ~hostMask & MaxValue(bits);
            range = new IpRange(FromBig(network, addr.AddressFamily), FromBig(network | hostMask, addr.AddressFamily)) { Prefix = prefix };
            return true;
        }

        int dash = text.IndexOf('-');
        if (dash > 0)
        {
            string left = text[..dash].Trim(), right = text[(dash + 1)..].Trim();
            if (!TryParseAddress(left, out var first)) return false;
            IPAddress last;
            if (first.AddressFamily == AddressFamily.InterNetwork && right.Length is > 0 and <= 3 && right.All(char.IsAsciiDigit))
            {
                int octet = int.Parse(right, CultureInfo.InvariantCulture);
                if (octet > 255) return false;
                var bytes = first.GetAddressBytes();
                bytes[3] = (byte)octet;
                last = new IPAddress(bytes);
            }
            else if (!TryParseAddress(right, out last))
            {
                return false;
            }
            if (first.AddressFamily != last.AddressFamily || ToBig(first) > ToBig(last)) return false;
            range = new IpRange(first, last);
            return true;
        }

        if (!TryParseAddress(text, out var single)) return false;
        range = new IpRange(single, single);
        return true;
    }

    /// <summary>Strict address parse: dotted-quad IPv4 (no "10.1" shorthand) or any valid IPv6 literal, optionally in brackets.</summary>
    public static bool TryParseAddress(string text, out IPAddress address)
    {
        address = IPAddress.None;
        text = text.Trim();
        if (text.StartsWith('[') && text.EndsWith(']')) text = text[1..^1];
        if (text.Contains(':'))
        {
            if (!IPAddress.TryParse(text, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return false;
            address = v6.IsIPv4MappedToIPv6 ? v6.MapToIPv4() : v6;
            return true;
        }
        if (!Ipv4Strict.IsMatch(text) || !IPAddress.TryParse(text, out var v4)) return false;
        address = v4;
        return true;
    }

    public bool Contains(IPAddress address)
    {
        if (First is null || Last is null) return false;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily != First.AddressFamily) return false;
        var v = ToBig(address);
        return v >= ToBig(First) && v <= ToBig(Last);
    }

    /// <summary>Number of addresses in the range, saturated at <see cref="ulong.MaxValue"/> for huge IPv6 blocks.</summary>
    public ulong Count
    {
        get
        {
            if (First is null || Last is null) return 0;
            var n = ToBig(Last) - ToBig(First) + 1;
            return n > ulong.MaxValue ? ulong.MaxValue : (ulong)n;
        }
    }

    /// <summary>Enumerates the addresses in order, optionally skipping the network and broadcast address of IPv4 CIDR blocks.</summary>
    public IEnumerable<IPAddress> Enumerate(bool skipNetworkAndBroadcast)
    {
        if (First is null || Last is null) yield break;
        var family = First.AddressFamily;
        BigInteger start = ToBig(First), end = ToBig(Last);
        if (skipNetworkAndBroadcast && family == AddressFamily.InterNetwork && Prefix is >= 0 and < 31)
        {
            start += 1;
            end -= 1;
        }
        // Keep the IPv6 zone (e.g. fe80::1%12): link-local addresses cannot be reached without it.
        long scope = family == AddressFamily.InterNetworkV6 ? First.ScopeId : 0;
        for (var v = start; v <= end; v++)
        {
            var address = FromBig(v, family);
            yield return scope != 0 ? new IPAddress(address.GetAddressBytes(), scope) : address;
        }
    }

    public override string ToString() => Prefix >= 0 ? $"{First}/{Prefix}" : First.Equals(Last) ? First.ToString() : $"{First}-{Last}";

    internal static BigInteger ToBig(IPAddress address) => new(address.GetAddressBytes(), isUnsigned: true, isBigEndian: true);

    private static BigInteger MaxValue(int bits) => (BigInteger.One << bits) - 1;

    internal static IPAddress FromBig(BigInteger value, AddressFamily family)
    {
        int size = family == AddressFamily.InterNetwork ? 4 : 16;
        var raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        var bytes = new byte[size];
        int copy = Math.Min(raw.Length, size);
        Buffer.BlockCopy(raw, raw.Length - copy, bytes, size - copy, copy);
        return new IPAddress(bytes);
    }
}

internal static class TargetParser
{
    public const int MaxAddresses = 65536;

    private static readonly char[] Separators = { ',', ' ', '\n', '\r', '\t', ';' };
    private static readonly Regex HostPort = new(@"^(?<host>[A-Za-z0-9.\-]+|\[[0-9A-Fa-f:.]+\]):(?<port>\d{1,5})$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private enum Kind { Range, Url, Name }

    private readonly record struct Token(Kind Kind, string Text, IpRange Range, string Host, Uri? Url);

    /// <summary>Quick syntax check used by the UI before a run. Does not resolve DNS.</summary>
    public static bool TryValidate(string text, out string error)
    {
        error = string.Empty;
        var parts = Split(text);
        if (parts.Count == 0)
        {
            error = "Enter at least one target: an IP, CIDR, range, host name or URL.";
            return false;
        }
        foreach (var part in parts)
        {
            if (!TryClassify(part, out var token, out var reason))
            {
                error = $"'{part}' is not a valid target: {reason}";
                return false;
            }
            if (token.Kind == Kind.Range && token.Range.First.AddressFamily == AddressFamily.InterNetworkV6 && token.Range.Prefix is >= 0 and < 112)
            {
                error = $"'{part}' is too large: IPv6 CIDR blocks must be /112 or smaller.";
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// Expands the target text into addresses (resolving host names / URLs), de-duplicated, in order.
    /// Addresses on the exclusion list are dropped here, before the address cap is applied, and every user-supplied
    /// host name is pinned to its address before discovery starts.
    /// </summary>
    public static async Task<List<ScanTarget>> ParseAsync(string text, ScanContext ctx)
    {
        var result = new List<ScanTarget>();
        var index = new Dictionary<IPAddress, int>();
        bool capped = false;
        long excluded = 0;

        void Add(IPAddress address, string hostname, Uri? seed)
        {
            if (ctx.IsExcluded(address))
            {
                excluded++;
                return;
            }
            bool known = index.TryGetValue(address, out int at);
            if (!known && result.Count >= MaxAddresses)
            {
                if (!capped) ctx.Log(LogLevel.Warn, "scope", $"Target list exceeds {MaxAddresses:N0} addresses; the rest is ignored");
                capped = true;
                return;
            }
            if (hostname.Length > 0 && !ctx.PinHost(hostname, address))
            {
                ctx.Log(LogLevel.Warn, "scope", $"{hostname} is already bound to another scanned address; {address} is scanned without that name");
                hostname = string.Empty;
            }
            if (known)
            {
                var existing = result[at];
                if (existing.Hostname.Length == 0 && hostname.Length > 0)
                {
                    result[at] = existing with { Hostname = hostname, SeedUrl = seed ?? existing.SeedUrl };
                    return;
                }
                if (existing.SeedUrl is null && seed is not null && (hostname.Length == 0 || hostname == existing.Hostname))
                {
                    result[at] = existing with { SeedUrl = seed };
                    return;
                }
                bool sameName = hostname.Length == 0 || hostname == existing.Hostname;
                bool sameSeed = seed is null || seed == existing.SeedUrl;
                if (sameName && sameSeed) return;
                // Another virtual host (or another start URL) on the same address: keep it so its content is audited too.
                var alias = new HostAlias(hostname.Length > 0 ? hostname : existing.Hostname, seed);
                if (existing.Aliases.Contains(alias)) return;
                result[at] = existing with { Aliases = existing.Aliases.Append(alias).ToArray() };
                string label = hostname.Length > 0 ? hostname : seed?.ToString() ?? address.ToString();
                ctx.Log(LogLevel.Notice, "scope", $"{label} resolves to {address}, which is already a target ({(existing.Hostname.Length > 0 ? existing.Hostname : address.ToString())}); the address is scanned once and {label} is audited as an additional web host");
                return;
            }
            index[address] = result.Count;
            result.Add(new ScanTarget(address, hostname, seed));
        }

        foreach (var part in Split(text))
        {
            ctx.Token.ThrowIfCancellationRequested();
            if (capped) break;
            if (!TryClassify(part, out var token, out var reason))
            {
                ctx.Log(LogLevel.Warn, "scope", $"Ignoring '{part}': {reason}");
                continue;
            }
            switch (token.Kind)
            {
                case Kind.Range:
                {
                    ulong count = token.Range.Count;
                    if (count > 1) ctx.Log(LogLevel.Info, "scope", $"{token.Range} expands to {Math.Min(count, (ulong)MaxAddresses):N0} address(es)");
                    foreach (var addr in token.Range.Enumerate(skipNetworkAndBroadcast: true))
                    {
                        Add(addr, string.Empty, null);
                        if (capped) break;
                    }
                    break;
                }
                case Kind.Url:
                case Kind.Name:
                {
                    if (IpRange.TryParseAddress(token.Host, out var literal))
                    {
                        Add(literal, string.Empty, token.Url);
                        break;
                    }
                    var resolved = await ResolveAsync(ctx, token.Host).ConfigureAwait(false);
                    if (resolved is null) break;
                    Add(resolved, token.Host.TrimEnd('.').ToLowerInvariant(), token.Url);
                    break;
                }
            }
        }
        if (excluded > 0) ctx.Log(LogLevel.Notice, "scope", $"{excluded:N0} address(es) skipped by the exclusion list");
        return result;
    }

    private static List<string> Split(string text) =>
        (text ?? string.Empty).Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    private static bool TryClassify(string part, out Token token, out string reason)
    {
        token = default;
        reason = string.Empty;

        if (part.Contains("://", StringComparison.Ordinal))
        {
            if (!Uri.TryCreate(part, UriKind.Absolute, out var uri) || (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
            {
                reason = "only http:// and https:// URLs are supported";
                return false;
            }
            string host = uri.HostNameType == UriHostNameType.IPv6 ? uri.Host.Trim('[', ']') : uri.IdnHost;
            if (host.Length == 0)
            {
                reason = "the URL has no host";
                return false;
            }
            token = new Token(Kind.Url, part, default, host, uri);
            return true;
        }

        if (IpRange.TryParse(part, out var range))
        {
            token = new Token(Kind.Range, part, range, string.Empty, null);
            return true;
        }

        var hp = HostPort.Match(part);
        if (hp.Success)
        {
            string host = hp.Groups["host"].Value.Trim('[', ']');
            int port = int.Parse(hp.Groups["port"].Value, CultureInfo.InvariantCulture);
            if (port is < 1 or > 65535)
            {
                reason = "port must be 1-65535";
                return false;
            }
            if (!IpRange.TryParseAddress(host, out _) && Uri.CheckHostName(host) != UriHostNameType.Dns)
            {
                reason = "invalid host name";
                return false;
            }
            string scheme = port is 443 or 8443 or 4443 or 7443 or 9443 ? "https" : "http";
            string authority = host.Contains(':') ? $"[{host}]" : host;
            token = new Token(Kind.Url, part, default, host, new Uri($"{scheme}://{authority}:{port}/"));
            return true;
        }

        int slash = part.IndexOf('/');
        if (slash > 0 && !IpRange.TryParseAddress(part[..slash], out _) && Uri.CheckHostName(part[..slash].Split(':')[0]) == UriHostNameType.Dns)
            return TryClassify("http://" + part, out token, out reason);

        if (slash >= 0 || (part.Contains('-') && IpRange.TryParseAddress(part.Split('-')[0], out _)))
        {
            reason = "malformed CIDR or address range";
            return false;
        }

        if (Uri.CheckHostName(part) == UriHostNameType.Dns && part.Any(char.IsAsciiLetter) && part.Length <= 253)
        {
            token = new Token(Kind.Name, part, default, part, null);
            return true;
        }

        reason = "not an IP address, CIDR, range, host name or URL";
        return false;
    }

    private static async Task<IPAddress?> ResolveAsync(ScanContext ctx, string host)
    {
        await ctx.GateAsync().ConfigureAwait(false);
        using var _ = ctx.BeginWork();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        cts.CancelAfter(Math.Max(3000, ctx.Options.ReadTimeoutMs * 2));
        var sw = Stopwatch.StartNew();
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(host, cts.Token).ConfigureAwait(false);
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
            var usable = addresses
                .Select(a => a.IsIPv4MappedToIPv6 ? a.MapToIPv4() : a)
                .Where(a => a.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Distinct()
                .ToList();
            var pick = usable.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? usable.FirstOrDefault();
            if (pick is null)
            {
                ctx.Log(LogLevel.Warn, "scope", $"'{host}' resolved to no usable address");
                return null;
            }
            ctx.Log(LogLevel.Info, "scope", $"Resolved {host} -> {pick}");
            if (usable.Count > 1)
                ctx.Log(LogLevel.Debug, "scope", $"{host} has {usable.Count} addresses ({string.Join(", ", usable.Take(8))}); scanning {pick} only");
            return pick;
        }
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            ctx.CountRequest(-1, error: true);
            ctx.Log(LogLevel.Warn, "scope", $"DNS resolution of '{host}' timed out");
            return null;
        }
        catch (SocketException ex)
        {
            ctx.CountRequest(-1, error: true);
            ctx.Log(LogLevel.Warn, "scope", $"Cannot resolve '{host}': {ex.SocketErrorCode}");
            return null;
        }
        catch (ArgumentException ex)
        {
            ctx.Log(LogLevel.Warn, "scope", $"Cannot resolve '{host}': {ex.Message}");
            return null;
        }
    }
}
