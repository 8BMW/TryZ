using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// TLS assessment for one service:
/// 1. a normal handshake through the OS TLS stack (SslStream) to obtain the certificate chain and the default negotiated cipher;
/// 2. hand-built ClientHello probes (raw TCP, read only up to ServerHello/Certificate) to test SSL 3.0 / TLS 1.0-1.3 support
///    independently of what the local OS is willing to negotiate, plus cipher-group, compression and renegotiation checks;
/// 3. certificate checks (validity, trust chain, hostname, signature and key strength).
/// No exploit traffic: every probe is a standard, well-formed handshake that is closed after the server's first flight.
/// </summary>
internal static class TlsAudit
{
    private const ushort Ssl30 = 0x0300, Tls10 = 0x0301, Tls11 = 0x0302, Tls12 = 0x0303, Tls13 = 0x0304;
    private const string Src = "tls";

    private enum Outcome { Accepted, Rejected, Inconclusive }

    private sealed class ProbeResult
    {
        public Outcome Outcome;
        public ushort Version;
        public ushort Cipher;
        public byte Compression;
        public bool SecureRenegotiation;
        public bool HelloRetry;
        public string Detail = string.Empty;
        public List<byte[]> Certificates { get; } = new();
    }

    private sealed class OsHandshake
    {
        public X509Certificate2? Leaf;
        public List<X509Certificate2> Chain { get; } = new();
        public SslPolicyErrors PolicyErrors;
        public SslProtocols Protocol;
        public string Cipher = string.Empty;
    }

    // ------------------------------------------------------------------ cipher suite catalogue

    [Flags]
    private enum Cat { None = 0, Aead = 1, Cbc = 2, Rc4 = 4, Des = 8, TripleDes = 16, Null = 32, Export = 64, Anon = 128, Fs = 256, Tls13 = 512 }

    private sealed record Suite(ushort Id, string Name, Cat Cat);

    private static readonly Suite[] Suites =
    {
        new(0x1301, "TLS_AES_128_GCM_SHA256", Cat.Tls13 | Cat.Aead | Cat.Fs),
        new(0x1302, "TLS_AES_256_GCM_SHA384", Cat.Tls13 | Cat.Aead | Cat.Fs),
        new(0x1303, "TLS_CHACHA20_POLY1305_SHA256", Cat.Tls13 | Cat.Aead | Cat.Fs),
        new(0xC02B, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", Cat.Aead | Cat.Fs),
        new(0xC02F, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", Cat.Aead | Cat.Fs),
        new(0xC02C, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", Cat.Aead | Cat.Fs),
        new(0xC030, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", Cat.Aead | Cat.Fs),
        new(0xCCA9, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", Cat.Aead | Cat.Fs),
        new(0xCCA8, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Cat.Aead | Cat.Fs),
        new(0x009E, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", Cat.Aead | Cat.Fs),
        new(0x009F, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", Cat.Aead | Cat.Fs),
        new(0xCCAA, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", Cat.Aead | Cat.Fs),
        new(0x009C, "TLS_RSA_WITH_AES_128_GCM_SHA256", Cat.Aead),
        new(0x009D, "TLS_RSA_WITH_AES_256_GCM_SHA384", Cat.Aead),
        new(0xC023, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", Cat.Cbc | Cat.Fs),
        new(0xC027, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", Cat.Cbc | Cat.Fs),
        new(0xC024, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", Cat.Cbc | Cat.Fs),
        new(0xC028, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", Cat.Cbc | Cat.Fs),
        new(0xC009, "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", Cat.Cbc | Cat.Fs),
        new(0xC013, "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", Cat.Cbc | Cat.Fs),
        new(0xC00A, "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", Cat.Cbc | Cat.Fs),
        new(0xC014, "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", Cat.Cbc | Cat.Fs),
        new(0x0067, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", Cat.Cbc | Cat.Fs),
        new(0x006B, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", Cat.Cbc | Cat.Fs),
        new(0x0033, "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", Cat.Cbc | Cat.Fs),
        new(0x0039, "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", Cat.Cbc | Cat.Fs),
        new(0x003C, "TLS_RSA_WITH_AES_128_CBC_SHA256", Cat.Cbc),
        new(0x003D, "TLS_RSA_WITH_AES_256_CBC_SHA256", Cat.Cbc),
        new(0x002F, "TLS_RSA_WITH_AES_128_CBC_SHA", Cat.Cbc),
        new(0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", Cat.Cbc),
        new(0x0041, "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", Cat.Cbc),
        new(0x0084, "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", Cat.Cbc),
        new(0xC012, "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", Cat.TripleDes | Cat.Cbc | Cat.Fs),
        new(0xC008, "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", Cat.TripleDes | Cat.Cbc | Cat.Fs),
        new(0x0016, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", Cat.TripleDes | Cat.Cbc | Cat.Fs),
        new(0x000A, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", Cat.TripleDes | Cat.Cbc),
        new(0xC011, "TLS_ECDHE_RSA_WITH_RC4_128_SHA", Cat.Rc4 | Cat.Fs),
        new(0xC007, "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", Cat.Rc4 | Cat.Fs),
        new(0x0005, "TLS_RSA_WITH_RC4_128_SHA", Cat.Rc4),
        new(0x0004, "TLS_RSA_WITH_RC4_128_MD5", Cat.Rc4),
        new(0x0009, "TLS_RSA_WITH_DES_CBC_SHA", Cat.Des | Cat.Cbc),
        new(0x0015, "TLS_DHE_RSA_WITH_DES_CBC_SHA", Cat.Des | Cat.Cbc | Cat.Fs),
        new(0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", Cat.Export | Cat.Rc4),
        new(0x0006, "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", Cat.Export | Cat.Cbc),
        new(0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", Cat.Export | Cat.Cbc),
        new(0x0014, "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", Cat.Export | Cat.Cbc),
        new(0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", Cat.Export | Cat.Cbc),
        new(0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", Cat.Export | Cat.Rc4),
        new(0x0001, "TLS_RSA_WITH_NULL_MD5", Cat.Null),
        new(0x0002, "TLS_RSA_WITH_NULL_SHA", Cat.Null),
        new(0x003B, "TLS_RSA_WITH_NULL_SHA256", Cat.Null),
        new(0xC010, "TLS_ECDHE_RSA_WITH_NULL_SHA", Cat.Null | Cat.Fs),
        new(0xC006, "TLS_ECDHE_ECDSA_WITH_NULL_SHA", Cat.Null | Cat.Fs),
        new(0x0018, "TLS_DH_anon_WITH_RC4_128_MD5", Cat.Anon | Cat.Rc4),
        new(0x001B, "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", Cat.Anon | Cat.TripleDes | Cat.Cbc),
        new(0x0034, "TLS_DH_anon_WITH_AES_128_CBC_SHA", Cat.Anon | Cat.Cbc),
        new(0x003A, "TLS_DH_anon_WITH_AES_256_CBC_SHA", Cat.Anon | Cat.Cbc),
        new(0x00A6, "TLS_DH_anon_WITH_AES_128_GCM_SHA256", Cat.Anon | Cat.Aead),
        new(0xC018, "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", Cat.Anon | Cat.Cbc),
        new(0xC019, "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", Cat.Anon | Cat.Cbc),
        new(0xC016, "TLS_ECDH_anon_WITH_RC4_128_SHA", Cat.Anon | Cat.Rc4),
        new(0xC017, "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", Cat.Anon | Cat.TripleDes | Cat.Cbc),
    };

    private static readonly Dictionary<ushort, Suite> SuiteById = Suites.ToDictionary(s => s.Id);

    private static readonly byte[] HelloRetryRandom = Convert.FromHexString("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C");

    /// <summary>Weak cipher groups probed individually (each probe offers only that group).</summary>
    private static readonly (Cat Cat, Severity Sev, string Title, string Why)[] WeakGroups =
    {
        (Cat.Null, Severity.High, "NULL (unencrypted) cipher suites accepted",
            "NULL cipher suites authenticate the peer but do not encrypt traffic at all."),
        (Cat.Anon, Severity.High, "Anonymous (unauthenticated) cipher suites accepted",
            "Anonymous Diffie-Hellman suites send no server certificate, so any man-in-the-middle can impersonate the server."),
        (Cat.Export, Severity.High, "EXPORT-grade cipher suites accepted (FREAK / Logjam)",
            "40/56-bit export suites can be broken in hours and enable downgrade attacks such as FREAK (CVE-2015-0204) and Logjam (CVE-2015-4000)."),
        (Cat.Rc4, Severity.Medium, "RC4 cipher suites accepted",
            "RC4 keystream biases allow plaintext recovery (CVE-2013-2566, CVE-2015-2808); RC4 is prohibited by RFC 7465."),
        (Cat.Des, Severity.Medium, "Single-DES cipher suites accepted",
            "56-bit DES keys can be brute-forced with commodity hardware."),
        (Cat.TripleDes, Severity.Medium, "3DES cipher suites accepted (SWEET32)",
            "64-bit block ciphers such as 3DES are vulnerable to birthday attacks on long sessions (SWEET32, CVE-2016-2183)."),
    };

    // ------------------------------------------------------------------ entry point

    /// <summary>Certificate and protocol checks for a TLS service; reports findings via ctx.AddFinding.</summary>
    public static async Task AuditAsync(ScanContext ctx, OpenService svc)
    {
        string where = $"{svc.Host.Ip}:{svc.Port}";
        string? sni = SniName(svc.Host);
        ctx.Log(LogLevel.Info, Src, $"TLS audit started on {where}" + (sni != null ? $" (SNI {sni})" : string.Empty));

        // 1. Normal OS handshake: certificate + default cipher.
        var os = await OsHandshakeAsync(ctx, svc, sni).ConfigureAwait(false);
        if (os != null)
            ctx.Log(LogLevel.Info, Src, $"{where} negotiated {ProtocolName(os.Protocol)} {os.Cipher}".TrimEnd());

        // 2. Protocol support with raw ClientHello probes.
        var results = new Dictionary<ushort, ProbeResult>();
        foreach (ushort v in new[] { Tls13, Tls12, Tls11, Tls10, Ssl30 })
        {
            var r = await ProbeAsync(ctx, svc, sni, v, DefaultSuites(v), deflate: false, wantCertificates: v != Tls13).ConfigureAwait(false);
            if (r.Outcome == Outcome.Inconclusive && v is Tls10 or Tls11 or Tls12 or Tls13)
                r = await OsProtocolFallbackAsync(ctx, svc, sni, v, r).ConfigureAwait(false);
            results[v] = r;
            ctx.Log(LogLevel.Debug, Src, $"{where} {VersionName(v)}: {r.Outcome}{(r.Outcome == Outcome.Accepted ? " cipher " + SuiteName(r.Cipher) : string.Empty)} {r.Detail}".TrimEnd());
        }

        ReportProtocols(ctx, svc, results);

        // highest legacy (<= TLS 1.2) protocol the server accepts, used for cipher/extension probes
        ushort legacy = 0;
        foreach (ushort v in new[] { Tls12, Tls11, Tls10, Ssl30 })
            if (results[v].Outcome == Outcome.Accepted) { legacy = v; break; }

        if (legacy != 0)
            await CipherChecksAsync(ctx, svc, sni, legacy, results[legacy]).ConfigureAwait(false);

        if (os != null && os.Cipher.Length > 0) ReportNegotiatedCipher(ctx, svc, os);

        // 3. Certificate.
        X509Certificate2? leaf = os?.Leaf;
        var chain = os?.Chain ?? new List<X509Certificate2>();
        string certSource = "OS TLS handshake";
        var rawCerts = new List<X509Certificate2>();
        try
        {
            if (leaf == null)
            {
                var raw = results.Values.FirstOrDefault(r => r.Certificates.Count > 0)?.Certificates;
                if (raw != null)
                {
                    foreach (var der in raw)
                    {
                        try { rawCerts.Add(X509CertificateLoader.LoadCertificate(der)); }
                        catch (CryptographicException ex) { ctx.Log(LogLevel.Debug, Src, $"{where} could not parse certificate from handshake: {ex.Message}"); }
                    }
                    if (rawCerts.Count > 0)
                    {
                        leaf = rawCerts[0];
                        chain = rawCerts.Skip(1).ToList();
                        certSource = "raw TLS handshake";
                    }
                }
            }
            if (leaf == null && svc.Certificate != null)
            {
                leaf = svc.Certificate;
                certSource = "service identification handshake";
            }

            if (leaf != null) CheckCertificate(ctx, svc, sni, leaf, chain, certSource);
            else ctx.Log(LogLevel.Warn, Src, $"{where}: no server certificate could be obtained; certificate checks skipped");
        }
        finally
        {
            foreach (var c in rawCerts) c.Dispose();
            if (os != null)
            {
                os.Leaf?.Dispose();
                foreach (var c in os.Chain) c.Dispose();
            }
        }

        ctx.Log(LogLevel.Ok, Src, $"TLS audit finished on {where}");
    }

    // ------------------------------------------------------------------ protocol reporting

    private static void ReportProtocols(ScanContext ctx, OpenService svc, Dictionary<ushort, ProbeResult> r)
    {
        string summary = string.Join(", ", new[] { Ssl30, Tls10, Tls11, Tls12, Tls13 }.Select(v => $"{VersionName(v)}={r[v].Outcome.ToString().ToLowerInvariant()}"));
        ctx.Log(LogLevel.Info, Src, $"{svc.Host.Ip}:{svc.Port} protocol support: {summary}");

        if (r[Ssl30].Outcome == Outcome.Accepted)
            Add(ctx, svc, Severity.High, "SSL 3.0 accepted (POODLE, CVE-2014-3566)", 327,
                "The server completes an SSL 3.0 handshake. SSL 3.0 is broken (POODLE padding oracle, CVE-2014-3566) and prohibited by RFC 7568.",
                $"ClientHello offering only SSL 3.0 was answered with ServerHello version SSL 3.0, cipher {SuiteName(r[Ssl30].Cipher)}. Protocol summary: {summary}",
                "Disable SSL 2.0/3.0 in the server's TLS configuration (e.g. nginx ssl_protocols TLSv1.2 TLSv1.3; Apache SSLProtocol -all +TLSv1.2 +TLSv1.3; Windows SCHANNEL registry keys).");

        foreach (var (v, name) in new[] { (Tls10, "TLS 1.0"), (Tls11, "TLS 1.1") })
            if (r[v].Outcome == Outcome.Accepted)
                Add(ctx, svc, Severity.Medium, $"Deprecated {name} accepted", 327,
                    $"The server negotiates {name}, which was formally deprecated by RFC 8996 (2021). It relies on SHA-1/MD5 in the handshake and CBC constructions vulnerable to BEAST/Lucky13-style attacks, and fails PCI DSS requirements.",
                    $"ClientHello offering only {name} was answered with ServerHello version {name}, cipher {SuiteName(r[v].Cipher)}. Protocol summary: {summary}",
                    "Disable TLS 1.0 and TLS 1.1; allow only TLS 1.2 and TLS 1.3.");

        bool modernRejected = r[Tls12].Outcome == Outcome.Rejected && r[Tls13].Outcome == Outcome.Rejected;
        bool anyLegacy = r[Ssl30].Outcome == Outcome.Accepted || r[Tls10].Outcome == Outcome.Accepted || r[Tls11].Outcome == Outcome.Accepted;
        if (modernRejected && anyLegacy)
            Add(ctx, svc, Severity.Medium, "TLS 1.2 and TLS 1.3 not supported", 327,
                "The server only supports obsolete protocol versions. Modern clients (browsers, current OS TLS stacks) refuse to connect, and the remaining protocols are cryptographically weak.",
                $"ClientHello probes for TLS 1.2 and TLS 1.3 were rejected ({r[Tls12].Detail}; {r[Tls13].Detail}). Protocol summary: {summary}",
                "Upgrade the TLS library / server software and enable TLS 1.2 and TLS 1.3.");
        else if (r[Tls13].Outcome == Outcome.Rejected && r[Tls12].Outcome == Outcome.Accepted)
            Add(ctx, svc, Severity.Info, "TLS 1.3 not supported", 327,
                "The server supports TLS 1.2 but not TLS 1.3. TLS 1.3 removes legacy algorithms, always provides forward secrecy and encrypts more of the handshake.",
                $"ClientHello offering only TLS 1.3 was rejected ({r[Tls13].Detail}). Protocol summary: {summary}",
                "Enable TLS 1.3 when the server software supports it.");
    }

    private static async Task CipherChecksAsync(ScanContext ctx, OpenService svc, string? sni, ushort legacy, ProbeResult baseline)
    {
        string where = $"{svc.Host.Ip}:{svc.Port}";
        string ver = VersionName(legacy);

        // Server-preferred cipher when offered the full list (strongest first).
        if (SuiteById.TryGetValue(baseline.Cipher, out var preferred))
        {
            ctx.Log(LogLevel.Info, Src, $"{where} preferred {ver} cipher: {preferred.Name}");
            if (legacy >= Tls10 && (preferred.Cat & Cat.Fs) == 0 && (preferred.Cat & (Cat.Null | Cat.Anon | Cat.Export)) == 0)
            {
                var fs = await ProbeAsync(ctx, svc, sni, legacy, Suites.Where(s => (s.Cat & Cat.Fs) != 0 && (s.Cat & Cat.Tls13) == 0 && (s.Cat & (Cat.Null | Cat.Anon | Cat.Export)) == 0).Select(s => s.Id).ToArray(), false, false).ConfigureAwait(false);
                bool fsSupported = fs.Outcome == Outcome.Accepted && SuiteById.TryGetValue(fs.Cipher, out var fsSuite) && (fsSuite.Cat & Cat.Fs) != 0;
                if (fs.Outcome != Outcome.Inconclusive)
                    Add(ctx, svc, fsSupported ? Severity.Low : Severity.Medium,
                        fsSupported ? "Server prefers cipher suites without forward secrecy" : "No forward secrecy (no ECDHE/DHE cipher suites)", 327,
                        "With static RSA key exchange, anyone who later obtains the server's private key can decrypt all previously recorded sessions.",
                        $"{ver} ClientHello offering ECDHE/AEAD suites first was answered with {preferred.Name}." + (fsSupported ? $" A probe offering only (EC)DHE suites succeeded with {SuiteName(fs.Cipher)}." : " A probe offering only (EC)DHE suites was rejected."),
                        "Enable ECDHE key exchange and prefer ECDHE + AES-GCM / ChaCha20-Poly1305 suites (server cipher order on).");
            }
            else if ((preferred.Cat & Cat.Cbc) != 0 && (preferred.Cat & (Cat.Rc4 | Cat.TripleDes | Cat.Des | Cat.Export | Cat.Null)) == 0)
            {
                Add(ctx, svc, Severity.Low, "Server prefers CBC-mode cipher suite", 327,
                    "When offered AEAD suites (AES-GCM, ChaCha20-Poly1305) first, the server still selected a CBC-mode suite. CBC with MAC-then-encrypt is the root of padding-oracle attacks (Lucky13, POODLE-TLS).",
                    $"{ver} ClientHello listing AEAD suites first was answered with {preferred.Name}.",
                    "Prefer AEAD cipher suites (ECDHE-*-AES-GCM, ECDHE-*-CHACHA20-POLY1305) and enable server cipher-order preference.");
            }
        }

        // Weak groups.
        foreach (var g in WeakGroups)
        {
            var ids = Suites.Where(s => (s.Cat & g.Cat) != 0 && (s.Cat & Cat.Tls13) == 0).Select(s => s.Id).ToArray();
            var r = await ProbeAsync(ctx, svc, sni, legacy, ids, false, false).ConfigureAwait(false);
            if (r.Outcome == Outcome.Accepted && SuiteById.TryGetValue(r.Cipher, out var s) && (s.Cat & g.Cat) != 0)
                Add(ctx, svc, g.Sev, g.Title, 327,
                    g.Why + " The server accepted such a suite when the client offered nothing stronger.",
                    $"{ver} ClientHello offering only {g.Cat} suites ({ids.Length} suites) was answered with ServerHello cipher {s.Name}.",
                    "Remove the weak suites from the server cipher list (e.g. OpenSSL string 'HIGH:!aNULL:!eNULL:!EXPORT:!DES:!3DES:!RC4:!MD5'; Windows: IIS Crypto / Disable-TlsCipherSuite).");
            else
                ctx.Log(LogLevel.Debug, Src, $"{where} {g.Cat} suites: {r.Outcome} {r.Detail}".TrimEnd());
        }

        // TLS compression (CRIME). SSL 3.0 servers are covered by the SSL 3.0 finding.
        if (legacy >= Tls10)
        {
            var c = await ProbeAsync(ctx, svc, sni, legacy, DefaultSuites(legacy), deflate: true, wantCertificates: false).ConfigureAwait(false);
            if (c.Outcome == Outcome.Accepted && c.Compression == 1)
                Add(ctx, svc, Severity.Medium, "TLS compression enabled (CRIME, CVE-2012-4929)", 200,
                    "The server agrees to DEFLATE compression at the TLS layer. Combined with attacker-influenced plaintext, compression lets an attacker recover secrets such as session cookies (CRIME).",
                    $"{ver} ClientHello offering compression methods [DEFLATE, null] was answered with compression method 1 (DEFLATE).",
                    "Disable TLS-level compression (OpenSSL: SSL_OP_NO_COMPRESSION; upgrade the TLS library).");

            if (!baseline.SecureRenegotiation)
                Add(ctx, svc, Severity.Low, "Secure renegotiation (RFC 5746) not supported", 300,
                    "The server did not acknowledge the renegotiation_info extension. Servers without RFC 5746 support may be vulnerable to the TLS renegotiation prefix-injection attack (CVE-2009-3555) if renegotiation is allowed.",
                    $"{ver} ClientHello with renegotiation_info extension was answered by a ServerHello without renegotiation_info (cipher {SuiteName(baseline.Cipher)}).",
                    "Upgrade the TLS library so that RFC 5746 secure renegotiation is supported, or disable renegotiation.");
        }
    }

    private static void ReportNegotiatedCipher(ScanContext ctx, OpenService svc, OsHandshake os)
    {
        string name = os.Cipher;
        string ev = $"Default handshake from this machine negotiated {ProtocolName(os.Protocol)} with {name}.";
        if (name.Contains("NULL", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.High, "NULL (unencrypted) cipher suites accepted", 327, "The default handshake negotiated a NULL cipher suite: traffic is not encrypted.", ev, "Remove NULL suites from the server cipher list.");
        else if (name.Contains("EXPORT", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.High, "EXPORT-grade cipher suites accepted (FREAK / Logjam)", 327, "The default handshake negotiated an export-grade suite.", ev, "Remove EXPORT suites from the server cipher list.");
        else if (name.Contains("_anon_", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.High, "Anonymous (unauthenticated) cipher suites accepted", 327, "The default handshake negotiated an anonymous suite (no server authentication).", ev, "Remove anonymous suites (aNULL) from the server cipher list.");
        else if (name.Contains("RC4", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.Medium, "RC4 cipher suites accepted", 327, "The default handshake negotiated RC4 (RFC 7465 prohibits RC4).", ev, "Remove RC4 suites from the server cipher list.");
        else if (name.Contains("3DES", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.Medium, "3DES cipher suites accepted (SWEET32)", 327, "The default handshake negotiated a 64-bit block cipher (SWEET32, CVE-2016-2183).", ev, "Remove 3DES suites from the server cipher list.");
        else if (name.Contains("_DES_", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.Medium, "Single-DES cipher suites accepted", 327, "The default handshake negotiated single DES.", ev, "Remove DES suites from the server cipher list.");
        else if (name.Contains("_CBC_", StringComparison.OrdinalIgnoreCase))
            Add(ctx, svc, Severity.Low, "Server prefers CBC-mode cipher suite", 327,
                "The default handshake from a modern client negotiated a CBC-mode suite instead of an AEAD suite (AES-GCM / ChaCha20-Poly1305).", ev,
                "Prefer AEAD cipher suites and enable server cipher-order preference.");
    }

    // ------------------------------------------------------------------ certificate checks

    private static void CheckCertificate(ScanContext ctx, OpenService svc, string? sni, X509Certificate2 leaf, List<X509Certificate2> presented, string source)
    {
        string where = $"{svc.Host.Ip}:{svc.Port}";
        var sans = DnsNames(leaf);
        string cn = leaf.GetNameInfo(X509NameType.SimpleName, false);
        DateTime notBefore = leaf.NotBefore.ToUniversalTime(), notAfter = leaf.NotAfter.ToUniversalTime(), now = DateTime.UtcNow;
        string certInfo =
            $"Subject: {leaf.Subject}\nIssuer: {leaf.Issuer}\nSerial: {leaf.SerialNumber}\n" +
            $"Valid: {notBefore:yyyy-MM-dd HH:mm} UTC to {notAfter:yyyy-MM-dd HH:mm} UTC\n" +
            $"SAN DNS: {(sans.Count > 0 ? string.Join(", ", sans.Take(25)) + (sans.Count > 25 ? $" (+{sans.Count - 25} more)" : string.Empty) : "(none)")}\n" +
            $"Signature: {SigName(leaf.SignatureAlgorithm)}; Key: {KeyDescription(leaf)}\n" +
            $"SHA-256 fingerprint: {leaf.GetCertHashString(HashAlgorithmName.SHA256)}\nSource: {source}";
        ctx.Log(LogLevel.Info, Src, $"{where} certificate CN={cn}, issuer={leaf.GetNameInfo(X509NameType.SimpleName, true)}, expires {notAfter:yyyy-MM-dd}");

        // validity
        if (now > notAfter)
            Add(ctx, svc, Severity.Medium, "TLS certificate expired", 324,
                $"The server certificate expired on {notAfter:yyyy-MM-dd} ({(int)(now - notAfter).TotalDays} days ago). Clients will show errors, and users trained to click through warnings become easy targets for interception.",
                certInfo, "Renew the certificate and install it with its full intermediate chain; automate renewal (ACME / certificate monitoring).");
        else if (now < notBefore)
            Add(ctx, svc, Severity.Medium, "TLS certificate not yet valid", 295,
                $"The server certificate is only valid from {notBefore:yyyy-MM-dd HH:mm} UTC. Either the wrong certificate is deployed or the issuing system clock is wrong.",
                certInfo, "Deploy a currently valid certificate and check time synchronisation on the issuing system.");
        else if ((notAfter - now).TotalDays <= 30)
            Add(ctx, svc, Severity.Low, "TLS certificate expires within 30 days", 324,
                $"The server certificate expires on {notAfter:yyyy-MM-dd} ({Math.Max(0, (int)(notAfter - now).TotalDays)} days left).",
                certInfo, "Renew the certificate before it expires and automate renewal.");

        // chain
        bool selfIssued = leaf.SubjectName.RawData.AsSpan().SequenceEqual(leaf.IssuerName.RawData);
        using (var chain = new X509Chain())
        {
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid | X509VerificationFlags.IgnoreCtlNotTimeValid;
            foreach (var c in presented) chain.ChainPolicy.ExtraStore.Add(c);
            bool built;
            try { built = chain.Build(leaf); }
            catch (CryptographicException ex)
            {
                built = false;
                ctx.Log(LogLevel.Debug, Src, $"{where} chain build error: {ex.Message}");
            }
            var status = chain.ChainStatus.Select(s => s.Status).Aggregate(X509ChainStatusFlags.NoError, (a, b) => a | b);
            string statusText = string.Join("; ", chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}").Distinct());
            string path = string.Join(" -> ", chain.ChainElements.Select(e => e.Certificate.GetNameInfo(X509NameType.SimpleName, false)));
            var trustProblems = status & ~(X509ChainStatusFlags.NotTimeValid | X509ChainStatusFlags.NotTimeNested | X509ChainStatusFlags.CtlNotTimeValid
                                           | X509ChainStatusFlags.RevocationStatusUnknown | X509ChainStatusFlags.OfflineRevocation);

            if (!built || trustProblems != X509ChainStatusFlags.NoError)
            {
                if (selfIssued && (presented.Count == 0 || trustProblems.HasFlag(X509ChainStatusFlags.UntrustedRoot)))
                    Add(ctx, svc, Severity.Medium, "Self-signed TLS certificate", 295,
                        "The server presents a self-signed certificate that does not chain to a trusted certificate authority. Clients cannot authenticate the server, so connections are open to man-in-the-middle interception unless the certificate is pinned.",
                        certInfo + $"\nChain status: {statusText}",
                        "Replace it with a certificate from a trusted public CA (or an internal CA distributed to all clients).");
                else if (trustProblems.HasFlag(X509ChainStatusFlags.PartialChain))
                    Add(ctx, svc, Severity.Low, "Incomplete TLS certificate chain", 295,
                        "The certificate chain could not be built to a trusted root from the certificates the server sent and the local trust store (AIA downloads disabled). The server is most likely missing an intermediate certificate; clients that do not fetch intermediates (many non-browser clients, Firefox, Java, curl) will fail validation.",
                        certInfo + $"\nCertificates sent by server: {presented.Count + 1}\nChain: {path}\nChain status: {statusText}",
                        "Configure the server to send the full chain (leaf + intermediates), e.g. fullchain.pem in nginx/Apache.");
                else
                    Add(ctx, svc, Severity.Medium, "Untrusted TLS certificate chain", 295,
                        "The certificate chain does not validate against the system trust store. Clients cannot authenticate the server, which enables man-in-the-middle interception.",
                        certInfo + $"\nChain: {path}\nChain status: {statusText}",
                        "Use a certificate issued by a trusted CA and send the complete chain.");
            }

            // weak signatures on leaf and intermediates (the trust anchor's own signature is irrelevant)
            var elements = chain.ChainElements.Select(e => e.Certificate).ToList();
            if (elements.Count == 0) elements.Add(leaf);
            for (int i = 0; i < elements.Count; i++)
            {
                var c = elements[i];
                bool isRoot = i == elements.Count - 1 && elements.Count > 1 && c.SubjectName.RawData.AsSpan().SequenceEqual(c.IssuerName.RawData);
                if (isRoot) continue;
                var (weak, hash) = WeakSignature(c.SignatureAlgorithm);
                if (!weak) continue;
                string which = i == 0 ? "server certificate" : $"intermediate certificate '{c.GetNameInfo(X509NameType.SimpleName, false)}'";
                Add(ctx, svc, hash == "SHA-1" ? Severity.Medium : Severity.High, $"Weak certificate signature algorithm ({hash})", 328,
                    $"The {which} is signed with {SigName(c.SignatureAlgorithm)}. {hash} collisions are practical (SHAttered / chosen-prefix attacks), allowing forged certificates; browsers reject such certificates.",
                    certInfo + $"\nWeakly signed: {c.Subject} ({SigName(c.SignatureAlgorithm)})",
                    "Re-issue the certificate (and intermediates) with a SHA-256 or stronger signature.");
            }
        }

        // hostname
        if (sni != null)
        {
            var names = sans.Count > 0 ? sans : (cn.Length > 0 ? new List<string> { cn } : new List<string>());
            if (!names.Any(n => HostMatches(n, sni)))
                Add(ctx, svc, Severity.Medium, "TLS certificate hostname mismatch", 297,
                    $"The certificate is not valid for the host name '{sni}'. Clients will reject the connection or users will be trained to accept certificate warnings.",
                    certInfo + $"\nRequested host: {sni}\nNames checked ({(sans.Count > 0 ? "SAN" : "CN fallback")}): {string.Join(", ", names.Take(25))}",
                    "Issue a certificate whose subjectAltName contains this host name (or a matching wildcard).");
        }

        // key strength
        string key = KeyDescription(leaf);
        int bits = KeyBits(leaf, out string alg);
        bool weakKey = alg switch { "RSA" => bits < 2048, "DSA" => bits < 2048, "EC" => bits < 256, _ => false };
        if (weakKey && bits > 0)
            Add(ctx, svc, bits < 1024 && alg != "EC" ? Severity.High : Severity.Medium, $"Weak certificate public key ({alg} {bits} bits)", 326,
                $"The server certificate uses a {alg} key of {bits} bits. Current guidance (NIST SP 800-57, CA/Browser Forum) requires at least RSA 2048 bits or ECC 256 bits; smaller keys may be factorable by well-resourced attackers.",
                certInfo + $"\nPublic key: {key}",
                "Generate a new key pair (RSA 2048+ or ECDSA P-256+) and re-issue the certificate.");
    }

    private static List<string> DnsNames(X509Certificate2 cert)
    {
        var list = new List<string>();
        foreach (var ext in cert.Extensions)
        {
            if (ext.Oid?.Value != "2.5.29.17") continue;
            try
            {
                var san = ext as X509SubjectAlternativeNameExtension ?? new X509SubjectAlternativeNameExtension(ext.RawData, ext.Critical);
                list.AddRange(san.EnumerateDnsNames());
            }
            catch (CryptographicException) { /* malformed SAN: treated as absent */ }
        }
        return list;
    }

    /// <summary>RFC 6125 matching: case-insensitive, wildcard only as the complete left-most label and matching exactly one label.</summary>
    private static bool HostMatches(string pattern, string host)
    {
        pattern = pattern.Trim().TrimEnd('.');
        host = host.Trim().TrimEnd('.');
        if (pattern.Length == 0) return false;
        if (string.Equals(pattern, host, StringComparison.OrdinalIgnoreCase)) return true;
        if (!pattern.StartsWith("*.", StringComparison.Ordinal)) return false;
        string suffix = pattern[1..]; // ".example.com"
        if (suffix.Count(ch => ch == '.') < 2) return false; // no "*.com"
        if (!host.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)) return false;
        string label = host[..^suffix.Length];
        return label.Length > 0 && !label.Contains('.');
    }

    private static (bool Weak, string Hash) WeakSignature(Oid oid) => oid.Value switch
    {
        "1.2.840.113549.1.1.2" => (true, "MD2"),
        "1.2.840.113549.1.1.3" => (true, "MD4"),
        "1.2.840.113549.1.1.4" => (true, "MD5"),
        "1.2.840.113549.1.1.5" or "1.3.14.3.2.29" or "1.2.840.10045.4.1" or "1.2.840.10040.4.3" => (true, "SHA-1"),
        _ => (false, string.Empty),
    };

    private static string SigName(Oid oid) => oid.Value switch
    {
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.3" => "md4WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" or "1.3.14.3.2.29" => "sha1WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10040.4.3" => "dsa-with-SHA1",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "Ed25519",
        _ => oid.FriendlyName ?? oid.Value ?? "unknown",
    };

    private static int KeyBits(X509Certificate2 cert, out string alg)
    {
        alg = cert.PublicKey.Oid.Value switch
        {
            "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10" => "RSA",
            "1.2.840.10045.2.1" => "EC",
            "1.2.840.10040.4.1" => "DSA",
            "1.3.101.112" => "Ed25519",
            "1.3.101.113" => "Ed448",
            _ => cert.PublicKey.Oid.FriendlyName ?? "unknown",
        };
        try
        {
            switch (alg)
            {
                case "RSA":
                    using (var rsa = cert.GetRSAPublicKey()) return rsa?.KeySize ?? 0;
                case "EC":
                    using (var ec = cert.GetECDsaPublicKey()) return ec?.KeySize ?? 0;
                case "DSA":
                    using (var dsa = cert.GetDSAPublicKey()) return dsa?.KeySize ?? 0;
                case "Ed25519":
                    return 256;
                case "Ed448":
                    return 456;
                default:
                    return 0;
            }
        }
        catch (CryptographicException)
        {
            return 0;
        }
        catch (PlatformNotSupportedException)
        {
            return 0;
        }
    }

    private static string KeyDescription(X509Certificate2 cert)
    {
        int bits = KeyBits(cert, out string alg);
        return bits > 0 ? $"{alg} {bits} bits" : alg;
    }

    // ------------------------------------------------------------------ OS handshake

    private static async Task<OsHandshake?> OsHandshakeAsync(ScanContext ctx, OpenService svc, string? sni)
    {
        await ctx.GateAsync().ConfigureAwait(false);
        using var work = ctx.BeginWork();
        var sw = Stopwatch.StartNew();
        var result = new OsHandshake();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        try
        {
            using var tcp = new TcpClient(svc.Host.Address.AddressFamily);
            cts.CancelAfter(ctx.Options.ConnectTimeoutMs);
            await tcp.ConnectAsync(svc.Host.Address, svc.Port, cts.Token).ConfigureAwait(false);
            cts.CancelAfter(ctx.Options.ReadTimeoutMs);
            using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = sni ?? svc.Host.Ip,
                EnabledSslProtocols = SslProtocols.None,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = (_, cert, chain, errors) =>
                {
                    result.PolicyErrors = errors;
                    if (cert != null) result.Leaf = X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
                    if (chain != null)
                        for (int i = 1; i < chain.ChainElements.Count; i++)
                            result.Chain.Add(X509CertificateLoader.LoadCertificate(chain.ChainElements[i].Certificate.RawData));
                    return true; // audit only: validation is done separately
                },
            };
            await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);
            result.Protocol = ssl.SslProtocol;
            try { result.Cipher = ssl.NegotiatedCipherSuite.ToString(); }
            catch (NotSupportedException) { result.Cipher = string.Empty; }
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
            return result;
        }
        catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or AuthenticationException or CryptographicException or ObjectDisposedException)
        {
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds, true);
            ctx.Log(LogLevel.Debug, Src, $"{svc.Host.Ip}:{svc.Port} OS TLS handshake failed: {Describe(ex)}");
            // keep a certificate captured before the failure, if any
            return result.Leaf != null ? result : null;
        }
    }

    /// <summary>
    /// Used only when a raw probe was inconclusive (timeout / network error): retries with the OS TLS stack restricted to one version.
    /// A local refusal (the OS has the protocol disabled) is logged as "not testable from this machine", never reported as a finding.
    /// </summary>
    private static async Task<ProbeResult> OsProtocolFallbackAsync(ScanContext ctx, OpenService svc, string? sni, ushort version, ProbeResult raw)
    {
#pragma warning disable SYSLIB0039 // TLS 1.0/1.1 are requested deliberately to test whether the server still accepts them
        SslProtocols p = version switch { Tls10 => SslProtocols.Tls, Tls11 => SslProtocols.Tls11, Tls12 => SslProtocols.Tls12, _ => SslProtocols.Tls13 };
#pragma warning restore SYSLIB0039
        await ctx.GateAsync().ConfigureAwait(false);
        using var work = ctx.BeginWork();
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        bool connected = false;
        try
        {
            using var tcp = new TcpClient(svc.Host.Address.AddressFamily);
            cts.CancelAfter(ctx.Options.ConnectTimeoutMs);
            await tcp.ConnectAsync(svc.Host.Address, svc.Port, cts.Token).ConfigureAwait(false);
            connected = true;
            cts.CancelAfter(ctx.Options.ReadTimeoutMs);
            using var ssl = new SslStream(tcp.GetStream(), false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = sni ?? svc.Host.Ip,
                EnabledSslProtocols = p,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            }, cts.Token).ConfigureAwait(false);
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
            return new ProbeResult
            {
                Outcome = ssl.SslProtocol == p ? Outcome.Accepted : Outcome.Inconclusive,
                Version = version,
                SecureRenegotiation = true,
                Detail = $"(OS TLS stack fallback, negotiated {ProtocolName(ssl.SslProtocol)})",
            };
        }
        catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex) when (ex is OperationCanceledException or SocketException or IOException or AuthenticationException or ObjectDisposedException or NotSupportedException or ArgumentException)
        {
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds, !connected);
            ctx.Log(LogLevel.Debug, Src, $"{svc.Host.Ip}:{svc.Port} {VersionName(version)} not testable from this machine (raw probe {raw.Detail.Trim()}; OS stack: {Describe(ex)})");
            raw.Detail = "(not testable from this machine)";
            return raw;
        }
    }

    // ------------------------------------------------------------------ raw ClientHello probe

    private static ushort[] DefaultSuites(ushort version) => version == Tls13
        ? Suites.Where(s => (s.Cat & Cat.Tls13) != 0).Select(s => s.Id).ToArray()
        : Suites.Where(s => (s.Cat & (Cat.Tls13 | Cat.Null | Cat.Anon | Cat.Export)) == 0).Select(s => s.Id).ToArray();

    private static async Task<ProbeResult> ProbeAsync(ScanContext ctx, OpenService svc, string? sni, ushort version, IReadOnlyList<ushort> suites, bool deflate, bool wantCertificates)
    {
        await ctx.GateAsync().ConfigureAwait(false);
        using var work = ctx.BeginWork();
        var sw = Stopwatch.StartNew();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.Token);
        bool connected = false;
        try
        {
            using var tcp = new TcpClient(svc.Host.Address.AddressFamily) { NoDelay = true };
            cts.CancelAfter(ctx.Options.ConnectTimeoutMs);
            await tcp.ConnectAsync(svc.Host.Address, svc.Port, cts.Token).ConfigureAwait(false);
            connected = true;
            cts.CancelAfter(ctx.Options.ReadTimeoutMs);
            var stream = tcp.GetStream();
            byte[] hello = BuildClientHello(version, suites, sni, deflate);
            await stream.WriteAsync(hello, cts.Token).ConfigureAwait(false);
            var r = await ReadServerFlightAsync(stream, version, wantCertificates, cts.Token).ConfigureAwait(false);
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
            return r;
        }
        catch (OperationCanceledException) when (ctx.Token.IsCancellationRequested)
        {
            throw;
        }
        catch (OperationCanceledException)
        {
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds, true);
            return new ProbeResult { Outcome = Outcome.Inconclusive, Version = version, Detail = connected ? "(timeout waiting for ServerHello)" : "(connect timeout)" };
        }
        catch (Exception ex) when (ex is SocketException or IOException or ObjectDisposedException)
        {
            // Connection reset/closed right after our ClientHello is how many stacks refuse a protocol version.
            ctx.CountRequest(sw.Elapsed.TotalMilliseconds, !connected);
            return connected
                ? new ProbeResult { Outcome = Outcome.Rejected, Version = version, Detail = $"(connection closed: {Describe(ex)})" }
                : new ProbeResult { Outcome = Outcome.Inconclusive, Version = version, Detail = $"(connect failed: {Describe(ex)})" };
        }
    }

    private static byte[] BuildClientHello(ushort version, IReadOnlyList<ushort> suites, string? sni, bool deflate)
    {
        var body = new List<byte>(512);
        ushort legacyVersion = version == Tls13 ? Tls12 : version;
        Put16(body, legacyVersion);
        body.AddRange(RandomNumberGenerator.GetBytes(32));
        if (version == Tls13)
        {
            body.Add(32);
            body.AddRange(RandomNumberGenerator.GetBytes(32)); // middlebox-compatibility session id
        }
        else
        {
            body.Add(0);
        }

        var cs = new List<ushort>(suites);
        if (version == Ssl30) cs.Add(0x00FF); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (SSL 3.0 has no extensions)
        Put16(body, cs.Count * 2);
        foreach (var s in cs) Put16(body, s);

        if (deflate) body.AddRange(new byte[] { 2, 1, 0 });
        else body.AddRange(new byte[] { 1, 0 });

        if (version != Ssl30)
        {
            var ext = new List<byte>(256);
            if (sni != null)
            {
                byte[] name = Encoding.ASCII.GetBytes(sni);
                var d = new List<byte>();
                Put16(d, name.Length + 3);
                d.Add(0);
                Put16(d, name.Length);
                d.AddRange(name);
                AddExt(ext, 0x0000, d);
            }
            // supported_groups: x25519, secp256r1, secp384r1, secp521r1, x448, ffdhe2048, ffdhe3072
            AddExt(ext, 0x000A, U16List(0x001D, 0x0017, 0x0018, 0x0019, 0x001E, 0x0100, 0x0101));
            AddExt(ext, 0x000B, new List<byte> { 1, 0 }); // ec_point_formats: uncompressed
            if (version >= Tls12)
                AddExt(ext, 0x000D, U16List(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0807, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201, 0x0402, 0x0202));
            AddExt(ext, 0xFF01, new List<byte> { 0 }); // renegotiation_info (initial handshake)
            if (version == Tls13)
            {
                AddExt(ext, 0x002B, new List<byte> { 2, 0x03, 0x04 }); // supported_versions: TLS 1.3 only
                // key_share: a genuine ephemeral P-256 public key (some stacks, e.g. SChannel, reject arbitrary X25519 bytes with
                // decode_error). Servers preferring another group answer with a HelloRetryRequest, which still proves TLS 1.3 support.
                var pub = new List<byte> { 4 };
                using (var ecdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256))
                {
                    var q = ecdh.ExportParameters(false).Q;
                    pub.AddRange(q.X ?? Array.Empty<byte>());
                    pub.AddRange(q.Y ?? Array.Empty<byte>());
                }
                var ks = new List<byte>();
                Put16(ks, 2 + 2 + pub.Count);
                Put16(ks, 0x0017);
                Put16(ks, pub.Count);
                ks.AddRange(pub);
                AddExt(ext, 0x0033, ks);
                AddExt(ext, 0x002D, new List<byte> { 1, 1 }); // psk_key_exchange_modes: psk_dhe_ke
            }
            Put16(body, ext.Count);
            body.AddRange(ext);
        }

        var msg = new List<byte>(body.Count + 9) { 0x16 };
        Put16(msg, version == Ssl30 ? Ssl30 : Tls10); // record-layer version
        Put16(msg, body.Count + 4);
        msg.Add(0x01); // client_hello
        msg.Add((byte)(body.Count >> 16));
        msg.Add((byte)(body.Count >> 8));
        msg.Add((byte)body.Count);
        msg.AddRange(body);
        return msg.ToArray();
    }

    private static async Task<ProbeResult> ReadServerFlightAsync(Stream stream, ushort offered, bool wantCertificates, CancellationToken token)
    {
        var result = new ProbeResult { Outcome = Outcome.Rejected, Version = offered };
        var hs = new List<byte>();
        int total = 0;
        bool gotHello = false;
        byte[] header = new byte[5];
        while (total < 256 * 1024)
        {
            if (!await ReadExactAsync(stream, header, token).ConfigureAwait(false))
            {
                result.Detail = gotHello ? result.Detail : "(connection closed without ServerHello)";
                return result;
            }
            byte type = header[0];
            int len = (header[3] << 8) | header[4];
            if (type is < 20 or > 24 || header[1] != 3 || len > 18432)
            {
                result.Outcome = gotHello ? result.Outcome : Outcome.Rejected;
                if (!gotHello) result.Detail = $"(non-TLS response: {Convert.ToHexString(header)})";
                return result;
            }
            byte[] payload = new byte[len];
            if (!await ReadExactAsync(stream, payload, token).ConfigureAwait(false)) return result;
            total += len + 5;

            if (type == 21) // alert
            {
                if (!gotHello)
                {
                    result.Outcome = Outcome.Rejected;
                    result.Detail = len >= 2 ? $"(alert {AlertName(payload[1])})" : "(alert)";
                }
                return result;
            }
            if (type != 22) // change_cipher_spec / application data: server flight is now encrypted
                return result;

            hs.AddRange(payload);
            while (hs.Count >= 4)
            {
                int mlen = (hs[1] << 16) | (hs[2] << 8) | hs[3];
                if (hs.Count < 4 + mlen) break;
                byte mtype = hs[0];
                byte[] m = hs.GetRange(4, mlen).ToArray();
                hs.RemoveRange(0, 4 + mlen);
                switch (mtype)
                {
                    case 2: // server_hello
                        ParseServerHello(m, result);
                        gotHello = true;
                        result.Outcome = result.Version == offered ? Outcome.Accepted : Outcome.Rejected;
                        if (result.Outcome == Outcome.Rejected) result.Detail = $"(server answered with {VersionName(result.Version)})";
                        if (!wantCertificates || result.Version == Tls13 || result.Outcome != Outcome.Accepted) return result;
                        break;
                    case 11: // certificate (TLS <= 1.2 only, in clear)
                        ParseCertificates(m, result.Certificates);
                        return result;
                    case 14: // server_hello_done
                        return result;
                }
            }
        }
        return result;
    }

    private static void ParseServerHello(byte[] m, ProbeResult r)
    {
        int p = 0;
        if (m.Length < 38) { r.Detail = "(short ServerHello)"; return; }
        r.Version = (ushort)((m[0] << 8) | m[1]);
        r.HelloRetry = m.AsSpan(2, 32).SequenceEqual(HelloRetryRandom);
        p = 34;
        int sid = m[p++];
        p += sid;
        if (p + 3 > m.Length) return;
        r.Cipher = (ushort)((m[p] << 8) | m[p + 1]);
        p += 2;
        r.Compression = m[p++];
        if (p + 2 > m.Length) return;
        int extLen = (m[p] << 8) | m[p + 1];
        p += 2;
        int end = Math.Min(m.Length, p + extLen);
        while (p + 4 <= end)
        {
            int et = (m[p] << 8) | m[p + 1];
            int el = (m[p + 2] << 8) | m[p + 3];
            p += 4;
            if (p + el > end) break;
            if (et == 0x002B && el == 2) r.Version = (ushort)((m[p] << 8) | m[p + 1]);
            if (et == 0xFF01) r.SecureRenegotiation = true;
            p += el;
        }
        if (r.HelloRetry) r.Detail = "(HelloRetryRequest)";
    }

    private static void ParseCertificates(byte[] m, List<byte[]> into)
    {
        if (m.Length < 3) return;
        int total = (m[0] << 16) | (m[1] << 8) | m[2];
        int p = 3, end = Math.Min(m.Length, 3 + total);
        while (p + 3 <= end && into.Count < 10)
        {
            int len = (m[p] << 16) | (m[p + 1] << 8) | m[p + 2];
            p += 3;
            if (len <= 0 || p + len > end) break;
            into.Add(m.AsSpan(p, len).ToArray());
            p += len;
        }
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, CancellationToken token)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(read), token).ConfigureAwait(false);
            if (n == 0) return false;
            read += n;
        }
        return true;
    }

    // ------------------------------------------------------------------ helpers

    private static void Add(ScanContext ctx, OpenService svc, Severity sev, string title, int cwe, string description, string evidence, string remediation) =>
        ctx.AddFinding(sev, title, svc.Host.Ip, svc.Port, cwe, description, $"{svc.Host.Ip}:{svc.Port}/tcp ({svc.Service})\n{evidence}", remediation);

    private static string? SniName(LiveHost host)
    {
        string h = host.Hostname.Trim().TrimEnd('.');
        if (h.Length == 0 || IPAddress.TryParse(h, out _)) return null;
        foreach (char c in h)
            if (c > 127 || !(char.IsLetterOrDigit(c) || c is '-' or '.' or '_')) return null;
        return h;
    }

    private static void Put16(List<byte> b, int v)
    {
        b.Add((byte)(v >> 8));
        b.Add((byte)v);
    }

    private static List<byte> U16List(params ushort[] values)
    {
        var l = new List<byte>(values.Length * 2 + 2);
        Put16(l, values.Length * 2);
        foreach (var v in values) Put16(l, v);
        return l;
    }

    private static void AddExt(List<byte> ext, ushort type, List<byte> data)
    {
        Put16(ext, type);
        Put16(ext, data.Count);
        ext.AddRange(data);
    }

    private static string SuiteName(ushort id) => SuiteById.TryGetValue(id, out var s) ? s.Name : $"0x{id:X4}";

    private static string VersionName(ushort v) => v switch
    {
        Ssl30 => "SSL 3.0",
        Tls10 => "TLS 1.0",
        Tls11 => "TLS 1.1",
        Tls12 => "TLS 1.2",
        Tls13 => "TLS 1.3",
        _ => $"0x{v:X4}",
    };

#pragma warning disable SYSLIB0039, CS0618 // naming legacy protocol values only
    private static string ProtocolName(SslProtocols p) => p switch
    {
        SslProtocols.Ssl3 => "SSL 3.0",
        SslProtocols.Tls => "TLS 1.0",
        SslProtocols.Tls11 => "TLS 1.1",
        SslProtocols.Tls12 => "TLS 1.2",
        SslProtocols.Tls13 => "TLS 1.3",
        _ => p.ToString(),
    };
#pragma warning restore SYSLIB0039, CS0618

    private static string AlertName(byte d) => d switch
    {
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        47 => "illegal_parameter",
        50 => "decode_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        109 => "missing_extension",
        112 => "unrecognized_name",
        _ => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    private static string Describe(Exception ex)
    {
        var inner = ex.InnerException;
        return inner != null && inner.Message != ex.Message ? $"{ex.Message} ({inner.Message})" : ex.Message;
    }
}
