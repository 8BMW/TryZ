using System.Buffers.Binary;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Real service identification on an open TCP port: server greetings, TLS handshake, HTTP request,
/// and protocol-specific read-only handshakes (RDP, SMB, MongoDB, MSSQL, PostgreSQL, Redis, Memcached, VNC, SSH KEXINIT).
/// The only login ever attempted is the standard anonymous FTP check.
/// </summary>
internal static class ServiceProbe
{
    // Ports where a silent server is expected; only wait briefly for a greeting before moving on.
    private static readonly HashSet<int> PlainHttpPorts = new()
    {
        80, 81, 591, 2082, 2086, 3000, 3128, 4848, 5000, 5001, 5601, 5800, 5985, 7001, 8000, 8008, 8080, 8081, 8086, 8088,
        8180, 8500, 8888, 9000, 9090, 9200, 15672, 50070,
    };

    private static readonly HashSet<int> TlsPorts = new()
    {
        443, 636, 853, 2083, 2087, 3269, 4443, 5061, 5986, 6443, 7443, 8443, 8883, 9443, 10000, 10250,
    };

    // Implicit-TLS services that greet the client after the handshake.
    private static readonly HashSet<int> TlsGreetingPorts = new() { 465, 563, 990, 992, 993, 995, 6697 };

    /// <summary>Banner grab / protocol probes to identify the service, product and version on an open port.</summary>
    public static async Task<OpenService> IdentifyAsync(ScanContext ctx, LiveHost host, int port)
    {
        var svc = new OpenService { Host = host, Port = port, Service = PortLists.GuessService(port) };
        await ctx.Concurrency.WaitAsync(ctx.Token).ConfigureAwait(false);
        try
        {
            using var work = ctx.BeginWork();
            await new Prober(ctx, svc).RunAsync().ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ctx.Token.IsCancellationRequested)
        {
            ctx.Log(LogLevel.Debug, "service", $"{host.Ip}:{port} identification timed out");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // Network I/O against arbitrary services: any failure just ends identification for this port.
            ctx.Token.ThrowIfCancellationRequested();
            ctx.Log(LogLevel.Debug, "service", $"{host.Ip}:{port} probe error: {ex.GetType().Name}: {ex.Message}");
        }
        finally
        {
            ctx.Concurrency.Release();
        }

        if (string.IsNullOrEmpty(svc.Service)) svc.Service = PortLists.GuessService(port);
        svc.Banner = Text.Sanitize(svc.Banner);
        if (svc.Product.Length > 0 || svc.Facts.Count > 0)
        {
            string facts = string.Join(", ", svc.Facts.Where(f => !f.Key.StartsWith("ssh.", StringComparison.Ordinal) || f.Key == "ssh.protocol")
                .Take(8).Select(f => $"{f.Key}={Text.Clip(f.Value, 60)}"));
            ctx.Log(LogLevel.Debug, "service", $"{host.Ip}:{port} {svc.Service} {svc.DisplayBanner} {facts}".TrimEnd());
        }
        return svc;
    }

    // ====================================================================== prober

    private sealed class Prober(ScanContext ctx, OpenService svc)
    {
        private int Port => svc.Port;
        private LiveHost Host => svc.Host;
        private string Endpoint => $"{Host.Ip}:{Port}";
        private int ReadMs => ctx.Options.ReadTimeoutMs;

        private string Sni => IPAddress.TryParse(Host.Hostname, out _) ? string.Empty : Host.Hostname;

        public async Task RunAsync()
        {
            bool identified = Port switch
            {
                3389 => await RdpAsync().ConfigureAwait(false),
                445 => await SmbAsync(netbios: false).ConfigureAwait(false),
                139 => await SmbAsync(netbios: true).ConfigureAwait(false),
                27017 or 27018 or 27019 => await MongoAsync().ConfigureAwait(false),
                11211 => await MemcachedAsync().ConfigureAwait(false),
                5432 => await PostgresAsync().ConfigureAwait(false),
                1433 => await MssqlAsync().ConfigureAwait(false),
                6379 => await RedisAsync().ConfigureAwait(false),
                _ => false,
            };
            if (!identified) await GenericAsync().ConfigureAwait(false);
        }

        private Task<Conn?> OpenAsync() => Conn.OpenAsync(ctx, Host.Address, Port);

        // ------------------------------------------------------------------ generic flow

        private async Task GenericAsync()
        {
            var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return;
            try
            {
                bool shortWait = PlainHttpPorts.Contains(Port) || TlsPorts.Contains(Port) || TlsGreetingPorts.Contains(Port);
                int greetMs = shortWait ? Math.Min(400, ReadMs) : Math.Min(1500, ReadMs);
                if (await conn.WaitForDataAsync(greetMs).ConfigureAwait(false))
                {
                    var greeting = await conn.ReceiveAsync(null, Math.Min(ReadMs, 2500), idleMs: 350).ConfigureAwait(false);
                    if (greeting.Length > 0)
                    {
                        await ClassifyGreetingAsync(conn, greeting).ConfigureAwait(false);
                        return;
                    }
                    if (conn.Closed)
                    {
                        svc.Facts["tcpwrapped"] = "true";
                        svc.Banner = string.Empty;
                        ctx.Log(LogLevel.Debug, "service", $"{Endpoint} closed the connection without data (tcpwrapped)");
                        return;
                    }
                }

                if (PlainHttpPorts.Contains(Port))
                {
                    var outcome = await HttpExchangeAsync(conn).ConfigureAwait(false);
                    if (outcome is HttpOutcome.Http or HttpOutcome.Other) return;
                    await conn.DisposeAsync().ConfigureAwait(false);
                    conn = await OpenAsync().ConfigureAwait(false);
                    if (conn is null) return;
                    if (await conn.UpgradeTlsAsync(Sni).ConfigureAwait(false))
                    {
                        CaptureTls(conn);
                        await AfterTlsAsync(conn).ConfigureAwait(false);
                    }
                    return;
                }

                if (await conn.UpgradeTlsAsync(Sni).ConfigureAwait(false))
                {
                    CaptureTls(conn);
                    await AfterTlsAsync(conn).ConfigureAwait(false);
                    return;
                }

                await conn.DisposeAsync().ConfigureAwait(false);
                conn = await OpenAsync().ConfigureAwait(false);
                if (conn is null) return;
                await HttpExchangeAsync(conn).ConfigureAwait(false);
            }
            finally
            {
                if (conn is not null) await conn.DisposeAsync().ConfigureAwait(false);
            }
        }

        private async Task AfterTlsAsync(Conn conn)
        {
            if (TlsGreetingPorts.Contains(Port))
            {
                var greeting = await conn.ReceiveAsync(null, Math.Min(ReadMs, 2000), idleMs: 350).ConfigureAwait(false);
                if (greeting.Length > 0)
                {
                    await ClassifyGreetingAsync(conn, greeting).ConfigureAwait(false);
                    return;
                }
            }
            var outcome = await HttpExchangeAsync(conn).ConfigureAwait(false);
            if (outcome == HttpOutcome.None && svc.Service is "unknown" or "" ) svc.Service = "ssl";
        }

        private void CaptureTls(Conn conn)
        {
            var ssl = conn.Ssl;
            if (ssl is null) return;
            svc.Tls = true;
            svc.Facts["tls.protocol"] = Text.TlsName(ssl.SslProtocol);
            try
            {
                svc.Facts["tls.cipher"] = ssl.NegotiatedCipherSuite.ToString();
            }
            catch (NotSupportedException)
            {
            }
            if (Sni.Length > 0) svc.Facts["tls.sni"] = Sni;
            var cert = CopyCertificate(ssl.RemoteCertificate);
            if (cert is null) return;
            svc.Certificate = cert;
            svc.Facts["tls.subject"] = cert.Subject;
            svc.Facts["tls.issuer"] = cert.Issuer;
            svc.Facts["tls.not_after"] = cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
        }

        private static X509Certificate2? CopyCertificate(X509Certificate? cert)
        {
            if (cert is null) return null;
            try
            {
                return X509CertificateLoader.LoadCertificate(cert.GetRawCertData());
            }
            catch (CryptographicException)
            {
                return null;
            }
        }

        // ------------------------------------------------------------------ greeting classification

        private async Task ClassifyGreetingAsync(Conn conn, byte[] data)
        {
            string text = Text.Latin1(data);
            svc.Banner = text;

            if (data.Length >= 3 && data[0] == 0xFF && data[1] >= 0xFA)
            {
                await TelnetAsync(conn, data).ConfigureAwait(false);
                return;
            }
            int sshAt = text.StartsWith("SSH-", StringComparison.Ordinal) ? 0 : text.IndexOf("\nSSH-", StringComparison.Ordinal) + 1;
            if (sshAt >= 0 && (sshAt > 0 || text.StartsWith("SSH-", StringComparison.Ordinal)))
            {
                await SshAsync(conn, data, sshAt).ConfigureAwait(false);
                return;
            }
            if (TryMySql(data)) return;
            if (text.StartsWith("RFB ", StringComparison.Ordinal))
            {
                await VncAsync(conn, text).ConfigureAwait(false);
                return;
            }
            if (text.StartsWith("220", StringComparison.Ordinal))
            {
                await Handle220Async(conn, data).ConfigureAwait(false);
                return;
            }
            if (text.StartsWith("+OK", StringComparison.Ordinal))
            {
                await Pop3Async(conn, text).ConfigureAwait(false);
                return;
            }
            if (text.StartsWith("* OK", StringComparison.Ordinal) || text.StartsWith("* PREAUTH", StringComparison.Ordinal))
            {
                await ImapAsync(conn, text).ConfigureAwait(false);
                return;
            }
            if (text.StartsWith("@RSYNCD:", StringComparison.Ordinal))
            {
                svc.Service = "rsync";
                svc.Product = "rsync";
                var m = Regex.Match(text, @"@RSYNCD:\s*([\d.]+)");
                if (m.Success) svc.Facts["rsync.protocol"] = m.Groups[1].Value;
                return;
            }
            if (text.StartsWith("HTTP/", StringComparison.Ordinal))
            {
                ParseHttp(data);
                return;
            }
            if (text.StartsWith(':') && text.Contains(" NOTICE ", StringComparison.Ordinal))
            {
                svc.Service = "irc";
                return;
            }
            if (Regex.IsMatch(text, @"^20[01] .*\b(NNTP|news)", RegexOptions.IgnoreCase))
            {
                svc.Service = "nntp";
                return;
            }
            // Unrecognised greeting: keep it as the banner, port-based service name stays.
            svc.Banner = FirstLines(text, 2);
        }

        // ------------------------------------------------------------------ SSH

        private async Task SshAsync(Conn conn, byte[] data, int at)
        {
            string text = Text.Latin1(data);
            int eol = text.IndexOf('\n', at);
            string line = (eol >= 0 ? text[at..eol] : text[at..]).TrimEnd('\r');
            svc.Service = "ssh";
            svc.Banner = line;
            var m = Regex.Match(line, @"^SSH-(?<proto>[\d.]+)-(?<soft>\S+)(?:\s+(?<comment>.*))?$");
            if (!m.Success) return;
            string proto = m.Groups["proto"].Value, soft = m.Groups["soft"].Value, comment = m.Groups["comment"].Value.Trim();
            svc.Facts["ssh.protocol"] = proto;
            if (comment.Length > 0) svc.Facts["ssh.comment"] = comment;
            (svc.Product, svc.Version) = ParseSshSoftware(soft);
            var os = Regex.Match(comment, @"(Ubuntu|Debian|FreeBSD|Raspbian|CentOS|Red Hat|Fedora|Alpine)", RegexOptions.IgnoreCase);
            if (os.Success) svc.Facts["os.hint"] = os.Groups[1].Value;

            if (proto is not ("2.0" or "1.99")) return;
            // Read the server KEXINIT (algorithm lists) exactly like ssh2-enum-algos; no key exchange is performed.
            byte[] rest = eol >= 0 && eol + 1 < data.Length ? data[(eol + 1)..] : Array.Empty<byte>();
            if (!await conn.SendAsync(Encoding.ASCII.GetBytes("SSH-2.0-TryZ_Scanner_1.0\r\n")).ConfigureAwait(false)) return;
            var sw = Stopwatch.StartNew();
            var packet = await conn.ReceiveAsync(SshPacketComplete, ReadMs, prefix: rest, max: 40000).ConfigureAwait(false);
            ctx.CountRequest(packet.Length > rest.Length ? sw.Elapsed.TotalMilliseconds : -1);
            ParseKexInit(packet);
        }

        private static bool SshPacketComplete(ReadOnlySpan<byte> d) =>
            d.Length >= 5 && (BinaryPrimitives.ReadUInt32BigEndian(d) is var len && (len > 35000 || d.Length >= 4 + len));

        private void ParseKexInit(byte[] d)
        {
            if (d.Length < 6) return;
            uint plen = BinaryPrimitives.ReadUInt32BigEndian(d);
            if (plen > 35000 || d.Length < 4 + plen) return;
            int pad = d[4];
            int end = 4 + (int)plen - pad;
            int p = 5;
            if (end <= p || d[p] != 20) return; // SSH_MSG_KEXINIT
            p += 1 + 16;
            var names = new string[10];
            for (int k = 0; k < names.Length; k++)
            {
                if (p + 4 > end) return;
                int l = (int)BinaryPrimitives.ReadUInt32BigEndian(d.AsSpan(p));
                p += 4;
                if (l < 0 || p + l > end) return;
                names[k] = Encoding.ASCII.GetString(d, p, l);
                p += l;
            }
            svc.Facts["ssh.kex_algorithms"] = names[0];
            svc.Facts["ssh.hostkey_algorithms"] = names[1];
            svc.Facts["ssh.ciphers"] = names[2];
            svc.Facts["ssh.macs"] = names[4];
            svc.Facts["ssh.compression"] = names[6];
        }

        private static (string Product, string Version) ParseSshSoftware(string soft)
        {
            Match m;
            if ((m = Regex.Match(soft, @"^OpenSSH_for_Windows_([\w.]+)", RegexOptions.IgnoreCase)).Success) return ("OpenSSH for Windows", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^OpenSSH[_-]([\w.]+)", RegexOptions.IgnoreCase)).Success) return ("OpenSSH", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^dropbear(?:[_-]([\w.]+))?", RegexOptions.IgnoreCase)).Success) return ("Dropbear sshd", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^libssh[_-]?([\w.]+)?", RegexOptions.IgnoreCase)).Success) return ("libssh", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^Cisco-([\w.]+)", RegexOptions.IgnoreCase)).Success) return ("Cisco SSH", m.Groups[1].Value);
            if (soft.StartsWith("ROSSSH", StringComparison.OrdinalIgnoreCase)) return ("MikroTik RouterOS sshd", string.Empty);
            if ((m = Regex.Match(soft, @"^mod_sftp(?:/([\w.]+))?", RegexOptions.IgnoreCase)).Success) return ("ProFTPD mod_sftp", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^WeOnlyDo(?:-wodFTPD)?[_ ]?([\d.]+)?", RegexOptions.IgnoreCase)).Success) return ("WeOnlyDo sshd", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^Bitvise SSH Server \(WinSSHD\) ([\d.]+)", RegexOptions.IgnoreCase)).Success) return ("Bitvise WinSSHD", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^AsyncSSH_([\w.]+)", RegexOptions.IgnoreCase)).Success) return ("AsyncSSH", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^paramiko_([\w.]+)", RegexOptions.IgnoreCase)).Success) return ("Paramiko", m.Groups[1].Value);
            if ((m = Regex.Match(soft, @"^Go$", RegexOptions.IgnoreCase)).Success) return ("Go x/crypto/ssh", string.Empty);
            if ((m = Regex.Match(soft, @"^([A-Za-z][A-Za-z.]*)[_-]([\d][\w.]*)$")).Success) return (m.Groups[1].Value, m.Groups[2].Value);
            return (soft, string.Empty);
        }

        // ------------------------------------------------------------------ MySQL / MariaDB

        private bool TryMySql(byte[] d)
        {
            if (d.Length < 6 || d[3] != 0) return false;
            int len = d[0] | d[1] << 8 | d[2] << 16;
            if (len < 2 || len > 1024 || len > d.Length - 4 + 512) return false;
            if (d[4] == 0xFF && d.Length >= 8)
            {
                // ERR packet: e.g. "Host 'x' is not allowed to connect to this MySQL server"
                string msg = Encoding.UTF8.GetString(d, 7, Math.Min(len - 3, d.Length - 7));
                if (!msg.Contains("MySQL", StringComparison.OrdinalIgnoreCase) && !msg.Contains("MariaDB", StringComparison.OrdinalIgnoreCase)
                    && !msg.Contains("not allowed to connect", StringComparison.OrdinalIgnoreCase)) return false;
                svc.Service = "mysql";
                svc.Product = msg.Contains("MariaDB", StringComparison.OrdinalIgnoreCase) ? "MariaDB" : "MySQL";
                svc.Facts["mysql.rejected"] = "true";
                svc.Banner = msg;
                return true;
            }
            if (d[4] != 10) return false;
            int nul = Array.IndexOf(d, (byte)0, 5);
            if (nul < 0 || nul - 5 > 120) return false;
            string version = Encoding.ASCII.GetString(d, 5, nul - 5);
            if (!Regex.IsMatch(version, @"^\d+\.\d+")) return false;

            svc.Service = "mysql";
            svc.Banner = version;
            var maria = Regex.Match(version, @"^(?:5\.5\.5-)?([\d.]+)-MariaDB", RegexOptions.IgnoreCase);
            if (maria.Success)
            {
                svc.Product = "MariaDB";
                svc.Version = maria.Groups[1].Value;
            }
            else
            {
                svc.Product = "MySQL";
                svc.Version = Regex.Match(version, @"^[\d.]+").Value;
            }
            if (version.Length > svc.Version.Length) svc.Facts["mysql.version_string"] = version;
            // thread id(4) + auth data 1 (8) + filler(1) + capability flags low (2)
            int cap = nul + 1 + 4 + 8 + 1;
            if (cap + 2 <= d.Length)
            {
                int flags = d[cap] | d[cap + 1] << 8;
                svc.Facts["mysql.ssl"] = (flags & 0x0800) != 0 ? "true" : "false";
            }
            var plugin = Regex.Match(Text.Latin1(d), @"(mysql_native_password|caching_sha2_password|sha256_password|auth_gssapi_client|client_ed25519|mysql_old_password)");
            if (plugin.Success) svc.Facts["mysql.auth_plugin"] = plugin.Value;
            return true;
        }

        // ------------------------------------------------------------------ VNC

        private async Task VncAsync(Conn conn, string text)
        {
            var m = Regex.Match(text, @"^RFB (\d{3})\.(\d{3})");
            svc.Service = "vnc";
            svc.Product = "VNC";
            if (!m.Success) return;
            int major = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture), minor = int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture);
            svc.Version = $"protocol {major}.{minor}";
            svc.Banner = m.Value;
            if (minor == 889) svc.Product = "Apple remote desktop vnc";
            string reply = major > 3 || minor >= 8 ? "RFB 003.008\n" : minor == 7 ? "RFB 003.007\n" : "RFB 003.003\n";
            var sw = Stopwatch.StartNew();
            if (!await conn.SendAsync(Encoding.ASCII.GetBytes(reply)).ConfigureAwait(false)) return;
            bool v33 = reply == "RFB 003.003\n";
            var data = await conn.ReceiveAsync(d => v33 ? d.Length >= 4 : d.Length >= 1 && d.Length >= 1 + d[0], ReadMs).ConfigureAwait(false);
            ctx.CountRequest(data.Length > 0 ? sw.Elapsed.TotalMilliseconds : -1);
            var types = new List<int>();
            if (v33 && data.Length >= 4)
            {
                types.Add((int)BinaryPrimitives.ReadUInt32BigEndian(data));
            }
            else if (!v33 && data.Length >= 1)
            {
                int n = data[0];
                for (int i = 1; i <= n && i < data.Length; i++) types.Add(data[i]);
                if (n == 0) svc.Facts["vnc.error"] = Text.Sanitize(Text.Latin1(data.AsSpan(Math.Min(5, data.Length)).ToArray()), 120);
            }
            if (types.Count == 0) return;
            svc.Facts["vnc.security_types"] = string.Join(",", types.Select(VncSecurityName));
            svc.Facts["vnc.noauth"] = types.Contains(1) ? "true" : "false";
            if (types.Contains(30)) svc.Product = "Apple remote desktop vnc";
        }

        private static string VncSecurityName(int t) => t switch
        {
            0 => "Invalid",
            1 => "None",
            2 => "VNC Authentication",
            5 => "RA2",
            6 => "RA2ne",
            16 => "Tight",
            17 => "Ultra",
            18 => "TLS",
            19 => "VeNCrypt",
            30 => "Apple ARD",
            113 or 117 => "UltraVNC MS-Logon",
            _ => t.ToString(CultureInfo.InvariantCulture),
        };

        // ------------------------------------------------------------------ Telnet

        private async Task TelnetAsync(Conn conn, byte[] first)
        {
            svc.Service = svc.Tls ? "telnets" : "telnet";
            var text = new List<byte>();
            var data = first;
            for (int round = 0; round < 4 && data.Length > 0; round++)
            {
                var reply = new List<byte>();
                ParseTelnet(data, text, reply);
                if (reply.Count > 0 && !await conn.SendAsync(reply.ToArray()).ConfigureAwait(false)) break;
                if (reply.Count == 0 && text.Count(b => b > 0x20 && b < 0x7F) >= 6) break;
                data = await conn.ReceiveAsync(null, Math.Min(ReadMs, 1500), idleMs: 300).ConfigureAwait(false);
            }
            string banner = Text.Latin1(text.ToArray());
            svc.Banner = banner;
            if (Regex.IsMatch(banner, @"login:|username:|user name:", RegexOptions.IgnoreCase)) svc.Facts["telnet.login_prompt"] = "true";
            if (banner.Contains("User Access Verification", StringComparison.Ordinal)) svc.Product = "Cisco telnetd";
            else if (banner.Contains("MikroTik", StringComparison.OrdinalIgnoreCase)) svc.Product = "MikroTik RouterOS telnetd";
            else if (banner.Contains("Microsoft Telnet", StringComparison.OrdinalIgnoreCase)) svc.Product = "Microsoft Windows telnetd";
            else if (banner.Contains("BusyBox", StringComparison.OrdinalIgnoreCase)) svc.Product = "BusyBox telnetd";
            else svc.Product = "telnetd";
        }

        private static void ParseTelnet(byte[] data, List<byte> text, List<byte> reply)
        {
            for (int i = 0; i < data.Length; i++)
            {
                byte b = data[i];
                if (b != 0xFF)
                {
                    text.Add(b);
                    continue;
                }
                if (i + 1 >= data.Length) break;
                byte cmd = data[i + 1];
                if (cmd is >= 251 and <= 254)
                {
                    if (i + 2 >= data.Length) break;
                    byte opt = data[i + 2];
                    if (cmd == 253) reply.AddRange(new byte[] { 0xFF, 252, opt });      // DO   -> WONT
                    else if (cmd == 251) reply.AddRange(new byte[] { 0xFF, 254, opt }); // WILL -> DONT
                    i += 2;
                }
                else if (cmd == 250)
                {
                    int se = i + 2;
                    while (se + 1 < data.Length && !(data[se] == 0xFF && data[se + 1] == 240)) se++;
                    i = se + 1;
                }
                else if (cmd == 0xFF)
                {
                    text.Add(0xFF);
                    i++;
                }
                else
                {
                    i++;
                }
            }
        }

        // ------------------------------------------------------------------ FTP / SMTP (220 greetings)

        private static readonly Regex SmtpWords = new(@"\b(E?SMTP|Postfix|Exim|Sendmail|MTA|mail|Exchange|qmail|Haraka)\b", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex FtpWords = new(@"\bFTP\b|FTPd|FileZilla|ProFTPD|Pure-FTPd|Serv-U|vsFTPd|wu-[\d.]", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private async Task Handle220Async(Conn conn, byte[] data)
        {
            data = await ReadReplyAsync(conn, data).ConfigureAwait(false);
            string text = Text.Latin1(data);
            svc.Banner = FirstLines(text, 3);
            bool smtp = SmtpWords.IsMatch(text), ftp = FtpWords.IsMatch(text);
            bool isFtp = ftp && !smtp || (ftp == smtp && Port is 21 or 990 or 2121 or 2021 or 8021);
            bool isSmtp = smtp && !ftp || (ftp == smtp && Port is 25 or 465 or 587 or 2525 or 26);
            if (isFtp) await FtpAsync(conn, text).ConfigureAwait(false);
            else if (isSmtp) await SmtpAsync(conn, text).ConfigureAwait(false);
        }

        private static bool ReplyComplete(ReadOnlySpan<byte> d)
        {
            // RFC 959/5321 multi-line replies end with a line "ddd " (code followed by a space).
            string s = Text.Latin1(d.ToArray());
            if (!s.EndsWith('\n')) return false;
            var lines = s.Split('\n', StringSplitOptions.RemoveEmptyEntries);
            string last = lines.Length > 0 ? lines[^1].TrimEnd('\r') : string.Empty;
            return last.Length >= 3 && char.IsAsciiDigit(last[0]) && char.IsAsciiDigit(last[1]) && char.IsAsciiDigit(last[2])
                   && (last.Length == 3 || last[3] == ' ');
        }

        private async Task<byte[]> ReadReplyAsync(Conn conn, byte[] have)
        {
            if (ReplyComplete(have)) return have;
            return await conn.ReceiveAsync(ReplyComplete, ReadMs, prefix: have, max: 16384).ConfigureAwait(false);
        }

        private async Task<string> CommandAsync(Conn conn, string line)
        {
            var reply = await conn.ExchangeAsync(Encoding.ASCII.GetBytes(line + "\r\n"), ReplyComplete, ReadMs, max: 16384).ConfigureAwait(false);
            return Text.Latin1(reply);
        }

        private static readonly (Regex Re, string Product)[] FtpRules =
        {
            (new Regex(@"\(vsFTPd ([\d.]+)\)", RegexOptions.IgnoreCase), "vsftpd"),
            (new Regex(@"vsFTPd()", RegexOptions.IgnoreCase), "vsftpd"),
            (new Regex(@"ProFTPD(?: ([\d.]+[a-z]?\d*))?", RegexOptions.IgnoreCase), "ProFTPD"),
            (new Regex(@"Pure-FTPd()", RegexOptions.IgnoreCase), "Pure-FTPd"),
            (new Regex(@"FileZilla Server(?: version)?\s*([\d.]+(?: ?beta)?)?", RegexOptions.IgnoreCase), "FileZilla ftpd"),
            (new Regex(@"Microsoft FTP Service()", RegexOptions.IgnoreCase), "Microsoft ftpd"),
            (new Regex(@"Serv-U FTP Server v?([\d.]+)?", RegexOptions.IgnoreCase), "Serv-U ftpd"),
            (new Regex(@"\bwu-([\d.]+(?:\(\d+\))?)", RegexOptions.IgnoreCase), "WU-FTPD"),
            (new Regex(@"MikroTik FTP server \(MikroTik ([\d.]+)\)", RegexOptions.IgnoreCase), "MikroTik router ftpd"),
            (new Regex(@"bftpd ([\d.]+)", RegexOptions.IgnoreCase), "bftpd"),
            (new Regex(@"Xlight FTP Server ([\d.]+)", RegexOptions.IgnoreCase), "Xlight ftpd"),
        };

        private async Task FtpAsync(Conn conn, string greeting)
        {
            svc.Service = svc.Tls ? "ftps" : "ftp";
            ApplyRules(greeting, FtpRules);

            string feat = await CommandAsync(conn, "FEAT").ConfigureAwait(false);
            if (feat.StartsWith("211", StringComparison.Ordinal))
            {
                svc.Facts["ftp.feat"] = Text.Clip(string.Join(" ", feat.Split('\n').Skip(1).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith("211", StringComparison.Ordinal))), 300);
                svc.Facts["ftp.auth_tls"] = Regex.IsMatch(feat, @"^\s*AUTH\s+.*TLS", RegexOptions.Multiline | RegexOptions.IgnoreCase) ? "true" : "false";
            }

            // Standard anonymous-access check (one attempt, read-only, like nmap ftp-anon).
            string user = await CommandAsync(conn, "USER anonymous").ConfigureAwait(false);
            bool anon = false;
            if (user.StartsWith("230", StringComparison.Ordinal))
            {
                anon = true;
            }
            else if (user.StartsWith("331", StringComparison.Ordinal) || user.StartsWith("332", StringComparison.Ordinal))
            {
                string pass = await CommandAsync(conn, "PASS anonymous@").ConfigureAwait(false);
                anon = pass.StartsWith("230", StringComparison.Ordinal);
                if (!anon && pass.Length > 0) svc.Facts["ftp.anonymous_reply"] = Text.Clip(pass.Trim(), 120);
            }
            else if (user.Length > 0)
            {
                svc.Facts["ftp.anonymous_reply"] = Text.Clip(user.Trim(), 120);
            }
            if (user.Length > 0) svc.Facts["ftp.anonymous"] = anon ? "true" : "false";
            await conn.SendAsync(Encoding.ASCII.GetBytes("QUIT\r\n")).ConfigureAwait(false);
        }

        private static readonly (Regex Re, string Product)[] SmtpRules =
        {
            (new Regex(@"Microsoft ESMTP MAIL Service(?:, Version: ([\d.]+))?", RegexOptions.IgnoreCase), "Microsoft ESMTP"),
            (new Regex(@"\bPostfix\b()", RegexOptions.IgnoreCase), "Postfix smtpd"),
            (new Regex(@"\bExim ([\d.]+)", RegexOptions.IgnoreCase), "Exim smtpd"),
            (new Regex(@"\bSendmail ([\w.\/+\-]+)", RegexOptions.IgnoreCase), "Sendmail"),
            (new Regex(@"hMailServer(?: ([\d.]+))?", RegexOptions.IgnoreCase), "hMailServer smtpd"),
            (new Regex(@"OpenSMTPD()", RegexOptions.IgnoreCase), "OpenSMTPD"),
            (new Regex(@"Haraka(?:/([\d.]+))?", RegexOptions.IgnoreCase), "Haraka smtpd"),
            (new Regex(@"MailEnable(?: Service, Version: ([\w.\-]+))?", RegexOptions.IgnoreCase), "MailEnable smtpd"),
            (new Regex(@"Zimbra()", RegexOptions.IgnoreCase), "Zimbra smtpd"),
            (new Regex(@"\bqmail\b()", RegexOptions.IgnoreCase), "qmail smtpd"),
            (new Regex(@"Exchange()", RegexOptions.IgnoreCase), "Microsoft Exchange smtpd"),
        };

        private async Task SmtpAsync(Conn conn, string greeting)
        {
            svc.Service = svc.Tls ? "smtps" : Port == 587 ? "submission" : "smtp";
            ApplyRules(greeting, SmtpRules);
            string ehlo = await CommandAsync(conn, "EHLO tryz.local").ConfigureAwait(false);
            if (ehlo.StartsWith("250", StringComparison.Ordinal))
            {
                var keywords = ehlo.Split('\n').Skip(1).Select(l => l.TrimEnd('\r'))
                    .Where(l => l.Length > 4).Select(l => l[4..].Trim()).ToList();
                svc.Facts["smtp.extensions"] = Text.Clip(string.Join(", ", keywords), 300);
                svc.Facts["smtp.starttls"] = keywords.Any(k => k.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase)) ? "true" : "false";
                svc.Facts["smtp.vrfy"] = keywords.Any(k => k.StartsWith("VRFY", StringComparison.OrdinalIgnoreCase)) ? "true" : "false";
                svc.Facts["smtp.expn"] = keywords.Any(k => k.StartsWith("EXPN", StringComparison.OrdinalIgnoreCase)) ? "true" : "false";
                var auth = keywords.FirstOrDefault(k => k.StartsWith("AUTH", StringComparison.OrdinalIgnoreCase));
                if (auth != null) svc.Facts["smtp.auth"] = auth.Length > 5 ? auth[5..].Trim() : string.Empty;
                if (svc.Product.Length == 0) ApplyRules(ehlo, SmtpRules);
            }
            else if (ehlo.Length > 0)
            {
                svc.Facts["smtp.ehlo_reply"] = Text.Clip(ehlo.Trim(), 120);
            }
            await conn.SendAsync(Encoding.ASCII.GetBytes("QUIT\r\n")).ConfigureAwait(false);
        }

        // ------------------------------------------------------------------ POP3 / IMAP

        private static readonly (Regex Re, string Product)[] MailboxRules =
        {
            (new Regex(@"Dovecot()", RegexOptions.IgnoreCase), "Dovecot"),
            (new Regex(@"Courier()", RegexOptions.IgnoreCase), "Courier"),
            (new Regex(@"Cyrus (?:IMAP|POP3)?\s*(?:v|Murder )?([\d.]+)?", RegexOptions.IgnoreCase), "Cyrus"),
            (new Regex(@"Microsoft Exchange(?: Server)?(?: (\d{4}))?", RegexOptions.IgnoreCase), "Microsoft Exchange"),
            (new Regex(@"Zimbra()", RegexOptions.IgnoreCase), "Zimbra"),
            (new Regex(@"hMailServer()", RegexOptions.IgnoreCase), "hMailServer"),
            (new Regex(@"UW IMAP|IMAP4rev1 (20\d\d\.\d+)", RegexOptions.IgnoreCase), "UW imapd"),
            (new Regex(@"Qpopper(?: \(version ([\d.]+)\))?", RegexOptions.IgnoreCase), "Qpopper"),
        };

        private async Task Pop3Async(Conn conn, string greeting)
        {
            svc.Service = svc.Tls ? "pop3s" : "pop3";
            svc.Banner = FirstLines(greeting, 1);
            if (ApplyRules(greeting, MailboxRules)) svc.Product += " pop3d";
            var capa = Text.Latin1(await conn.ExchangeAsync("CAPA\r\n"u8.ToArray(),
                d => d.StartsWith("-ERR"u8) && d.IndexOf((byte)'\n') >= 0 || d.EndsWith("\r\n.\r\n"u8), ReadMs).ConfigureAwait(false));
            if (capa.StartsWith("+OK", StringComparison.Ordinal))
            {
                var caps = capa.Split('\n').Skip(1).Select(l => l.Trim()).Where(l => l.Length > 0 && l != ".").ToList();
                svc.Facts["pop3.capabilities"] = Text.Clip(string.Join(" ", caps), 300);
                svc.Facts["pop3.stls"] = caps.Any(c => c.Equals("STLS", StringComparison.OrdinalIgnoreCase)) ? "true" : "false";
                if (svc.Product.Length == 0 && ApplyRules(capa, MailboxRules)) svc.Product += " pop3d";
            }
            await conn.SendAsync("QUIT\r\n"u8.ToArray()).ConfigureAwait(false);
        }

        private async Task ImapAsync(Conn conn, string greeting)
        {
            svc.Service = svc.Tls ? "imaps" : "imap";
            svc.Banner = FirstLines(greeting, 1);
            if (ApplyRules(greeting, MailboxRules)) svc.Product += " imapd";
            string caps = Regex.Match(greeting, @"\[CAPABILITY ([^\]]+)\]", RegexOptions.IgnoreCase).Groups[1].Value;
            if (caps.Length == 0)
            {
                string reply = Text.Latin1(await conn.ExchangeAsync("a1 CAPABILITY\r\n"u8.ToArray(),
                    d => d.IndexOf("a1 "u8) >= 0 && d.EndsWith("\r\n"u8), ReadMs).ConfigureAwait(false));
                caps = Regex.Match(reply, @"^\* CAPABILITY (.+)$", RegexOptions.Multiline | RegexOptions.IgnoreCase).Groups[1].Value.Trim();
            }
            if (caps.Length > 0)
            {
                var list = caps.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                svc.Facts["imap.capabilities"] = Text.Clip(caps, 300);
                svc.Facts["imap.starttls"] = list.Any(c => c.Equals("STARTTLS", StringComparison.OrdinalIgnoreCase)) ? "true" : "false";
                svc.Facts["imap.logindisabled"] = list.Any(c => c.Equals("LOGINDISABLED", StringComparison.OrdinalIgnoreCase)) ? "true" : "false";
            }
            await conn.SendAsync("a2 LOGOUT\r\n"u8.ToArray()).ConfigureAwait(false);
        }

        private bool ApplyRules(string text, (Regex Re, string Product)[] rules)
        {
            foreach (var (re, product) in rules)
            {
                var m = re.Match(text);
                if (!m.Success) continue;
                svc.Product = product;
                svc.Version = m.Groups.Count > 1 ? m.Groups[1].Value.Trim() : string.Empty;
                return true;
            }
            return false;
        }

        // ------------------------------------------------------------------ HTTP

        private enum HttpOutcome { None, Http, Other }

        private string HostHeader
        {
            get
            {
                string h = Host.Hostname;
                if (IPAddress.TryParse(h, out var a) && a.AddressFamily == AddressFamily.InterNetworkV6) h = $"[{h}]";
                bool defaultPort = svc.Tls ? Port == 443 : Port == 80;
                return defaultPort ? h : $"{h}:{Port.ToString(CultureInfo.InvariantCulture)}";
            }
        }

        private async Task<HttpOutcome> HttpExchangeAsync(Conn conn)
        {
            string request = $"GET / HTTP/1.1\r\nHost: {HostHeader}\r\nUser-Agent: {ctx.Options.UserAgent}\r\nAccept: */*\r\nConnection: close\r\n\r\n";
            var data = await conn.ExchangeAsync(Encoding.ASCII.GetBytes(request), HttpComplete, ReadMs, max: 96 * 1024).ConfigureAwait(false);
            if (data.Length == 0) return HttpOutcome.None;
            if (data.Length >= 2 && data[0] == 0x15 && data[1] == 0x03) return HttpOutcome.None; // TLS alert: plain text sent to a TLS port
            if (!Text.Latin1(data.AsSpan(0, Math.Min(5, data.Length)).ToArray()).StartsWith("HTTP/", StringComparison.Ordinal))
            {
                // A server that answers our request with something else (or a late greeting).
                await ClassifyGreetingAsync(conn, data).ConfigureAwait(false);
                return HttpOutcome.Other;
            }
            var https = ParseHttp(data);
            return https && !svc.Tls ? HttpOutcome.None : HttpOutcome.Http;
        }

        private static bool HttpComplete(ReadOnlySpan<byte> d)
        {
            int he = d.IndexOf("\r\n\r\n"u8);
            if (he < 0) return d.Length >= 32 * 1024;
            int bodyStart = he + 4;
            int bodyLen = d.Length - bodyStart;
            string headers = Encoding.Latin1.GetString(d[..he]);
            var status = Regex.Match(headers, @"^HTTP/\d(?:\.\d)? (\d{3})");
            if (status.Success && status.Groups[1].Value is "204" or "304") return true;
            var cl = Regex.Match(headers, @"^Content-Length:\s*(\d+)", RegexOptions.Multiline | RegexOptions.IgnoreCase);
            if (cl.Success && long.TryParse(cl.Groups[1].Value, NumberStyles.None, CultureInfo.InvariantCulture, out long n))
                return bodyLen >= Math.Min(n, 64 * 1024);
            if (Regex.IsMatch(headers, @"^Transfer-Encoding:.*chunked", RegexOptions.Multiline | RegexOptions.IgnoreCase))
                return d[bodyStart..].IndexOf("0\r\n\r\n"u8) is var z && (z == 0 || (z > 0 && d[bodyStart + z - 1] == (byte)'\n')) || bodyLen >= 64 * 1024;
            return bodyLen >= 64 * 1024;
        }

        /// <summary>Parses an HTTP response. Returns true when the server says the port expects HTTPS.</summary>
        private bool ParseHttp(byte[] data)
        {
            int he = data.AsSpan().IndexOf("\r\n\r\n"u8);
            string head = Text.Latin1(he >= 0 ? data[..he] : data);
            byte[] bodyBytes = he >= 0 ? data[(he + 4)..] : Array.Empty<byte>();
            var lines = head.Split("\r\n");
            string statusLine = lines[0];
            var headers = new List<KeyValuePair<string, string>>();
            foreach (var line in lines.Skip(1))
            {
                int colon = line.IndexOf(':');
                if (colon > 0) headers.Add(new(line[..colon].Trim(), line[(colon + 1)..].Trim()));
            }
            string Header(string name) => headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value ?? string.Empty;

            if (Header("Transfer-Encoding").Contains("chunked", StringComparison.OrdinalIgnoreCase)) bodyBytes = Dechunk(bodyBytes);
            bool latin1 = Regex.IsMatch(Header("Content-Type"), @"charset=(iso-8859-1|latin1|windows-1252)", RegexOptions.IgnoreCase);
            string body = latin1 ? Encoding.Latin1.GetString(bodyBytes) : Encoding.UTF8.GetString(bodyBytes);
            var sm = Regex.Match(statusLine, @"^HTTP/[\d.]+ (\d{3})");
            int status = sm.Success ? int.Parse(sm.Groups[1].Value, CultureInfo.InvariantCulture) : 0;

            if (!svc.Tls && status == 400 && Regex.IsMatch(body, @"plain HTTP request was sent to HTTPS port|speaking plain HTTP to an SSL-enabled|use the HTTPS scheme|requires? (TLS|SSL|HTTPS)", RegexOptions.IgnoreCase))
            {
                svc.Facts["http.requires_tls"] = "true";
                return true;
            }

            svc.Http = true;
            svc.Service = svc.Tls ? "https" : "http";
            svc.Facts["http.status"] = status.ToString(CultureInfo.InvariantCulture);
            string server = Header("Server"), powered = Header("X-Powered-By"), location = Header("Location"),
                auth = Header("WWW-Authenticate"), ctype = Header("Content-Type");
            if (server.Length > 0) svc.Facts["http.server"] = server;
            if (powered.Length > 0) svc.Facts["http.powered_by"] = powered;
            if (location.Length > 0) svc.Facts["http.location"] = location;
            if (auth.Length > 0) svc.Facts["http.www_authenticate"] = auth;
            if (ctype.Length > 0) svc.Facts["http.content_type"] = ctype;
            var title = Regex.Match(body, @"<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            string titleText = title.Success ? Regex.Replace(WebUtility.HtmlDecode(title.Groups[1].Value), @"\s+", " ").Trim() : string.Empty;
            if (titleText.Length > 0) svc.Facts["http.title"] = Text.Clip(titleText, 150);

            if (server.Length > 0) (svc.Product, svc.Version) = ParseServerHeader(server);
            var os = Regex.Match(server, @"\((Ubuntu|Debian|CentOS|Red Hat|Fedora|Win32|Win64|Unix|FreeBSD|Raspbian)\)", RegexOptions.IgnoreCase);
            if (os.Success) svc.Facts["os.hint"] = os.Groups[1].Value;

            var parts = new List<string> { statusLine.Trim() };
            if (server.Length > 0) parts.Add("Server: " + server);
            if (titleText.Length > 0) parts.Add("Title: " + titleText);
            svc.Banner = string.Join(" | ", parts);

            DetectJsonApis(status, body, Header("X-elastic-product"));
            return false;
        }

        private void DetectJsonApis(int status, string body, string elasticHeader)
        {
            if (elasticHeader.Length > 0)
            {
                svc.Service = "elasticsearch";
                svc.Product = elasticHeader;
                svc.Version = string.Empty;
                svc.Facts["elasticsearch.noauth"] = status == 200 ? "true" : "false";
            }
            string trimmed = body.TrimStart();
            if (!trimmed.StartsWith('{')) return;
            try
            {
                using var doc = JsonDocument.Parse(trimmed, new JsonDocumentOptions { AllowTrailingCommas = true });
                var root = doc.RootElement;
                if (root.ValueKind != JsonValueKind.Object) return;
                if (root.TryGetProperty("version", out var v) && v.ValueKind == JsonValueKind.Object
                    && v.TryGetProperty("number", out var number) && number.ValueKind == JsonValueKind.String
                    && (root.TryGetProperty("cluster_name", out _) || root.TryGetProperty("tagline", out _)))
                {
                    bool openSearch = v.TryGetProperty("distribution", out var dist) && dist.ValueKind == JsonValueKind.String
                                      && string.Equals(dist.GetString(), "opensearch", StringComparison.OrdinalIgnoreCase);
                    svc.Service = "elasticsearch";
                    svc.Product = openSearch ? "OpenSearch" : "Elasticsearch";
                    svc.Version = number.GetString() ?? string.Empty;
                    svc.Facts["elasticsearch.noauth"] = status == 200 ? "true" : "false";
                    if (root.TryGetProperty("cluster_name", out var cn) && cn.ValueKind == JsonValueKind.String)
                        svc.Facts["elasticsearch.cluster_name"] = cn.GetString() ?? string.Empty;
                }
                else if (root.TryGetProperty("couchdb", out _) && root.TryGetProperty("version", out var cv) && cv.ValueKind == JsonValueKind.String)
                {
                    svc.Service = "couchdb";
                    svc.Product = "Apache CouchDB";
                    svc.Version = cv.GetString() ?? string.Empty;
                }
            }
            catch (JsonException)
            {
            }
        }

        private static readonly (Regex Re, string Product)[] ServerRules =
        {
            (new Regex(@"^nginx(?:/([\d.]+))?", RegexOptions.IgnoreCase), "nginx"),
            (new Regex(@"^openresty(?:/([\d.]+))?", RegexOptions.IgnoreCase), "OpenResty web app server"),
            (new Regex(@"^Tengine(?:/([\d.]+))?", RegexOptions.IgnoreCase), "Tengine httpd"),
            (new Regex(@"^Apache-Coyote/([\d.]+)", RegexOptions.IgnoreCase), "Apache Tomcat/Coyote JSP engine"),
            (new Regex(@"^Apache(?:/([\d.]+))?", RegexOptions.IgnoreCase), "Apache httpd"),
            (new Regex(@"^Microsoft-IIS/([\d.]+)", RegexOptions.IgnoreCase), "Microsoft IIS httpd"),
            (new Regex(@"^Microsoft-HTTPAPI/([\d.]+)", RegexOptions.IgnoreCase), "Microsoft HTTPAPI httpd"),
            (new Regex(@"^lighttpd(?:/([\d.]+))?", RegexOptions.IgnoreCase), "lighttpd"),
            (new Regex(@"^LiteSpeed(?:/([\d.]+))?", RegexOptions.IgnoreCase), "LiteSpeed httpd"),
            (new Regex(@"^Caddy()", RegexOptions.IgnoreCase), "Caddy httpd"),
            (new Regex(@"^Jetty\(([^)]+)\)", RegexOptions.IgnoreCase), "Jetty"),
            (new Regex(@"^gunicorn(?:/([\d.]+))?", RegexOptions.IgnoreCase), "Gunicorn"),
            (new Regex(@"^Werkzeug/([\d.]+)", RegexOptions.IgnoreCase), "Werkzeug httpd"),
            (new Regex(@"^uvicorn()", RegexOptions.IgnoreCase), "Uvicorn"),
            (new Regex(@"^Kestrel()", RegexOptions.IgnoreCase), "Microsoft Kestrel httpd"),
            (new Regex(@"^squid/([\w.]+)", RegexOptions.IgnoreCase), "Squid http proxy"),
            (new Regex(@"^cloudflare()", RegexOptions.IgnoreCase), "Cloudflare http proxy"),
            (new Regex(@"^AmazonS3()", RegexOptions.IgnoreCase), "Amazon S3"),
            (new Regex(@"^awselb/([\d.]+)", RegexOptions.IgnoreCase), "AWS Elastic Load Balancer"),
            (new Regex(@"^Varnish()", RegexOptions.IgnoreCase), "Varnish http accelerator"),
            (new Regex(@"^thttpd/([\w.]+)", RegexOptions.IgnoreCase), "thttpd"),
            (new Regex(@"^mini_httpd/([\w.]+)", RegexOptions.IgnoreCase), "mini_httpd"),
            (new Regex(@"^Boa/([\w.]+)", RegexOptions.IgnoreCase), "Boa httpd"),
            (new Regex(@"^GoAhead-(?:Webs|http)()", RegexOptions.IgnoreCase), "GoAhead WebServer"),
            (new Regex(@"^SimpleHTTP/[\d.]+ Python/([\d.]+)", RegexOptions.IgnoreCase), "Python SimpleHTTPServer"),
            (new Regex(@"^BaseHTTP/[\d.]+ Python/([\d.]+)", RegexOptions.IgnoreCase), "Python BaseHTTPServer"),
            (new Regex(@"^TornadoServer/([\d.]+)", RegexOptions.IgnoreCase), "Tornado httpd"),
            (new Regex(@"^Node\.js()", RegexOptions.IgnoreCase), "Node.js"),
            (new Regex(@"^MiniServ/([\d.]+)", RegexOptions.IgnoreCase), "Webmin MiniServ"),
            (new Regex(@"^Oracle-HTTP-Server()", RegexOptions.IgnoreCase), "Oracle HTTP Server"),
            (new Regex(@"^WebLogic(?: Server)? ?([\d.]+)?", RegexOptions.IgnoreCase), "Oracle WebLogic Server"),
            (new Regex(@"^IBM_HTTP_Server(?:/([\d.]+))?", RegexOptions.IgnoreCase), "IBM HTTP Server"),
            (new Regex(@"^Zope/\(?([\w.]+)", RegexOptions.IgnoreCase), "Zope"),
            (new Regex(@"^CherryPy/([\d.]+)", RegexOptions.IgnoreCase), "CherryPy httpd"),
            (new Regex(@"^RomPager/([\w.]+)", RegexOptions.IgnoreCase), "Allegro RomPager"),
            (new Regex(@"^mini_httpd()", RegexOptions.IgnoreCase), "mini_httpd"),
        };

        private static (string Product, string Version) ParseServerHeader(string server)
        {
            foreach (var (re, product) in ServerRules)
            {
                var m = re.Match(server);
                if (m.Success) return (product, m.Groups.Count > 1 ? m.Groups[1].Value : string.Empty);
            }
            var generic = Regex.Match(server, @"^([A-Za-z][\w\-. ]{0,40}?)/(\d[\w.\-]*)");
            if (generic.Success) return (generic.Groups[1].Value.Trim(), generic.Groups[2].Value);
            return (Text.Clip(server, 60), string.Empty);
        }

        private static byte[] Dechunk(byte[] body)
        {
            using var output = new MemoryStream();
            int p = 0;
            while (p < body.Length)
            {
                int eol = body.AsSpan(p).IndexOf("\r\n"u8);
                if (eol < 0) break;
                string sizeText = Encoding.ASCII.GetString(body, p, eol).Split(';')[0].Trim();
                if (!int.TryParse(sizeText, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size) || size <= 0) break;
                int start = p + eol + 2;
                int take = Math.Min(size, body.Length - start);
                if (take <= 0) break;
                output.Write(body, start, take);
                p = start + size + 2;
            }
            return output.Length > 0 ? output.ToArray() : body;
        }

        // ------------------------------------------------------------------ RDP

        private async Task<bool> RdpAsync()
        {
            // 1) Ask for everything: learn the protocol the server prefers.
            var best = await RdpNegotiateAsync(0x0000000B, captureCertificate: true).ConfigureAwait(false);
            if (best is null) return false;
            svc.Service = "ms-wbt-server";
            svc.Product = "Microsoft Terminal Services";
            var (type, value) = best.Value;
            if (type == 2) svc.Facts["rdp.protocol"] = RdpProtocolName(value);
            else if (type == 3) svc.Facts["rdp.negotiation_failure"] = RdpFailureName(value);
            else svc.Facts["rdp.protocol"] = "Standard RDP Security (legacy server, no negotiation)";

            // 2) Offer TLS only (no CredSSP): a HYBRID_REQUIRED failure means NLA is enforced.
            var tlsOnly = await RdpNegotiateAsync(0x00000001, captureCertificate: false).ConfigureAwait(false);
            if (tlsOnly is { } t)
            {
                bool nlaRequired = t.Type == 3 && t.Value == 5;
                svc.Facts["rdp.nla"] = nlaRequired ? "true" : "false";
            }
            else if (type == 2)
            {
                svc.Facts["rdp.nla"] = value is 2 or 8 ? "true" : "false";
            }

            // 3) Offer legacy Standard RDP Security only: acceptance means the weak RC4-based mode is allowed.
            var legacy = await RdpNegotiateAsync(0x00000000, captureCertificate: false).ConfigureAwait(false);
            if (legacy is { } l)
                svc.Facts["rdp.standard_security"] = l.Type == 0 || (l.Type == 2 && l.Value == 0) ? "true" : "false";

            svc.Banner = $"RDP {(svc.Facts.TryGetValue("rdp.protocol", out var p) ? p : string.Empty)}; NLA required: {(svc.Facts.TryGetValue("rdp.nla", out var n) ? n : "unknown")}";
            return true;
        }

        /// <summary>X.224 Connection Request with RDP_NEG_REQ. Returns (0, 0) for a server without negotiation support,
        /// (2, selectedProtocol) for RDP_NEG_RSP and (3, failureCode) for RDP_NEG_FAILURE; null if not RDP.</summary>
        private async Task<(byte Type, uint Value)?> RdpNegotiateAsync(uint requested, bool captureCertificate)
        {
            await using var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return null;
            var packet = new byte[]
            {
                0x03, 0x00, 0x00, 0x13,                         // TPKT, length 19
                0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,       // X.224 CR TPDU
                0x01, 0x00, 0x08, 0x00, 0, 0, 0, 0,             // RDP_NEG_REQ
            };
            BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(15), requested);
            var data = await conn.ExchangeAsync(packet, d => d.Length >= 4 && d.Length >= (d[2] << 8 | d[3]), ReadMs, max: 1024).ConfigureAwait(false);
            if (data.Length < 11 || data[0] != 0x03 || data[1] != 0x00 || (data[5] & 0xF0) != 0xD0) return null;
            int tpkt = data[2] << 8 | data[3];
            if (tpkt < 19 || data.Length < 19) return (0, 0);
            byte type = data[11];
            uint value = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(15));
            if (captureCertificate && type == 2 && value != 0 && await conn.UpgradeTlsAsync(Sni).ConfigureAwait(false) && conn.Ssl is { } ssl)
            {
                var cert = CopyCertificate(ssl.RemoteCertificate);
                if (cert != null)
                {
                    svc.Certificate = cert;
                    svc.Facts["rdp.cert_subject"] = cert.Subject;
                    svc.Facts["rdp.cert_not_after"] = cert.NotAfter.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
                }
                svc.Facts["rdp.tls_protocol"] = Text.TlsName(ssl.SslProtocol);
            }
            return (type, value);
        }

        private static string RdpProtocolName(uint p) => p switch
        {
            0 => "Standard RDP Security",
            1 => "TLS",
            2 => "CredSSP (NLA)",
            4 => "RDSTLS",
            8 => "CredSSP with Early User Authorization (NLA)",
            _ => $"0x{p:X}",
        };

        private static string RdpFailureName(uint code) => code switch
        {
            1 => "SSL_REQUIRED_BY_SERVER",
            2 => "SSL_NOT_ALLOWED_BY_SERVER",
            3 => "SSL_CERT_NOT_ON_SERVER",
            4 => "INCONSISTENT_FLAGS",
            5 => "HYBRID_REQUIRED_BY_SERVER",
            6 => "SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER",
            _ => $"0x{code:X}",
        };

        // ------------------------------------------------------------------ SMB

        private async Task<bool> SmbAsync(bool netbios)
        {
            bool smb2 = false;
            await using (var conn = await OpenAsync().ConfigureAwait(false))
            {
                if (conn is null) return false;
                if (netbios && !await NetbiosSessionAsync(conn).ConfigureAwait(false)) return false;
                var reply = await conn.ExchangeAsync(Smb2NegotiateRequest(), NbssComplete, ReadMs, max: 65536 + 4).ConfigureAwait(false);
                smb2 = ParseSmb2Negotiate(reply);
            }

            bool? smb1 = null;
            await using (var conn = await OpenAsync().ConfigureAwait(false))
            {
                if (conn is not null && (!netbios || await NetbiosSessionAsync(conn).ConfigureAwait(false)))
                {
                    var reply = await conn.ExchangeAsync(Smb1NegotiateRequest(), NbssComplete, ReadMs, max: 65536 + 4).ConfigureAwait(false);
                    smb1 = ParseSmb1Negotiate(reply);
                }
            }
            if (!smb2 && smb1 != true) return false;

            svc.Service = netbios ? "netbios-ssn" : "microsoft-ds";
            if (smb1 is { } s1) svc.Facts["smb.smb1"] = s1 ? "true" : "false";
            var parts = new List<string>();
            if (svc.Facts.TryGetValue("smb.dialect", out var dialect)) parts.Add($"SMB dialect {dialect}");
            if (svc.Facts.TryGetValue("smb.signing_required", out var sr)) parts.Add(sr == "true" ? "signing required" : "signing not required");
            if (smb1 == true) parts.Add("SMBv1 enabled");
            if (svc.Facts.TryGetValue("smb.domain", out var dom)) parts.Add($"domain {dom}");
            if (svc.Facts.TryGetValue("smb.server_name", out var srv)) parts.Add($"name {srv}");
            svc.Banner = string.Join("; ", parts);
            return true;
        }

        private static bool NbssComplete(ReadOnlySpan<byte> d) => d.Length >= 4 && d.Length >= 4 + (d[1] << 16 | d[2] << 8 | d[3]);

        private async Task<bool> NetbiosSessionAsync(Conn conn)
        {
            var called = NetbiosName("*SMBSERVER", 0x20);
            var calling = NetbiosName("TRYZ", 0x00);
            var req = new byte[4 + called.Length + calling.Length];
            req[0] = 0x81;
            req[3] = (byte)(called.Length + calling.Length);
            called.CopyTo(req, 4);
            calling.CopyTo(req, 4 + called.Length);
            var reply = await conn.ExchangeAsync(req, NbssComplete, ReadMs, max: 256).ConfigureAwait(false);
            return reply.Length >= 4 && reply[0] == 0x82;
        }

        private static byte[] NetbiosName(string name, byte suffix)
        {
            var raw = new byte[16];
            var ascii = Encoding.ASCII.GetBytes(name.PadRight(15)[..15]);
            ascii.CopyTo(raw, 0);
            raw[15] = suffix;
            var encoded = new byte[34];
            encoded[0] = 32;
            for (int i = 0; i < 16; i++)
            {
                encoded[1 + i * 2] = (byte)('A' + (raw[i] >> 4));
                encoded[2 + i * 2] = (byte)('A' + (raw[i] & 0x0F));
            }
            return encoded;
        }

        private static byte[] Smb2NegotiateRequest()
        {
            ushort[] dialects = { 0x0202, 0x0210, 0x0300, 0x0302, 0x0311 };
            const int header = 64, fixedBody = 36;
            int dialectsEnd = header + fixedBody + dialects.Length * 2;      // 110
            int ctx1 = (dialectsEnd + 7) & ~7;                                // 112
            int ctx1Len = 8 + 38;                                             // preauth integrity: 6 + 32-byte salt
            int ctx2 = (ctx1 + ctx1Len + 7) & ~7;                             // 160
            int ctx2Len = 8 + 6;                                              // encryption: count + 2 ciphers
            int total = ctx2 + ctx2Len;
            var smb = new byte[total];
            var s = smb.AsSpan();
            s[0] = 0xFE; s[1] = (byte)'S'; s[2] = (byte)'M'; s[3] = (byte)'B';
            BinaryPrimitives.WriteUInt16LittleEndian(s[4..], 64);           // StructureSize
            BinaryPrimitives.WriteUInt16LittleEndian(s[12..], 0);           // Command NEGOTIATE
            BinaryPrimitives.WriteUInt16LittleEndian(s[14..], 1);           // CreditRequest
            int b = header;
            BinaryPrimitives.WriteUInt16LittleEndian(s[b..], 36);           // StructureSize
            BinaryPrimitives.WriteUInt16LittleEndian(s[(b + 2)..], (ushort)dialects.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(b + 4)..], 0x0001); // SecurityMode: signing enabled
            BinaryPrimitives.WriteUInt32LittleEndian(s[(b + 8)..], 0x7F);   // Capabilities
            RandomNumberGenerator.Fill(s.Slice(b + 12, 16));               // ClientGuid
            BinaryPrimitives.WriteUInt32LittleEndian(s[(b + 28)..], (uint)ctx1); // NegotiateContextOffset
            BinaryPrimitives.WriteUInt16LittleEndian(s[(b + 32)..], 2);     // NegotiateContextCount
            for (int i = 0; i < dialects.Length; i++)
                BinaryPrimitives.WriteUInt16LittleEndian(s[(b + 36 + i * 2)..], dialects[i]);
            // SMB2_PREAUTH_INTEGRITY_CAPABILITIES
            BinaryPrimitives.WriteUInt16LittleEndian(s[ctx1..], 1);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx1 + 2)..], 38);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx1 + 8)..], 1);   // HashAlgorithmCount
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx1 + 10)..], 32); // SaltLength
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx1 + 12)..], 1);  // SHA-512
            RandomNumberGenerator.Fill(s.Slice(ctx1 + 14, 32));
            // SMB2_ENCRYPTION_CAPABILITIES
            BinaryPrimitives.WriteUInt16LittleEndian(s[ctx2..], 2);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx2 + 2)..], 6);
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx2 + 8)..], 2);   // CipherCount
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx2 + 10)..], 2);  // AES-128-GCM
            BinaryPrimitives.WriteUInt16LittleEndian(s[(ctx2 + 12)..], 1);  // AES-128-CCM
            return WithNbss(smb);
        }

        private static byte[] Smb1NegotiateRequest()
        {
            var dialect = Encoding.ASCII.GetBytes("\u0002NT LM 0.12\0");
            var smb = new byte[32 + 3 + dialect.Length];
            smb[0] = 0xFF; smb[1] = (byte)'S'; smb[2] = (byte)'M'; smb[3] = (byte)'B';
            smb[4] = 0x72;                                                   // SMB_COM_NEGOTIATE
            smb[9] = 0x18;                                                   // Flags: case-insensitive, canonical paths
            BinaryPrimitives.WriteUInt16LittleEndian(smb.AsSpan(10), 0xC001); // Flags2: unicode, NT status, long names
            BinaryPrimitives.WriteUInt16LittleEndian(smb.AsSpan(26), 0xFEFF); // PID
            smb[32] = 0;                                                     // WordCount
            BinaryPrimitives.WriteUInt16LittleEndian(smb.AsSpan(33), (ushort)dialect.Length);
            dialect.CopyTo(smb, 35);
            return WithNbss(smb);
        }

        private static byte[] WithNbss(byte[] smb)
        {
            var packet = new byte[smb.Length + 4];
            packet[1] = (byte)(smb.Length >> 16);
            packet[2] = (byte)(smb.Length >> 8);
            packet[3] = (byte)smb.Length;
            smb.CopyTo(packet, 4);
            return packet;
        }

        private bool ParseSmb2Negotiate(byte[] d)
        {
            if (d.Length < 4 + 64 + 8 || d[4] != 0xFE || d[5] != (byte)'S' || d[6] != (byte)'M' || d[7] != (byte)'B') return false;
            uint status = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(4 + 8));
            if (status != 0)
            {
                svc.Facts["smb2.negotiate_status"] = $"0x{status:X8}";
                return false;
            }
            int body = 4 + 64;
            ushort securityMode = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(body + 2));
            ushort dialect = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(body + 4));
            svc.Facts["smb.dialect"] = dialect switch
            {
                0x0202 => "2.0.2",
                0x0210 => "2.1",
                0x0300 => "3.0",
                0x0302 => "3.0.2",
                0x0311 => "3.1.1",
                0x02FF => "2.x (wildcard)",
                _ => $"0x{dialect:X4}",
            };
            svc.Facts["smb.signing_enabled"] = (securityMode & 0x01) != 0 ? "true" : "false";
            svc.Facts["smb.signing_required"] = (securityMode & 0x02) != 0 ? "true" : "false";
            if (d.Length >= body + 48)
            {
                long fileTime = BinaryPrimitives.ReadInt64LittleEndian(d.AsSpan(body + 40));
                if (fileTime > 0)
                {
                    try
                    {
                        svc.Facts["smb.server_time"] = DateTime.FromFileTimeUtc(fileTime).ToString("yyyy-MM-dd HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
                    }
                    catch (ArgumentOutOfRangeException)
                    {
                    }
                }
            }
            return true;
        }

        private bool ParseSmb1Negotiate(byte[] d)
        {
            if (d.Length < 4 + 32 + 3 || d[4] != 0xFF || d[5] != (byte)'S' || d[6] != (byte)'M' || d[7] != (byte)'B' || d[8] != 0x72) return false;
            uint status = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(9));
            if (status != 0) return false;
            int wc = d[4 + 32];
            if (wc < 1) return false;
            int w = 4 + 33;
            ushort index = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(w));
            if (index == 0xFFFF) return false;
            if (wc == 17 && d.Length >= w + 34 + 2)
            {
                byte securityMode = d[w + 2];
                svc.Facts["smb1.signing_required"] = (securityMode & 0x08) != 0 ? "true" : "false";
                uint caps = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(w + 19));
                int challengeLen = d[w + 33];
                int byteCount = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(w + 34));
                int data = w + 36;
                if ((caps & 0x80000000) == 0 && challengeLen <= byteCount && data + byteCount <= d.Length)
                {
                    // Non-extended-security response: challenge, then OEM/Unicode domain and server names.
                    var names = Encoding.Unicode.GetString(d, data + challengeLen, Math.Max(0, byteCount - challengeLen) & ~1)
                        .Split('\0', StringSplitOptions.RemoveEmptyEntries);
                    if (names.Length > 0) svc.Facts["smb.domain"] = Text.Sanitize(names[0], 64);
                    if (names.Length > 1) svc.Facts["smb.server_name"] = Text.Sanitize(names[1], 64);
                }
            }
            return true;
        }

        // ------------------------------------------------------------------ MongoDB

        private async Task<bool> MongoAsync()
        {
            await using var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return false;
            var hello = await MongoCommandAsync(conn, Bson.Doc(("hello", 1), ("$db", "admin")), opMsg: true).ConfigureAwait(false);
            bool opMsg = hello is not null;
            Conn active = conn;
            Conn? legacy = null;
            try
            {
                if (hello is null)
                {
                    legacy = await OpenAsync().ConfigureAwait(false);
                    if (legacy is null) return false;
                    active = legacy;
                    hello = await MongoCommandAsync(legacy, Bson.Doc(("isMaster", 1)), opMsg: false).ConfigureAwait(false);
                    if (hello is null) return false;
                }
                svc.Service = "mongodb";
                svc.Product = "MongoDB";
                if (hello.TryGetValue("maxWireVersion", out var wire) && wire is int wv) svc.Facts["mongodb.wire_version"] = wv.ToString(CultureInfo.InvariantCulture);
                if (hello.TryGetValue("setName", out var rs) && rs is string set) svc.Facts["mongodb.replica_set"] = set;

                var build = await MongoCommandAsync(active, opMsg ? Bson.Doc(("buildInfo", 1), ("$db", "admin")) : Bson.Doc(("buildInfo", 1)), opMsg).ConfigureAwait(false);
                if (build != null && build.TryGetValue("version", out var ver) && ver is string version) svc.Version = version;

                // Read-only check whether commands that need privileges work without credentials (like nmap mongodb-databases).
                var list = await MongoCommandAsync(active,
                    opMsg ? Bson.Doc(("listDatabases", 1), ("nameOnly", true), ("$db", "admin")) : Bson.Doc(("listDatabases", 1), ("nameOnly", true)), opMsg).ConfigureAwait(false);
                if (list != null)
                {
                    bool ok = list.TryGetValue("ok", out var okv) && okv is double d1 ? d1 >= 1 : okv is int i1 && i1 >= 1;
                    svc.Facts["mongodb.noauth"] = ok ? "true" : "false";
                    if (!ok && list.TryGetValue("errmsg", out var err) && err is string e) svc.Facts["mongodb.auth_error"] = Text.Clip(e, 120);
                }
                svc.Banner = $"MongoDB {svc.Version}".Trim();
                return true;
            }
            finally
            {
                if (legacy is not null) await legacy.DisposeAsync().ConfigureAwait(false);
            }
        }

        private int _mongoRequestId;

        private async Task<Dictionary<string, object?>?> MongoCommandAsync(Conn conn, byte[] doc, bool opMsg)
        {
            int id = Interlocked.Increment(ref _mongoRequestId);
            byte[] msg;
            if (opMsg)
            {
                msg = new byte[16 + 4 + 1 + doc.Length];
                BinaryPrimitives.WriteInt32LittleEndian(msg.AsSpan(12), 2013);
                doc.CopyTo(msg, 21);
            }
            else
            {
                var ns = Encoding.ASCII.GetBytes("admin.$cmd\0");
                msg = new byte[16 + 4 + ns.Length + 8 + doc.Length];
                BinaryPrimitives.WriteInt32LittleEndian(msg.AsSpan(12), 2004);
                ns.CopyTo(msg, 20);
                BinaryPrimitives.WriteInt32LittleEndian(msg.AsSpan(20 + ns.Length + 4), -1);
                doc.CopyTo(msg, 20 + ns.Length + 8);
            }
            BinaryPrimitives.WriteInt32LittleEndian(msg, msg.Length);
            BinaryPrimitives.WriteInt32LittleEndian(msg.AsSpan(4), id);

            var reply = await conn.ExchangeAsync(msg, d => d.Length >= 4 && d.Length >= BinaryPrimitives.ReadInt32LittleEndian(d), ReadMs, max: 1 << 20).ConfigureAwait(false);
            if (reply.Length < 21) return null;
            int op = BinaryPrimitives.ReadInt32LittleEndian(reply.AsSpan(12));
            if (op == 2013 && reply[20] == 0) return Bson.Parse(reply.AsSpan(21));
            if (op == 1 && reply.Length > 36) return Bson.Parse(reply.AsSpan(36));
            return null;
        }

        // ------------------------------------------------------------------ Memcached / Redis / PostgreSQL / MSSQL

        private async Task<bool> MemcachedAsync()
        {
            await using var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return false;
            string reply = Text.Latin1(await conn.ExchangeAsync("version\r\n"u8.ToArray(), d => d.IndexOf((byte)'\n') >= 0, ReadMs).ConfigureAwait(false));
            var m = Regex.Match(reply, @"^VERSION ([\w.\-]+)");
            if (!m.Success) return false;
            svc.Service = "memcached";
            svc.Product = "Memcached";
            svc.Version = m.Groups[1].Value;
            svc.Banner = reply.Trim();
            svc.Facts["memcached.noauth"] = "true";
            return true;
        }

        private async Task<bool> RedisAsync()
        {
            await using var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return false;
            string ping = Text.Latin1(await conn.ExchangeAsync("PING\r\n"u8.ToArray(), d => d.IndexOf((byte)'\n') >= 0, ReadMs).ConfigureAwait(false)).Trim();
            if (ping.Length == 0 || (ping[0] != '+' && ping[0] != '-')) return false;
            svc.Service = "redis";
            svc.Product = "Redis key-value store";
            svc.Banner = ping;
            if (ping.StartsWith("+PONG", StringComparison.Ordinal))
            {
                svc.Facts["redis.auth"] = "none";
                svc.Facts["redis.noauth"] = "true";
                var info = Text.Latin1(await conn.ExchangeAsync("INFO server\r\n"u8.ToArray(), RedisBulkComplete, ReadMs, max: 65536).ConfigureAwait(false));
                var v = Regex.Match(info, @"redis_version:([\w.\-]+)");
                if (v.Success) svc.Version = v.Groups[1].Value;
                var os = Regex.Match(info, @"\nos:([^\r\n]+)");
                if (os.Success) svc.Facts["redis.os"] = os.Groups[1].Value.Trim();
                var mode = Regex.Match(info, @"redis_mode:(\w+)");
                if (mode.Success) svc.Facts["redis.mode"] = mode.Groups[1].Value;
            }
            else if (ping.Contains("NOAUTH", StringComparison.OrdinalIgnoreCase) || ping.Contains("Authentication required", StringComparison.OrdinalIgnoreCase))
            {
                svc.Facts["redis.auth"] = "required";
                svc.Facts["redis.noauth"] = "false";
            }
            else if (ping.StartsWith("-DENIED", StringComparison.Ordinal))
            {
                svc.Facts["redis.auth"] = "protected-mode";
                svc.Facts["redis.noauth"] = "false";
            }
            await conn.SendAsync("QUIT\r\n"u8.ToArray()).ConfigureAwait(false);
            return true;
        }

        private static bool RedisBulkComplete(ReadOnlySpan<byte> d)
        {
            if (d.Length == 0) return false;
            if (d[0] != (byte)'$') return d.IndexOf((byte)'\n') >= 0;
            int eol = d.IndexOf("\r\n"u8);
            if (eol < 0) return false;
            if (!int.TryParse(Encoding.ASCII.GetString(d[1..eol]), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int len)) return true;
            return len < 0 || d.Length >= eol + 2 + len + 2;
        }

        private async Task<bool> PostgresAsync()
        {
            await using var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return false;
            var req = new byte[8];
            BinaryPrimitives.WriteInt32BigEndian(req, 8);
            BinaryPrimitives.WriteInt32BigEndian(req.AsSpan(4), 80877103); // SSLRequest
            var reply = await conn.ExchangeAsync(req, d => d.Length >= 1, ReadMs, max: 512).ConfigureAwait(false);
            if (reply.Length == 0 || reply[0] is not ((byte)'S' or (byte)'N' or (byte)'E')) return false;
            svc.Service = "postgresql";
            svc.Product = "PostgreSQL DB";
            svc.Facts["postgresql.ssl"] = reply[0] == (byte)'S' ? "true" : "false";
            svc.Banner = reply[0] == (byte)'S' ? "PostgreSQL (SSL supported)" : "PostgreSQL (SSL not offered)";
            return true;
        }

        private async Task<bool> MssqlAsync()
        {
            await using var conn = await OpenAsync().ConfigureAwait(false);
            if (conn is null) return false;
            // TDS PRELOGIN: VERSION, ENCRYPTION, INSTOPT, THREADID, MARS, terminator.
            byte[] tokens = { 0x00, 0x01, 0x02, 0x03, 0x04 };
            int[] lengths = { 6, 1, 1, 4, 1 };
            int tableLen = tokens.Length * 5 + 1;
            int dataLen = lengths.Sum();
            var payload = new byte[tableLen + dataLen];
            int offset = tableLen;
            for (int i = 0; i < tokens.Length; i++)
            {
                payload[i * 5] = tokens[i];
                BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(i * 5 + 1), (ushort)offset);
                BinaryPrimitives.WriteUInt16BigEndian(payload.AsSpan(i * 5 + 3), (ushort)lengths[i]);
                offset += lengths[i];
            }
            payload[tableLen - 1] = 0xFF;
            payload[tableLen + 6] = 0x00; // ENCRYPT_OFF (client supports encryption)
            var packet = new byte[8 + payload.Length];
            packet[0] = 0x12; // PRELOGIN
            packet[1] = 0x01; // EOM
            BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2), (ushort)packet.Length);
            payload.CopyTo(packet, 8);

            var reply = await conn.ExchangeAsync(packet, d => d.Length >= 8 && d.Length >= (d[2] << 8 | d[3]), ReadMs, max: 4096).ConfigureAwait(false);
            if (reply.Length < 8 + 6 || reply[0] != 0x04) return false;
            svc.Service = "ms-sql-s";
            svc.Product = "Microsoft SQL Server";
            for (int p = 8; p + 5 <= reply.Length && reply[p] != 0xFF; p += 5)
            {
                byte token = reply[p];
                int off = 8 + BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(p + 1));
                int len = BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(p + 3));
                if (off + len > reply.Length) break;
                if (token == 0x00 && len >= 6)
                {
                    int major = reply[off], minor = reply[off + 1];
                    int build = BinaryPrimitives.ReadUInt16BigEndian(reply.AsSpan(off + 2));
                    svc.Version = $"{major}.{minor:00}.{build}";
                    string year = MssqlYear(major, minor);
                    if (year.Length > 0) svc.Product = $"Microsoft SQL Server {year}";
                }
                else if (token == 0x01 && len >= 1)
                {
                    svc.Facts["mssql.encryption"] = reply[off] switch
                    {
                        0 => "off (login packet only)",
                        1 => "on",
                        2 => "not supported",
                        3 => "required",
                        _ => $"0x{reply[off]:X2}",
                    };
                }
            }
            svc.Banner = $"{svc.Product} {svc.Version}".Trim();
            return true;
        }

        private static string MssqlYear(int major, int minor) => major switch
        {
            8 => "2000",
            9 => "2005",
            10 => minor >= 50 ? "2008 R2" : "2008",
            11 => "2012",
            12 => "2014",
            13 => "2016",
            14 => "2017",
            15 => "2019",
            16 => "2022",
            17 => "2025",
            _ => string.Empty,
        };

        private static string FirstLines(string text, int count) =>
            string.Join(" | ", text.Split('\n').Select(l => l.Trim('\r', ' ')).Where(l => l.Length > 0).Take(count));
    }

    // ====================================================================== connection

    private delegate bool Completion(ReadOnlySpan<byte> data);

    /// <summary>One TCP connection (optionally upgraded to TLS) with timeout-bounded reads that never corrupt the stream.</summary>
    private sealed class Conn : IAsyncDisposable
    {
        private readonly ScanContext _ctx;
        private readonly Socket _socket;
        private readonly NetworkStream _net;
        private readonly byte[] _buffer = new byte[16 * 1024];
        private SslStream? _ssl;
        private Task<int>? _pending;
        private int _disposed;

        private Conn(ScanContext ctx, Socket socket)
        {
            _ctx = ctx;
            _socket = socket;
            _net = new NetworkStream(socket, ownsSocket: true);
        }

        public bool Closed { get; private set; }
        public SslStream? Ssl => _ssl;
        private Stream Stream => _ssl is not null ? _ssl : _net;

        public static async Task<Conn?> OpenAsync(ScanContext ctx, IPAddress address, int port)
        {
            await ctx.GateAsync().ConfigureAwait(false);
            var sw = Stopwatch.StartNew();
            try
            {
                var socket = await TcpConnector.ConnectAsync(ctx, new IPEndPoint(address, port), ctx.Options.ConnectTimeoutMs).ConfigureAwait(false);
                ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
                return new Conn(ctx, socket);
            }
            catch (Exception ex) when (ex is SocketException or TimeoutException)
            {
                ctx.Token.ThrowIfCancellationRequested();
                ctx.CountRequest(-1, error: true);
                ctx.Log(LogLevel.Debug, "service", $"connect {address}:{port} failed: {ex.Message}");
                return null;
            }
        }

        /// <summary>Waits until the server sends something (or closes) without consuming any bytes.</summary>
        public async Task<bool> WaitForDataAsync(int timeoutMs)
        {
            long deadline = Environment.TickCount64 + timeoutMs;
            while (true)
            {
                try
                {
                    if (_socket.Poll(0, SelectMode.SelectRead)) return true;
                }
                catch (Exception ex) when (ex is SocketException or ObjectDisposedException)
                {
                    return true;
                }
                if (Environment.TickCount64 >= deadline) return false;
                await Task.Delay(20, _ctx.Token).ConfigureAwait(false);
            }
        }

        public async Task<bool> UpgradeTlsAsync(string sni)
        {
            if (_pending is not null || Closed) return false;
            var ssl = new SslStream(_net, leaveInnerStreamOpen: true);
            var options = new SslClientAuthenticationOptions
            {
                TargetHost = sni,
                // Identification only: certificate problems are reported by the TLS audit, not here.
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            };
            await _ctx.GateAsync().ConfigureAwait(false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_ctx.Token);
            cts.CancelAfter(_ctx.Options.ReadTimeoutMs);
            var sw = Stopwatch.StartNew();
            try
            {
                await ssl.AuthenticateAsClientAsync(options, cts.Token).ConfigureAwait(false);
                _ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
                _ssl = ssl;
                return true;
            }
            catch (OperationCanceledException) when (!_ctx.Token.IsCancellationRequested)
            {
                _ctx.CountRequest(-1);
            }
            catch (Exception ex) when (ex is AuthenticationException or IOException or SocketException or Win32Exception
                                           or InvalidOperationException or ObjectDisposedException)
            {
                _ctx.Token.ThrowIfCancellationRequested();
                _ctx.CountRequest(sw.Elapsed.TotalMilliseconds);
                _ctx.Log(LogLevel.Debug, "service", $"TLS handshake with {_socket.RemoteEndPoint}: {(ex.InnerException ?? ex).Message}");
            }
            ssl.Dispose();
            Closed = true;
            return false;
        }

        public async Task<bool> SendAsync(byte[] data)
        {
            if (Closed) return false;
            await _ctx.GateAsync().ConfigureAwait(false);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(_ctx.Token);
            cts.CancelAfter(_ctx.Options.ReadTimeoutMs);
            try
            {
                await Stream.WriteAsync(data, cts.Token).ConfigureAwait(false);
                await Stream.FlushAsync(cts.Token).ConfigureAwait(false);
                return true;
            }
            catch (OperationCanceledException) when (!_ctx.Token.IsCancellationRequested)
            {
                Closed = true;
                return false;
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or NotSupportedException)
            {
                _ctx.Token.ThrowIfCancellationRequested();
                Closed = true;
                return false;
            }
        }

        /// <summary>Sends a request and collects the reply; counts the round trip for throughput/latency metrics.</summary>
        public async Task<byte[]> ExchangeAsync(byte[] request, Completion? complete, int totalMs, int idleMs = 0, int max = 64 * 1024)
        {
            var sw = Stopwatch.StartNew();
            if (!await SendAsync(request).ConfigureAwait(false))
            {
                _ctx.CountRequest(-1, error: true);
                return Array.Empty<byte>();
            }
            var reply = await ReceiveAsync(complete, totalMs, idleMs, max).ConfigureAwait(false);
            _ctx.CountRequest(reply.Length > 0 ? sw.Elapsed.TotalMilliseconds : -1);
            return reply;
        }

        /// <summary>
        /// Reads until <paramref name="complete"/> says the message is whole, the peer closes, <paramref name="max"/> bytes arrive,
        /// the total timeout passes, or (when idleMs &gt; 0) no new data arrives for idleMs after the first bytes.
        /// </summary>
        public async Task<byte[]> ReceiveAsync(Completion? complete, int totalMs, int idleMs = 0, int max = 64 * 1024, byte[]? prefix = null)
        {
            using var acc = new MemoryStream();
            if (prefix is { Length: > 0 })
            {
                acc.Write(prefix);
                if (complete != null && complete(acc.GetBuffer().AsSpan(0, (int)acc.Length))) return acc.ToArray();
            }
            long deadline = Environment.TickCount64 + Math.Max(1, totalMs);
            while (acc.Length < max)
            {
                long remaining = deadline - Environment.TickCount64;
                if (remaining <= 0) break;
                int wait = acc.Length > 0 && idleMs > 0 ? (int)Math.Min(remaining, idleMs) : (int)remaining;
                int n = await ReadOnceAsync(acc, wait).ConfigureAwait(false);
                if (n <= 0) break;
                if (complete != null && complete(acc.GetBuffer().AsSpan(0, (int)acc.Length))) break;
            }
            return acc.ToArray();
        }

        /// <summary>One read. Returns bytes read, 0 when closed, -1 on timeout (the read stays pending and is resumed next call).</summary>
        private async Task<int> ReadOnceAsync(MemoryStream into, int timeoutMs)
        {
            if (Closed) return 0;
            var read = _pending ??= Stream.ReadAsync(_buffer.AsMemory()).AsTask();
            if (!read.IsCompleted)
            {
                using var delayCts = CancellationTokenSource.CreateLinkedTokenSource(_ctx.Token);
                var delay = Task.Delay(Math.Max(1, timeoutMs), delayCts.Token);
                var winner = await Task.WhenAny(read, delay).ConfigureAwait(false);
                delayCts.Cancel();
                if (winner != read)
                {
                    _ctx.Token.ThrowIfCancellationRequested();
                    return -1;
                }
            }
            _pending = null;
            int n;
            try
            {
                n = await read.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException or AuthenticationException or InvalidOperationException)
            {
                Closed = true;
                return 0;
            }
            if (n <= 0)
            {
                Closed = true;
                return 0;
            }
            into.Write(_buffer, 0, n);
            return n;
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return ValueTask.CompletedTask;
            Closed = true;
            try
            {
                _ssl?.Dispose();
            }
            catch (IOException)
            {
            }
            _net.Dispose();
            _socket.Dispose();
            // Observe a read abandoned on timeout so its socket-closed exception is not reported as unobserved.
            _pending?.ContinueWith(static t => _ = t.Exception, CancellationToken.None, TaskContinuationOptions.OnlyOnFaulted, TaskScheduler.Default);
            _pending = null;
            return ValueTask.CompletedTask;
        }
    }

    // ====================================================================== helpers

    private static class Bson
    {
        public static byte[] Doc(params (string Key, object Value)[] fields)
        {
            using var ms = new MemoryStream();
            ms.Write(new byte[4]);
            Span<byte> num = stackalloc byte[4];
            foreach (var (key, value) in fields)
            {
                var name = Encoding.UTF8.GetBytes(key);
                switch (value)
                {
                    case int i:
                        ms.WriteByte(0x10);
                        ms.Write(name);
                        ms.WriteByte(0);
                        BinaryPrimitives.WriteInt32LittleEndian(num, i);
                        ms.Write(num);
                        break;
                    case bool b:
                        ms.WriteByte(0x08);
                        ms.Write(name);
                        ms.WriteByte(0);
                        ms.WriteByte(b ? (byte)1 : (byte)0);
                        break;
                    case string s:
                        var bytes = Encoding.UTF8.GetBytes(s);
                        ms.WriteByte(0x02);
                        ms.Write(name);
                        ms.WriteByte(0);
                        BinaryPrimitives.WriteInt32LittleEndian(num, bytes.Length + 1);
                        ms.Write(num);
                        ms.Write(bytes);
                        ms.WriteByte(0);
                        break;
                }
            }
            ms.WriteByte(0);
            var doc = ms.ToArray();
            BinaryPrimitives.WriteInt32LittleEndian(doc, doc.Length);
            return doc;
        }

        /// <summary>Minimal BSON reader for top-level scalar fields (nested documents are parsed recursively).</summary>
        public static Dictionary<string, object?> Parse(ReadOnlySpan<byte> d)
        {
            var result = new Dictionary<string, object?>(StringComparer.Ordinal);
            if (d.Length < 5) return result;
            int limit = Math.Min(BinaryPrimitives.ReadInt32LittleEndian(d), d.Length);
            int i = 4;
            while (i < limit - 1)
            {
                byte type = d[i++];
                if (type == 0) break;
                int nameLen = d[i..limit].IndexOf((byte)0);
                if (nameLen < 0) break;
                string name = Encoding.UTF8.GetString(d.Slice(i, nameLen));
                i += nameLen + 1;
                switch (type)
                {
                    case 0x01:
                        if (i + 8 > limit) return result;
                        result[name] = BinaryPrimitives.ReadDoubleLittleEndian(d[i..]);
                        i += 8;
                        break;
                    case 0x02:
                    {
                        if (i + 4 > limit) return result;
                        int len = BinaryPrimitives.ReadInt32LittleEndian(d[i..]);
                        if (len < 1 || i + 4 + len > limit) return result;
                        result[name] = Encoding.UTF8.GetString(d.Slice(i + 4, len - 1));
                        i += 4 + len;
                        break;
                    }
                    case 0x03:
                    case 0x04:
                    {
                        if (i + 4 > limit) return result;
                        int len = BinaryPrimitives.ReadInt32LittleEndian(d[i..]);
                        if (len < 5 || i + len > limit) return result;
                        result[name] = type == 0x03 ? Parse(d.Slice(i, len)) : null;
                        i += len;
                        break;
                    }
                    case 0x05:
                    {
                        if (i + 4 > limit) return result;
                        int len = BinaryPrimitives.ReadInt32LittleEndian(d[i..]);
                        if (len < 0) return result;
                        i += 4 + 1 + len;
                        break;
                    }
                    case 0x07: i += 12; break;
                    case 0x08:
                        if (i >= limit) return result;
                        result[name] = d[i] != 0;
                        i += 1;
                        break;
                    case 0x09:
                    case 0x11:
                        i += 8;
                        break;
                    case 0x12:
                        if (i + 8 > limit) return result;
                        result[name] = BinaryPrimitives.ReadInt64LittleEndian(d[i..]);
                        i += 8;
                        break;
                    case 0x0A:
                    case 0x7F:
                    case 0xFF:
                        result[name] = null;
                        break;
                    case 0x10:
                        if (i + 4 > limit) return result;
                        result[name] = BinaryPrimitives.ReadInt32LittleEndian(d[i..]);
                        i += 4;
                        break;
                    case 0x13: i += 16; break;
                    default: return result;
                }
            }
            return result;
        }
    }

    private static class Text
    {
        public static string Latin1(byte[] data) => Encoding.Latin1.GetString(data);

        /// <summary>Printable ASCII only, control characters collapsed to single spaces, at most <paramref name="max"/> characters.</summary>
        public static string Sanitize(string s, int max = 200)
        {
            var sb = new StringBuilder(Math.Min(s.Length, max));
            bool space = false;
            foreach (char c in s)
            {
                if (c is >= ' ' and < (char)0x7F)
                {
                    if (c == ' ' && space) continue;
                    sb.Append(c);
                    space = c == ' ';
                }
                else if (!space && sb.Length > 0)
                {
                    sb.Append(' ');
                    space = true;
                }
                if (sb.Length >= max) break;
            }
            return sb.ToString().Trim();
        }

        public static string Clip(string s, int max) => s.Length <= max ? s : s[..max] + "...";

        public static string TlsName(SslProtocols protocol) => (int)protocol switch
        {
            0x3000 => "TLSv1.3",
            0x0C00 => "TLSv1.2",
            0x0300 => "TLSv1.1",
            0x00C0 => "TLSv1.0",
            0x0030 => "SSLv3",
            0x000C => "SSLv2",
            _ => protocol.ToString(),
        };
    }
}
