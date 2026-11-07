using System.Globalization;
using System.Text.RegularExpressions;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>
/// Offline rules evaluated for every identified service: risky exposures (cleartext / legacy protocols,
/// unauthenticated databases, remote administration) and well-known vulnerable versions from banners.
/// No network traffic is generated here; everything is derived from what ServiceProbe observed.
/// </summary>
internal static class VulnRules
{
    private const string BannerCaveat =
        " Note: the version comes from the service banner. Linux/BSD distributions often backport security fixes without changing " +
        "the upstream version string, so verify against the installed package version before acting.";

    /// <summary>Exposure and known-vulnerable-version rules for one identified service. Reports findings and returns the port's risk rating.</summary>
    public static Severity Evaluate(ScanContext ctx, OpenService svc)
    {
        var e = new Evaluator(ctx, svc);
        e.ExposureRules();
        e.VersionRules();
        return e.Risk;
    }

    private sealed class Evaluator
    {
        private readonly ScanContext _ctx;
        private readonly OpenService _svc;
        private readonly string _text;
        private readonly string _distroNote;

        public Severity Risk { get; private set; }

        public Evaluator(ScanContext ctx, OpenService svc)
        {
            _ctx = ctx;
            _svc = svc;
            _text = string.Join("\n", $"{svc.Product} {svc.Version}".Trim(), svc.Banner, FactText("http.server"), FactText("http.powered_by"));
            Risk = IsGeneric ? Severity.Info : Severity.Low;
            var distro = Regex.Match(_text, @"\b(Ubuntu|Debian|deb\d+u\d+|el[5-9]|Red Hat|CentOS|Rocky|AlmaLinux|FreeBSD|Raspbian|SUSE|Amazon Linux|amzn\d)\b", RegexOptions.IgnoreCase);
            _distroNote = distro.Success
                ? $" A distribution build was detected (\"{distro.Value}\"), so a backported fix is plausible."
                : string.Empty;
        }

        private bool IsGeneric => _svc.Service.Length == 0
            || _svc.Service.Equals("unknown", StringComparison.OrdinalIgnoreCase)
            || _svc.Service.Equals("tcpwrapped", StringComparison.OrdinalIgnoreCase);

        private string FactText(string key) => _svc.Facts.TryGetValue(key, out var v) ? v : string.Empty;

        private bool? Fact(string key)
        {
            if (!_svc.Facts.TryGetValue(key, out var v)) return null;
            return v.Trim().ToLowerInvariant() switch
            {
                "true" or "yes" or "1" or "on" or "enabled" => true,
                "false" or "no" or "0" or "off" or "disabled" => false,
                _ => null,
            };
        }

        /// <summary>True when the service name is one of <paramref name="names"/>, or the service is unidentified and sits on one of the default ports.</summary>
        private bool Is(string[] names, params int[] ports)
        {
            foreach (var n in names)
                if (_svc.Service.Equals(n, StringComparison.OrdinalIgnoreCase)) return true;
            return IsGeneric && Array.IndexOf(ports, _svc.Port) >= 0;
        }

        private bool ProductHas(string word) =>
            _svc.Product.Contains(word, StringComparison.OrdinalIgnoreCase) || _svc.Banner.Contains(word, StringComparison.OrdinalIgnoreCase);

        private string Where => $"{_svc.Host.Ip}:{_svc.Port}/tcp";

        private string Observed
        {
            get
            {
                var parts = new List<string> { $"{Where} open", $"service={_svc.Service}" };
                if (_svc.Product.Length > 0) parts.Add($"product={_svc.DisplayBanner}");
                if (_svc.Banner.Length > 0) parts.Add($"banner=\"{_svc.Banner}\"");
                return string.Join(", ", parts);
            }
        }

        private void Add(Severity sev, string title, int cwe, string description, string evidence, string remediation)
        {
            _ctx.AddFinding(sev, title, _svc.Host.Ip, _svc.Port, cwe, description, evidence, remediation);
            if (sev > Risk) Risk = sev;
        }

        // ------------------------------------------------------------ exposure rules

        public void ExposureRules()
        {
            // Telnet
            if (Is(["telnet"], 23))
                Add(Severity.High, "Telnet service exposed (cleartext remote login)", 319,
                    "A Telnet service is reachable. Telnet transmits credentials and the whole session in cleartext, so anyone on the network path can capture passwords and hijack sessions.",
                    Observed,
                    "Disable Telnet and use SSH instead. If the device only supports Telnet, restrict it to a dedicated management network or VPN with firewall rules.");

            // FTP
            if (Is(["ftp"], 21))
            {
                if (!_svc.Tls)
                    Add(Severity.Medium, "FTP service exposed (cleartext authentication)", 319,
                        "An FTP service is reachable. Plain FTP sends user names, passwords and file contents unencrypted.",
                        Observed + (FactText("ftp.auth_tls").Length > 0 ? $", AUTH TLS={FactText("ftp.auth_tls")}" : string.Empty),
                        "Replace FTP with SFTP or enforce FTPS (explicit AUTH TLS required for all logins). Restrict access to trusted networks.");
                if (Fact("ftp.anonymous") == true)
                    Add(Severity.High, "Anonymous FTP login allowed", 284,
                        "The FTP server accepted a login as user \"anonymous\". Anyone can list and download files, and possibly upload, depending on permissions.",
                        Observed + ", anonymous login accepted (ftp.anonymous=true)",
                        "Disable anonymous access (e.g. anonymous_enable=NO in vsftpd, <Anonymous> block removed in ProFTPD) unless it is an intentional public mirror with read-only, non-sensitive content.");
            }

            // Berkeley r-services
            if (_svc.Port is >= 512 and <= 514 && (IsGeneric || Is(["exec", "rexec", "login", "rlogin", "shell", "rsh"])))
            {
                string name = _svc.Port switch { 512 => "rexec", 513 => "rlogin", _ => "rsh" };
                Add(Severity.High, $"Legacy Berkeley r-service exposed ({name})", 319,
                    $"The {name} service is reachable. Berkeley r-services authenticate by source address/.rhosts trust and transmit data in cleartext; they are trivially abused for remote command execution.",
                    Observed,
                    "Disable rexec/rlogin/rsh (remove them from inetd/xinetd/systemd) and use SSH.");
            }

            // SMB
            if (Is(["smb", "microsoft-ds", "netbios-ssn", "cifs"], 139, 445) || _svc.Facts.ContainsKey("smb.dialect"))
            {
                string dialect = FactText("smb.dialect");
                if (Fact("smb.smb1") == true)
                    Add(Severity.High, "SMBv1 protocol enabled", 327,
                        "The server negotiates the obsolete SMB 1.0 protocol. SMBv1 has no modern integrity/encryption protections and is the attack surface of MS17-010 (EternalBlue, CVE-2017-0144) used by WannaCry and NotPetya. Unpatched hosts with SMBv1 are remotely exploitable.",
                        Observed + ", smb.smb1=true" + (dialect.Length > 0 ? $", dialect={dialect}" : string.Empty),
                        "Disable SMBv1 (Windows: Set-SmbServerConfiguration -EnableSMB1Protocol $false / remove the SMB1Protocol feature; Samba: server min protocol = SMB2_10). Make sure MS17-010 is installed.");
                if (Fact("smb.signing_required") == false)
                    Add(Severity.Medium, "SMB signing not required", 294,
                        "The SMB server does not require message signing. An attacker in a man-in-the-middle position can relay NTLM authentication to this host (SMB relay) and tamper with traffic.",
                        Observed + ", smb.signing_required=false" + (dialect.Length > 0 ? $", dialect={dialect}" : string.Empty),
                        "Require SMB signing (GPO: 'Microsoft network server: Digitally sign communications (always)' = Enabled; Samba: server signing = mandatory).");
            }

            // RDP
            if (Is(["rdp", "ms-wbt-server"], 3389))
            {
                Add(Severity.Medium, "Remote Desktop (RDP) exposed", 668,
                    "Remote Desktop is reachable from the scanning position. Exposed RDP is a primary target for password spraying and for pre-authentication vulnerabilities such as BlueKeep (CVE-2019-0708).",
                    Observed,
                    "Do not expose RDP directly; publish it through a VPN or RD Gateway with MFA, restrict source addresses, and enable account lockout.");
                if (Fact("rdp.nla") == false)
                    Add(Severity.High, "RDP Network Level Authentication (NLA) not enforced", 287,
                        "The RDP service accepts connections without Network Level Authentication, so a full graphical session is created before the user authenticates. This exposes the logon screen to anyone and widens the pre-auth attack surface (e.g. CVE-2019-0708).",
                        Observed + ", rdp.nla=false (server accepted standard RDP security / TLS without CredSSP)",
                        "Enable 'Require user authentication for remote connections by using Network Level Authentication' (GPO or System Properties > Remote).");
            }

            // VNC
            if (Is(["vnc", "rfb"], 5900, 5901, 5902, 5903) || _svc.Banner.StartsWith("RFB ", StringComparison.Ordinal))
                Add(Severity.High, "VNC remote desktop exposed", 668,
                    "A VNC server is reachable. VNC authentication is a single short password (DES challenge, max 8 characters) and sessions are usually unencrypted.",
                    Observed,
                    "Restrict VNC to localhost and tunnel it over SSH or a VPN; never expose it to untrusted networks.");

            // Databases and data stores
            DataStore(["mysql"], [3306], "MySQL", "mysql", null);
            DataStore(["postgresql", "postgres"], [5432], "PostgreSQL", "postgresql", null);
            DataStore(["mssql", "ms-sql-s", "ms-sql"], [1433], "Microsoft SQL Server", "sql server", null);
            DataStore(["oracle", "oracle-tns", "tns"], [1521], "Oracle TNS listener", "oracle", null);
            DataStore(["mongodb", "mongod", "mongo"], [27017, 27018], "MongoDB", "mongodb", "mongodb.noauth");
            DataStore(["redis"], [6379], "Redis", "redis", "redis.noauth");
            DataStore(["elasticsearch", "elastic"], [9200, 9300], "Elasticsearch", "elasticsearch", "elasticsearch.noauth");
            DataStore(["memcached", "memcache"], [11211], "Memcached", "memcached", "memcached.noauth");
            DataStore(["couchdb"], [5984], "CouchDB", "couchdb", null);
            DataStore(["cassandra"], [9042], "Cassandra", "cassandra", null);

            if (Fact("postgres.ssl") == false)
                Add(Severity.Low, "PostgreSQL does not support SSL/TLS", 319,
                    "The PostgreSQL server answered the SSLRequest with 'N', so client connections (including passwords for non-SCRAM methods) are unencrypted.",
                    Observed + ", postgres.ssl=false",
                    "Enable ssl = on in postgresql.conf with a valid certificate and use hostssl entries in pg_hba.conf.");

            // Docker Engine API
            if (_svc.Port == 2375 && !_svc.Tls && (IsGeneric || _svc.Http || Is(["docker"]) || ProductHas("docker")))
                Add(Severity.Critical, "Docker Engine API exposed without TLS (port 2375)", 306,
                    "The Docker daemon API listens on TCP 2375 without TLS client authentication. Anyone who can reach it can start privileged containers and take over the host.",
                    Observed,
                    "Bind the Docker socket to localhost/unix socket only, or require mutual TLS on 2376 (--tlsverify). Block 2375 at the firewall.");

            // Kubernetes
            if (Is(["kubernetes", "kube-apiserver", "kubelet", "https", "http"], 6443, 10250) && (_svc.Port is 6443 or 10250))
            {
                string what = _svc.Port == 10250 ? "Kubelet API" : "Kubernetes API server";
                Add(Severity.Medium, $"{what} exposed (port {_svc.Port})", 668,
                    $"The {what} is reachable from the scanning position. If anonymous authentication or permissive RBAC is configured it allows cluster takeover (e.g. command execution in pods via the kubelet).",
                    Observed,
                    "Restrict control-plane and kubelet ports to the cluster network, disable anonymous auth (--anonymous-auth=false) and use Webhook authorization for kubelets.");
            }

            // SMTP
            if (Is(["smtp", "submission", "smtps"], 25, 587, 465) || _svc.Facts.ContainsKey("smtp.starttls"))
            {
                if (Fact("smtp.vrfy") == true)
                    Add(Severity.Low, "SMTP VRFY command enabled (user enumeration)", 200,
                        "The mail server answers VRFY, which lets anyone check whether a mailbox/user name exists.",
                        Observed + ", smtp.vrfy=true",
                        "Disable VRFY/EXPN (Postfix: disable_vrfy_command = yes; Exim: remove 'verify' ACL for VRFY; Sendmail: PrivacyOptions=goaway).");
                if (Fact("smtp.starttls") == false && !_svc.Tls)
                    Add(Severity.Low, "SMTP service does not offer STARTTLS", 319,
                        "The SMTP server does not advertise STARTTLS in its EHLO response, so mail and any SMTP AUTH credentials travel in cleartext.",
                        Observed + ", smtp.starttls=false",
                        "Configure a certificate and enable STARTTLS (Postfix: smtpd_tls_security_level = may/encrypt).");
            }
        }

        private void DataStore(string[] names, int[] ports, string display, string productWord, string? noAuthKey)
        {
            bool match = Is(names, ports) || ProductHas(productWord) || (noAuthKey != null && _svc.Facts.ContainsKey(noAuthKey));
            if (!match) return;
            if (productWord == "mysql" && ProductHas("mariadb")) display = "MariaDB";
            Add(Severity.Medium, $"{display} database service reachable from the network", 668,
                $"The {display} service accepts TCP connections from the scanning position. Databases should only be reachable by the application servers that need them; network exposure enables password guessing and exploitation of server vulnerabilities.",
                Observed,
                $"Bind {display} to localhost or an internal interface and restrict access with host firewall / security group rules to the application hosts only.");
            if (noAuthKey != null && Fact(noAuthKey) == true)
                Add(Severity.Critical, $"{display} accessible without authentication", 306,
                    $"The {display} service answered a read-only status/info request without any credentials. Anyone who can reach it can read and modify all stored data (and for Redis, often achieve code execution by rewriting files).",
                    Observed + $", {noAuthKey}=true (unauthenticated read-only request succeeded)",
                    $"Enable authentication on {display} (e.g. Redis requirepass/ACLs, MongoDB security.authorization: enabled, Elasticsearch xpack.security.enabled: true, Memcached SASL) and restrict network access.");
        }

        // ------------------------------------------------------------ version rules

        private string? Ver(string pattern)
        {
            var m = Regex.Match(_text, pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            return m.Success ? m.Groups["v"].Value : null;
        }

        private void Cve(Severity sev, string title, int cwe, string product, string version, string description, string remediation, string? extra = null)
        {
            string evidence = $"{Observed}. Version banner indicates {product} {version}." + (extra != null ? " " + extra : string.Empty);
            Add(sev, title, cwe,
                $"Version banner indicates {product} {version}, which is in the affected range. {description}{_distroNote}{BannerCaveat}",
                evidence, remediation);
        }

        /// <summary>Version reported by ServiceProbe when its product name contains <paramref name="word"/>.</summary>
        private string? ProductVersion(string word) =>
            _svc.Product.Contains(word, StringComparison.OrdinalIgnoreCase) ? VersionComparer.Extract(_svc.Version) : null;

        private static bool Lt(string v, string bound) => VersionComparer.Compare(v, bound) < 0;
        private static bool Ge(string v, string bound) => VersionComparer.Compare(v, bound) >= 0;
        private static bool Eq(string v, string bound) => VersionComparer.Compare(v, bound) == 0;

        public void VersionRules()
        {
            OpenSsh();
            Dropbear();
            Ftp();
            Exim();
            Apache();
            Nginx();
            Iis();
            Redis();
            Elasticsearch();
            MySql();
            Php();
            OpenSsl();
        }

        private void OpenSsh()
        {
            var win = Ver(@"OpenSSH[_/ \-]?for[_ ]Windows[_ ](?<v>\d+\.\d+(?:\.\d+)?(?:p\d+)?)");
            var v = win ?? Ver(@"OpenSSH[_/ \-]?(?<v>\d+\.\d+(?:p\d+)?)") ?? ProductVersion("openssh");
            if (v == null) return;
            // regreSSHion depends on glibc's async-signal-unsafe syslog; Win32-OpenSSH is not affected.
            if (win == null && ((Ge(v, "8.5p1") && Lt(v, "9.8p1")) || Lt(v, "4.4p1")))
                Cve(Severity.High, $"OpenSSH {v} regreSSHion signal handler race (CVE-2024-6387)", 364, "OpenSSH", v,
                    "CVE-2024-6387 is a race condition in sshd's SIGALRM handler (LoginGraceTime) that allows unauthenticated remote code execution as root on glibc-based Linux systems.",
                    "Upgrade to OpenSSH 9.8p1 or later (or the distribution package that includes the CVE-2024-6387 fix). Temporary mitigation: LoginGraceTime 0 in sshd_config (exposes the server to connection exhaustion).");
            if (Lt(v, "9.6"))
                Cve(Severity.Medium, $"OpenSSH {v} Terrapin prefix truncation (CVE-2023-48795)", 354, "OpenSSH", v,
                    "CVE-2023-48795 (Terrapin) lets a man-in-the-middle drop messages at the start of the secure channel when ChaCha20-Poly1305 or Encrypt-then-MAC modes are negotiated, downgrading connection security (e.g. disabling keystroke timing obfuscation).",
                    "Upgrade to OpenSSH 9.6 or later (strict key exchange), or disable chacha20-poly1305@openssh.com and *-etm@openssh.com MACs until upgraded.");
            if (Lt(v, "7.7"))
                Cve(Severity.Medium, $"OpenSSH {v} username enumeration (CVE-2018-15473)", 203, "OpenSSH", v,
                    "CVE-2018-15473: sshd before 7.7 responds differently to authentication requests for valid and invalid users, allowing remote enumeration of account names.",
                    "Upgrade to OpenSSH 7.7 or later.");
        }

        private void Dropbear()
        {
            var v = Ver(@"dropbear(?:[_ ]sshd)?[_ /](?<v>\d{4}\.\d+)") ?? ProductVersion("dropbear");
            if (v == null) return;
            if (Lt(v, "2016.74"))
                Cve(Severity.Critical, $"Dropbear SSH {v} format string vulnerability (CVE-2016-7406)", 134, "Dropbear SSH", v,
                    "CVE-2016-7406: format string flaw in Dropbear before 2016.74 allows remote attackers to execute arbitrary code via crafted user names or host arguments.",
                    "Upgrade Dropbear to 2016.74 or later (preferably the current release); update the firmware of embedded devices.");
            else if (Lt(v, "2022.83"))
                Cve(Severity.Medium, $"Outdated Dropbear SSH {v} (multiple CVEs)", 1104, "Dropbear SSH", v,
                    "Dropbear releases before 2022.83 lack fixes for several vulnerabilities (e.g. CVE-2021-36369 trivial-auth bypass in the client, CVE-2020-36254 path validation).",
                    "Upgrade Dropbear (or the device firmware) to a current release.");
        }

        private void Ftp()
        {
            var vs = Ver(@"vsftpd[ /:]*\(?v?(?<v>\d+\.\d+\.\d+[a-z]?)") ?? ProductVersion("vsftpd");
            if (vs != null && Eq(vs, "2.3.4"))
                Cve(Severity.Critical, "vsftpd 2.3.4 backdoor (CVE-2011-2523)", 506, "vsftpd", vs,
                    "The vsftpd 2.3.4 source archive distributed in mid-2011 contained a backdoor: a user name ending in ':)' opens a root shell on TCP port 6200. Note: legitimate builds of 2.3.4 are not backdoored, but the version must be verified.",
                    "Replace vsftpd with a clean, current build from a trusted source and investigate the host for compromise.");

            var pf = Ver(@"ProFTPD[ /](?<v>\d+\.\d+\.\d+[a-z]?(?:rc\d+)?)") ?? ProductVersion("proftpd");
            if (pf == null) return;
            if (Eq(pf, "1.3.5"))
                Cve(Severity.Critical, "ProFTPD 1.3.5 mod_copy unauthenticated file copy (CVE-2015-3306)", 284, "ProFTPD", pf,
                    "CVE-2015-3306: the mod_copy module allows unauthenticated SITE CPFR/CPTO commands, letting remote attackers copy arbitrary files (commonly used to write a web shell for code execution).",
                    "Upgrade ProFTPD to 1.3.5a or later, or disable mod_copy (LoadModule removal / <IfModule mod_copy.c> SiteCopy off).");
            if (Lt(pf, "1.3.5e") || (Ge(pf, "1.3.6") && Lt(pf, "1.3.6b")))
                Cve(Severity.Critical, $"ProFTPD {pf} mod_copy arbitrary file copy (CVE-2019-12815)", 284, "ProFTPD", pf,
                    "CVE-2019-12815: mod_copy in ProFTPD before 1.3.5e and 1.3.6 before 1.3.6b allows remote file copy without the required permissions (remote code execution when combined with a web root).",
                    "Upgrade ProFTPD to 1.3.6b / 1.3.5e or later, or disable mod_copy.");
            if (Lt(pf, "1.3.7"))
                Cve(Severity.Medium, $"Outdated ProFTPD {pf}", 1104, "ProFTPD", pf,
                    "ProFTPD releases older than 1.3.7 lack fixes for multiple published vulnerabilities (e.g. CVE-2020-9273 use-after-free, CVE-2019-18217 denial of service).",
                    "Upgrade ProFTPD to the current stable release.");
        }

        private void Exim()
        {
            var v = Ver(@"\bExim[ /](?<v>\d+\.\d+(?:\.\d+)?)") ?? ProductVersion("exim");
            if (v == null) return;
            if (Ge(v, "4.87") && Lt(v, "4.92"))
                Cve(Severity.Critical, $"Exim {v} remote command execution (CVE-2019-10149)", 78, "Exim", v,
                    "CVE-2019-10149 ('Return of the WIZard'): improper validation of recipient addresses in deliver_message() in Exim 4.87 to 4.91 allows remote command execution as root.",
                    "Upgrade Exim to 4.92 or later (current release recommended).");
            if (Lt(v, "4.90.1"))
                Cve(Severity.Critical, $"Exim {v} base64 decode buffer overflow (CVE-2018-6789)", 787, "Exim", v,
                    "CVE-2018-6789: an off-by-one in b64decode() in Exim before 4.90.1 allows unauthenticated remote code execution via a crafted AUTH message.",
                    "Upgrade Exim to a current release.");
            if (Lt(v, "4.94.2"))
                Cve(Severity.Critical, $"Exim {v} 21Nails vulnerabilities (CVE-2020-28017 and others)", 190, "Exim", v,
                    "Exim before 4.94.2 is affected by the 21Nails set of vulnerabilities (e.g. CVE-2020-28017 integer overflow in receive_add_recipient, CVE-2020-28020), several of which allow unauthenticated remote code execution.",
                    "Upgrade Exim to 4.94.2 or later.");
            if (Lt(v, "4.96.1"))
                Cve(Severity.High, $"Exim {v} SPA/NTLM and EXTERNAL auth out-of-bounds write (CVE-2023-42115)", 787, "Exim", v,
                    "CVE-2023-42115: out-of-bounds write in the EXTERNAL SMTP authenticator in Exim before 4.96.1 allows unauthenticated remote code execution when that authenticator is configured.",
                    "Upgrade Exim to 4.96.1 or later.");
        }

        private void Apache()
        {
            var v = Ver(@"\bApache(?:[ _\-]?httpd| HTTP Server)?[/ ](?<v>\d+\.\d+\.\d+)");
            if (v == null) return;
            if (Eq(v, "2.4.49"))
                Cve(Severity.Critical, "Apache httpd 2.4.49 path traversal / RCE (CVE-2021-41773)", 22, "Apache httpd", v,
                    "CVE-2021-41773: a path normalization flaw in Apache 2.4.49 allows path traversal to files outside the document root (and remote code execution when mod_cgi is enabled) if 'Require all denied' is not set on the filesystem root.",
                    "Upgrade Apache httpd to 2.4.51 or later immediately.");
            if (Eq(v, "2.4.49") || Eq(v, "2.4.50"))
                Cve(Severity.Critical, $"Apache httpd {v} path traversal / RCE (CVE-2021-42013)", 22, "Apache httpd", v,
                    "CVE-2021-42013: the fix for CVE-2021-41773 in 2.4.50 was incomplete; double URL-encoded traversal sequences still allow file disclosure and remote code execution with mod_cgi.",
                    "Upgrade Apache httpd to 2.4.51 or later immediately.");
            if (Ge(v, "2.4.0") && Lt(v, "2.4.49"))
                Cve(Severity.High, $"Apache httpd {v} mod_proxy SSRF (CVE-2021-40438)", 918, "Apache httpd", v,
                    "CVE-2021-40438: a crafted request URI path can cause mod_proxy to forward the request to an origin server chosen by the remote user (server-side request forgery). Only exploitable when mod_proxy is in use.",
                    "Upgrade Apache httpd to the current 2.4 release.");
            if (Lt(v, "2.4.0"))
                Cve(Severity.High, $"End-of-life Apache httpd {v}", 1104, "Apache httpd", v,
                    "Apache httpd branches before 2.4 (2.2 reached end of life in 2017) receive no security fixes and are affected by many published vulnerabilities.",
                    "Migrate to the current Apache httpd 2.4 release.");
            else if (Lt(v, "2.4.62"))
                Cve(Severity.Medium, $"Outdated Apache httpd {v} (multiple CVEs)", 1104, "Apache httpd", v,
                    "Apache httpd releases before 2.4.62 miss fixes for multiple published vulnerabilities, e.g. CVE-2023-44487 / CVE-2024-27316 (HTTP/2 denial of service), CVE-2024-38474 and CVE-2024-38476 (mod_rewrite / handler confusion, fixed in 2.4.60) and CVE-2024-40898 (SSRF on Windows, fixed in 2.4.62).",
                    "Upgrade Apache httpd to the latest 2.4 release.");
        }

        private void Nginx()
        {
            var v = Ver(@"\bnginx[/ ](?<v>\d+\.\d+\.\d+)") ?? ProductVersion("nginx");
            if (v == null) return;
            if (Ge(v, "0.6.18") && Lt(v, "1.20.1"))
                Cve(Severity.High, $"nginx {v} DNS resolver off-by-one (CVE-2021-23017)", 193, "nginx", v,
                    "CVE-2021-23017: an off-by-one error in the nginx resolver (0.6.18 - 1.20.0) allows a forged DNS response to cause a 1-byte memory overwrite, leading to worker crash or potentially code execution. Only exploitable when the 'resolver' directive is used.",
                    "Upgrade nginx to 1.20.1 / 1.21.0 or later.");
            if (Lt(v, "1.20.0"))
                Cve(Severity.Medium, $"Outdated nginx {v}", 1104, "nginx", v,
                    "This nginx release is older than every currently supported branch and lacks fixes for published vulnerabilities (e.g. CVE-2019-9511/9513/9516 HTTP/2 resource exhaustion, CVE-2021-23017).",
                    "Upgrade nginx to the current stable or mainline release.");
        }

        private void Iis()
        {
            var v = Ver(@"Microsoft[- ]IIS[/ ](?<v>\d+\.\d+)") ?? (_svc.Product.Contains("IIS", StringComparison.OrdinalIgnoreCase) ? VersionComparer.Extract(_svc.Version) : null);
            if (v == null) return;
            if (Eq(v, "6.0"))
                Cve(Severity.Critical, "Microsoft IIS 6.0 WebDAV buffer overflow (CVE-2017-7269)", 119, "Microsoft IIS", v,
                    "CVE-2017-7269: buffer overflow in ScStoragePathFromUrl in the IIS 6.0 WebDAV service allows remote code execution via a long PROPFIND If header. IIS 6.0 (Windows Server 2003) is end-of-life and will not receive fixes.",
                    "Decommission Windows Server 2003 / IIS 6.0; until then disable WebDAV and isolate the host.");
            if (Lt(v, "7.5"))
                Cve(Severity.High, $"End-of-life Microsoft IIS {v}", 1104, "Microsoft IIS", v,
                    "IIS versions before 7.5 ship with Windows releases that are out of support and no longer receive security updates.",
                    "Migrate the site to a supported Windows Server release.");
        }

        private void Redis()
        {
            var v = Ver(@"redis(?:_version:|[ /]v?|\s+server\s+v=)(?<v>\d+\.\d+\.\d+)") ?? ProductVersion("redis");
            if (v == null) return;
            if (Lt(v, "6.0"))
                Cve(Severity.Medium, $"End-of-life Redis {v}", 1104, "Redis", v,
                    "Redis versions before 6.0 are out of support, have no ACL system (a single shared password at most) and lack fixes for several published vulnerabilities (e.g. CVE-2021-32626 Lua stack overflow, CVE-2022-0543 Debian Lua sandbox escape).",
                    "Upgrade to a supported Redis release and enable ACLs.");
            bool fixedLua = (Ge(v, "6.2.20") && Lt(v, "7.0")) || (Ge(v, "7.2.11") && Lt(v, "7.4")) || (Ge(v, "7.4.6") && Lt(v, "8.0"))
                            || (Ge(v, "8.0.4") && Lt(v, "8.2")) || Ge(v, "8.2.2");
            if (!fixedLua)
                Cve(Severity.High, $"Redis {v} Lua use-after-free (CVE-2025-49844)", 416, "Redis", v,
                    "CVE-2025-49844 ('RediShell'): a use-after-free in the Lua scripting engine lets a client that can run EVAL escape the Lua sandbox and execute code on the host. Fixed in 6.2.20, 7.2.11, 7.4.6, 8.0.4 and 8.2.2. Exploitation requires the ability to run commands (trivial when Redis has no password).",
                    "Upgrade Redis to a fixed release; restrict EVAL/EVALSHA via ACLs (-@scripting) and require authentication.");
        }

        private void Elasticsearch()
        {
            var v = ProductVersion("elasticsearch") ?? Ver(@"elasticsearch[ /:]*v?(?<v>\d+\.\d+\.\d+)") ?? Ver("\"number\"\\s*:\\s*\"(?<v>\\d+\\.\\d+\\.\\d+)\"");
            if (v == null) return;
            if (Lt(v, "1.2.0"))
                Cve(Severity.Critical, $"Elasticsearch {v} dynamic scripting RCE (CVE-2014-3120)", 284, "Elasticsearch", v,
                    "CVE-2014-3120: Elasticsearch before 1.2 enables dynamic MVEL scripting by default, allowing unauthenticated remote code execution through the search API.",
                    "Upgrade Elasticsearch to a supported release and enable security.");
            if (Lt(v, "1.3.8") || (Ge(v, "1.4.0") && Lt(v, "1.4.3")))
                Cve(Severity.Critical, $"Elasticsearch {v} Groovy sandbox escape (CVE-2015-1427)", 284, "Elasticsearch", v,
                    "CVE-2015-1427: the Groovy scripting sandbox in Elasticsearch before 1.3.8 and 1.4.x before 1.4.3 can be bypassed for unauthenticated remote code execution.",
                    "Upgrade Elasticsearch to a supported release.");
            if (Lt(v, "1.6.1"))
                Cve(Severity.High, $"Elasticsearch {v} snapshot API directory traversal (CVE-2015-5531)", 22, "Elasticsearch", v,
                    "CVE-2015-5531: directory traversal in the snapshot API of Elasticsearch before 1.6.1 allows reading arbitrary files.",
                    "Upgrade Elasticsearch to a supported release.");
            if (Lt(v, "7.0.0"))
                Cve(Severity.Medium, $"End-of-life Elasticsearch {v}", 1104, "Elasticsearch", v,
                    "Elasticsearch releases before 7.x are end-of-life and receive no security fixes; older releases also ship with security disabled by default.",
                    "Upgrade to a supported Elasticsearch release with security (TLS + authentication) enabled.");
        }

        private void MySql()
        {
            if (ProductHas("mariadb") || _svc.Version.Contains("mariadb", StringComparison.OrdinalIgnoreCase)) return;
            var v = Ver(@"\bMySQL[ /](?<v>\d+\.\d+\.\d+)") ?? ProductVersion("mysql");
            if (v == null) return;
            if (Lt(v, "8.4"))
            {
                string branch = Lt(v, "5.6") ? "5.5 and older (EOL December 2018)"
                    : Lt(v, "5.7") ? "5.6 (EOL February 2021)"
                    : Lt(v, "8.0") ? "5.7 (EOL October 2023)"
                    : "8.0 - 8.3 (8.0 EOL April 2026; 8.1-8.3 were short-lived innovation releases)";
                Cve(Severity.Medium, $"End-of-life MySQL {v}", 1104, "MySQL", v,
                    $"The MySQL branch {branch} no longer receives security updates from Oracle; each quarterly Critical Patch Update lists new server vulnerabilities that remain unfixed on this version.",
                    "Upgrade to a supported MySQL LTS release (8.4 or later).");
            }
        }

        private void Php()
        {
            var v = Ver(@"\bPHP/(?<v>\d+\.\d+\.\d+)");
            if (v == null) return;
            if (Lt(v, "8.2"))
                Cve(Severity.Medium, $"End-of-life PHP {v} disclosed in X-Powered-By", 1104, "PHP", v,
                    "This PHP branch no longer receives security fixes (PHP 7.4 ended November 2022, 8.0 November 2023, 8.1 December 2025). Vulnerabilities fixed later (e.g. CVE-2024-4577 CGI argument injection, CVE-2024-8926) remain unpatched.",
                    "Upgrade to a supported PHP release (8.2 or later) and set expose_php = Off in php.ini.");
        }

        private void OpenSsl()
        {
            var v = Ver(@"\bOpenSSL[/ ](?<v>\d+\.\d+\.\d+[a-z]?)");
            if (v == null) return;
            if (Ge(v, "1.0.1") && Lt(v, "1.0.1g"))
                Cve(Severity.High, $"OpenSSL {v} Heartbleed (CVE-2014-0160)", 125, "OpenSSL", v,
                    "CVE-2014-0160 (Heartbleed): the TLS heartbeat extension in OpenSSL 1.0.1 - 1.0.1f leaks up to 64 KB of process memory per request, including private keys and session data. (TryZ does not send heartbeat probes; this is version-based only.)",
                    "Upgrade OpenSSL, then revoke and re-issue certificates and rotate credentials that may have been exposed.");
            if (Lt(v, "1.1.0"))
                Cve(Severity.Medium, $"End-of-life OpenSSL {v}", 1104, "OpenSSL", v,
                    "OpenSSL 1.0.x and older reached end of life (1.0.2 in December 2019) and are affected by many published vulnerabilities.",
                    "Rebuild/upgrade the server against a supported OpenSSL 3.x release.");
            else if (Lt(v, "3.0.0"))
                Cve(Severity.Medium, $"End-of-life OpenSSL {v}", 1104, "OpenSSL", v,
                    "OpenSSL 1.1.1 reached end of public support in September 2023.",
                    "Upgrade to a supported OpenSSL 3.x release (or a vendor with extended support).");
        }
    }
}

/// <summary>
/// Compares software version strings as found in banners and in NVD CPE data:
/// "8.9p1", "2.4.49", "1.0.2k", "2016.74", "1.3.6rc1", "5.7.33-0ubuntu0.18.04.1".
/// Numeric dotted parts compare numerically; "pN" is a post-release patch level; a single trailing letter
/// (OpenSSL / ProFTPD style) sorts after the bare version; rc/beta/alpha/dev sort before it.
/// </summary>
internal static class VersionComparer
{
    private static readonly Regex Head = new(@"^\s*v?(?<num>\d+(?:\.\d+)*)(?:[._\-]?(?<sfx>[a-z]+)(?<sfxn>\d+)?)?",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>Returns the leading version token of <paramref name="text"/> (e.g. "5.7.33" from "5.7.33-0ubuntu0.18.04.1"), or null.</summary>
    public static string? Extract(string? text)
    {
        if (string.IsNullOrWhiteSpace(text)) return null;
        var m = Head.Match(text);
        if (!m.Success) return null;
        string s = m.Groups["num"].Value;
        if (m.Groups["sfx"].Success)
        {
            string sfx = m.Groups["sfx"].Value.ToLowerInvariant();
            string n = m.Groups["sfxn"].Value;
            bool keep = (sfx == "p" && n.Length > 0) || (sfx.Length == 1 && n.Length == 0) || IsPre(sfx, n.Length > 0);
            if (keep) s += sfx + n;
        }
        return s;
    }

    public static bool TryParse(string? text, out long[] parts)
    {
        parts = Array.Empty<long>();
        if (string.IsNullOrWhiteSpace(text)) return false;
        var m = Head.Match(text);
        if (!m.Success) return false;
        var list = new List<long>();
        foreach (var p in m.Groups["num"].Value.Split('.'))
            list.Add(long.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out long n) ? n : 0);
        if (m.Groups["sfx"].Success)
        {
            string sfx = m.Groups["sfx"].Value.ToLowerInvariant();
            string digits = m.Groups["sfxn"].Value;
            long num = digits.Length > 0 && long.TryParse(digits, NumberStyles.None, CultureInfo.InvariantCulture, out long d) ? d : 0;
            if (sfx == "p" && digits.Length > 0)
            {
                // OpenSSH portable patch level: 8.9p1 > 8.9
                list.Add(num);
            }
            else if (IsPre(sfx, digits.Length > 0))
            {
                list.Add(-1);
                list.Add(num);
            }
            else if (sfx.Length == 1 && digits.Length == 0)
            {
                // letter releases: 1.0.2k > 1.0.2a > 1.0.2
                list.Add(sfx[0] - 'a' + 1);
            }
        }
        parts = list.ToArray();
        return true;
    }

    private static bool IsPre(string sfx, bool hasDigits) => sfx is "rc" or "beta" or "alpha" or "pre" or "dev"
        || (hasDigits && sfx is "a" or "b" or "m");

    /// <summary>Compares two versions; unparsable versions compare as equal to nothing (they sort lowest).</summary>
    public static int Compare(string a, string b)
    {
        bool okA = TryParse(a, out var pa), okB = TryParse(b, out var pb);
        if (!okA || !okB) return okA.CompareTo(okB);
        int n = Math.Max(pa.Length, pb.Length);
        for (int i = 0; i < n; i++)
        {
            long x = i < pa.Length ? pa[i] : 0, y = i < pb.Length ? pb[i] : 0;
            if (x != y) return x.CompareTo(y);
        }
        return 0;
    }

    /// <summary>True when <paramref name="version"/> lies in the (optional) bounds, the way NVD cpeMatch ranges are expressed.</summary>
    public static bool InRange(string version, string? startIncluding, string? startExcluding, string? endIncluding, string? endExcluding)
    {
        if (!TryParse(version, out _)) return false;
        if (!string.IsNullOrEmpty(startIncluding) && Compare(version, startIncluding) < 0) return false;
        if (!string.IsNullOrEmpty(startExcluding) && Compare(version, startExcluding) <= 0) return false;
        if (!string.IsNullOrEmpty(endIncluding) && Compare(version, endIncluding) > 0) return false;
        if (!string.IsNullOrEmpty(endExcluding) && Compare(version, endExcluding) >= 0) return false;
        return true;
    }
}
