using System.Runtime.InteropServices;
using System.Threading.Channels;
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Shell;

/// <summary>
/// Command-line scan runner: drives a full assessment without the GUI and writes reports to disk, for automation and
/// CI. Authorization is enforced exactly as in the UI — a non-loopback target must be confirmed with --authorize.
/// </summary>
internal static class HeadlessRunner
{
    /// <summary>True when the arguments request a headless scan (as opposed to launching the GUI).</summary>
    public static bool IsHeadless(string[] args) =>
        args.Any(a => a is "scan" or "--scan" or "--target" or "-t" || a is "--help" or "-h" && args.Contains("scan"));

    public static int Run(string[] args)
    {
        EnsureConsole();
        if (args.Contains("--help") || args.Contains("-h"))
        {
            PrintUsage();
            return 0;
        }
        Opts o;
        try { o = Opts.Parse(args); }
        catch (ArgumentException ex)
        {
            Console.Error.WriteLine($"tryz: {ex.Message}");
            PrintUsage();
            return 2;
        }

        if (o.Target.Length == 0)
        {
            Console.Error.WriteLine("tryz: no target. Use: TryZ.exe scan <target> [options]");
            return 2;
        }
        if (!TargetParser.TryValidate(o.Target, out string error))
        {
            Console.Error.WriteLine($"tryz: invalid target: {error}");
            return 2;
        }
        bool loopback = MainForm.IsLoopbackTarget(o.Target);
        if (!loopback && !o.Authorized)
        {
            Console.Error.WriteLine(
                $"tryz: refusing to scan '{o.Target}' without authorization.\n" +
                "      Only scan systems you own or have written permission to assess.\n" +
                "      Re-run with --authorize to confirm you are authorized for this target.");
            return 3;
        }

        var settings = AppSettings.Load();
        o.ApplyTo(settings);
        var options = ScanOptions.From(settings, o.ProfileIndex, o.Threads > 0 ? o.Threads : settings.DefaultThreads);
        var request = new ScanRequest(o.Target, o.ProfileIndex, options.Threads, options);

        Console.Error.WriteLine($"TryZ {typeof(HeadlessRunner).Assembly.GetName().Version} — scanning {o.Target} " +
            $"({ScanOptions.ProfileNames[o.ProfileIndex]}, {options.Threads} workers)");
        if (options.RunActiveChecks) Console.Error.WriteLine("  active injection testing: ENABLED");
        if (options.HttpProxy.Length > 0) Console.Error.WriteLine($"  proxy: {options.HttpProxy}");

        var session = new Session { Target = o.Target, Profile = ScanOptions.ProfileNames[o.ProfileIndex], Threads = options.Threads, StartedAt = DateTime.Now };
        int exit = RunScanAsync(request, session, o.Quiet).GetAwaiter().GetResult();

        PrintSummary(session);
        WriteReports(o, session, settings);
        return exit;
    }

    private static async Task<int> RunScanAsync(ScanRequest request, Session session, bool quiet)
    {
        using var engine = new ScanEngine();
        ChannelReader<ScanEvent> reader = engine.Start(request);
        bool failed = false;
        try
        {
            await foreach (var ev in reader.ReadAllAsync().ConfigureAwait(false))
            {
                session.Apply(ev);
                switch (ev)
                {
                    case FindingFound f:
                        Console.Error.WriteLine($"  [{f.Finding.Severity,-8}] {f.Finding.Title}  ({f.Finding.Host}{(f.Finding.Port > 0 ? ":" + f.Finding.Port : "")})");
                        break;
                    case ScanLog log when !quiet && log.Level >= LogLevel.Notice:
                        Console.Error.WriteLine($"  {log.Level,-6} {log.Source}: {log.Text}");
                        break;
                    case ScanFailed:
                        failed = true;
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"tryz: scan error: {ex.Message}");
            return 1;
        }
        return failed ? 1 : 0;
    }

    private static void PrintSummary(Session session)
    {
        var c = session.SeverityCounts;
        Console.Error.WriteLine();
        Console.Error.WriteLine($"Scan complete in {session.ElapsedSeconds:0.0}s — {session.Hosts.Items.Count} host(s), " +
            $"{session.Ports.Items.Count} open port(s), {session.FindingCount} finding(s), {session.TotalRequests:N0} requests");
        Console.Error.WriteLine($"  Critical {c[(int)Severity.Critical]}  High {c[(int)Severity.High]}  " +
            $"Medium {c[(int)Severity.Medium]}  Low {c[(int)Severity.Low]}  Info {c[(int)Severity.Info]}");
    }

    private static void WriteReports(Opts o, Session session, AppSettings settings)
    {
        foreach (var format in o.Formats)
        {
            var info = ReportExporter.Describe(format);
            string path = o.OutPath.Length > 0
                ? (o.Formats.Count == 1 ? o.OutPath : Path.ChangeExtension(o.OutPath, info.Extension))
                : $"tryz-{info.FileTag}-{DateTime.Now:yyyyMMdd-HHmmss}.{info.Extension}";
            try
            {
                ReportExporter.Write(path, format, session, settings);
                Console.Error.WriteLine($"  wrote {info.Name}: {Path.GetFullPath(path)}");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                Console.Error.WriteLine($"tryz: could not write {path}: {ex.Message}");
            }
        }
    }

    private static void PrintUsage()
    {
        Console.Error.WriteLine("""
            TryZ Security Suite — command-line scanner

            Usage: TryZ.exe scan <target> [options]

            Target: an IP address, CIDR block, address range, host name or URL.

            Scope:
              --authorize            Confirm you are authorized to scan the target (required for non-loopback).

            Profile & performance:
              --profile <name>       Quick | Full | Web | Custom          (default: Full)
              --threads <n>          Worker count                          (default: from settings)
              --rate <n>             Max requests per second

            Modules:
              --active               Enable active injection testing (XSS, SQLi, traversal, open redirect)
              --discover             Enable dictionary content discovery
              --subdomains           Enable DNS sub-domain enumeration
              --udp                  Enable UDP service probes
              --nvd <key>            Enable NVD CVE lookup with the given API key

            Authenticated scanning:
              --cookie <value>       Cookie header sent with every request
              --header "N: v"        Extra request header (repeatable)
              --auth <value>         Authorization header value (e.g. "Bearer ...")
              --proxy <url>          Route HTTP(S) through a proxy (e.g. http://127.0.0.1:8080)

            Output:
              --out <path>           Report path (extension set per format when multiple)
              --format <list>        html,json,sarif,csv,md,pdf           (default: html,json)
              --wordlist <path>      Extra word-list file for content discovery
              --quiet                Only print findings and the summary

            Example:
              TryZ.exe scan https://example.test --authorize --active --discover --format html,sarif --out report
            """);
    }

    // ---- console attach (WinExe has no console by default) ----------------------------------
    private static void EnsureConsole()
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            if (!AttachConsole(-1)) AllocConsole();
        }
        catch (DllNotFoundException) { }
        catch (EntryPointNotFoundException) { }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AttachConsole(int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AllocConsole();

    // ---- argument parsing -------------------------------------------------------------------
    private sealed class Opts
    {
        public string Target = string.Empty;
        public bool Authorized;
        public int ProfileIndex = 1;
        public int Threads;
        public int Rate;
        public bool Active, Discover, Subdomains, Udp, Quiet;
        public string Nvd = string.Empty;
        public string Cookie = string.Empty;
        public string Auth = string.Empty;
        public string Proxy = string.Empty;
        public string Wordlist = string.Empty;
        public string OutPath = string.Empty;
        public readonly List<string> Headers = new();
        public List<ExportFormat> Formats = new() { ExportFormat.Html, ExportFormat.Json };

        public static Opts Parse(string[] args)
        {
            var o = new Opts();
            bool formatsSet = false;
            for (int i = 0; i < args.Length; i++)
            {
                string a = args[i];
                string Next(string name) => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{name} needs a value");
                switch (a)
                {
                    case "scan" or "--scan": break;
                    case "--target" or "-t": o.Target = Next(a); break;
                    case "--authorize": o.Authorized = true; break;
                    case "--profile": o.ProfileIndex = ParseProfile(Next(a)); break;
                    case "--threads": o.Threads = ParseInt(Next(a), "--threads"); break;
                    case "--rate": o.Rate = ParseInt(Next(a), "--rate"); break;
                    case "--active": o.Active = true; break;
                    case "--discover": o.Discover = true; break;
                    case "--subdomains": o.Subdomains = true; break;
                    case "--udp": o.Udp = true; break;
                    case "--nvd": o.Nvd = Next(a); break;
                    case "--cookie": o.Cookie = Next(a); break;
                    case "--header" or "-H": o.Headers.Add(Next(a)); break;
                    case "--auth": o.Auth = Next(a); break;
                    case "--proxy": o.Proxy = Next(a); break;
                    case "--wordlist": o.Wordlist = Next(a); break;
                    case "--out" or "-o": o.OutPath = Next(a); break;
                    case "--format" or "-f": o.Formats = ParseFormats(Next(a)); formatsSet = true; break;
                    case "--quiet" or "-q": o.Quiet = true; break;
                    default:
                        if (a.StartsWith('-')) throw new ArgumentException($"unknown option {a}");
                        if (o.Target.Length == 0) o.Target = a;
                        else throw new ArgumentException($"unexpected argument {a}");
                        break;
                }
            }
            if (!formatsSet && o.Formats.Count == 0) o.Formats = new() { ExportFormat.Html, ExportFormat.Json };
            return o;
        }

        public void ApplyTo(AppSettings s)
        {
            if (Rate > 0) s.MaxRequestsPerSecond = Rate;
            if (Active) s.RunActiveChecks = true;
            if (Discover) s.RunContentDiscovery = true;
            if (Subdomains) s.RunSubdomainScan = true;
            if (Udp) s.UdpScan = true;
            if (Nvd.Length > 0) { s.EnableNvd = true; s.NvdApiKey = Nvd; }
            if (Cookie.Length > 0) s.SessionCookie = Cookie;
            if (Auth.Length > 0) s.AuthorizationHeader = Auth;
            if (Proxy.Length > 0) s.HttpProxy = Proxy;
            if (Wordlist.Length > 0) s.WordlistPath = Wordlist;
            if (Headers.Count > 0) s.ExtraHeaders = Headers.ToList();
        }

        private static int ParseProfile(string v) => v.ToLowerInvariant() switch
        {
            "quick" or "0" => 0,
            "full" or "1" => 1,
            "web" or "2" => 2,
            "custom" or "3" => 3,
            _ => throw new ArgumentException($"unknown profile '{v}' (Quick|Full|Web|Custom)"),
        };

        private static int ParseInt(string v, string name) =>
            int.TryParse(v, out int n) && n > 0 ? n : throw new ArgumentException($"{name} must be a positive integer");

        private static List<ExportFormat> ParseFormats(string list)
        {
            var result = new List<ExportFormat>();
            foreach (var raw in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                result.Add(raw.ToLowerInvariant() switch
                {
                    "html" or "htm" => ExportFormat.Html,
                    "json" => ExportFormat.Json,
                    "sarif" => ExportFormat.Sarif,
                    "csv" => ExportFormat.Csv,
                    "md" or "markdown" => ExportFormat.Markdown,
                    "pdf" => ExportFormat.Pdf,
                    _ => throw new ArgumentException($"unknown format '{raw}'"),
                });
            }
            return result.Distinct().ToList();
        }
    }
}
