using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Shell;

/// <summary>
/// The <c>schedule</c> command-line verb: register, list and remove recurring TryZ scans as Windows Scheduled Tasks.
/// A scheduled scan runs the headless scanner against a target on an interval or at a daily time; alert channels come
/// from the saved settings. Creating a schedule for a non-loopback target requires <c>--authorize</c>, exactly like a scan.
/// </summary>
internal static class ScheduleCommand
{
    public static int Run(string[] args)
    {
        string sub = args.Length > 1 ? args[1].ToLowerInvariant() : "list";
        return sub switch
        {
            "list" or "ls" => List(),
            "add" or "create" => Add(args),
            "remove" or "rm" or "delete" or "del" => Remove(args),
            "--help" or "-h" => Usage(0),
            _ => Usage(2, $"unknown schedule command '{sub}'"),
        };
    }

    private static int Add(string[] args)
    {
        string name = "", target = "", at = "";
        int every = 0;
        bool authorized = false;
        var forward = new List<string>();
        bool afterSep = false;
        for (int i = 2; i < args.Length; i++)
        {
            string a = args[i];
            string Next(string n) => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{n} needs a value");
            if (afterSep) { forward.Add(a); continue; }
            try
            {
                switch (a)
                {
                    case "--": afterSep = true; break;
                    case "--name": name = Next(a); break;
                    case "--target" or "-t": target = Next(a); break;
                    case "--every": every = ParsePositive(Next(a), "--every"); break;
                    case "--at": at = NormalizeTime(Next(a)); break;
                    case "--authorize": authorized = true; forward.Add(a); break;
                    default:
                        if (!a.StartsWith('-') && target.Length == 0) target = a;
                        else forward.Add(a); // forwarded to the scan command (e.g. --active, --profile full)
                        break;
                }
            }
            catch (ArgumentException ex)
            {
                return Usage(2, ex.Message);
            }
        }

        if (name.Length == 0) return Usage(2, "schedule add needs --name <id>");
        if (target.Length == 0) return Usage(2, "schedule add needs a target");
        if (!TargetParser.TryValidate(target, out string error)) { Console.Error.WriteLine($"tryz: invalid target: {error}"); return 2; }
        if (every > 0 && at.Length > 0) return Usage(2, "use either --every or --at, not both");
        if (every == 0 && at.Length == 0) return Usage(2, "schedule add needs --every <minutes> or --at HH:mm");
        if (!MainForm.IsLoopbackTarget(target) && !authorized)
        {
            Console.Error.WriteLine("tryz: scheduling a scan of a non-loopback target requires --authorize (you confirm you are authorized to scan it on every run).");
            return 3;
        }

        // --authorize is already added to the task command by ScheduleManager; avoid passing it twice.
        forward.RemoveAll(a => a == "--authorize");
        var result = ScheduleManager.Create(name, target, forward, every, at.Length > 0 ? at : null);
        if (!result.Success)
        {
            Console.Error.WriteLine($"tryz: could not create schedule: {result.Combined}");
            return 1;
        }
        string when = at.Length > 0 ? $"daily at {at}" : $"every {every} minute(s)";
        Console.Error.WriteLine($"Scheduled '{name}' — {when}: \"{ScheduleManager.ExecutablePath}\" {ScheduleManager.BuildRunArguments(target, forward)}");
        return 0;
    }

    private static int Remove(string[] args)
    {
        string name = "";
        for (int i = 2; i < args.Length; i++)
        {
            if (args[i] is "--name" && i + 1 < args.Length) name = args[++i];
            else if (!args[i].StartsWith('-') && name.Length == 0) name = args[i];
        }
        if (name.Length == 0) return Usage(2, "schedule remove needs --name <id>");
        var result = ScheduleManager.Delete(name);
        if (!result.Success) { Console.Error.WriteLine($"tryz: could not remove schedule: {result.Combined}"); return 1; }
        Console.Error.WriteLine($"Removed scheduled task '{name}'.");
        return 0;
    }

    private static int List()
    {
        var tasks = ScheduleManager.List();
        if (tasks.Count == 0)
        {
            Console.Error.WriteLine("No TryZ scheduled tasks.");
            return 0;
        }
        Console.Error.WriteLine($"TryZ scheduled tasks ({tasks.Count}):");
        foreach (var t in tasks)
            Console.Error.WriteLine($"  {t.Name,-24}  next: {t.NextRun,-22}  {t.Status}");
        return 0;
    }

    private static int ParsePositive(string v, string name) =>
        int.TryParse(v, out int n) && n > 0 ? n : throw new ArgumentException($"{name} must be a positive integer");

    private static string NormalizeTime(string v)
    {
        if (!TimeOnly.TryParse(v, System.Globalization.CultureInfo.InvariantCulture, out var t))
            throw new ArgumentException("--at must be a time like 02:30");
        return t.ToString("HH:mm", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static int Usage(int code, string? error = null)
    {
        if (error != null) Console.Error.WriteLine($"tryz: {error}");
        Console.Error.WriteLine("""
            TryZ scheduling — recurring scans via Windows Task Scheduler

            Usage:
              TryZ.exe schedule add --name <id> <target> [--authorize] (--every <minutes> | --at HH:mm) [-- <scan options>]
              TryZ.exe schedule list
              TryZ.exe schedule remove --name <id>

            Scan options after "--" are passed to each scheduled run, e.g. --active --discover --alerts.
            Example:
              TryZ.exe schedule add --name nightly example.test --authorize --at 02:30 -- --active --alerts
            """);
        return code;
    }
}
