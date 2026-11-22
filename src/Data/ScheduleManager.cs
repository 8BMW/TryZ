using System.Diagnostics;
using System.Text;

namespace TryZ.Data;

/// <summary>
/// Registers, lists and removes recurring TryZ scans as Windows Scheduled Tasks (via <c>schtasks.exe</c>), so a scan
/// runs unattended on a schedule even when the UI is closed and survives reboots. Each task simply launches the TryZ
/// executable in headless mode against the given target; alerting is driven by the saved settings. Tasks live under a
/// <c>\TryZ\</c> folder so they are easy to find and remove.
/// </summary>
internal static class ScheduleManager
{
    private const string Folder = "TryZ";

    public sealed record ScheduledTask(string Name, string FullName, string NextRun, string Status);

    public sealed record CommandResult(bool Success, string Output, string Error)
    {
        public string Combined => string.Join("\n", new[] { Output, Error }.Where(s => s.Length > 0));
    }

    /// <summary>The TryZ executable to schedule. The real host .exe, not the dotnet launcher, so the task is self-contained.</summary>
    public static string ExecutablePath => Environment.ProcessPath ?? Path.Combine(AppContext.BaseDirectory, "TryZ.exe");

    /// <summary>Builds the headless command line a scheduled run executes (shown to the user; also the task action).</summary>
    public static string BuildRunArguments(string target, IReadOnlyList<string> extraArgs)
    {
        var sb = new StringBuilder();
        sb.Append("scan ").Append(Quote(target)).Append(" --authorize");
        foreach (var a in extraArgs) sb.Append(' ').Append(a.Contains(' ') ? Quote(a) : a);
        return sb.ToString();
    }

    /// <summary>
    /// Creates (or replaces) a scheduled task. Exactly one of <paramref name="everyMinutes"/> or <paramref name="dailyAt"/>
    /// must be set: a minute interval, or a daily clock time ("HH:mm").
    /// </summary>
    public static CommandResult Create(string name, string target, IReadOnlyList<string> extraArgs, int everyMinutes, string? dailyAt)
    {
        if (!OperatingSystem.IsWindows()) return new CommandResult(false, "", "scheduling requires Windows");
        string safe = SafeName(name);
        if (safe.Length == 0) return new CommandResult(false, "", "a task name is required");
        string run = $"\"{ExecutablePath}\" {BuildRunArguments(target, extraArgs)}";
        var args = new List<string> { "/Create", "/F", "/TN", $"{Folder}\\{safe}", "/TR", run };
        if (dailyAt is { Length: > 0 })
        {
            args.AddRange(new[] { "/SC", "DAILY", "/ST", dailyAt });
        }
        else
        {
            int mins = Math.Clamp(everyMinutes, 1, 60 * 24 * 7);
            args.AddRange(new[] { "/SC", "MINUTE", "/MO", mins.ToString() });
        }
        return Run(args);
    }

    public static CommandResult Delete(string name)
    {
        if (!OperatingSystem.IsWindows()) return new CommandResult(false, "", "scheduling requires Windows");
        string safe = SafeName(name);
        return Run(new[] { "/Delete", "/F", "/TN", $"{Folder}\\{safe}" });
    }

    /// <summary>Lists the TryZ scheduled tasks currently registered.</summary>
    public static IReadOnlyList<ScheduledTask> List()
    {
        if (!OperatingSystem.IsWindows()) return Array.Empty<ScheduledTask>();
        var result = Run(new[] { "/Query", "/FO", "CSV", "/NH" });
        if (!result.Success) return Array.Empty<ScheduledTask>();
        var tasks = new List<ScheduledTask>();
        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var cols = ParseCsvLine(line);
            if (cols.Count < 3) continue;
            string full = cols[0];
            if (!full.Contains($"\\{Folder}\\", StringComparison.OrdinalIgnoreCase)) continue;
            string shortName = full[(full.LastIndexOf('\\') + 1)..];
            tasks.Add(new ScheduledTask(shortName, full, cols[1], cols[2]));
        }
        return tasks;
    }

    private static CommandResult Run(IReadOnlyList<string> arguments)
    {
        var psi = new ProcessStartInfo("schtasks.exe")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        foreach (var a in arguments) psi.ArgumentList.Add(a);
        try
        {
            using var proc = Process.Start(psi);
            if (proc == null) return new CommandResult(false, "", "could not start schtasks.exe");
            string output = proc.StandardOutput.ReadToEnd();
            string error = proc.StandardError.ReadToEnd();
            proc.WaitForExit(30_000);
            bool ok = proc.HasExited && proc.ExitCode == 0;
            return new CommandResult(ok, output.Trim(), error.Trim());
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException or IOException)
        {
            return new CommandResult(false, "", ex.Message);
        }
    }

    private static string Quote(string s) => s.Contains(' ') || s.Contains('"') ? "\"" + s.Replace("\"", "\\\"") + "\"" : s;

    private static string SafeName(string name)
    {
        var sb = new StringBuilder();
        foreach (char c in name.Trim())
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '-');
        string s = sb.ToString().Trim('-');
        return s.Length > 64 ? s[..64] : s;
    }

    private static List<string> ParseCsvLine(string line)
    {
        var cols = new List<string>();
        var sb = new StringBuilder();
        bool quoted = false;
        for (int i = 0; i < line.Length; i++)
        {
            char c = line[i];
            if (c == '"')
            {
                if (quoted && i + 1 < line.Length && line[i + 1] == '"') { sb.Append('"'); i++; }
                else quoted = !quoted;
            }
            else if (c == ',' && !quoted) { cols.Add(sb.ToString()); sb.Clear(); }
            else sb.Append(c);
        }
        cols.Add(sb.ToString().TrimEnd('\r'));
        return cols;
    }
}
