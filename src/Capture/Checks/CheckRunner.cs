#if DEBUG
using System.Diagnostics;
using System.Reflection;
using TryZ.Data;
using TryZ.Views;

namespace TryZ.Capture.Checks;

/// <summary>A group of non-UI checks run by <c>TryZ.exe --checks [suite ...]</c>.</summary>
internal interface ICheckSuite
{
    string Name { get; }
    Task RunAsync(CheckContext c);
}

internal sealed class CheckContext
{
    private readonly List<string> _lines = new();
    private string _suite = string.Empty;

    public int Passed { get; private set; }
    public int Failed { get; private set; }
    public IReadOnlyList<string> Lines => _lines;

    /// <summary>Unique scratch folder for files written by this check run.</summary>
    public string TempDir { get; } = Path.Combine(Path.GetTempPath(), "tryz-checks", Guid.NewGuid().ToString("N"));

    internal void Begin(string suite)
    {
        _suite = suite;
        _lines.Add($"== {suite}");
    }

    public bool Check(string name, bool ok, string? detail = null)
    {
        if (ok) Passed++; else Failed++;
        _lines.Add($"{(ok ? "PASS" : "FAIL")}  {_suite}: {name}{(string.IsNullOrEmpty(detail) ? string.Empty : $"  ({detail})")}");
        return ok;
    }

    public bool Equal<T>(string name, T expected, T actual) =>
        Check(name, EqualityComparer<T>.Default.Equals(expected, actual), $"expected {expected}, got {actual}");

    public void Crash(Exception ex)
    {
        Failed++;
        _lines.Add($"FAIL  {_suite}: suite threw {ex.GetType().Name}: {ex.Message}");
        _lines.Add(ex.StackTrace ?? string.Empty);
    }
}

/// <summary>Stand-in for the main window so views can be built and driven without one.</summary>
internal sealed class CheckShell : IShell
{
    public Session Session { get; } = new();
    public AppSettings Settings { get; } = new();
    public List<(ExportFormat Format, ReportScope? Scope)> Exports { get; } = new();
    public List<string> Notices { get; } = new();
    public List<string> UserLog { get; } = new();

    public void ExportReport(ExportFormat format, ReportScope? scope = null) => Exports.Add((format, scope));
    public void UseCustomProfile() { }
    public void Notify(string title, string text, IconId icon = IconId.InfoMark) => Notices.Add($"{title}: {text}");
    public void NavigateTo(int module) { }
    public void OpenInWorkbench(string method, string url) { }
    public void SelectHostInPortAudit(string ip) { }
    public void LogUser(string source, string text) => UserLog.Add($"{source}: {text}");

    public static IEnumerable<T> Find<T>(Control root) where T : Control
    {
        foreach (Control child in root.Controls)
        {
            if (child is T result) yield return result;
            foreach (var descendant in Find<T>(child)) yield return descendant;
        }
    }
}

internal static class CheckRunner
{
    /// <summary>Runs every suite (or the ones named on the command line) and writes checks.txt next to the executable.</summary>
    public static int Run(string[] args)
    {
        var wanted = args.SkipWhile(a => a != "--checks").Skip(1).Where(a => !a.StartsWith("--", StringComparison.Ordinal)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var suites = Assembly.GetExecutingAssembly().GetTypes()
            .Where(t => !t.IsAbstract && typeof(ICheckSuite).IsAssignableFrom(t))
            .Select(t => (ICheckSuite)Activator.CreateInstance(t)!)
            .Where(s => wanted.Count == 0 || wanted.Contains(s.Name))
            .OrderBy(s => s.Name, StringComparer.Ordinal)
            .ToList();

        var c = new CheckContext();
        Directory.CreateDirectory(c.TempDir);
        var sw = Stopwatch.StartNew();
        foreach (var suite in suites)
        {
            c.Begin(suite.Name);
            try
            {
                suite.RunAsync(c).GetAwaiter().GetResult();
            }
            catch (Exception ex)
            {
                c.Crash(ex);
            }
        }
        var lines = c.Lines.ToList();
        lines.Add($"{c.Passed} passed, {c.Failed} failed, {suites.Count} suite(s), {sw.Elapsed.TotalSeconds:0.0} s");
        File.WriteAllLines(Path.Combine(AppContext.BaseDirectory, "checks.txt"), lines);
        return c.Failed == 0 ? 0 : 1;
    }
}
#endif
