using System.Text;

namespace TryZ.Data;

/// <summary>
/// Optional persistent activity log. When enabled, every log line the engine emits is appended to a dated file under
/// <c>%APPDATA%\TryZ\logs</c> so a scan leaves an audit trail that survives the session. Writing is best-effort and
/// thread-safe; a file error disables the sink for the rest of the run rather than interrupting the scan.
/// </summary>
internal static class FileLog
{
    private static readonly object Gate = new();
    private static readonly string[] LevelNames = { "DEBUG", "INFO", "NOTE", "OK", "WARN", "ALERT" };
    private static bool _enabled;
    private static string _directory = DefaultDirectory;
    private static StreamWriter? _writer;
    private static DateOnly _writerDay;
    private static bool _failed;

    public static string DefaultDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TryZ", "logs");

    /// <summary>The file currently being written, or the file that would be written today when enabled.</summary>
    public static string CurrentPath => Path.Combine(_directory, $"tryz-{DateTime.Now:yyyyMMdd}.log");

    /// <summary>Turns file logging on or off. Safe to call repeatedly (e.g. when settings change).</summary>
    public static void Configure(bool enabled, string? directory = null)
    {
        lock (Gate)
        {
            _enabled = enabled;
            if (!string.IsNullOrWhiteSpace(directory)) _directory = directory!;
            _failed = false;
            if (!enabled) Close();
        }
    }

    public static void Write(string timeText, LogLevel level, string source, string text)
    {
        if (!_enabled) return;
        lock (Gate)
        {
            if (!_enabled || _failed) return;
            try
            {
                var writer = EnsureWriter();
                string name = (int)level >= 0 && (int)level < LevelNames.Length ? LevelNames[(int)level] : level.ToString();
                writer.Write(timeText);
                writer.Write("  ");
                writer.Write(name.PadRight(5));
                writer.Write("  ");
                writer.Write(source);
                writer.Write(": ");
                writer.WriteLine(text);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ObjectDisposedException)
            {
                _failed = true; // stop trying for this run; the in-memory log still works
                Close();
            }
        }
    }

    private static StreamWriter EnsureWriter()
    {
        var today = DateOnly.FromDateTime(DateTime.Now);
        if (_writer != null && _writerDay == today) return _writer;
        Close();
        Directory.CreateDirectory(_directory);
        _writer = new StreamWriter(new FileStream(CurrentPath, FileMode.Append, FileAccess.Write, FileShare.Read), new UTF8Encoding(false))
        {
            AutoFlush = true,
        };
        _writerDay = today;
        _writer.WriteLine($"---- TryZ activity log, session started {DateTime.Now:yyyy-MM-dd HH:mm:ss} ----");
        return _writer;
    }

    private static void Close()
    {
        try { _writer?.Dispose(); }
        catch (IOException) { }
        _writer = null;
    }
}
