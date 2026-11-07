namespace TryZ.Data;

internal enum LogLevel { Debug, Info, Notice, Ok, Warn, Alert }
internal enum FindingStatus { New, Confirmed, FalsePositive, Accepted }
internal enum TaskState { Queued, Running, Done, Cancelled }
internal enum ScanState { Idle, Running, Paused, Stopped, Completed }

internal sealed class HostRecord
{
    public required string Ip { get; init; }
    public required string Hostname { get; init; }
    public required string OsGuess { get; init; }
    public required int LatencyMs { get; init; }
    public required int Ttl { get; init; }
    public required string Role { get; init; }
    public int OpenPorts { get; set; }
    public string State { get; set; } = "Up";

    public string LatencyText => $"{LatencyMs} ms";
}

internal sealed class PortRecord
{
    public required string HostIp { get; init; }
    public required int Port { get; init; }
    public required string Proto { get; init; }
    public required string State { get; init; }
    public required string Service { get; init; }
    public required string Banner { get; init; }
    public required Severity Risk { get; init; }
}

internal sealed class Finding
{
    public required int Id { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }
    public required int Cwe { get; init; }
    public required string Description { get; init; }
    public required string Evidence { get; init; }
    public required string Remediation { get; init; }
    public FindingStatus Status { get; set; }

    public string CweText => $"CWE-{Cwe}";

    public string StatusText => Status switch
    {
        FindingStatus.Confirmed => "Confirmed",
        FindingStatus.FalsePositive => "False positive",
        FindingStatus.Accepted => "Accepted",
        _ => "New",
    };
}

internal sealed class UrlRecord
{
    public required string Host { get; init; }
    public required string Path { get; init; }
    public required string Url { get; init; }
    public required string Method { get; init; }
    public required int Status { get; init; }
    public required string ContentType { get; init; }
    public required long Size { get; init; }
    public required int TimeMs { get; init; }

    private string? _statusText, _sizeText, _timeText;

    public string StatusText => _statusText ??= Status.ToString();
    public string SizeText => _sizeText ??= Size >= 1024 ? $"{Size / 1024.0:0.0} KB" : $"{Size} B";
    public string TimeText => _timeText ??= $"{TimeMs} ms";
}

internal sealed class TaskItem
{
    public required int Id { get; init; }
    public required string Title { get; init; }
    public required string Module { get; init; }
    public TaskState State { get; set; }
    public int Progress { get; set; }

    public string StateText => State switch
    {
        TaskState.Running => "Running",
        TaskState.Done => "Done",
        TaskState.Cancelled => "Cancelled",
        _ => "Queued",
    };
}

internal sealed class LogEntry
{
    public required string TimeText { get; init; }
    public required LogLevel Level { get; init; }
    public required string Source { get; init; }
    public required string Text { get; init; }

    public string LevelName => Level switch
    {
        LogLevel.Debug => "DEBUG",
        LogLevel.Notice => "NOTE",
        LogLevel.Ok => "OK",
        LogLevel.Warn => "WARN",
        LogLevel.Alert => "ALERT",
        _ => "INFO",
    };
}
