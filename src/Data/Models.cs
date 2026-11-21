namespace TryZ.Data;

internal enum LogLevel { Debug, Info, Notice, Ok, Warn, Alert }
internal enum FindingStatus { New, Confirmed, FalsePositive, Accepted }
internal enum TaskState { Queued, Running, Done, Cancelled }
internal enum ScanState { Idle, Running, Paused, Stopped, Completed, Failed }

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

    /// <summary>Stable identifier of the check that produced the finding (e.g. "svc.telnet-exposed"). Used for diffing and SARIF.</summary>
    public string RuleId { get; init; } = string.Empty;
    public string Proto { get; init; } = "tcp";
    /// <summary>Product and version the finding applies to, when known (e.g. "OpenSSH 7.4").</summary>
    public string Product { get; init; } = string.Empty;
    public IReadOnlyList<string> Cves { get; init; } = Array.Empty<string>();
    public double? Cvss { get; set; }
    public string CvssVector { get; set; } = string.Empty;
    /// <summary>Exploitation intelligence (CISA KEV, FIRST EPSS); null until enrichment has run.</summary>
    public ThreatInfo? Threat { get; set; }

    /// <summary>Identity of the finding across scans: same check, same host, same port.</summary>
    public string Fingerprint => $"{(RuleId.Length > 0 ? RuleId : Title)}|{Host}|{Proto}/{Port}";

    public string CweText => $"CWE-{Cwe}";
    public string CveText => Cves.Count == 0 ? string.Empty : Cves.Count == 1 ? Cves[0] : $"{Cves[0]} +{Cves.Count - 1}";

    public string StatusText => Status switch
    {
        FindingStatus.Confirmed => "Confirmed",
        FindingStatus.FalsePositive => "False positive",
        FindingStatus.Accepted => "Accepted",
        _ => "New",
    };
}

/// <summary>Known-exploitation data for the CVEs behind a finding.</summary>
internal sealed class ThreatInfo
{
    /// <summary>At least one CVE is listed in the CISA Known Exploited Vulnerabilities catalog.</summary>
    public bool Kev { get; init; }
    public string KevCve { get; init; } = string.Empty;
    public DateOnly? KevDateAdded { get; init; }
    public DateOnly? KevDueDate { get; init; }
    public bool KevRansomware { get; init; }
    public string KevAction { get; init; } = string.Empty;
    /// <summary>Highest FIRST EPSS probability (0..1) over the finding's CVEs.</summary>
    public double? Epss { get; init; }
    public double? EpssPercentile { get; init; }
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
