using TryZ.Data;

namespace TryZ.Engine;

internal abstract record ScanEvent;
internal sealed record ScanLog(LogLevel Level, string Source, string Text) : ScanEvent;
internal sealed record HostFound(HostRecord Host) : ScanEvent;
internal sealed record HostStateChanged(string Ip, string State) : ScanEvent;
internal sealed record PortFound(PortRecord Port) : ScanEvent;
internal sealed record FindingFound(Finding Finding) : ScanEvent;
/// <summary>Scoring or exploitation data that arrived after the finding was reported. Null members leave the value unchanged.</summary>
internal sealed record FindingEnriched(int Id, double? Cvss, string? CvssVector, ThreatInfo? Threat) : ScanEvent;
internal sealed record UrlBatch(UrlRecord[] Urls) : ScanEvent;
internal sealed record TaskAdded(TaskItem Task) : ScanEvent;
internal sealed record TaskChanged(int Id, TaskState State, int Progress) : ScanEvent;
internal sealed record ScanMetrics(double Elapsed, double RequestsPerSecond, double LatencyMs, int ActiveThreads,
    double Progress, string PhaseText, long TotalRequests, double[] PhaseProgress) : ScanEvent;
internal sealed record ScanCompleted : ScanEvent;
internal sealed record ScanFailed : ScanEvent;

internal sealed record ScanRequest(string Target, int ProfileIndex, int Threads, ScanOptions Options);
