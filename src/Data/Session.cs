using TryZ.Engine;

namespace TryZ.Data;

internal sealed class RowStore<T> where T : class
{
    private readonly List<T> _items = new();

    public IReadOnlyList<T> Items => _items;
    public int Generation { get; private set; }
    public int MutationVersion { get; private set; }

    public void Add(T item) => _items.Add(item);
    public void AddRange(IEnumerable<T> items) => _items.AddRange(items);
    public void Touch() => MutationVersion++;

    public void Clear()
    {
        _items.Clear();
        Generation++;
    }
}

internal sealed class LogBuffer
{
    private const int Capacity = 250_000;
    private readonly List<LogEntry> _items = new();

    public IReadOnlyList<LogEntry> Items => _items;
    public int Generation { get; private set; }

    public void Add(LogEntry entry)
    {
        if (_items.Count >= Capacity)
        {
            _items.RemoveRange(0, Capacity / 5);
            Generation++;
        }
        _items.Add(entry);
    }

    public void Clear()
    {
        _items.Clear();
        Generation++;
    }
}

internal readonly record struct ThroughputSample(double RequestsPerSecond, double LatencyMs);

internal sealed class Session
{
    public static readonly string[] PhaseNames = { "Host discovery", "Port audit", "Vulnerability audit", "Web crawl", "Report assembly" };

    private readonly Dictionary<string, HostRecord> _hostsByIp = new();
    private readonly Dictionary<int, TaskItem> _tasksById = new();
    private readonly Dictionary<string, List<PortRecord>> _portsByHost = new();
    private readonly Dictionary<int, Finding> _findingsById = new();
    // Survives a rescan on purpose: the user told us what the box is worth, a new scan doesn't change that.
    private readonly Dictionary<string, AssetImportance> _importance = new(StringComparer.OrdinalIgnoreCase);

    public string Name { get; set; } = "untitled.tzs";
    public string Target { get; set; } = string.Empty;
    public string Profile { get; set; } = string.Empty;
    public int Threads { get; set; }
    public DateTime? StartedAt { get; set; }
    public string FilterText { get; set; } = string.Empty;

    public RowStore<HostRecord> Hosts { get; } = new();
    public RowStore<PortRecord> Ports { get; } = new();
    public RowStore<Finding> Findings { get; } = new();
    public RowStore<UrlRecord> Urls { get; } = new();
    public RowStore<TaskItem> Tasks { get; } = new();
    public LogBuffer Log { get; } = new();
    public List<ThroughputSample> Samples { get; } = new();
    public int SamplesGeneration { get; private set; }

    public int[] SeverityCounts { get; } = new int[5];
    public double[] PhaseProgress { get; } = new double[5];
    public double Progress { get; private set; }
    public double ElapsedSeconds { get; private set; }
    public double RequestsPerSecond { get; private set; }
    public double LatencyMs { get; private set; }
    public int ActiveThreads { get; private set; }
    public long TotalRequests { get; private set; }
    public string PhaseText { get; private set; } = "Idle";
    public bool Dirty { get; set; } = true;

    public int FindingCount => Findings.Items.Count;

    public IReadOnlyList<PortRecord> PortsFor(string ip) =>
        _portsByHost.TryGetValue(ip, out var list) ? list : Array.Empty<PortRecord>();

    /// <summary>Hosts the user rated as something other than Normal.</summary>
    public IReadOnlyDictionary<string, AssetImportance> Importance => _importance;

    public AssetImportance ImportanceOf(string host) =>
        !string.IsNullOrWhiteSpace(host) && _importance.TryGetValue(host.Trim(), out var value) ? value : AssetImportance.Normal;

    public void SetImportance(string host, AssetImportance value)
    {
        if (string.IsNullOrWhiteSpace(host)) return;
        host = host.Trim();
        if (ImportanceOf(host) == value) return;
        if (value == AssetImportance.Normal) _importance.Remove(host);
        else _importance[host] = value;
        // Ranking depends on it, so views keyed on the finding store pick the change up.
        Findings.Touch();
        Dirty = true;
    }

    public PriorityScore PriorityOf(Finding f) => Prioritizer.Evaluate(f, ImportanceOf(f.Host));

    public void Clear()
    {
        Name = "untitled.tzs";
        StartedAt = null;
        _importance.Clear();
        ResetResults();
    }

    public void ResetResults()
    {
        Hosts.Clear();
        Ports.Clear();
        Findings.Clear();
        Urls.Clear();
        Tasks.Clear();
        Log.Clear();
        Samples.Clear();
        SamplesGeneration++;
        _hostsByIp.Clear();
        _findingsById.Clear();
        _tasksById.Clear();
        _portsByHost.Clear();
        Array.Clear(SeverityCounts);
        Array.Clear(PhaseProgress);
        Progress = 0;
        ElapsedSeconds = 0;
        RequestsPerSecond = 0;
        LatencyMs = 0;
        ActiveThreads = 0;
        TotalRequests = 0;
        PhaseText = "Idle";
        Dirty = true;
    }

    public void AddLog(LogLevel level, string source, string text)
    {
        Log.Add(new LogEntry
        {
            TimeText = (StartedAt ?? DateTime.Now).AddSeconds(ElapsedSeconds).ToString("HH:mm:ss.fff"),
            Level = level,
            Source = source,
            Text = text,
        });
        Dirty = true;
    }

    public void Apply(ScanEvent ev)
    {
        Dirty = true;
        switch (ev)
        {
            case ScanLog log:
                AddLog(log.Level, log.Source, log.Text);
                break;
            case HostFound h:
                _hostsByIp[h.Host.Ip] = h.Host;
                Hosts.Add(h.Host);
                break;
            case HostStateChanged hs:
                if (_hostsByIp.TryGetValue(hs.Ip, out var stateHost))
                {
                    stateHost.State = hs.State;
                    Hosts.Touch();
                }
                break;
            case PortFound p:
                Ports.Add(p.Port);
                if (!_portsByHost.TryGetValue(p.Port.HostIp, out var list))
                    _portsByHost[p.Port.HostIp] = list = new List<PortRecord>();
                list.Add(p.Port);
                if (_hostsByIp.TryGetValue(p.Port.HostIp, out var portHost) && p.Port.State == "open")
                {
                    portHost.OpenPorts++;
                    Hosts.Touch();
                }
                break;
            case FindingFound f:
                Findings.Add(f.Finding);
                _findingsById[f.Finding.Id] = f.Finding;
                SeverityCounts[(int)f.Finding.Severity]++;
                break;
            case FindingEnriched fe:
                if (_findingsById.TryGetValue(fe.Id, out var enriched))
                {
                    if (fe.Cvss is { } score) enriched.Cvss = score;
                    if (fe.CvssVector != null) enriched.CvssVector = fe.CvssVector;
                    if (fe.Threat != null) enriched.Threat = fe.Threat;
                    Findings.Touch();
                }
                break;
            case UrlBatch u:
                Urls.AddRange(u.Urls);
                break;
            case TaskAdded t:
                _tasksById[t.Task.Id] = t.Task;
                Tasks.Add(t.Task);
                break;
            case TaskChanged tc:
                if (_tasksById.TryGetValue(tc.Id, out var task))
                {
                    task.State = tc.State;
                    task.Progress = tc.Progress;
                    Tasks.Touch();
                }
                break;
            case ScanMetrics m:
                ElapsedSeconds = m.Elapsed;
                RequestsPerSecond = m.RequestsPerSecond;
                LatencyMs = m.LatencyMs;
                ActiveThreads = m.ActiveThreads;
                Progress = m.Progress;
                PhaseText = m.PhaseText;
                TotalRequests = m.TotalRequests;
                Array.Copy(m.PhaseProgress, PhaseProgress, PhaseProgress.Length);
                Samples.Add(new ThroughputSample(m.RequestsPerSecond, m.LatencyMs));
                break;
        }
    }

    /// <summary>Snapshot of the session results for saving to disk.</summary>
    public SessionFile ToFile() => new()
    {
        SavedAt = DateTime.Now,
        Target = Target,
        Profile = Profile,
        Threads = Threads,
        StartedAt = StartedAt,
        ElapsedSeconds = ElapsedSeconds,
        TotalRequests = TotalRequests,
        PhaseProgress = (double[])PhaseProgress.Clone(),
        Hosts = Hosts.Items.Select(h => new HostDto
        {
            Ip = h.Ip, Hostname = h.Hostname, OsGuess = h.OsGuess, LatencyMs = h.LatencyMs, Ttl = h.Ttl,
            Role = h.Role, OpenPorts = h.OpenPorts, State = h.State,
        }).ToList(),
        Ports = Ports.Items.Select(p => new PortDto
        {
            HostIp = p.HostIp, Port = p.Port, Proto = p.Proto, State = p.State, Service = p.Service, Banner = p.Banner, Risk = p.Risk,
        }).ToList(),
        Findings = Findings.Items.Select(f => new FindingDto
        {
            Id = f.Id, Severity = f.Severity, Title = f.Title, Host = f.Host, Port = f.Port, Cwe = f.Cwe,
            Description = f.Description, Evidence = f.Evidence, Remediation = f.Remediation, Status = f.Status,
            RuleId = f.RuleId, Proto = f.Proto, Product = f.Product, Cves = f.Cves.ToList(), Cvss = f.Cvss, CvssVector = f.CvssVector,
            Threat = f.Threat is { } t ? ThreatDto.From(t) : null,
        }).ToList(),
        Urls = Urls.Items.Select(u => new UrlDto
        {
            Host = u.Host, Path = u.Path, Url = u.Url, Method = u.Method, Status = u.Status,
            ContentType = u.ContentType, Size = u.Size, TimeMs = u.TimeMs,
        }).ToList(),
        Log = Log.Items.Select(l => new LogDto { Time = l.TimeText, Level = l.Level, Source = l.Source, Text = l.Text }).ToList(),
        Assets = _importance.OrderBy(a => a.Key, StringComparer.OrdinalIgnoreCase)
            .Select(a => new AssetDto { Host = a.Key, Importance = a.Value }).ToList(),
    };

    /// <summary>Replaces the current results with a saved session.</summary>
    public void LoadFrom(SessionFile file, string name)
    {
        ResetResults();
        _importance.Clear();
        foreach (var a in file.Assets)
        {
            if (a == null || string.IsNullOrWhiteSpace(a.Host) || !Enum.IsDefined(a.Importance) || a.Importance == AssetImportance.Normal) continue;
            _importance[a.Host.Trim()] = a.Importance;
        }
        Name = name;
        Target = file.Target;
        Profile = file.Profile;
        Threads = file.Threads;
        StartedAt = file.StartedAt;
        ElapsedSeconds = file.ElapsedSeconds;
        TotalRequests = file.TotalRequests;
        for (int i = 0; i < PhaseProgress.Length && i < file.PhaseProgress.Length; i++)
            PhaseProgress[i] = Math.Clamp(file.PhaseProgress[i], 0, 1);
        Progress = 0;
        for (int i = 0; i < PhaseProgress.Length; i++) Progress += PhaseProgress[i] * ScanContext.PhaseWeights[i];
        PhaseText = Progress >= 0.999 ? "Completed" : "Loaded";

        foreach (var h in file.Hosts)
        {
            if (string.IsNullOrEmpty(h.Ip) || _hostsByIp.ContainsKey(h.Ip)) continue;
            var host = new HostRecord
            {
                Ip = h.Ip,
                Hostname = h.Hostname ?? string.Empty,
                OsGuess = h.OsGuess ?? string.Empty,
                LatencyMs = h.LatencyMs,
                Ttl = h.Ttl,
                Role = h.Role ?? string.Empty,
                OpenPorts = h.OpenPorts,
                State = h.State ?? "Up",
            };
            _hostsByIp[host.Ip] = host;
            Hosts.Add(host);
        }
        foreach (var p in file.Ports)
        {
            var port = new PortRecord
            {
                HostIp = p.HostIp ?? string.Empty,
                Port = p.Port,
                Proto = p.Proto ?? "tcp",
                State = p.State ?? "open",
                Service = p.Service ?? string.Empty,
                Banner = p.Banner ?? string.Empty,
                Risk = p.Risk,
            };
            Ports.Add(port);
            if (!_portsByHost.TryGetValue(port.HostIp, out var list))
                _portsByHost[port.HostIp] = list = new List<PortRecord>();
            list.Add(port);
        }
        foreach (var f in file.Findings)
        {
            var finding = new Finding
            {
                Id = f.Id,
                Severity = (Severity)Math.Clamp((int)f.Severity, 0, 4),
                Title = f.Title ?? string.Empty,
                Host = f.Host ?? string.Empty,
                Port = f.Port,
                Cwe = f.Cwe,
                Description = f.Description ?? string.Empty,
                Evidence = f.Evidence ?? string.Empty,
                Remediation = f.Remediation ?? string.Empty,
                Status = f.Status,
                RuleId = f.RuleId ?? string.Empty,
                Proto = string.IsNullOrEmpty(f.Proto) ? "tcp" : f.Proto,
                Product = f.Product ?? string.Empty,
                Cves = f.Cves?.Where(c => !string.IsNullOrWhiteSpace(c)).ToArray() ?? Array.Empty<string>(),
                Cvss = f.Cvss is >= 0 and <= 10 ? f.Cvss : null,
                CvssVector = f.CvssVector ?? string.Empty,
                Threat = f.Threat?.ToInfo(),
            };
            Findings.Add(finding);
            _findingsById[finding.Id] = finding;
            SeverityCounts[(int)finding.Severity]++;
        }
        foreach (var u in file.Urls)
        {
            Urls.Add(new UrlRecord
            {
                Host = u.Host ?? string.Empty,
                Path = u.Path ?? string.Empty,
                Url = u.Url ?? string.Empty,
                Method = u.Method ?? "GET",
                Status = u.Status,
                ContentType = u.ContentType ?? string.Empty,
                Size = u.Size,
                TimeMs = u.TimeMs,
            });
        }
        foreach (var l in file.Log)
        {
            Log.Add(new LogEntry
            {
                TimeText = l.Time ?? string.Empty,
                Level = l.Level,
                Source = l.Source ?? string.Empty,
                Text = l.Text ?? string.Empty,
            });
        }
        Dirty = true;
    }

    public void CancelOpenTasks()
    {
        foreach (var t in Tasks.Items)
            if (t.State is TaskState.Running or TaskState.Queued)
                t.State = TaskState.Cancelled;
        Tasks.Touch();
        ActiveThreads = 0;
        RequestsPerSecond = 0;
        Dirty = true;
    }

    public void EndActivity()
    {
        ActiveThreads = 0;
        RequestsPerSecond = 0;
        Dirty = true;
    }
}
