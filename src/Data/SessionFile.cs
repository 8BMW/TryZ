using System.Text.Json;
using System.Text.Json.Serialization;

namespace TryZ.Data;

/// <summary>On-disk form of a session (*.tzs, UTF-8 JSON).</summary>
internal sealed class SessionFile
{
    public const int CurrentFormat = 1;

    public int Format { get; set; } = CurrentFormat;
    public string Producer { get; set; } = "TryZ Security Suite";
    public DateTime SavedAt { get; set; }
    public string Target { get; set; } = string.Empty;
    public string Profile { get; set; } = string.Empty;
    public int Threads { get; set; }
    public DateTime? StartedAt { get; set; }
    public double ElapsedSeconds { get; set; }
    public long TotalRequests { get; set; }
    public double[] PhaseProgress { get; set; } = new double[5];
    public List<HostDto> Hosts { get; set; } = new();
    public List<PortDto> Ports { get; set; } = new();
    public List<FindingDto> Findings { get; set; } = new();
    public List<UrlDto> Urls { get; set; } = new();
    public List<LogDto> Log { get; set; } = new();

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter() },
    };

    public static void Write(string path, SessionFile file)
    {
        string temp = path + ".tmp";
        using (var stream = File.Create(temp))
            JsonSerializer.Serialize(stream, file, Options);
        File.Move(temp, path, overwrite: true);
    }

    /// <exception cref="InvalidDataException">The file is not a TryZ session.</exception>
    public static SessionFile Read(string path)
    {
        SessionFile? file;
        try
        {
            using var stream = File.OpenRead(path);
            file = JsonSerializer.Deserialize<SessionFile>(stream, Options);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"The file is not a valid TryZ session: {ex.Message}", ex);
        }
        if (file == null) throw new InvalidDataException("The file is empty.");
        if (file.Format < 1 || file.Format > CurrentFormat)
            throw new InvalidDataException($"Unsupported session format version {file.Format}.");
        file.Hosts ??= new();
        file.Ports ??= new();
        file.Findings ??= new();
        file.Urls ??= new();
        file.Log ??= new();
        file.PhaseProgress ??= new double[5];
        file.Target ??= string.Empty;
        file.Profile ??= string.Empty;
        return file;
    }
}

internal sealed class HostDto
{
    public string Ip { get; set; } = string.Empty;
    public string Hostname { get; set; } = string.Empty;
    public string OsGuess { get; set; } = string.Empty;
    public int LatencyMs { get; set; }
    public int Ttl { get; set; }
    public string Role { get; set; } = string.Empty;
    public int OpenPorts { get; set; }
    public string State { get; set; } = "Up";
}

internal sealed class PortDto
{
    public string HostIp { get; set; } = string.Empty;
    public int Port { get; set; }
    public string Proto { get; set; } = "tcp";
    public string State { get; set; } = "open";
    public string Service { get; set; } = string.Empty;
    public string Banner { get; set; } = string.Empty;
    public Severity Risk { get; set; }
}

internal sealed class FindingDto
{
    public int Id { get; set; }
    public Severity Severity { get; set; }
    public string Title { get; set; } = string.Empty;
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; }
    public int Cwe { get; set; }
    public string Description { get; set; } = string.Empty;
    public string Evidence { get; set; } = string.Empty;
    public string Remediation { get; set; } = string.Empty;
    public FindingStatus Status { get; set; }
}

internal sealed class UrlDto
{
    public string Host { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public string Url { get; set; } = string.Empty;
    public string Method { get; set; } = "GET";
    public int Status { get; set; }
    public string ContentType { get; set; } = string.Empty;
    public long Size { get; set; }
    public int TimeMs { get; set; }
}

internal sealed class LogDto
{
    public string Time { get; set; } = string.Empty;
    public LogLevel Level { get; set; }
    public string Source { get; set; } = string.Empty;
    public string Text { get; set; } = string.Empty;
}
