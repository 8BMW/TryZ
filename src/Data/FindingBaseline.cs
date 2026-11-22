using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TryZ.Data;

/// <summary>
/// Remembers the findings seen on a target so a later scan can report only what is new. The baseline is a set of finding
/// fingerprints stored per target under <c>%APPDATA%\TryZ\state</c>; it drives new-finding alerts for scheduled and
/// headless scans. Storing only fingerprints (not evidence) keeps the state small and free of sensitive response data.
/// </summary>
internal sealed class FindingBaseline
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public string Target { get; set; } = string.Empty;
    public DateTime UpdatedAt { get; set; }
    public List<string> Fingerprints { get; set; } = new();

    private static string Directory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "TryZ", "state");

    /// <summary>Stable, filesystem-safe file name derived from the target string.</summary>
    private static string PathFor(string target)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(target.Trim().ToLowerInvariant()));
        string id = Convert.ToHexString(hash)[..16].ToLowerInvariant();
        return Path.Combine(Directory, $"baseline-{id}.json");
    }

    public static FindingBaseline Load(string target)
    {
        try
        {
            string path = PathFor(target);
            if (File.Exists(path))
            {
                var loaded = JsonSerializer.Deserialize<FindingBaseline>(File.ReadAllText(path));
                if (loaded != null)
                {
                    loaded.Fingerprints ??= new();
                    return loaded;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
        }
        return new FindingBaseline { Target = target };
    }

    /// <summary>The findings in <paramref name="findings"/> whose fingerprints are not in this baseline, i.e. newly observed.</summary>
    public List<Finding> NewSince(IEnumerable<Finding> findings)
    {
        var known = new HashSet<string>(Fingerprints, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<Finding>();
        foreach (var f in findings)
            if (!known.Contains(f.Fingerprint) && seen.Add(f.Fingerprint))
                result.Add(f);
        return result;
    }

    /// <summary>True when a baseline file already exists for this target (so a first-ever scan is not all-new noise).</summary>
    public static bool Exists(string target)
    {
        try { return File.Exists(PathFor(target)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>Replaces the stored fingerprints with those of the current scan.</summary>
    public void Update(IEnumerable<Finding> findings, string target)
    {
        Target = target;
        UpdatedAt = DateTime.Now;
        Fingerprints = findings.Select(f => f.Fingerprint).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        try
        {
            System.IO.Directory.CreateDirectory(Directory);
            string path = PathFor(target);
            string tmp = path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(this, JsonOptions));
            File.Move(tmp, path, overwrite: true);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }
}
