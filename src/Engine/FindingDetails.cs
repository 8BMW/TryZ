using System.Text;
using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Optional metadata attached to a finding when it is reported.</summary>
internal sealed record FindingDetails
{
    public string RuleId { get; init; } = string.Empty;
    public string Proto { get; init; } = "tcp";
    public string Product { get; init; } = string.Empty;
    public IReadOnlyList<string> Cves { get; init; } = Array.Empty<string>();
    public double? Cvss { get; init; }
    public string CvssVector { get; init; } = string.Empty;
    public Confidence Confidence { get; init; } = Confidence.Firm;

    /// <summary>Rule id derived from a title, for checks that do not declare one: lower case, words joined by '-'.</summary>
    public static string Slug(string title)
    {
        var sb = new StringBuilder(title.Length);
        bool dash = false;
        foreach (char c in title)
        {
            if (char.IsAsciiLetterOrDigit(c))
            {
                if (dash && sb.Length > 0) sb.Append('-');
                sb.Append(char.ToLowerInvariant(c));
                dash = false;
            }
            else if (c == '(') break;
            else dash = true;
        }
        if (sb.Length > 64) sb.Length = 64;
        return sb.ToString().TrimEnd('-');
    }
}
