using TryZ.Engine;

namespace TryZ.Data;

internal sealed record ComparisonRow(string Kind, string Change, string Host, string Endpoint, string Name, string Before, string After);

/// <summary>Compares observed findings and services without claiming missing observations were fixed.</summary>
internal static class ScanComparison
{
    private readonly record struct Key(string Identity, string Host, string Proto, int Port);

    public static List<ComparisonRow> Build(SessionFile baseline, SessionFile current)
    {
        var rows = new List<ComparisonRow>();
        var oldFindings = (baseline.Findings ?? []).Where(f => f != null).ToList();
        var newFindings = (current.Findings ?? []).Where(f => f != null).ToList();
        // Format 1 has no rule ID. Resolve an exact title/location to an explicit ID only when unambiguous.
        var aliases = oldFindings.Concat(newFindings).Where(f => !string.IsNullOrWhiteSpace(f.RuleId))
            .GroupBy(TitleKey).ToDictionary(g => g.Key, g => g.Select(f => Norm(f.RuleId)).Distinct().ToArray());
        Key FindingKey(FindingDto f)
        {
            string identity = Norm(f.RuleId);
            if (identity.Length == 0 && aliases.TryGetValue(TitleKey(f), out var ids) && ids.Length == 1) identity = ids[0];
            if (identity.Length == 0) identity = Norm(FindingDetails.Slug(f.Title ?? ""));
            return new Key(identity, Norm(f.Host), Proto(f.Proto), f.Port);
        }
        Compare(
            oldFindings, newFindings,
            FindingKey,
            f => f.Title ?? "", f => $"{f.Severity}; {f.Product ?? ""}",
            (change, f, before, after) => new ComparisonRow("Finding", change, f.Host ?? "", Endpoint(f.Proto, f.Port), f.Title ?? "", before, after), rows);
        Compare(
            (baseline.Ports ?? []).Where(p => p != null && string.Equals(p.State, "open", StringComparison.OrdinalIgnoreCase)),
            (current.Ports ?? []).Where(p => p != null && string.Equals(p.State, "open", StringComparison.OrdinalIgnoreCase)),
            p => new Key("", Norm(p.HostIp), Proto(p.Proto), p.Port),
            p => p.Service ?? "", p => $"{p.Service ?? ""}; {p.Banner ?? ""}; risk {p.Risk}",
            (change, p, before, after) => new ComparisonRow("Service", change, p.HostIp ?? "", Endpoint(p.Proto, p.Port), p.Service ?? "", before, after), rows);
        return rows.OrderBy(r => r.Kind, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Host, StringComparer.OrdinalIgnoreCase)
            .ThenBy(r => r.Endpoint, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Name, StringComparer.OrdinalIgnoreCase).ThenBy(r => r.Change).ToList();
    }

    private static void Compare<T>(IEnumerable<T> before, IEnumerable<T> after, Func<T, Key> key, Func<T, string> name,
        Func<T, string> detail, Func<string, T, string, string, ComparisonRow> row, List<ComparisonRow> output) where T : class
    {
        var old = before.GroupBy(key).ToDictionary(g => g.Key, g => g.ToList());
        var now = after.GroupBy(key).ToDictionary(g => g.Key, g => g.ToList());
        foreach (var k in old.Keys.Union(now.Keys))
        {
            var a = old.TryGetValue(k, out var left) ? left : [];
            var b = now.TryGetValue(k, out var right) ? right : [];
            // Pair identical observations first. This preserves duplicate counts without inventing changes when order differs.
            var remaining = new List<T>(b);
            var unmatched = new List<T>();
            foreach (var item in a)
            {
                int i = remaining.FindIndex(x => string.Equals(name(item), name(x), StringComparison.OrdinalIgnoreCase)
                    && string.Equals(detail(item), detail(x), StringComparison.OrdinalIgnoreCase));
                if (i >= 0)
                {
                    var match = remaining[i]; remaining.RemoveAt(i);
                    output.Add(row("Unchanged", match, detail(item), detail(match)));
                }
                else unmatched.Add(item);
            }
            // Pair same titles/services next; one changed occurrence remains one changed row.
            for (int n = unmatched.Count - 1; n >= 0; n--)
            {
                var item = unmatched[n];
                int i = remaining.FindIndex(x => string.Equals(name(item), name(x), StringComparison.OrdinalIgnoreCase));
                if (i < 0) continue;
                var match = remaining[i]; remaining.RemoveAt(i); unmatched.RemoveAt(n);
                output.Add(row("Changed", match, detail(item), detail(match)));
            }
            // Same identity can have a renamed title or a changed service name.
            int pairs = Math.Min(unmatched.Count, remaining.Count);
            for (int i = 0; i < pairs; i++)
                output.Add(row("Changed", remaining[i], $"{name(unmatched[i])}: {detail(unmatched[i])}", $"{name(remaining[i])}: {detail(remaining[i])}"));
            foreach (var item in unmatched.Skip(pairs)) output.Add(row("Not observed", item, detail(item), "Not observed in current scan"));
            foreach (var item in remaining.Skip(pairs)) output.Add(row("New", item, "Not observed in baseline", detail(item)));
        }
    }

    private static Key TitleKey(FindingDto f) => new(Norm(f.Title), Norm(f.Host), Proto(f.Proto), f.Port);
    private static string Norm(string? text) => (text ?? "").Trim().ToUpperInvariant();
    private static string Proto(string? text) => string.IsNullOrWhiteSpace(text) ? "TCP" : Norm(text);
    private static string Endpoint(string? proto, int port) => port > 0 ? $"{port}/{Proto(proto).ToLowerInvariant()}" : Proto(proto).ToLowerInvariant();
}
