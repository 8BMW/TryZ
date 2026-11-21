namespace TryZ.Data;

internal enum ReportTemplate { Executive, Technical, Remediation, Inventory, WebReview }

/// <summary>
/// What goes into a report: the template it was built for and the sections the user left switched on.
/// The same scope drives the preview and every export format, so what you see is what you send.
/// </summary>
internal sealed record ReportScope
{
    public static readonly string[] TemplateNames =
    {
        "Executive Summary", "Technical Findings", "Remediation Plan", "Host Inventory", "Web Application Review",
    };

    /// <summary>Everything: what the File and Reports menu exports have always written.</summary>
    public static readonly ReportScope Complete = new();

    public ReportTemplate Template { get; init; } = ReportTemplate.Technical;
    public bool Cover { get; init; } = true;
    public bool Severity { get; init; } = true;
    public bool Findings { get; init; } = true;
    public bool Evidence { get; init; } = true;
    public bool Hosts { get; init; } = true;

    /// <summary>Section defaults for a template, as the Reports view applies them.</summary>
    public static ReportScope For(ReportTemplate t) => new()
    {
        Template = t,
        Cover = t is ReportTemplate.Executive or ReportTemplate.Technical or ReportTemplate.WebReview,
        Severity = t is ReportTemplate.Executive or ReportTemplate.Technical,
        Findings = t is ReportTemplate.Technical or ReportTemplate.Remediation or ReportTemplate.WebReview,
        Evidence = t is ReportTemplate.Technical or ReportTemplate.WebReview,
        Hosts = t is ReportTemplate.Technical or ReportTemplate.Inventory,
    };

    public string Name => TemplateNames[(int)Template];

    /// <summary>Document heading. The technical report keeps its long-standing title.</summary>
    public string Heading => Template == ReportTemplate.Technical ? "Security Assessment Report" : Name;

    public bool IncludesPlan => Template is ReportTemplate.Remediation or ReportTemplate.Executive;

    /// <summary>The executive summary only carries the top of the plan; the rest is one click away in the full plan.</summary>
    public int PlanLimit => Template == ReportTemplate.Executive ? 5 : int.MaxValue;

    public string FileTag(string fallback) => Template switch
    {
        ReportTemplate.Executive => "executive-summary",
        ReportTemplate.Remediation => "remediation-plan",
        ReportTemplate.Inventory => "inventory",
        ReportTemplate.WebReview => "web-review",
        _ => fallback,
    };

    /// <summary>Findings in this report, most severe first.</summary>
    public List<Finding> SelectFindings(Session s)
    {
        IEnumerable<Finding> items = s.Findings.Items;
        if (Template == ReportTemplate.WebReview)
        {
            var web = WebEndpoints(s);
            items = items.Where(f => IsWebFinding(f, web));
        }
        return items.OrderByDescending(f => f.Severity).ThenBy(f => f.Host, StringComparer.Ordinal).ThenBy(f => f.Port).ThenBy(f => f.Id).ToList();
    }

    public static bool IsWebService(string service)
    {
        string name = (service ?? string.Empty).Trim().ToLowerInvariant();
        if (name.StartsWith("ssl/", StringComparison.Ordinal)) name = name[4..];
        // MS RPC over HTTP shares the prefix but isn't something a web review covers.
        return name.StartsWith("http", StringComparison.Ordinal) && name != "http-rpc-epmap";
    }

    /// <summary>host|port pairs that served HTTP, either by service detection or because the crawler fetched pages there.</summary>
    public static HashSet<string> WebEndpoints(Session s)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var p in s.Ports.Items)
            if (p.State == "open" && IsWebService(p.Service)) set.Add($"{p.HostIp}|{p.Port}");
        foreach (var u in s.Urls.Items)
            if (Uri.TryCreate(u.Url, UriKind.Absolute, out var uri)) set.Add($"{uri.Host}|{uri.Port}");
        return set;
    }

    public static bool IsWebFinding(Finding f, HashSet<string> webEndpoints)
    {
        if (f.RuleId.StartsWith("custom.", StringComparison.OrdinalIgnoreCase)) return true; // custom rules are HTTP rules
        if (string.Equals(f.Proto, "dns", StringComparison.OrdinalIgnoreCase)) return true;   // dangling aliases: subdomain takeover
        if (!string.Equals(f.Proto, "tcp", StringComparison.OrdinalIgnoreCase)) return false;
        if (webEndpoints.Contains($"{f.Host}|{f.Port}")) return true;
        // Nothing recorded for the port (an imported or trimmed session): fall back to the usual web ports.
        return webEndpoints.Count == 0 && f.Port is 80 or 443 or 8000 or 8008 or 8080 or 8443 or 8888;
    }
}
