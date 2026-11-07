using System.Globalization;
using System.Net;
using System.Text;

namespace TryZ.Data;

/// <summary>Builds standalone report files (HTML, CSV) from the results recorded in a session.</summary>
internal static class ReportWriter
{
    private static readonly string[] SeverityNames = { "Info", "Low", "Medium", "High", "Critical" };
    private static readonly string[] SeverityColors = { "#7d848c", "#3f7fb8", "#b89a1c", "#c86a1e", "#c0332b" };

    private static string H(string? text) => WebUtility.HtmlEncode(text ?? string.Empty);

    public static string BuildHtml(Session s, string footer)
    {
        var findings = s.Findings.Items
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.Host, StringComparer.Ordinal)
            .ThenBy(f => f.Port)
            .ToList();
        int open = s.Ports.Items.Count(p => p.State == "open");
        var counts = s.SeverityCounts;
        var sb = new StringBuilder(64 * 1024);
        string version = System.Windows.Forms.Application.ProductVersion.Split('+')[0];

        sb.Append("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
        sb.Append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
        sb.Append("<title>").Append(H($"Security assessment - {s.Target}")).Append("</title>\n<style>\n");
        sb.Append("""
            :root{--ink:#22242a;--muted:#6b7078;--rule:#d5d8dc;--band:#8e1c1c;--bg:#ffffff;--head:#34383d}
            *{box-sizing:border-box}
            body{margin:0;background:#eceef0;color:var(--ink);font:14px/1.5 "Segoe UI",Tahoma,Arial,sans-serif}
            main{max-width:1100px;margin:24px auto;background:var(--bg);padding:32px 40px;box-shadow:0 2px 10px rgba(0,0,0,.12)}
            h1{font:700 26px Georgia,serif;margin:0 0 4px;border-left:6px solid var(--band);padding-left:12px}
            h2{font:700 18px Georgia,serif;margin:32px 0 10px;border-bottom:1px solid var(--rule);padding-bottom:4px}
            h3{font-size:15px;margin:0 0 6px}
            .sub{color:var(--muted);margin:0 0 20px 18px}
            table{border-collapse:collapse;width:100%;margin:8px 0}
            th{background:var(--head);color:#fff;text-align:left;font-weight:600;padding:5px 8px;font-size:12px}
            td{border-bottom:1px solid var(--rule);padding:5px 8px;vertical-align:top;font-size:13px}
            td.mono,code,pre{font-family:Consolas,"Courier New",monospace}
            .kv td:first-child{color:var(--muted);width:180px}
            .sev{display:inline-block;min-width:64px;padding:1px 8px;border-radius:3px;color:#fff;font-weight:600;font-size:12px;text-align:center}
            .cards{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}
            .card{flex:1 1 120px;border:1px solid var(--rule);border-top:4px solid;padding:8px 12px}
            .card b{display:block;font-size:24px}
            .finding{border:1px solid var(--rule);border-left:5px solid;padding:12px 16px;margin:14px 0;page-break-inside:avoid}
            .meta{color:var(--muted);font-size:12px;margin-bottom:8px}
            pre{background:#f4f5f6;border:1px solid var(--rule);padding:8px;white-space:pre-wrap;word-break:break-all;font-size:12px;max-height:420px;overflow:auto}
            footer{color:var(--muted);font-size:12px;margin-top:32px;border-top:1px solid var(--rule);padding-top:8px}
            @media print{body{background:#fff}main{box-shadow:none;margin:0}}

            """);
        sb.Append("</style>\n</head>\n<body>\n<main>\n");

        sb.Append("<h1>Security Assessment Report</h1>\n");
        sb.Append("<p class=\"sub\">Target ").Append(H(s.Target.Length > 0 ? s.Target : "(none)"))
          .Append(" &middot; generated ").Append(H(DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)))
          .Append(" by TryZ Security Suite ").Append(H(version)).Append("</p>\n");

        // ---------------------------------------------------------------- executive summary
        sb.Append("<h2>Executive summary</h2>\n<p>");
        if (s.Hosts.Items.Count == 0 && s.FindingCount == 0)
        {
            sb.Append("No hosts or findings were recorded in this session.");
        }
        else
        {
            sb.Append(H($"The assessment of {s.Target} found {s.Hosts.Items.Count} live host(s) exposing {open} open TCP service(s). "));
            sb.Append(H($"{s.FindingCount} finding(s) were recorded: {counts[4]} critical, {counts[3]} high, {counts[2]} medium, {counts[1]} low and {counts[0]} informational. "));
            if (counts[4] + counts[3] > 0)
                sb.Append(H("Critical and high severity items should be remediated first; details and remediation guidance follow below."));
            else if (counts[2] > 0)
                sb.Append(H("No critical or high severity issues were identified; medium severity items should be scheduled for remediation."));
            else
                sb.Append(H("No critical, high or medium severity issues were identified by the checks that ran."));
        }
        sb.Append("</p>\n");
        sb.Append("<p class=\"meta\">Results reflect only the checks performed by TryZ during this run (TCP connect scan, service banners, TLS and HTTP configuration checks, crawling");
        sb.Append(" and optional NVD lookups). Absence of a finding does not prove absence of a vulnerability.</p>\n");

        sb.Append("<div class=\"cards\">\n");
        for (int i = 4; i >= 0; i--)
            sb.Append("<div class=\"card\" style=\"border-top-color:").Append(SeverityColors[i]).Append("\"><b>")
              .Append(counts[i]).Append("</b>").Append(SeverityNames[i]).Append("</div>\n");
        sb.Append("</div>\n");

        sb.Append("<table class=\"kv\">\n");
        Row(sb, "Target", s.Target);
        Row(sb, "Profile", s.Profile);
        Row(sb, "Worker threads", s.Threads > 0 ? s.Threads.ToString(CultureInfo.InvariantCulture) : "-");
        Row(sb, "Started", s.StartedAt?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "-");
        Row(sb, "Duration", TimeSpan.FromSeconds(s.ElapsedSeconds).ToString(@"hh\:mm\:ss", CultureInfo.InvariantCulture));
        Row(sb, "Requests sent", s.TotalRequests.ToString("N0", CultureInfo.InvariantCulture));
        Row(sb, "Hosts up", s.Hosts.Items.Count.ToString(CultureInfo.InvariantCulture));
        Row(sb, "Open services", open.ToString(CultureInfo.InvariantCulture));
        Row(sb, "URLs crawled", s.Urls.Items.Count.ToString("N0", CultureInfo.InvariantCulture));
        sb.Append("</table>\n");

        // ---------------------------------------------------------------- hosts
        sb.Append("<h2>Hosts</h2>\n");
        if (s.Hosts.Items.Count == 0) sb.Append("<p>No hosts recorded.</p>\n");
        else
        {
            sb.Append("<table>\n<tr><th>Address</th><th>Hostname</th><th>OS guess</th><th>TTL</th><th>Latency</th><th>Open ports</th><th>State</th></tr>\n");
            foreach (var h in s.Hosts.Items.OrderBy(h => IpSortKey(h.Ip)))
            {
                sb.Append("<tr><td class=\"mono\">").Append(H(h.Ip)).Append("</td><td>").Append(H(h.Hostname))
                  .Append("</td><td>").Append(H(h.OsGuess)).Append("</td><td>").Append(h.Ttl)
                  .Append("</td><td>").Append(h.LatencyMs).Append(" ms</td><td>").Append(h.OpenPorts)
                  .Append("</td><td>").Append(H(h.State)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");
        }

        // ---------------------------------------------------------------- ports
        sb.Append("<h2>Open services</h2>\n");
        var ports = s.Ports.Items.Where(p => p.State == "open").OrderBy(p => IpSortKey(p.HostIp)).ThenBy(p => p.Port).ToList();
        if (ports.Count == 0) sb.Append("<p>No open services recorded.</p>\n");
        else
        {
            sb.Append("<table>\n<tr><th>Host</th><th>Port</th><th>Service</th><th>Banner / product</th><th>Risk</th></tr>\n");
            foreach (var p in ports)
            {
                sb.Append("<tr><td class=\"mono\">").Append(H(p.HostIp)).Append("</td><td class=\"mono\">").Append(p.Port).Append('/').Append(H(p.Proto))
                  .Append("</td><td>").Append(H(p.Service)).Append("</td><td class=\"mono\">").Append(H(p.Banner))
                  .Append("</td><td>").Append(Badge(p.Risk)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");
        }

        // ---------------------------------------------------------------- findings
        sb.Append("<h2>Findings</h2>\n");
        if (findings.Count == 0) sb.Append("<p>No findings recorded.</p>\n");
        else
        {
            sb.Append("<table>\n<tr><th>#</th><th>Severity</th><th>Title</th><th>Host</th><th>Port</th><th>CWE</th><th>Status</th></tr>\n");
            foreach (var f in findings)
            {
                sb.Append("<tr><td><a href=\"#f").Append(f.Id).Append("\">").Append(f.Id).Append("</a></td><td>").Append(Badge(f.Severity))
                  .Append("</td><td>").Append(H(f.Title)).Append("</td><td class=\"mono\">").Append(H(f.Host))
                  .Append("</td><td class=\"mono\">").Append(f.Port > 0 ? f.Port.ToString(CultureInfo.InvariantCulture) : "-")
                  .Append("</td><td>").Append(f.Cwe > 0 ? H(f.CweText) : "-").Append("</td><td>").Append(H(f.StatusText)).Append("</td></tr>\n");
            }
            sb.Append("</table>\n");

            foreach (var f in findings)
            {
                sb.Append("<div class=\"finding\" id=\"f").Append(f.Id).Append("\" style=\"border-left-color:").Append(SeverityColors[(int)f.Severity]).Append("\">\n");
                sb.Append("<h3>").Append(Badge(f.Severity)).Append(' ').Append(H(f.Title)).Append("</h3>\n");
                sb.Append("<div class=\"meta\">").Append(H(f.Host)).Append(f.Port > 0 ? ":" + f.Port.ToString(CultureInfo.InvariantCulture) : string.Empty)
                  .Append(f.Cwe > 0 ? " &middot; " + H(f.CweText) : string.Empty).Append(" &middot; ").Append(H(f.StatusText)).Append("</div>\n");
                sb.Append("<p><strong>Description.</strong> ").Append(H(f.Description)).Append("</p>\n");
                if (f.Evidence.Length > 0) sb.Append("<p><strong>Evidence</strong></p>\n<pre>").Append(H(f.Evidence)).Append("</pre>\n");
                sb.Append("<p><strong>Remediation.</strong> ").Append(H(f.Remediation)).Append("</p>\n</div>\n");
            }
        }

        sb.Append("<footer>");
        if (footer.Length > 0) sb.Append(H(footer)).Append("<br>");
        sb.Append("Generated by TryZ Security Suite. This report contains information about the security posture of the assessed systems; handle it as confidential.");
        sb.Append("</footer>\n</main>\n</body>\n</html>\n");
        return sb.ToString();
    }

    public static string BuildFindingsCsv(Session s)
    {
        var sb = new StringBuilder();
        sb.Append("Id,Severity,Title,Host,Port,CWE,Status,Description,Evidence,Remediation\r\n");
        foreach (var f in s.Findings.Items.OrderByDescending(f => f.Severity).ThenBy(f => f.Id))
        {
            sb.Append(f.Id).Append(',')
              .Append(Csv(f.Severity.ToString())).Append(',')
              .Append(Csv(f.Title)).Append(',')
              .Append(Csv(f.Host)).Append(',')
              .Append(f.Port).Append(',')
              .Append(f.Cwe > 0 ? f.CweText : string.Empty).Append(',')
              .Append(Csv(f.StatusText)).Append(',')
              .Append(Csv(f.Description)).Append(',')
              .Append(Csv(f.Evidence)).Append(',')
              .Append(Csv(f.Remediation)).Append("\r\n");
        }
        return sb.ToString();
    }

    private static void Row(StringBuilder sb, string key, string value) =>
        sb.Append("<tr><td>").Append(H(key)).Append("</td><td>").Append(H(value.Length > 0 ? value : "-")).Append("</td></tr>\n");

    private static string Badge(Severity severity) =>
        $"<span class=\"sev\" style=\"background:{SeverityColors[(int)severity]}\">{SeverityNames[(int)severity]}</span>";

    private static string Csv(string value)
    {
        // Neutralise spreadsheet formula injection, then quote.
        if (value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r') value = "'" + value;
        return "\"" + value.Replace("\"", "\"\"") + "\"";
    }

    private static string IpSortKey(string ip)
    {
        if (IPAddress.TryParse(ip, out var addr))
            return Convert.ToHexString(addr.GetAddressBytes()).PadLeft(32, '0');
        return "~" + ip;
    }
}
