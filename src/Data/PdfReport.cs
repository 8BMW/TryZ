using System.Globalization;
using System.Text;
using PdfSharp.Drawing;
using PdfSharp.Pdf;

namespace TryZ.Data;

/// <summary>Creates a local, multi-page PDF without a browser or external service.</summary>
internal static class PdfReport
{
    public static void Write(string path, Session session, string footer, ReportScope? scope = null)
    {
        scope ??= ReportScope.Complete;
        var findings = scope.SelectFindings(session);
        using var doc = new PdfDocument();
        doc.Info.Title = scope.Template == ReportTemplate.Technical ? "TryZ Security Assessment" : "TryZ " + scope.Name;
        doc.Info.Author = "TryZ Security Suite";
        using var layout = new Layout(doc);
        layout.Heading(scope.Heading, 18);
        layout.Line($"Target: {session.Target}");
        if (scope.Cover)
        {
            layout.Line($"Profile: {session.Profile}");
            layout.Line($"Started: {session.StartedAt?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "Unknown"}");
        }
        layout.Line($"Summary: {session.Hosts.Items.Count} hosts, {session.Ports.Items.Count(p => p.State == "open")} open services, {session.FindingCount} findings.");
        if (scope.Severity)
        {
            var c = session.SeverityCounts;
            layout.Line($"By severity: {c[4]} critical, {c[3]} high, {c[2]} medium, {c[1]} low, {c[0]} informational.");
        }
        layout.Line("Results cover only the checks performed; absence of a finding does not prove absence of a vulnerability.");

        if (scope.IncludesPlan)
        {
            var plan = RemediationPlan.Build(session, findings);
            layout.Heading(scope.Template == ReportTemplate.Executive ? "Top priorities" : "Remediation plan");
            layout.Line(plan.Summary());
            foreach (var i in plan.Items.Take(scope.PlanLimit))
            {
                layout.Heading($"{i.Rank}. [{i.TierText} {i.Score.ToString("0", CultureInfo.InvariantCulture)}/100] {i.Title}");
                layout.Line($"Target date: {i.DueText}{(i.Overdue ? " (overdue)" : string.Empty)} | {i.DueBasis}");
                layout.Line($"Severity: {i.Severity}{(i.Kev ? " | Known exploited (CISA KEV)" + (i.Ransomware ? ", ransomware use" : string.Empty) : string.Empty)}"
                    + (i.Epss is double e ? $" | EPSS {e.ToString("P1", CultureInfo.InvariantCulture)}" : string.Empty));
                layout.Line("Action: " + i.Action);
                layout.Line("Affected: " + string.Join(", ", i.Endpoints));
                if (i.Cves.Count > 0) layout.Line("CVEs: " + string.Join(", ", i.Cves));
            }
            if (plan.Items.Count > scope.PlanLimit) layout.Line($"{plan.Items.Count - scope.PlanLimit} more work item(s) are in the full remediation plan.");
            if (plan.Items.Count > 0) layout.Line(RemediationPlan.Disclaimer);
        }

        if (scope.Hosts)
        {
            layout.Heading("Hosts and open services");
            if (session.Hosts.Items.Count == 0) layout.Line("No hosts recorded.");
            foreach (var host in session.Hosts.Items)
            {
                var importance = session.ImportanceOf(host.Ip);
                layout.Line($"{host.Ip}  {host.Hostname}  {host.OsGuess}{(importance == AssetImportance.Normal ? string.Empty : "  importance: " + Prioritizer.ImportanceNames[(int)importance])}");
            }
            foreach (var port in session.Ports.Items.Where(p => p.State == "open"))
                layout.Line($"{port.HostIp}:{port.Port}/{port.Proto}  {port.Service}  {port.Banner}");
        }

        if (scope.Findings)
        {
            layout.Heading("Findings");
            if (scope.Template == ReportTemplate.WebReview) layout.Line($"{findings.Count} of {session.FindingCount} finding(s) concern web-facing services.");
            if (findings.Count == 0) layout.Line("No findings recorded.");
            foreach (var f in findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Id))
            {
                layout.Heading($"[{f.Severity}] {f.Title}");
                layout.Line($"Host: {f.Host}:{f.Port}/{f.Proto} | Status: {f.StatusText} | CWE: {(f.Cwe > 0 ? f.CweText : "-")}");
                if (f.Cves.Count > 0) layout.Line($"CVEs: {string.Join(", ", f.Cves)}");
                if (f.Cvss is double score) layout.Line($"CVSS: {score.ToString("0.0", CultureInfo.InvariantCulture)} {f.CvssVector}");
                if (f.Threat is { } t) layout.Line($"KEV: {(t.Kev ? "Yes" : "No")}" + (t.Epss is double epss ? $" | EPSS: {epss.ToString("P2", CultureInfo.InvariantCulture)}" : ""));
                layout.Line("Description: " + f.Description);
                if (scope.Evidence && f.Evidence.Length > 0) layout.Line("Evidence: " + f.Evidence);
                layout.Line("Remediation: " + f.Remediation);
            }
        }
        if (footer.Length > 0) { layout.Heading("Notes"); layout.Line(footer); }
        layout.Finish();
        doc.Save(path);
    }

    private sealed class Layout : IDisposable
    {
        private readonly PdfDocument _doc;
        private readonly XFont _regular = new("Segoe UI", 10, XFontStyleEx.Regular);
        private readonly XFont _bold = new("Segoe UI", 11, XFontStyleEx.Bold);
        private readonly XFont _title = new("Segoe UI", 18, XFontStyleEx.Bold);
        private XGraphics? _graphics;
        private double _y;
        private const double Left = 42, Width = 510, Bottom = 800;
        public Layout(PdfDocument doc) { _doc = doc; NewPage(); }
        private void NewPage()
        {
            _graphics?.Dispose();
            var page = _doc.AddPage();
            page.Size = PdfSharp.PageSize.A4;
            _graphics = XGraphics.FromPdfPage(page);
            _y = 42;
        }
        public void Heading(string text, int size = 11)
        {
            if (_y > Bottom - 45) NewPage();
            _y += 8;
            WriteText(text, size == 18 ? _title : _bold, size == 18 ? 23 : 16);
            _y += 3;
        }
        public void Line(string text) { WriteText(text, _regular, 14); _y += 3; }
        private void WriteText(string text, XFont font, double lineHeight)
        {
            text = Clean(text);
            foreach (string paragraph in text.Split('\n'))
            {
                string remaining = paragraph;
                if (remaining.Length == 0) { if (_y + lineHeight > Bottom) NewPage(); _y += lineHeight; continue; }
                while (remaining.Length > 0)
                {
                    if (_y + lineHeight > Bottom) NewPage();
                    int end = remaining.Length;
                    if (_graphics!.MeasureString(remaining, font).Width > Width)
                    {
                        int lo = 1, hi = end;
                        while (lo < hi)
                        {
                            int mid = (lo + hi + 1) / 2;
                            if (_graphics.MeasureString(remaining[..mid], font).Width <= Width) lo = mid; else hi = mid - 1;
                        }
                        end = lo;
                        if (end < remaining.Length && end > 1 && char.IsHighSurrogate(remaining[end - 1]) && char.IsLowSurrogate(remaining[end])) end--;
                        int space = remaining.LastIndexOf(' ', end - 1, end);
                        if (space >= end / 2) end = space + 1;
                    }
                    string line = remaining[..end].TrimEnd();
                    if (line.Length > 0) _graphics!.DrawString(line, font, XBrushes.Black, new XRect(Left, _y, Width, lineHeight), XStringFormats.TopLeft);
                    _y += lineHeight;
                    remaining = remaining[end..].TrimStart(' ');
                }
            }
        }
        private static string Clean(string value)
        {
            var sb = new StringBuilder(value.Length);
            foreach (char c in value) if (c == '\n' || (!char.IsControl(c) && c != '\uFFFE' && c != '\uFFFF')) sb.Append(c); else if (c == '\t') sb.Append(' ');
            return sb.ToString();
        }
        public void Finish() { _graphics?.Dispose(); _graphics = null; }
        public void Dispose() => Finish();
    }
}
