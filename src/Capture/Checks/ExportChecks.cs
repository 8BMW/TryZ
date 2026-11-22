#if DEBUG
using System.Text.Json;
using PdfSharp.Pdf.IO;
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Capture.Checks;

internal sealed class ExportChecks : ICheckSuite
{
    public string Name => "export";
    public Task RunAsync(CheckContext c)
    {
        var s = new Session { Target = "example.test", Profile = "Quick Audit" };
        s.Apply(new HostFound(new HostRecord { Ip = "192.0.2.10", Hostname = "example.test", OsGuess = "Unknown", Ttl = 0, LatencyMs = 0, Role = "server" }));
        for (int i = 1; i <= 18; i++)
            s.Apply(new FindingFound(new Finding { Id = i, RuleId = "rule-one", Severity = Severity.High, Title = "Test finding " + i,
                Host = "192.0.2.10", Port = 443, Proto = "tcp", Cwe = 200, Status = FindingStatus.Confirmed,
                Description = "A description with enough words to wrap and paginate the generated report. " + new string('x', 220),
                Evidence = "Response: <sensitive>&value", Remediation = "Review and repair.", Cves = ["CVE-2024-12345"], Cvss = 7.5,
                Threat = new ThreatInfo { Kev = true, Epss = 0.5 } }));
        var settings = new AppSettings();
        foreach (ExportFormat format in Enum.GetValues<ExportFormat>())
        {
            var info = ReportExporter.Describe(format);
            string path = Path.Combine(c.TempDir, "report." + info.Extension);
            ReportExporter.Write(path, format, s, settings);
            c.Check($"{format} writes nonempty {info.Extension}", new FileInfo(path).Length > 100);
            switch (format)
            {
                case ExportFormat.Html: c.Check("HTML is HTML", File.ReadAllText(path).StartsWith("<!DOCTYPE html>", StringComparison.Ordinal)); break;
                case ExportFormat.Csv: c.Check("CSV contains finding", File.ReadAllText(path).Contains("Test finding 1", StringComparison.Ordinal)); break;
                case ExportFormat.Markdown:
                    string md = File.ReadAllText(path);
                    c.Check("Markdown contains evidence as escaped text", md.Contains("&lt;sensitive&gt;&amp;value", StringComparison.Ordinal));
                    c.Check("Markdown includes remediation", md.Contains("Review and repair", StringComparison.Ordinal));
                    break;
                case ExportFormat.Json:
                    using (var json = JsonDocument.Parse(File.ReadAllText(path)))
                    {
                        var findings = json.RootElement.GetProperty("findings");
                        c.Equal("JSON has all findings", 18, findings.GetArrayLength());
                        c.Check("JSON preserves CVEs and threat intel", findings[0].GetProperty("cves")[0].GetString() == "CVE-2024-12345" && findings[0].GetProperty("threat").GetProperty("kev").GetBoolean());
                    }
                    break;
                case ExportFormat.Sarif:
                    using (var json = JsonDocument.Parse(File.ReadAllText(path)))
                    {
                        var root = json.RootElement;
                        var run = root.GetProperty("runs")[0];
                        c.Check("SARIF declares 2.1.0", root.GetProperty("version").GetString() == "2.1.0");
                        c.Equal("SARIF results count", 18, run.GetProperty("results").GetArrayLength());
                        c.Equal("SARIF deduplicates rules", 1, run.GetProperty("tool").GetProperty("driver").GetProperty("rules").GetArrayLength());
                    }
                    break;
                case ExportFormat.Pdf:
                    using (var pdf = PdfReader.Open(path, PdfDocumentOpenMode.Import)) c.Check("PDF is valid and paginates", pdf.PageCount > 1, $"{pdf.PageCount} pages");
                    break;
                case ExportFormat.Plan:
                    string plan = File.ReadAllText(path);
                    c.Check("Plan consolidates shared remediation", plan.Contains("Remediation Plan", StringComparison.Ordinal) && plan.Contains("18 finding", StringComparison.Ordinal));
                    c.Check("Plan includes the action guidance", plan.Contains("Review and repair", StringComparison.Ordinal));
                    break;
            }
        }
        return Task.CompletedTask;
    }
}
#endif
