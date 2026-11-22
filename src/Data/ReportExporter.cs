using System.Text;
using TryZ.Views;

namespace TryZ.Data;

/// <summary>Writes assessment results in the format selected by the user.</summary>
internal static class ReportExporter
{
    public sealed record FormatInfo(string Name, string Extension, string Filter, string FileTag);

    public static FormatInfo Describe(ExportFormat format) => format switch
    {
        ExportFormat.Html => new("HTML report", "html", "HTML report (*.html)|*.html;*.htm", "report"),
        ExportFormat.Csv => new("Findings CSV", "csv", "CSV file (*.csv)|*.csv", "findings"),
        ExportFormat.Json => new("Findings JSON", "json", "JSON file (*.json)|*.json", "findings"),
        ExportFormat.Sarif => new("SARIF 2.1.0", "sarif", "SARIF file (*.sarif)|*.sarif", "findings"),
        ExportFormat.Pdf => new("PDF report", "pdf", "PDF file (*.pdf)|*.pdf", "report"),
        ExportFormat.Markdown => new("Markdown report", "md", "Markdown file (*.md)|*.md", "report"),
        ExportFormat.Plan => new("Remediation plan", "md", "Markdown file (*.md)|*.md", "remediation-plan"),
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    /// <exception cref="IOException">The file could not be written.</exception>
    /// <exception cref="UnauthorizedAccessException">The file could not be written.</exception>
    public static void Write(string path, ExportFormat format, Session session, AppSettings settings)
    {
        var utf8 = new UTF8Encoding(false);
        switch (format)
        {
            case ExportFormat.Html: File.WriteAllText(path, ReportWriter.BuildHtml(session, settings.ReportAuthorLine), utf8); break;
            case ExportFormat.Csv: File.WriteAllText(path, ReportWriter.BuildFindingsCsv(session), new UTF8Encoding(true)); break;
            case ExportFormat.Json: File.WriteAllText(path, StructuredReport.FindingsJson(session), utf8); break;
            case ExportFormat.Sarif: File.WriteAllText(path, StructuredReport.Sarif(session), utf8); break;
            case ExportFormat.Markdown: File.WriteAllText(path, StructuredReport.Markdown(session, settings.ReportAuthorLine), utf8); break;
            case ExportFormat.Plan: File.WriteAllText(path, RemediationPlan.Build(session.Findings.Items).ToMarkdown(settings.ReportAuthorLine), utf8); break;
            case ExportFormat.Pdf: PdfReport.Write(path, session, settings.ReportAuthorLine); break;
            default: throw new ArgumentOutOfRangeException(nameof(format));
        }
    }
}
