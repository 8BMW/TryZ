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
        _ => throw new ArgumentOutOfRangeException(nameof(format)),
    };

    /// <summary>Name and file tag adjusted to the template, e.g. a CSV of the remediation plan is not a "Findings CSV".</summary>
    public static FormatInfo Describe(ExportFormat format, ReportScope scope)
    {
        var info = Describe(format);
        if (scope.Template == ReportTemplate.Technical) return info;
        string name = format switch
        {
            ExportFormat.Csv when scope.Template == ReportTemplate.Remediation => "Remediation plan CSV",
            ExportFormat.Csv when scope.Template == ReportTemplate.Inventory => "Service inventory CSV",
            ExportFormat.Sarif => info.Name,
            _ => $"{scope.Name} ({info.Extension.ToUpperInvariant()})",
        };
        // SARIF is a findings feed for other tools; naming it after a template would only confuse them.
        string tag = format == ExportFormat.Sarif ? info.FileTag : scope.FileTag(info.FileTag);
        return info with { Name = name, FileTag = tag };
    }

    /// <exception cref="IOException">The file could not be written.</exception>
    /// <exception cref="UnauthorizedAccessException">The file could not be written.</exception>
    public static void Write(string path, ExportFormat format, Session session, AppSettings settings, ReportScope? scope = null)
    {
        scope ??= ReportScope.Complete;
        var utf8 = new UTF8Encoding(false);
        switch (format)
        {
            case ExportFormat.Html: File.WriteAllText(path, ReportWriter.BuildHtml(session, settings.ReportAuthorLine, scope), utf8); break;
            case ExportFormat.Csv: File.WriteAllText(path, Csv(session, scope), new UTF8Encoding(true)); break;
            case ExportFormat.Json: File.WriteAllText(path, StructuredReport.FindingsJson(session, scope), utf8); break;
            case ExportFormat.Sarif: File.WriteAllText(path, StructuredReport.Sarif(session, scope), utf8); break;
            case ExportFormat.Markdown: File.WriteAllText(path, StructuredReport.Markdown(session, settings.ReportAuthorLine, scope), utf8); break;
            case ExportFormat.Pdf: PdfReport.Write(path, session, settings.ReportAuthorLine, scope); break;
            default: throw new ArgumentOutOfRangeException(nameof(format));
        }
    }

    private static string Csv(Session session, ReportScope scope) => scope.Template switch
    {
        ReportTemplate.Remediation => RemediationPlan.Build(session).Csv(),
        ReportTemplate.Inventory => ReportWriter.BuildServicesCsv(session),
        _ => ReportWriter.BuildFindingsCsv(session, scope),
    };
}
