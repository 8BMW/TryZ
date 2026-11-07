using System.Text;
using TryZ.Views;

namespace TryZ.Data;

/// <summary>Writes a session to disk in one of the export formats.</summary>
internal static class ReportExporter
{
    public sealed record FormatInfo(string Name, string Extension, string Filter, string FileTag);

    public static FormatInfo Describe(ExportFormat format) => format switch
    {
        ExportFormat.Csv => new("Findings CSV", "csv", "CSV file (*.csv)|*.csv", "findings"),
        _ => new("HTML report", "html", "HTML report (*.html)|*.html;*.htm", "report"),
    };

    /// <exception cref="IOException">The file could not be written.</exception>
    /// <exception cref="UnauthorizedAccessException">The file could not be written.</exception>
    public static void Write(string path, ExportFormat format, Session session, AppSettings settings)
    {
        switch (format)
        {
            case ExportFormat.Csv:
                File.WriteAllText(path, ReportWriter.BuildFindingsCsv(session), new UTF8Encoding(encoderShouldEmitUTF8Identifier: true));
                break;
            default:
                File.WriteAllText(path, ReportWriter.BuildHtml(session, settings.ReportAuthorLine), new UTF8Encoding(false));
                break;
        }
    }
}
