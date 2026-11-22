using System.Globalization;
using System.Net.Http;
using System.Net.Mail;
using System.Text;
using System.Text.Json;

namespace TryZ.Data;

/// <summary>
/// Sends notifications when a scan turns up new findings. Supports an HTTP webhook (Slack / Mattermost / Discord /
/// generic JSON receivers) and SMTP e-mail. Used by headless and scheduled scans so an unattended run can raise an
/// alert without the UI. Every channel is best-effort and independent; a failure is reported, never thrown.
/// </summary>
internal static class Alerting
{
    public sealed record Result(bool Attempted, bool WebhookSent, bool EmailSent, IReadOnlyList<string> Errors);

    /// <summary>True when at least one alert channel is configured and enabled.</summary>
    public static bool IsConfigured(AppSettings s) =>
        s.AlertOnNewFindings && (s.AlertWebhookUrl.Trim().Length > 0 ||
            (s.AlertEmailEnabled && s.AlertEmailTo.Trim().Length > 0 && s.AlertSmtpHost.Trim().Length > 0));

    public static async Task<Result> SendAsync(AppSettings s, string target, IReadOnlyList<Finding> newFindings, CancellationToken token = default)
    {
        ArgumentNullException.ThrowIfNull(s);
        var errors = new List<string>();
        if (newFindings.Count == 0 || !IsConfigured(s)) return new Result(false, false, false, errors);

        string subject = $"TryZ: {newFindings.Count} new finding(s) on {target}";
        string body = BuildText(target, newFindings);

        bool webhook = false, email = false;
        if (s.AlertWebhookUrl.Trim().Length > 0)
        {
            try { webhook = await PostWebhookAsync(s.AlertWebhookUrl.Trim(), subject, body, target, newFindings, token).ConfigureAwait(false); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or InvalidOperationException or UriFormatException)
            {
                errors.Add($"webhook: {ex.Message}");
            }
        }
        if (s.AlertEmailEnabled && s.AlertEmailTo.Trim().Length > 0 && s.AlertSmtpHost.Trim().Length > 0)
        {
            try { email = await SendEmailAsync(s, subject, body, token).ConfigureAwait(false); }
            catch (Exception ex) when (ex is SmtpException or InvalidOperationException or FormatException or IOException)
            {
                errors.Add($"email: {ex.Message}");
            }
        }
        return new Result(true, webhook, email, errors);
    }

    private static string BuildText(string target, IReadOnlyList<Finding> findings)
    {
        var sb = new StringBuilder();
        sb.Append(findings.Count).Append(" new finding(s) on ").Append(target).Append(" at ")
          .Append(DateTime.Now.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)).AppendLine(":");
        foreach (var f in findings.OrderByDescending(f => f.Severity).Take(40))
        {
            sb.Append("• [").Append(f.Severity).Append("] ").Append(f.Title);
            if (f.Host.Length > 0) sb.Append("  (").Append(f.Host).Append(f.Port > 0 ? ":" + f.Port.ToString(CultureInfo.InvariantCulture) : "").Append(')');
            if (f.Cwe > 0) sb.Append("  ").Append(f.CweText);
            sb.AppendLine();
        }
        if (findings.Count > 40) sb.Append("… and ").Append(findings.Count - 40).AppendLine(" more.");
        return sb.ToString();
    }

    private static async Task<bool> PostWebhookAsync(string url, string subject, string body, string target,
        IReadOnlyList<Finding> findings, CancellationToken token)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) || uri.Scheme is not ("http" or "https"))
            throw new UriFormatException("webhook URL must be an absolute http(s) URL");

        var counts = new Dictionary<string, int>();
        foreach (var f in findings) counts[f.Severity.ToString()] = counts.GetValueOrDefault(f.Severity.ToString()) + 1;
        // A payload that satisfies Slack/Mattermost ("text"), Discord ("content") and generic receivers ("findings").
        var payload = new
        {
            text = subject + "\n" + body,
            content = subject,
            target,
            newFindings = findings.Count,
            severityCounts = counts,
            findings = findings.OrderByDescending(f => f.Severity).Take(50).Select(f => new
            {
                severity = f.Severity.ToString(), title = f.Title, host = f.Host, port = f.Port,
                cwe = f.Cwe > 0 ? f.CweText : null, ruleId = f.RuleId, fingerprint = f.Fingerprint,
            }).ToArray(),
            generatedAt = DateTimeOffset.UtcNow,
        };
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "TryZ-Scanner/1.0");
        using var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
        using var resp = await http.PostAsync(uri, content, token).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
            throw new HttpRequestException($"HTTP {(int)resp.StatusCode} from webhook");
        return true;
    }

    private static async Task<bool> SendEmailAsync(AppSettings s, string subject, string body, CancellationToken token)
    {
        string from = s.AlertEmailFrom.Trim().Length > 0 ? s.AlertEmailFrom.Trim() : s.AlertSmtpUser.Trim();
        if (from.Length == 0) from = "tryz@localhost";
        using var message = new MailMessage { From = new MailAddress(from), Subject = subject, Body = body };
        foreach (var to in s.AlertEmailTo.Split(new[] { ',', ';' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            message.To.Add(to);
        if (message.To.Count == 0) throw new FormatException("no valid recipient address");

        using var client = new SmtpClient(s.AlertSmtpHost.Trim(), s.AlertSmtpPort)
        {
            EnableSsl = s.AlertSmtpStartTls,
            DeliveryMethod = SmtpDeliveryMethod.Network,
        };
        if (s.AlertSmtpUser.Trim().Length > 0)
            client.Credentials = new System.Net.NetworkCredential(s.AlertSmtpUser.Trim(), s.AlertSmtpPassword);
        // SmtpClient.Send is synchronous; run it off the calling thread and honour cancellation at the boundary.
        token.ThrowIfCancellationRequested();
        await Task.Run(() => client.Send(message), token).ConfigureAwait(false);
        return true;
    }
}
