#if DEBUG
using System.Net;
using System.Net.Http;
using System.Threading.Channels;
using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

internal sealed class ThreatIntelChecks : ICheckSuite
{
    public string Name => "threat-intel";
    public async Task RunAsync(CheckContext c)
    {
        var channel = Channel.CreateUnbounded<ScanEvent>();
        var options = new ScanOptions { EnableThreatIntel = true, MaxRequestsPerSecond = 5000 };
        using var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, options), channel.Writer, CancellationToken.None);
        ctx.AddFinding(Severity.High, "test", "127.0.0.1", 443, 1, "", "", "", new FindingDetails { Cves = ["CVE-2024-1111", "CVE-2024-2222"] });
        using var http = new HttpClient(new FakeHandler());
        await ThreatIntel.EnrichAsync(ctx, http);
        var events = new List<ScanEvent>();
        while (channel.Reader.TryRead(out var ev)) events.Add(ev);
        var enriched = events.OfType<FindingEnriched>().SingleOrDefault();
        c.Check("KEV match published", enriched?.Threat?.Kev == true && enriched.Threat.KevCve == "CVE-2024-1111");
        c.Check("ransomware and dates parsed", enriched?.Threat?.KevRansomware == true && enriched.Threat.KevDueDate == new DateOnly(2024, 2, 1));
        c.Check("highest EPSS score and matching percentile", enriched?.Threat?.Epss == 0.9 && enriched.Threat.EpssPercentile == 0.95);

        var failed = Channel.CreateUnbounded<ScanEvent>();
        using var failedCtx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, options), failed.Writer, CancellationToken.None);
        failedCtx.AddFinding(Severity.High, "test", "127.0.0.1", 443, 1, "", "", "", new FindingDetails { Cves = ["CVE-2024-1111"] });
        using var failedHttp = new HttpClient(new FakeHandler(failKev: true));
        await ThreatIntel.EnrichAsync(failedCtx, failedHttp);
        var failEvents = new List<ScanEvent>();
        while (failed.Reader.TryRead(out var ev)) failEvents.Add(ev);
        c.Check("KEV failure is not represented as negative", !failEvents.OfType<FindingEnriched>().Any());
        c.Check("KEV failure is logged", failEvents.OfType<ScanLog>().Any(e => e.Level == LogLevel.Warn));

        var partial = Channel.CreateUnbounded<ScanEvent>();
        using var partialCtx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, options), partial.Writer, CancellationToken.None);
        partialCtx.AddFinding(Severity.High, "test", "127.0.0.1", 443, 1, "", "", "", new FindingDetails { Cves = ["CVE-2024-1111"] });
        var handler = new FakeHandler(failEpss: true);
        using var partialHttp = new HttpClient(handler);
        await ThreatIntel.EnrichAsync(partialCtx, partialHttp, useCache: true);
        await ThreatIntel.EnrichAsync(partialCtx, partialHttp, useCache: true);
        var partialEvents = new List<ScanEvent>();
        while (partial.Reader.TryRead(out var ev)) partialEvents.Add(ev);
        c.Check("KEV remains available if EPSS fails", partialEvents.OfType<FindingEnriched>().Any(e => e.Threat?.Kev == true && e.Threat.Epss == null));
        c.Equal("catalog is cached across scans", 1, handler.KevRequests);

        using var cancel = new CancellationTokenSource();
        cancel.Cancel();
        using var canceledCtx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, options), Channel.CreateUnbounded<ScanEvent>().Writer, cancel.Token);
        canceledCtx.AddFinding(Severity.High, "test", "127.0.0.1", 443, 1, "", "", "", new FindingDetails { Cves = ["CVE-2024-1111"] });
        bool canceled = false;
        try { await ThreatIntel.EnrichAsync(canceledCtx, http); } catch (OperationCanceledException) { canceled = true; }
        c.Check("cancellation propagates", canceled);

        using var rulesCtx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, options), Channel.CreateUnbounded<ScanEvent>().Writer, CancellationToken.None);
        var host = new LiveHost { Address = IPAddress.Loopback, Hostname = string.Empty };
        VulnRules.Evaluate(rulesCtx, new OpenService { Host = host, Port = 21, Service = "ftp", Product = "vsftpd", Version = "2.3.4", Banner = "vsftpd 2.3.4" });
        VulnRules.Evaluate(rulesCtx, new OpenService { Host = host, Port = 3389, Service = "rdp" });
        var ruleFindings = rulesCtx.FindingsSnapshot();
        c.Check("built-in version CVE is linked", ruleFindings.Any(f => f.Title.Contains("CVE-2011-2523") && f.Cves.SequenceEqual(["CVE-2011-2523"])));
        var rdpFinding = ruleFindings.SingleOrDefault(f => f.Title == "Remote Desktop (RDP) exposed");
        c.Check("example CVEs in exposure descriptions are not linked", rdpFinding != null && rdpFinding.Description.Contains("CVE-2019-0708") && rdpFinding.Cves.Count == 0);
    }

    private sealed class FakeHandler(bool failKev = false, bool failEpss = false) : HttpMessageHandler
    {
        public int KevRequests { get; private set; }
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            bool isKev = request.RequestUri!.Host == "www.cisa.gov";
            if (isKev) KevRequests++;
            if ((isKev && failKev) || (!isKev && failEpss)) return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
            string body = isKev
                ? "{\"vulnerabilities\":[{\"cveID\":\"CVE-2024-1111\",\"dateAdded\":\"2024-01-01\",\"dueDate\":\"2024-02-01\",\"knownRansomwareCampaignUse\":\"Known\",\"requiredAction\":\"Patch\"}]}"
                : "{\"data\":[{\"cve\":\"CVE-2024-1111\",\"epss\":\"0.1\",\"percentile\":\"0.3\"},{\"cve\":\"CVE-2024-2222\",\"epss\":\"0.9\",\"percentile\":\"0.95\"}]}";
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(body) });
        }
    }
}
#endif
