#if DEBUG
using System.Net;
using System.Net.Http;
using System.Threading.Channels;
using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

/// <summary>Authenticated scanning: scope matching, header injection against a live site, redaction and expiry warnings.</summary>
internal sealed class AuthChecks : ICheckSuite
{
    public string Name => "auth";

    public async Task RunAsync(CheckContext c)
    {
        ScopeChecks(c);
        SettingsChecks(c);
        await HandlerChecks(c);
        await LiveChecks(c);
    }

    private static void ScopeChecks(CheckContext c)
    {
        c.Check("plain host scope", AuthHeader.Validate("app.example.com", "Cookie", "a=b") == null);
        c.Check("host:port scope", AuthHeader.Validate("10.0.0.5:8443", "Authorization", "Bearer x") == null);
        c.Check("wildcard scope", AuthHeader.Validate("*.example.com", "X-Api-Key", "k") == null);
        c.Check("bracketed IPv6 with port", AuthHeader.Validate("[2001:db8::1]:8443", "Cookie", "a=b") == null);
        c.Check("bare IPv6", AuthHeader.Validate("2001:db8::1", "Cookie", "a=b") == null);
        foreach (string bad in new[] { "", "http://app.example.com", "app.example.com/path", "*", "*.10.0.0.1", "a b", "host:0", "host:70000", "ex*ample.com", "[::1" })
            c.Check($"bad scope rejected: '{bad}'", AuthHeader.Validate(bad, "Cookie", "a=b") != null);
        c.Check("Host header can't be overridden", AuthHeader.Validate("a.test", "Host", "evil") != null);
        c.Check("header injection refused", AuthHeader.Validate("a.test", "Cookie", "a=b\r\nX-Evil: 1") != null);
        c.Check("bad header name refused", AuthHeader.Validate("a.test", "Coo kie", "a=b") != null);
        c.Check("empty value refused", AuthHeader.Validate("a.test", "Cookie", "") != null);

        var host = new AuthHeader("App.Example.com", "Cookie", "s=1");
        c.Check("host match ignores case and port", host.Matches(new Uri("https://app.example.COM:8443/x")));
        c.Check("other host not matched", !host.Matches(new Uri("https://evil.example.com/")));
        c.Check("suffix trick not matched", !host.Matches(new Uri("https://app.example.com.evil.test/")));
        var port = new AuthHeader("10.0.0.5:8443", "Cookie", "s=1");
        c.Check("port scope matches its port", port.Matches(new Uri("https://10.0.0.5:8443/")));
        c.Check("port scope skips other ports", !port.Matches(new Uri("http://10.0.0.5/")));
        var wild = new AuthHeader("*.example.com", "Cookie", "s=1");
        c.Check("wildcard matches subdomain", wild.Matches(new Uri("https://a.b.example.com/")));
        c.Check("wildcard skips the apex", !wild.Matches(new Uri("https://example.com/")));
        c.Check("wildcard skips look-alikes", !wild.Matches(new Uri("https://badexample.com/")));
        var v6 = new AuthHeader("[2001:db8::1]:8443", "Cookie", "s=1");
        c.Check("IPv6 scope matches", v6.Matches(new Uri("https://[2001:db8:0::1]:8443/")));

        var ipScope = new AuthHeader("192.0.2.10", "Cookie", "s=1");
        Func<string, IPAddress?> pins = n => n == "app.example.test" ? IPAddress.Parse("192.0.2.10") : null;
        c.Check("IP scope applies to a name pinned to it", ipScope.Matches(new Uri("https://app.example.test/"), pins));
        c.Check("IP scope ignores an unpinned name", !ipScope.Matches(new Uri("https://other.example.test/"), pins));
        c.Check("IP scope without a resolver stays literal", !ipScope.Matches(new Uri("https://app.example.test/")));

        var headers = new[] { new AuthHeader("a.test", "Cookie", "sid=abc123secret; theme=dark"), new AuthHeader("a.test", "Authorization", "Bearer eyJtoken.value") };
        string redacted = AuthHandler.Redact("Set-Cookie: sid=abc123secret\nEcho: eyJtoken.value\ntheme=dark", headers);
        c.Check("cookie value redacted", !redacted.Contains("abc123secret"));
        c.Check("bearer token redacted", !redacted.Contains("eyJtoken.value"));
        c.Check("redaction keeps the rest", redacted.Contains("Set-Cookie: sid=[redacted]"));
    }

    private static async Task HandlerChecks(CheckContext c)
    {
        var warnings = new List<string>();
        var codes = new Queue<HttpStatusCode>(Enumerable.Repeat(HttpStatusCode.OK, 300).Concat(Enumerable.Repeat(HttpStatusCode.Unauthorized, 12)));
        var stub = new StubHandler(() => codes.Count > 0 ? codes.Dequeue() : HttpStatusCode.OK);
        var used = new AuthHeader("a.test", "Cookie", "sid=1");
        var unused = new AuthHeader("typo.test", "Cookie", "sid=2");
        using var handler = new AuthHandler(stub, [used, unused], warnings.Add);
        using var client = new HttpClient(handler);
        for (int i = 0; i < 312; i++) using (await client.GetAsync("http://a.test/p" + i)) { }
        c.Equal("expiry warned after many earlier successes", 1, warnings.Count(w => w.Contains("in a row")));
        c.Check("handler sent the cookie", stub.LastCookie == "sid=1");
        c.Check("unused scope is reported", handler.Unused.SequenceEqual([unused]));
        warnings.Clear();
        codes = new Queue<HttpStatusCode>(Enumerable.Range(0, 40).Select(i => i % 5 == 0 ? HttpStatusCode.Unauthorized : HttpStatusCode.OK));
        using var handler2 = new AuthHandler(new StubHandler(() => codes.Count > 0 ? codes.Dequeue() : HttpStatusCode.OK), [used], warnings.Add);
        using var client2 = new HttpClient(handler2);
        for (int i = 0; i < 40; i++) using (await client2.GetAsync("http://a.test/q" + i)) { }
        c.Equal("scattered protected pages don't trip it", 0, warnings.Count);
    }

    private sealed class StubHandler(Func<HttpStatusCode> next) : HttpMessageHandler
    {
        public string? LastCookie;
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Headers.TryGetValues("Cookie", out var v)) LastCookie = string.Join("; ", v);
            return Task.FromResult(new HttpResponseMessage(next()));
        }
    }

    private static void SettingsChecks(CheckContext c)
    {
        string blob = SecretStore.Protect("tryz_session=" + TestSite.Credential);
        c.Check("secret is not stored in clear", !blob.Contains(TestSite.Credential, StringComparison.Ordinal) && blob.Length > 0);
        c.Equal("secret round-trips", "tryz_session=" + TestSite.Credential, SecretStore.Unprotect(blob));
        c.Check("damaged blob reads as missing", SecretStore.Unprotect("not base64!") == null);
        var s = new AppSettings
        {
            AuthHeaders =
            [
                new AuthHeaderSetting { Scope = "a.test", Name = "Cookie", Secret = blob },
                new AuthHeaderSetting { Scope = "b.test", Name = "Cookie", Secret = blob, Enabled = false },
                new AuthHeaderSetting { Scope = "c.test", Name = "Cookie", Secret = "garbage" },
                new AuthHeaderSetting { Scope = "http://bad", Name = "Cookie", Secret = blob },
            ],
        };
        var resolved = s.ResolveAuthHeaders();
        c.Check("only usable entries are resolved", resolved.Count == 1 && resolved[0].Scope == "a.test", $"{resolved.Count}");
        c.Equal("auth reaches scan options", 1, ScanOptions.From(s, 1, 4).Auth.Count);
        s.UseAuthentication = false;
        c.Equal("switching it off sends nothing", 0, ScanOptions.From(s, 1, 4).Auth.Count);
    }

    private static async Task LiveChecks(CheckContext c)
    {
        using var site = TestSite.TryStartAny();
        if (!c.Check("local test server available", site != null)) return;
        string dir = Path.Combine(c.TempDir, "auth-rules");
        Directory.CreateDirectory(dir);
        await File.WriteAllTextAsync(Path.Combine(dir, "account.json"), """
        {"id":"account-page","name":"Account page reachable","description":"test","remediation":"test","path":"/account","statuses":[200],"bodyContains":"Account dashboard"}
        """);
        var svc = new OpenService { Host = new LiveHost { Address = IPAddress.Loopback, Hostname = "127.0.0.1" }, Port = site!.Port, Http = true };

        async Task<(ScanContext Ctx, List<ScanEvent> Events)> Run(IReadOnlyList<AuthHeader> auth)
        {
            var channel = Channel.CreateUnbounded<ScanEvent>();
            var opts = new ScanOptions { Threads = 2, UseCustomRules = true, RulesDirectory = dir, MaxRequestsPerSecond = 1000, Auth = auth };
            var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, opts), channel.Writer, CancellationToken.None);
            await DetectionRules.LoadAsync(ctx);
            await DetectionRules.RunHttpRulesAsync(ctx, svc);
            channel.Writer.TryComplete();
            var events = new List<ScanEvent>();
            await foreach (var e in channel.Reader.ReadAllAsync()) events.Add(e);
            return (ctx, events);
        }

        string cookie = "tryz_session=" + TestSite.Credential;
        var (anon, _) = await Run(Array.Empty<AuthHeader>());
        c.Equal("anonymous scan can't see the account page", 0, anon.FindingCount);
        anon.Dispose();

        int before = site.AuthenticatedRequests;
        var (authed, _) = await Run([new AuthHeader($"127.0.0.1:{site.Port}", "Cookie", cookie)]);
        c.Equal("cookie unlocks the account page", 1, authed.FindingCount);
        c.Check("site saw the credential", site.AuthenticatedRequests > before);
        authed.Dispose();

        var (bearer, _) = await Run([new AuthHeader("127.0.0.1", "Authorization", "Bearer " + TestSite.Credential)]);
        c.Equal("bearer token works without a port", 1, bearer.FindingCount);
        bearer.Dispose();

        before = site.AuthenticatedRequests;
        var (wrongPort, _) = await Run([new AuthHeader($"127.0.0.1:{(site.Port == 65535 ? 1 : site.Port + 1)}", "Cookie", cookie)]);
        c.Check("other port's credential is never sent", wrongPort.FindingCount == 0 && site.AuthenticatedRequests == before);
        wrongPort.Dispose();

        var (otherHost, _) = await Run([new AuthHeader("intranet.example", "Cookie", cookie)]);
        c.Check("other host's credential is never sent", otherHost.FindingCount == 0 && site.AuthenticatedRequests == before);

        // Anything the engine stores passes through redaction.
        otherHost.Dispose();
        var channel = Channel.CreateUnbounded<ScanEvent>();
        using var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 2,
            new ScanOptions { Threads = 2, MaxRequestsPerSecond = 1000, Auth = [new AuthHeader("127.0.0.1", "Cookie", "tryz_session=wrong-session-1")] }), channel.Writer, CancellationToken.None);
        ctx.AddFinding(Severity.Low, "Echo", "127.0.0.1", site.Port, 200, "Reflected tryz_session=wrong-session-1", "Set-Cookie: tryz_session=wrong-session-1", "Fix.");
        var stored = ctx.FindingsSnapshot().Single();
        c.Check("evidence never stores the credential", !stored.Evidence.Contains("wrong-session-1") && !stored.Description.Contains("wrong-session-1"));

        for (int i = 0; i < 12; i++)
        {
            using var resp = await ctx.Http.GetAsync(new Uri($"http://127.0.0.1:{site.Port}/account"));
            c.Check($"stale cookie gets 401 ({i})", resp.StatusCode == HttpStatusCode.Unauthorized);
        }
        channel.Writer.TryComplete();
        var warnings = new List<string>();
        await foreach (var e in channel.Reader.ReadAllAsync())
            if (e is ScanLog { Source: "auth" } log) warnings.Add(log.Text);
        c.Equal("expired session warned once", 1, warnings.Count(w => w.Contains("expired")));
        var unusedChannel = Channel.CreateUnbounded<ScanEvent>();
        using (var unusedCtx = new ScanContext(new ScanRequest("127.0.0.1", 0, 1, new ScanOptions { Threads = 1, Auth = [new AuthHeader("typo.example", "Cookie", "a=bcde")] }), unusedChannel.Writer, CancellationToken.None))
        {
            unusedCtx.ReportUnusedAuth();
            unusedChannel.Writer.TryComplete();
            bool warned = false;
            await foreach (var e in unusedChannel.Reader.ReadAllAsync()) warned |= e is ScanLog { Source: "auth" } l && l.Text.Contains("typo.example") && l.Text.Contains("never sent");
            c.Check("scan end warns about a scope that matched nothing", warned);
        }
        using var follow = await ctx.HttpFollow.GetAsync(new Uri($"http://127.0.0.1:{site.Port}/account"));
        c.Check("redirect-following client never authenticates", follow.StatusCode == HttpStatusCode.Unauthorized);
    }
}
#endif
