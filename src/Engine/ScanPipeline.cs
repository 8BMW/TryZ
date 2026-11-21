using TryZ.Data;

namespace TryZ.Engine;

/// <summary>Runs the scan phases in order: discovery, port audit + service identification, vulnerability audit, crawl, report.</summary>
internal static class ScanPipeline
{
    public static async Task RunAsync(ScanContext ctx)
    {
        var o = ctx.Options;
        ctx.Log(LogLevel.Notice, "engine", $"Scan started: target {ctx.Request.Target}, profile {ScanOptions.ProfileNames[o.ProfileIndex]}, {o.Threads} workers, {o.MaxRequestsPerSecond} req/s limit");

        // ---------------------------------------------------------------- 1. targets + discovery
        ctx.ResetPhase(ScanContext.PhaseDiscovery);
        // Excluded addresses are dropped (and user-supplied names pinned) while parsing, before discovery starts.
        var targets = await TargetParser.ParseAsync(ctx.Request.Target, ctx).ConfigureAwait(false);
        if (targets.Count == 0)
        {
            ctx.Log(LogLevel.Warn, "scope", "No addresses left to scan after parsing, resolution and exclusions");
            for (int i = 0; i < 5; i++) ctx.SetPhase(i, 1);
            return;
        }
        ctx.Log(LogLevel.Info, "discover", $"{targets.Count} address(es) in scope");
        if (ctx.Options.Auth.Count > 0)
        {
            // Names and scopes only; values never reach the log.
            string list = string.Join(", ", ctx.Options.Auth.Select(a => $"{a.Name} for {a.Scope}").Distinct(StringComparer.OrdinalIgnoreCase));
            ctx.Log(LogLevel.Notice, "auth", $"Authenticated scan: {list}. Logout, sign-out and delete links are never followed.");
        }
        foreach (var t in targets)
        {
            if (t.Hostname.Length > 0) ctx.NoteHostname(t.Hostname);
            foreach (var alias in t.Aliases) ctx.NoteHostname(alias.Name);
        }
        await DetectionRules.LoadAsync(ctx).ConfigureAwait(false);
        var hosts = await HostDiscovery.RunAsync(ctx, targets).ConfigureAwait(false);
        ctx.SetPhase(ScanContext.PhaseDiscovery, 1);
        ctx.Log(LogLevel.Ok, "discover", $"Discovery finished: {hosts.Count} of {targets.Count} host(s) up");

        // ---------------------------------------------------------------- 2. ports + services
        ctx.ResetPhase(ScanContext.PhasePorts);
        var ports = PortLists.For(o);
        var services = new List<OpenService>();
        var servicesLock = new object();
        int hostsDone = 0;
        await Parallel.ForEachAsync(hosts, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(o.Threads / 8, 1, 16), CancellationToken = ctx.Token },
            async (host, _) =>
            {
                int task = ctx.AddTask($"Port sweep {host.Ip}", "Port Audit");
                ctx.UpdateTask(task, TaskState.Running, 0);
                ctx.Emit(new HostStateChanged(host.Ip, "Scanning"));
                ctx.Log(LogLevel.Info, "portaudit", $"TCP connect sweep started on {host.Ip} ({ports.Count} ports)");
                var open = await PortScanner.ScanAsync(ctx, host, ports, task).ConfigureAwait(false);
                var found = new List<OpenService>();
                var foundLock = new object();
                // Silent ports can take several seconds each (greeting wait, TLS and HTTP attempts), so identify in parallel.
                await Parallel.ForEachAsync(open, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(o.Threads / 4, 1, 16), CancellationToken = ctx.Token },
                    async (port, _) =>
                {
                    var svc = await ServiceProbe.IdentifyAsync(ctx, host, port).ConfigureAwait(false);
                    var risk = VulnRules.Evaluate(ctx, svc);
                    ctx.Emit(new PortFound(new PortRecord
                    {
                        HostIp = host.Ip,
                        Port = port,
                        Proto = "tcp",
                        State = "open",
                        Service = svc.Service,
                        Banner = svc.DisplayBanner,
                        Risk = risk,
                    }));
                    var level = risk >= Severity.High ? LogLevel.Warn : LogLevel.Info;
                    ctx.Log(level, "portaudit", $"open {port}/tcp on {host.Ip} ({svc.Service}) {svc.DisplayBanner}".TrimEnd());
                    lock (foundLock) found.Add(svc);
                }).ConfigureAwait(false);
                ctx.UpdateTask(task, TaskState.Done, 100);
                if (o.RunUdpScan)
                {
                    int udpTask = ctx.AddTask($"UDP probes {host.Ip}", "Port Audit");
                    ctx.UpdateTask(udpTask, TaskState.Running, 0);
                    found.AddRange(await UdpScanner.ScanAsync(ctx, host, udpTask).ConfigureAwait(false));
                    ctx.UpdateTask(udpTask, TaskState.Done, 100);
                }
                found.Sort((a, b) => a.Port != b.Port ? a.Port.CompareTo(b.Port) : string.CompareOrdinal(a.Proto, b.Proto));
                lock (servicesLock) services.AddRange(found);
                ctx.Emit(new HostStateChanged(host.Ip, "Audited"));
                ctx.Log(LogLevel.Ok, "portaudit", $"Sweep finished on {host.Ip}: {open.Count} open port(s)");
                ctx.SetPhase(ScanContext.PhasePorts, Interlocked.Increment(ref hostsDone) / (double)Math.Max(1, hosts.Count));
            }).ConfigureAwait(false);
        ctx.SetPhase(ScanContext.PhasePorts, 1);

        // ---------------------------------------------------------------- 3. vulnerability audit (TLS, HTTP, CVE lookup)
        ctx.ResetPhase(ScanContext.PhaseAudit);
        var webRoots = new List<Uri>();
        var rootsLock = new object();
        var auditable = services.Where(s => s.Tls || s.Http).ToList();
        int audited = 0;
        await Parallel.ForEachAsync(auditable, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(o.Threads / 4, 1, 16), CancellationToken = ctx.Token },
            async (svc, _) =>
            {
                int task = ctx.AddTask($"Audit checks {svc.Host.Ip}:{svc.Port}", "Vulnerability Audit");
                ctx.UpdateTask(task, TaskState.Running, 0);
                if (svc.Tls && o.RunTlsChecks) await TlsAudit.AuditAsync(ctx, svc).ConfigureAwait(false);
                ctx.UpdateTask(task, TaskState.Running, 40);
                if (svc.Http && o.RunWebChecks)
                {
                    var root = await HttpAudit.AuditAsync(ctx, svc).ConfigureAwait(false);
                    if (root != null) lock (rootsLock) webRoots.Add(root);
                    await DetectionRules.RunHttpRulesAsync(ctx, svc).ConfigureAwait(false);
                    // Other names / start URLs the user gave for this address are separate virtual hosts.
                    foreach (var alias in svc.Host.Aliases)
                    {
                        var vhost = ForAlias(svc, alias);
                        if (vhost is null) continue;
                        var aliasRoot = await HttpAudit.AuditAsync(ctx, vhost).ConfigureAwait(false);
                        if (aliasRoot != null) lock (rootsLock) webRoots.Add(aliasRoot);
                        await DetectionRules.RunHttpRulesAsync(ctx, vhost).ConfigureAwait(false);
                    }
                }
                ctx.UpdateTask(task, TaskState.Done, 100);
                ctx.SetPhase(ScanContext.PhaseAudit, 0.8 * Interlocked.Increment(ref audited) / Math.Max(1, auditable.Count));
            }).ConfigureAwait(false);

        if (o.EnableNvd && services.Count > 0)
        {
            int task = ctx.AddTask("NVD CVE lookup", "Vulnerability Audit");
            ctx.UpdateTask(task, TaskState.Running, 0);
            await NvdClient.LookupAsync(ctx, services).ConfigureAwait(false);
            ctx.UpdateTask(task, TaskState.Done, 100);
        }
        ctx.SetPhase(ScanContext.PhaseAudit, 1);

        // ---------------------------------------------------------------- 4. crawl
        ctx.ResetPhase(ScanContext.PhaseCrawl);
        if (o.RunCrawler && webRoots.Count > 0)
            await Crawler.RunAsync(ctx, webRoots.Distinct().ToList()).ConfigureAwait(false);
        else
            ctx.Log(LogLevel.Info, "crawler", "No web service found; crawl skipped");
        if (o.CheckTakeover)
        {
            int task = ctx.AddTask("Dangling DNS check", "Web Crawler");
            ctx.UpdateTask(task, TaskState.Running, 0);
            await TakeoverCheck.RunAsync(ctx, task).ConfigureAwait(false);
            ctx.UpdateTask(task, TaskState.Done, 100);
        }
        ctx.SetPhase(ScanContext.PhaseCrawl, 1);

        // Exploitation data is looked up once every check (including crawl-time ones) has reported.
        if (o.EnableThreatIntel && ctx.FindingsSnapshot().Any(f => f.Cves.Count > 0))
        {
            int task = ctx.AddTask("CISA KEV / EPSS enrichment", "Vulnerability Audit");
            ctx.UpdateTask(task, TaskState.Running, 0);
            await ThreatIntel.EnrichAsync(ctx).ConfigureAwait(false);
            ctx.UpdateTask(task, TaskState.Done, 100);
        }

        // ---------------------------------------------------------------- 5. report
        ctx.ResetPhase(ScanContext.PhaseReport);
        int report = ctx.AddTask("Assemble session summary", "Reports");
        ctx.UpdateTask(report, TaskState.Done, 100);
        ctx.SetPhase(ScanContext.PhaseReport, 1);
        ctx.Log(LogLevel.Ok, "engine", $"Scan finished in {ctx.ElapsedSeconds:0.0} s: {hosts.Count} host(s), {services.Count} open service(s), {ctx.FindingCount} finding(s)");
    }

    /// <summary>
    /// A view of a web service under one of its host's alias names (virtual host), or null when the alias adds nothing
    /// for this port (its start URL points at another port or scheme).
    /// </summary>
    private static OpenService? ForAlias(OpenService svc, HostAlias alias)
    {
        string name = alias.Name.Length > 0 ? alias.Name : svc.Host.Hostname;
        var seed = alias.SeedUrl;
        if (seed != null && (seed.Port != svc.Port || !seed.Scheme.Equals(svc.Scheme, StringComparison.OrdinalIgnoreCase))) seed = null;
        if (seed is null && name.Equals(svc.Host.Hostname, StringComparison.OrdinalIgnoreCase)) return null;
        var host = new LiveHost
        {
            Address = svc.Host.Address,
            Hostname = name,
            SeedUrl = seed,
            LatencyMs = svc.Host.LatencyMs,
            Ttl = svc.Host.Ttl,
            OsGuess = svc.Host.OsGuess,
        };
        var copy = new OpenService
        {
            Host = host,
            Port = svc.Port,
            Service = svc.Service,
            Product = svc.Product,
            Version = svc.Version,
            Banner = svc.Banner,
            Tls = svc.Tls,
            Http = svc.Http,
        };
        foreach (var fact in svc.Facts) copy.Facts[fact.Key] = fact.Value;
        return copy;
    }
}
