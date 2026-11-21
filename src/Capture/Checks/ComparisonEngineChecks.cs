#if DEBUG
using TryZ.Data;

namespace TryZ.Capture.Checks;

internal sealed class ComparisonEngineChecks : ICheckSuite
{
    public string Name => "comparison";
    public Task RunAsync(CheckContext c)
    {
        var old = new SessionFile { Findings = [
            F("ssh.old", "Old SSH", "HostA", 22, Severity.High),
            F("same", "Repeated finding", "HostA", 80, Severity.Low),
            F("same", "Repeated finding", "HostA", 80, Severity.High),
            F("changed", "Changed finding", "HostA", 443, Severity.Low),
        ], Ports = [ P("HostA", 22, "tcp", "ssh", "old"), P("HostA", 53, "udp", "dns", "") ] };
        var current = new SessionFile { Findings = [
            F("same", "Repeated finding", "hosta", 80, Severity.High),
            F("same", "Repeated finding", "HOSTA", 80, Severity.Low),
            F("same", "Repeated finding", "hosta", 80, Severity.Medium),
            F("changed", "Changed finding", "hosta", 443, Severity.High),
            F("new", "New finding", "hosta", 443, Severity.Low),
        ], Ports = [ P("hosta", 22, "tcp", "ssh", "new"), P("hosta", 53, "tcp", "dns", "") ] };
        var rows = ScanComparison.Build(old, current);
        c.Equal("duplicate observations survive", 3, rows.Count(r => r.Name == "Repeated finding"));
        c.Equal("reordered duplicates unchanged", 2, rows.Count(r => r.Name == "Repeated finding" && r.Change == "Unchanged"));
        c.Equal("extra duplicate is new", 1, rows.Count(r => r.Name == "Repeated finding" && r.Change == "New"));
        c.Check("severity change matched", rows.Any(r => r.Name == "Changed finding" && r.Change == "Changed"));
        c.Check("missing finding is not claimed fixed", rows.Any(r => r.Name == "Old SSH" && r.Change == "Not observed"));
        c.Check("new finding detected", rows.Any(r => r.Name == "New finding" && r.Change == "New"));
        c.Check("service banner changes", rows.Any(r => r.Kind == "Service" && r.Endpoint == "22/tcp" && r.Change == "Changed"));
        c.Check("different protocols not conflated", rows.Any(r => r.Endpoint == "53/udp" && r.Change == "Not observed") && rows.Any(r => r.Endpoint == "53/tcp" && r.Change == "New"));
        var legacy = new SessionFile { Findings = [ F("", "Old style finding", "hosta", 80, Severity.Low) ] };
        var modern = new SessionFile { Findings = [ F("old-style-finding", "Old style finding", "HOSTA", 80, Severity.Low) ] };
        c.Check("legacy title uses generated rule identity", ScanComparison.Build(legacy, modern).Single().Change == "Unchanged");
        modern.Findings[0].RuleId = "custom.unrelated-id";
        c.Check("legacy exact title resolves explicit modern identity", ScanComparison.Build(legacy, modern).Single().Change == "Unchanged");
        c.Equal("empty comparison", 0, ScanComparison.Build(new SessionFile(), new SessionFile()).Count);
        return Task.CompletedTask;
    }
    private static FindingDto F(string rule, string title, string host, int port, Severity severity) => new() { RuleId = rule, Title = title, Host = host, Port = port, Proto = "tcp", Severity = severity };
    private static PortDto P(string host, int port, string proto, string service, string banner) => new() { HostIp = host, Port = port, Proto = proto, State = "open", Service = service, Banner = banner };
}
#endif
