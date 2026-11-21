#if DEBUG
using System.Text;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

internal sealed class UdpResponseChecks : ICheckSuite
{
    public string Name => "udp-responses";
    public Task RunAsync(CheckContext c)
    {
        var dns = UdpScanner.ProbeForTest("dns");
        var dnsResponse = (byte[])dns.Request.Clone(); dnsResponse[2] |= 0x80;
        c.Check("DNS question and ID match", dns.Matches(dnsResponse));
        dnsResponse[15] ^= 1;
        c.Check("DNS rejects different question", !dns.Matches(dnsResponse));
        var ntp = UdpScanner.ProbeForTest("ntp");
        var ntpResponse = new byte[48]; ntpResponse[0] = 0x24;
        ntp.Request.AsSpan(40, 8).CopyTo(ntpResponse.AsSpan(24, 8));
        c.Check("NTP reply echoes timestamp", ntp.Matches(ntpResponse));
        ntpResponse[24] ^= 1;
        c.Check("NTP rejects unrelated reply", !ntp.Matches(ntpResponse));
        var netbios = UdpScanner.ProbeForTest("netbios-ns");
        var nbResponse = netbios.Request.ToList(); nbResponse[2] |= 0x80; nbResponse[7] = 1;
        nbResponse.AddRange([0xc0, 0x0c, 0, 0x21, 0, 1, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]);
        c.Check("NetBIOS node-status answer identified", netbios.Matches(nbResponse.ToArray()));
        nbResponse[netbios.Request.Length + 3] = 1;
        c.Check("NetBIOS rejects unrelated answer type", !netbios.Matches(nbResponse.ToArray()));
        var snmp = UdpScanner.ProbeForTest("snmp");
        var snmpResponse = (byte[])snmp.Request.Clone(); snmpResponse[13] = 0xa2;
        c.Check("SNMP response is structured and correlated", snmp.Matches(snmpResponse));
        var otherId = (byte[])snmpResponse.Clone(); otherId[18] ^= 1;
        c.Check("SNMP rejects wrong request ID", !snmp.Matches(otherId));
        var malformed = (byte[])snmpResponse.Clone(); malformed[1] = 1;
        c.Check("SNMP rejects malformed BER containing matching bytes", !snmp.Matches(malformed));
        c.Check("SNMP rejects truncated reply", !snmp.Matches(snmpResponse[..^1]));
        var ssdp = UdpScanner.ProbeForTest("ssdp");
        c.Check("SSDP identifies valid reply", ssdp.Matches(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nST: upnp:rootdevice\r\n\r\n")));
        c.Check("SSDP rejects status 2000", !ssdp.Matches(Encoding.ASCII.GetBytes("HTTP/1.1 2000 OK\r\nST: x\r\n\r\n")));
        c.Check("SSDP requires discovery header", !ssdp.Matches(Encoding.ASCII.GetBytes("HTTP/1.1 200 OK\r\nServer: web\r\n\r\n")));
        return Task.CompletedTask;
    }
}
#endif
