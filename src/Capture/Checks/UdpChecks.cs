#if DEBUG
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;
using TryZ.Engine;

namespace TryZ.Capture.Checks;

internal sealed class UdpChecks : ICheckSuite
{
    public string Name => "udp";
    public async Task RunAsync(CheckContext c)
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        int port = ((IPEndPoint)server.Client.LocalEndPoint!).Port;
        var opts = new ScanOptions { Threads = 2, Retries = 0, ReadTimeoutMs = 250, MaxRequestsPerSecond = 1000 };
        using var ctx = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, opts), Channel.CreateUnbounded<ScanEvent>().Writer, CancellationToken.None);
        var pending = UdpScanner.ProbeDnsForTestAsync(ctx, IPAddress.Loopback, port);
        var request = await server.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));
        byte[] response = (byte[])request.Buffer.Clone();
        response[2] |= 0x80;
        await server.SendAsync(response, request.RemoteEndPoint);
        c.Check("matching DNS response opens port", await pending);

        pending = UdpScanner.ProbeDnsForTestAsync(ctx, IPAddress.Loopback, port);
        request = await server.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(3));
        response = (byte[])request.Buffer.Clone();
        response[0] ^= 0xff;
        response[2] |= 0x80;
        await server.SendAsync(response, request.RemoteEndPoint);
        c.Check("unrelated response is not open", !await pending);

        using var cancel = new CancellationTokenSource();
        using var cancelledContext = new ScanContext(new ScanRequest("127.0.0.1", 0, 2, opts), Channel.CreateUnbounded<ScanEvent>().Writer, cancel.Token);
        cancel.Cancel();
        bool stopped = false;
        try { await UdpScanner.ProbeDnsForTestAsync(cancelledContext, IPAddress.Loopback, port); }
        catch (OperationCanceledException) { stopped = true; }
        c.Check("cancelled scan stops", stopped);
    }
}
#endif
