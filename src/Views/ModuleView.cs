using TryZ.Data;

namespace TryZ.Views;

internal enum ExportFormat { Html, Csv }

internal interface IShell
{
    Session Session { get; }
    AppSettings Settings { get; }
    void ExportReport(ExportFormat format);
    void UseCustomProfile();
    void Notify(string title, string text, IconId icon = IconId.InfoMark);
    void NavigateTo(int module);
    void OpenInWorkbench(string method, string url);
    void SelectHostInPortAudit(string ip);
    void LogUser(string source, string text);
}

internal abstract class ModuleView : SkinControl
{
    protected ModuleView(IShell shell)
    {
        Shell = shell;
    }

    protected IShell Shell { get; }
    protected Session Session => Shell.Session;

    public abstract string Title { get; }
    public abstract IconId IconKind { get; }
    public virtual string Subtitle => string.Empty;

    protected int HeaderHeight => Px(24);
    protected Rectangle Body => Rectangle.FromLTRB(Px(5), HeaderHeight + Px(5), Width - Px(6), Height - Px(5));

    public abstract void SyncData();
    public virtual void PrepareForCapture() { }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var r = new Rectangle(0, 0, Width, HeaderHeight);
        Draw.Gradient(g, r, Theme.Hex(0x34383D), Theme.Hex(0x282B2F));
        g.DrawLine(Draw.Pen(Theme.Hex(0x44484E)), 0, 0, Width, 0);
        g.DrawLine(Draw.Pen(Theme.BorderDark), 0, r.Bottom - 1, Width, r.Bottom - 1);
        int s = Px(16);
        g.DrawImage(Icons.Get(IconKind, s), Px(6), (r.Height - s) / 2, s, s);
        int tw = Draw.Measure(Title, BoldFont);
        Draw.Engraved(g, Title, BoldFont, new Rectangle(Px(27), 0, tw + 2, r.Height), Theme.TextBright);
        string sub = Subtitle;
        if (sub.Length > 0)
        {
            int x = Px(27) + tw + Px(10);
            Draw.Text(g, sub, UiFont, new Rectangle(x, 0, Math.Max(0, Width - x - Px(8)), r.Height), Theme.TextDim, TextFormatFlags.Right);
        }
    }
}

internal static class Schemas
{
    public static RowSet<HostRecord> Hosts(RowStore<HostRecord> store) => new(store,
        new Col<HostRecord>("IP Address", 104, h => h.Ip) { Compare = (a, b) => IpKey(a.Ip).CompareTo(IpKey(b.Ip)), Mono = true },
        new Col<HostRecord>("Hostname", 148, h => h.Hostname),
        new Col<HostRecord>("OS Guess", 164, h => h.OsGuess),
        new Col<HostRecord>("Open Ports", 78, h => h.OpenPorts.ToString()) { Compare = (a, b) => a.OpenPorts.CompareTo(b.OpenPorts), Align = HorizontalAlignment.Right, Mono = true },
        new Col<HostRecord>("Latency", 60, h => h.LatencyText) { Compare = (a, b) => a.LatencyMs.CompareTo(b.LatencyMs), Align = HorizontalAlignment.Right, Mono = true },
        new Col<HostRecord>("State", 70, h => h.State) { Color = h => HostStateColor(h.State) });

    public static RowSet<HostRecord> HostsCompact(RowStore<HostRecord> store) => new(store,
        new Col<HostRecord>("Host", 100, h => h.Ip) { Compare = (a, b) => IpKey(a.Ip).CompareTo(IpKey(b.Ip)), Mono = true },
        new Col<HostRecord>("Open", 40, h => h.OpenPorts.ToString()) { Compare = (a, b) => a.OpenPorts.CompareTo(b.OpenPorts), Align = HorizontalAlignment.Right, Mono = true });

    public static RowSet<PortRecord> Ports(RowStore<PortRecord> store) => new(store,
        new Col<PortRecord>("Port", 52, p => p.Port.ToString()) { Compare = (a, b) => a.Port.CompareTo(b.Port), Align = HorizontalAlignment.Right, Mono = true },
        new Col<PortRecord>("Proto", 42, p => p.Proto),
        new Col<PortRecord>("State", 56, p => p.State) { Color = p => p.State == "open" ? Theme.Ok : Theme.TextDim },
        new Col<PortRecord>("Service", 92, p => p.Service),
        new Col<PortRecord>("Banner", 250, p => p.Banner) { Mono = true },
        new Col<PortRecord>("Risk", 76, p => p.Risk.ToString(), CellKind.Severity) { Compare = (a, b) => a.Risk.CompareTo(b.Risk), Color = p => Theme.SeverityColor(p.Risk) });

    public static RowSet<Finding> Findings(RowStore<Finding> store) => new(store,
        new Col<Finding>("Severity", 78, f => f.Severity.ToString(), CellKind.Severity) { Compare = (a, b) => a.Severity.CompareTo(b.Severity), Color = f => Theme.SeverityColor(f.Severity) },
        new Col<Finding>("Title", 280, f => f.Title),
        new Col<Finding>("Host", 104, f => f.Host) { Compare = (a, b) => IpKey(a.Host).CompareTo(IpKey(b.Host)), Mono = true },
        new Col<Finding>("Port", 46, f => f.Port.ToString()) { Compare = (a, b) => a.Port.CompareTo(b.Port), Align = HorizontalAlignment.Right, Mono = true },
        new Col<Finding>("CWE", 70, f => f.CweText) { Compare = (a, b) => a.Cwe.CompareTo(b.Cwe), Mono = true },
        new Col<Finding>("Status", 86, f => f.StatusText) { Color = f => f.Status switch
        {
            FindingStatus.Confirmed => Theme.Critical,
            FindingStatus.FalsePositive => Theme.TextDim,
            FindingStatus.Accepted => Theme.Low,
            _ => Theme.Brass,
        } });

    public static RowSet<UrlRecord> Urls(RowStore<UrlRecord> store) => new(store,
        new Col<UrlRecord>("URL", 340, u => u.Url),
        new Col<UrlRecord>("Method", 60, u => u.Method) { Mono = true },
        new Col<UrlRecord>("Status", 48, u => u.StatusText) { Compare = (a, b) => a.Status.CompareTo(b.Status), Align = HorizontalAlignment.Right, Mono = true, Color = u => StatusColor(u.Status) },
        new Col<UrlRecord>("Type", 124, u => u.ContentType),
        new Col<UrlRecord>("Size", 66, u => u.SizeText) { Compare = (a, b) => a.Size.CompareTo(b.Size), Align = HorizontalAlignment.Right, Mono = true },
        new Col<UrlRecord>("Time", 58, u => u.TimeText) { Compare = (a, b) => a.TimeMs.CompareTo(b.TimeMs), Align = HorizontalAlignment.Right, Mono = true });

    public static RowSet<TaskItem> Tasks(RowStore<TaskItem> store) => new(store,
        new Col<TaskItem>("#", 34, t => t.Id.ToString()) { Compare = (a, b) => a.Id.CompareTo(b.Id), Align = HorizontalAlignment.Right, Mono = true },
        new Col<TaskItem>("Task", 250, t => t.Title),
        new Col<TaskItem>("Module", 124, t => t.Module),
        new Col<TaskItem>("State", 70, t => t.StateText) { Color = t => t.State switch
        {
            TaskState.Running => Theme.Brass,
            TaskState.Done => Theme.Ok,
            TaskState.Cancelled => Theme.Critical,
            _ => Theme.TextDim,
        } },
        new Col<TaskItem>("Progress", 150, t => t.Progress + "%", CellKind.Bar) { Compare = (a, b) => a.Progress.CompareTo(b.Progress), Bar = t => t.Progress, Color = t => t.State == TaskState.Done ? Theme.Ok : Theme.Brass });

    public static Color? HostStateColor(string state) => state switch
    {
        "Scanning" => Theme.Brass,
        "Audited" => Theme.Ok,
        _ => Theme.Text,
    };

    public static Color StatusColor(int status) => status switch
    {
        >= 500 => Theme.Critical,
        >= 400 => Theme.High,
        >= 300 => Theme.Low,
        _ => Theme.Ok,
    };

    public static uint IpKey(string ip)
    {
        uint key = 0;
        foreach (var part in ip.Split('.'))
            key = key << 8 | (byte.TryParse(part, out byte b) ? b : (byte)0);
        return key;
    }
}
