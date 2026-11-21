using System.Net.NetworkInformation;
using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Shell;

internal class SkinDialog : FrameForm
{
    private readonly List<SkinButton> _buttons = new();

    protected SkinDialog(string title, int logicalWidth, int logicalHeight) : base(false, false)
    {
        Caption.Title = title;
        LogicalClient = new Size(logicalWidth, logicalHeight);
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        Size = new Size(Px(logicalWidth), Px(logicalHeight));
    }

    protected Size LogicalClient { get; }

    protected Rectangle DialogBody
    {
        get
        {
            var c = ContentBounds;
            return Rectangle.FromLTRB(c.Left, c.Top, c.Right, c.Bottom - (_buttons.Count > 0 ? Px(38) : 0));
        }
    }

    protected SkinButton AddButton(string caption, DialogResult result, bool isDefault = false, bool isCancel = false)
    {
        var b = new SkinButton(caption) { DialogResult = result, BackColor = Theme.Hex(0x212327) };
        _buttons.Add(b);
        Controls.Add(b);
        if (isDefault) AcceptButton = b;
        if (isCancel) CancelButton = b;
        return b;
    }

    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        Size = new Size(Px(LogicalClient.Width), Px(LogicalClient.Height));
        if (Owner != null && Theme.DpiOverride != null)
            Location = new Point(Owner.Left + (Owner.Width - Width) / 2, Owner.Top + (Owner.Height - Height) / 2);
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var c = ContentBounds;
        int w = Px(78), h = Px(22);
        int x = c.Right - Px(9) - w;
        int y = c.Bottom - Px(8) - h;
        for (int i = _buttons.Count - 1; i >= 0; i--)
        {
            _buttons[i].SetBounds(x, y, w, h);
            x -= w + Px(6);
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var g = e.Graphics;
        var c = ContentBounds;
        Draw.Fill(g, c, Theme.Panel);
        if (_buttons.Count > 0)
        {
            var strip = Rectangle.FromLTRB(c.Left, c.Bottom - Px(38), c.Right, c.Bottom);
            Draw.Gradient(g, strip, Theme.Hex(0x282B2F), Theme.Hex(0x1F2125));
            Draw.EtchH(g, strip.Left, strip.Right, strip.Top);
        }
    }
}

internal sealed class MessageDialog : SkinDialog
{
    private readonly IconBox _icon;
    private readonly SkinLabel _label;

    private MessageDialog(string title, string text, IconId icon, bool yesNo) : base(title, 400, 150)
    {
        BackColor = Theme.Window;
        _icon = new IconBox(icon, 32);
        _label = new SkinLabel(text) { Wrap = true };
        Controls.Add(_icon);
        Controls.Add(_label);
        if (yesNo)
        {
            AddButton("Yes", DialogResult.Yes, isDefault: true);
            AddButton("No", DialogResult.No, isCancel: true);
        }
        else
        {
            var ok = AddButton("OK", DialogResult.OK, isDefault: true, isCancel: true);
            ok.TabIndex = 0;
        }
    }

    public static void Show(IWin32Window? owner, string title, string text, IconId icon = IconId.InfoMark)
    {
        using var dlg = new MessageDialog(title, text, icon, false);
        dlg.ShowDialog(owner);
    }

    public static bool Ask(IWin32Window? owner, string title, string text)
    {
        using var dlg = new MessageDialog(title, text, IconId.Warning, true);
        return dlg.ShowDialog(owner) == DialogResult.Yes;
    }

#if DEBUG
    public static MessageDialog ForCapture(string title, string text, IconId icon) => new(title, text, icon, false);
#endif

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        if (_icon == null) return;
        var body = DialogBody;
        _icon.SetBounds(body.X + Px(14), body.Y + Px(14), Px(36), Px(36));
        _label.SetBounds(body.X + Px(60), body.Y + Px(16), body.Width - Px(74), body.Height - Px(20));
    }
}

/// <summary>
/// Shown before the first scan of a target that is not on the authorized list. The user must confirm
/// ownership or written permission before the scan starts.
/// </summary>
internal sealed class AuthorizationDialog : SkinDialog
{
    private readonly IconBox _icon = new(IconId.Warning, 32);
    private readonly SkinLabel _heading = new("Confirm authorization", true) { TextColor = Theme.Brass };
    private readonly SkinLabel _text = new(
        "TryZ will send live network traffic to the target below: ping and TCP connection probes, service banner reads, " +
        "TLS handshakes and HTTP requests, and it will crawl any web site it finds. Scanning systems without the owner's " +
        "permission may be illegal in your country and may violate provider terms of service.") { Wrap = true };
    private readonly SkinLabel _targetCaption = new("Target") { TextColor = Theme.TextDim };
    private readonly SkinLabel _target;
    private readonly SkinCheck _confirm = new("I own this target or have written authorization to test it");
    private readonly SkinButton _start;

    public AuthorizationDialog(string target) : base("Authorization Required", 500, 290)
    {
        _target = new SkinLabel(target) { Mono = true, TextColor = Theme.TextBright, BackColor = Theme.Inset };
        Controls.AddRange(new Control[] { _icon, _heading, _text, _targetCaption, _target, _confirm });
        _start = AddButton("Start scan", DialogResult.OK, isDefault: true);
        AddButton("Cancel", DialogResult.Cancel, isCancel: true);
        _start.Enabled = false;
        _confirm.CheckedChanged += (_, _) => _start.Enabled = _confirm.Checked;
    }

#if DEBUG
    public SkinCheck ConfirmBox => _confirm;
    public SkinButton StartButton => _start;
#endif

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        _confirm.Focus();
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        if (_target == null) return;
        var b = DialogBody;
        _icon.SetBounds(b.X + Px(14), b.Y + Px(14), Px(36), Px(36));
        int x = b.X + Px(60), w = b.Right - x - Px(14);
        _heading.SetBounds(x, b.Y + Px(14), w, Px(17));
        int textH = Math.Max(Px(60), _text.WrappedHeight(w) + Px(4));
        _text.SetBounds(x, b.Y + Px(36), w, textH);
        int y = b.Y + Px(40) + textH;
        _targetCaption.SetBounds(x, y, Px(44), Px(20));
        _target.SetBounds(x + Px(46), y, w - Px(46), Px(20));
        _confirm.SetBounds(x, y + Px(30), w, Px(18));
    }
}

internal sealed class AboutDialog : SkinDialog
{
    private readonly LogoPane _logo = new();
    private readonly SkinLabel _name = new("TryZ Security Suite", true) { TextColor = Theme.Brass };
    private readonly SkinLabel _version = new($"Version {Application.ProductVersion.Split('+')[0]}, {(Environment.Is64BitProcess ? "64" : "32")}-bit") { TextColor = Theme.TextDim };
    private readonly SkinLabel _notice = new("Network security assessment for systems you are authorized to test.");
    private readonly SkinLabel _detail = new(
        "The built-in engine performs live network probes: host discovery (ICMP echo and TCP), TCP connect port scans, " +
        "service and banner identification, TLS certificate and protocol checks, HTTP security header and exposure checks, " +
        "web crawling and optional CVE lookups against the NIST NVD. It sends real traffic to the targets you enter. " +
        "Use it only on systems you own or have written permission to assess.") { Wrap = true, TextColor = Theme.TextDim };
    private readonly PropertySheet _sheet = new() { KeyWidth = 76 };

    public AboutDialog() : base("About TryZ Security Suite", 560, 330)
    {
        Controls.Add(_logo);
        Controls.Add(_name);
        Controls.Add(_version);
        Controls.Add(_notice);
        Controls.Add(_detail);
        Controls.Add(_sheet);
        _sheet.SetRows(new List<(string, string, Color?)>
        {
            ("Runtime", $".NET {Environment.Version}", null),
            ("Process", Environment.Is64BitProcess ? "x64" : "x86", null),
            ("Engine", "TryZ engine 1.0 (live)", Theme.Ok),
            ("Settings", "%APPDATA%\\TryZ", null),
        });
        AddButton("Close", DialogResult.OK, isDefault: true, isCancel: true);
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = DialogBody;
        var size = LogoArt.SizeFor(Dpi);
        int logoW = size.Width + Px(10), logoH = size.Height + Px(10);
        _logo.SetBounds(b.X + Px(10), b.Y + Px(10), logoW, logoH);
        int x = _logo.Right + Px(12);
        int w = b.Right - x - Px(10);
        _name.SetBounds(x, b.Y + Px(11), w, Px(16));
        _version.SetBounds(x, b.Y + Px(27), w, Px(15));
        _notice.SetBounds(x, b.Y + Px(47), w, Px(15));
        _detail.SetBounds(x, b.Y + Px(66), w, Math.Max(Px(82), b.Bottom - b.Y - Px(76)));
        _sheet.SetBounds(b.X + Px(10), _logo.Bottom + Px(8), logoW, Math.Max(Px(20), b.Bottom - _logo.Bottom - Px(18)));
    }
}

internal sealed class LogoPane : SkinControl
{
    public LogoPane()
    {
        BackColor = Theme.Inset;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Draw.Sunken(e.Graphics, ClientRectangle, Theme.Hex(0x141517));
        var logo = LogoArt.Get(Dpi);
        e.Graphics.DrawImageUnscaled(logo, (Width - logo.Width) / 2, (Height - logo.Height) / 2);
    }
}

internal sealed class SplashForm : Form
{
    private readonly string[] _lines;
    private readonly Timer _timer = new() { Interval = 40 };
    private readonly DateTime _started = DateTime.UtcNow;
    private readonly int _durationMs;
    private double _progress;

    public SplashForm(int durationMs = 1000, double frozenProgress = -1)
    {
        _lines = BuildLines();
        _durationMs = durationMs;
        AutoScaleMode = AutoScaleMode.None;
        FormBorderStyle = FormBorderStyle.None;
        StartPosition = FormStartPosition.CenterScreen;
        ShowInTaskbar = false;
        BackColor = Theme.Window;
        DoubleBuffered = true;
        KeyPreview = true;
        Icon = FrameForm.AppIcon;
        int dpi = Theme.DpiOf(this);
        Size = new Size(Theme.Scale(420, dpi), Theme.Scale(190, dpi));
        Click += (_, _) => Close();
        KeyDown += (_, _) => Close();
        if (frozenProgress >= 0)
        {
            _progress = frozenProgress;
            return;
        }
        _timer.Tick += (_, _) =>
        {
            _progress = Math.Min(1, (DateTime.UtcNow - _started).TotalMilliseconds / _durationMs);
            Invalidate();
            if (_progress >= 1) Close();
        };
        _timer.Start();
    }

    /// <summary>Startup lines describing the actual environment the engine will run in.</summary>
    private static string[] BuildLines()
    {
        string adapters;
        try
        {
            var up = NetworkInterface.GetAllNetworkInterfaces()
                .Count(n => n.OperationalStatus == OperationalStatus.Up && n.NetworkInterfaceType != NetworkInterfaceType.Loopback);
            adapters = $"Network adapters up: {up}";
        }
        catch (NetworkInformationException)
        {
            adapters = "Network adapters: unavailable";
        }
        return new[]
        {
            $".NET runtime {Environment.Version}, {(Environment.Is64BitProcess ? "x64" : "x86")}",
            "Settings: %APPDATA%\\TryZ\\settings.json",
            adapters,
            "Scan engine: TCP, TLS, HTTP, DNS, ICMP",
            "Engine: ready",
        };
    }

    protected override bool ShowWithoutActivation => false;

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        int dpi = Theme.DpiOf(this);
        int P(float v) => Theme.Scale(v, dpi);
        var r = ClientRectangle;
        Draw.Gradient(g, r, Theme.Hex(0x2C2F33), Theme.Hex(0x17191C));
        Draw.Frame(g, r, Theme.BorderDark);
        Draw.Frame(g, Rectangle.Inflate(r, -1, -1), Theme.Hex(0x4A4F55));

        var logo = LogoArt.Get(dpi);
        var pane = new Rectangle(P(10), P(10), logo.Width + P(10), logo.Height + P(10));
        Draw.Sunken(g, pane, Theme.Hex(0x141517));
        g.DrawImageUnscaled(logo, pane.X + P(5), pane.Y + P(5));

        int x = pane.Right + P(12), w = r.Width - x - P(12);
        Draw.Engraved(g, "TryZ Security Suite", Theme.UiLarge(dpi), new Rectangle(x, P(12), w, P(24)), Theme.Brass);
        Draw.Text(g, "Network security assessment", Theme.Ui(dpi), new Rectangle(x, P(36), w, P(14)), Theme.TextDim);
        Draw.EtchH(g, x, x + w, P(54));

        int shown = Math.Min(_lines.Length, (int)(_progress * _lines.Length) + 1);
        var mono = Theme.MonoSmall(dpi);
        for (int i = 0; i < shown; i++)
        {
            bool last = i == shown - 1;
            Draw.Text(g, _lines[i], mono, new Rectangle(x, P(60) + i * P(14), w, P(14)), last ? Theme.Text : Theme.TextDim);
        }

        var bar = new Rectangle(x, pane.Bottom - P(13), w, P(13));
        SegmentedProgress.PaintBlocks(g, bar, _progress, Theme.Hex(0xD6423A), Theme.Hex(0x7A1818), P(6), Math.Max(1, P(1)));
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _timer.Dispose();
        base.Dispose(disposing);
    }
}

internal sealed class OptionsDialog : SkinDialog
{
    private readonly AppSettings _settings;
    private readonly SkinTree _tree = new();
    private readonly Dictionary<TreeItem, Control> _pages = new();
    private readonly SkinLabel _pageTitle = new(string.Empty, true) { TextColor = Theme.Brass };
    private readonly List<string> _exclusions;
    private readonly List<string> _authorized;
    private SkinCheck _splash = null!;
    private SkinCheck _confirm = null!;
    private SkinCheck _autoscroll = null!;
    private SkinCheck _debugLines = null!;
    private SkinSpin _threads = null!;
    private SkinCombo _profile = null!;
    private SkinSpin _retries = null!;
    private SkinRadio[] _portRadios = null!;
    private SkinSpin _connectTimeout = null!;
    private SkinSpin _readTimeout = null!;
    private SkinSpin _rps = null!;
    private SkinCheck _backoff = null!;
    private SkinList _exclusionList = null!;
    private SkinCheck _assumeUp = null!;
    private SkinCheck _nvd = null!;
    private TextField _nvdKey = null!;
    private SkinSpin _crawlPages = null!;
    private SkinSpin _crawlDepth = null!;
    private SkinCheck _robots = null!;
    private TextField _userAgent = null!;
    private SkinCheck _udp = null!;
    private SkinCheck _intel = null!;
    private SkinCheck _takeover = null!;
    private SkinCheck _customRules = null!;
    private TextField _rulesDir = null!;
    private SkinList _authorizedList = null!;
    private TextField _footer = null!;

    public OptionsDialog(AppSettings settings) : base("Options", 660, 500)
    {
        _settings = settings;
        _exclusions = settings.Exclusions.ToList();
        _authorized = settings.AuthorizedTargets.ToList();
        Controls.Add(_tree);
        Controls.Add(_pageTitle);

        var general = AddPage(null, "General", BuildGeneral());
        var scan = AddPage(null, "Scan Defaults", BuildScan());
        AddPage(scan, "Timing", BuildTiming());
        AddPage(scan, "Exclusions", BuildExclusions());
        AddPage(scan, "Authorized Targets", BuildAuthorized());
        var engine = AddPage(null, "Engine", BuildEngine());
        AddPage(engine, "Web Crawler", BuildCrawler());
        AddPage(engine, "UDP Services", BuildUdp());
        AddPage(engine, "Threat Intelligence", BuildIntel());
        AddPage(engine, "Detection Rules", BuildRules());
        AddPage(null, "Logging", BuildLogging());
        AddPage(null, "Reports", BuildReports());
        scan.Expanded = true;
        engine.Expanded = true;

        _tree.Rebuild();
        _tree.SelectionChanged += (_, _) => ShowPage();
        _tree.SelectedItem = general;

        var ok = AddButton("OK", DialogResult.None, isDefault: true);
        ok.Click += (_, _) =>
        {
            if (!Apply()) return;
            DialogResult = DialogResult.OK;
            Close();
        };
        AddButton("Cancel", DialogResult.Cancel, isCancel: true);
        AddButton("Apply", DialogResult.None).Click += (_, _) => Apply();
    }

    private TreeItem AddPage(TreeItem? parent, string title, Control page)
    {
        var item = new TreeItem(title, IconId.Properties);
        if (parent == null) _tree.Roots.Add(item);
        else parent.Add(item);
        page.Visible = false;
        _pages[item] = page;
        Controls.Add(page);
        return item;
    }

    private static SkinPanel Stack(params EtchedGroup[] groups)
    {
        var panel = new StackPanel();
        foreach (var g in groups) panel.Controls.Add(g);
        return panel;
    }

    private static SkinLabel Note(string text) => new(text) { Wrap = true, TextColor = Theme.TextDim };

    private Control BuildGeneral()
    {
        var g1 = new EtchedGroup("Session Behaviour");
        _confirm = g1.Add(null, new SkinCheck("Ask before discarding or exiting during a running scan", _settings.ConfirmStop), height: 17);

        var g2 = new EtchedGroup("At Startup");
        _splash = g2.Add(null, new SkinCheck("Show splash screen", _settings.ShowSplash), height: 17);

        var g3 = new EtchedGroup("Storage");
        var sheet = new PropertySheet { KeyWidth = 90 };
        sheet.SetRows(new List<(string, string, Color?)>
        {
            ("Settings file", "%APPDATA%\\TryZ\\settings.json", null),
            ("Session files", "*.tzs (JSON)", null),
        });
        g3.Add(null, sheet, height: 36);
        return Stack(g1, g2, g3);
    }

    private Control BuildScan()
    {
        var g = new EtchedGroup("New Scan Defaults");
        g.LabelWidth = 110;
        _profile = g.Add("Profile", new SkinCombo(), width: 150);
        _profile.AddRange(ScanOptions.ProfileNames);
        _profile.SelectedIndex = Math.Clamp(_settings.DefaultProfile, 0, ScanOptions.ProfileNames.Length - 1);
        _threads = g.Add("Worker threads", new SkinSpin(Math.Clamp(_settings.DefaultThreads, 1, 256), 1, 256), width: 70);
        _retries = g.Add("Retries per probe", new SkinSpin(Math.Clamp(_settings.Retries, 0, 8), 0, 8), width: 70);

        var ports = new EtchedGroup("Port Selection (Custom profile)");
        int sel = Math.Clamp(_settings.CustomPortSelection, 0, 2);
        _portRadios = new[]
        {
            ports.Add(null, new SkinRadio("Top 100 TCP ports", sel == 0), height: 17),
            ports.Add(null, new SkinRadio("Top 1000 TCP ports", sel == 1), height: 17),
            ports.Add(null, new SkinRadio("All 65535 TCP ports (slow)", sel == 2), height: 17),
        };
        ports.Add(null, Note("Quick Audit always uses the top 100 ports, Full Audit the top 1000 and Web Only the common web ports."), height: 30);
        return Stack(g, ports);
    }

    private Control BuildTiming()
    {
        var g = new EtchedGroup("Pacing");
        g.LabelWidth = 130;
        _connectTimeout = g.Add("Connect timeout (ms)", new SkinSpin(Math.Clamp(_settings.ConnectTimeoutMs, 100, 30000), 100, 30000, 100), width: 80);
        _readTimeout = g.Add("Read timeout (ms)", new SkinSpin(Math.Clamp(_settings.ReadTimeoutMs, 100, 60000), 100, 60000, 100), width: 80);
        _rps = g.Add("Requests per second", new SkinSpin(Math.Clamp(_settings.MaxRequestsPerSecond, 1, 5000), 1, 5000, 10), width: 80);
        _backoff = g.Add(null, new SkinCheck("Back off automatically when the error rate climbs", _settings.AutoBackoff), height: 17);
        g.Add(null, Note("The request limit applies to every probe the engine sends (connects, banner reads, TLS handshakes, HTTP requests)."), height: 30);
        return Stack(g);
    }

    private Control BuildExclusions()
    {
        var g = new EtchedGroup("Excluded Addresses");
        _exclusionList = new SkinList();
        RefreshList(_exclusionList, _exclusions, IconId.Host);
        g.Add(null, _exclusionList, height: 140);
        var row = new TextField(cue: "10.0.0.5, 10.0.0.0/24 or 10.0.0.10-20");
        var add = new SkinButton("Add");
        var remove = new SkinButton("Remove");
        void AddEntry()
        {
            string text = row.Value.Trim();
            if (text.Length == 0) return;
            if (!IpRange.TryParse(text, out _))
            {
                MessageDialog.Show(this, "Exclusions", $"\"{text}\" is not a valid address, CIDR block or range.", IconId.Warning);
                return;
            }
            if (!_exclusions.Contains(text, StringComparer.OrdinalIgnoreCase)) _exclusions.Add(text);
            RefreshList(_exclusionList, _exclusions, IconId.Host);
            row.Value = string.Empty;
        }
        add.Click += (_, _) => AddEntry();
        row.Edit.KeyDown += (_, e) =>
        {
            if (e.KeyCode != Keys.Return) return;
            AddEntry();
            e.SuppressKeyPress = true;
        };
        remove.Click += (_, _) =>
        {
            int i = _exclusionList.SelectedIndex;
            if (i < 0 || i >= _exclusions.Count) return;
            _exclusions.RemoveAt(i);
            RefreshList(_exclusionList, _exclusions, IconId.Host);
        };
        g.AddRow(null, 22, (row, 0), (add, 66), (remove, 66));
        g.Add(null, Note("Excluded addresses are never probed, even when they fall inside a target range."), height: 30);
        return Stack(g);
    }

    private Control BuildAuthorized()
    {
        var g = new EtchedGroup("Targets Confirmed as Authorized");
        _authorizedList = new SkinList();
        RefreshList(_authorizedList, _authorized, IconId.Globe);
        g.Add(null, _authorizedList, height: 160);
        var remove = new SkinButton("Remove");
        var clear = new SkinButton("Remove All");
        remove.Click += (_, _) =>
        {
            int i = _authorizedList.SelectedIndex;
            if (i < 0 || i >= _authorized.Count) return;
            _authorized.RemoveAt(i);
            RefreshList(_authorizedList, _authorized, IconId.Globe);
        };
        clear.Click += (_, _) =>
        {
            _authorized.Clear();
            RefreshList(_authorizedList, _authorized, IconId.Globe);
        };
        g.AddRow(null, 22, (new SkinLabel(), 0), (remove, 80), (clear, 80));
        g.Add(null, Note("You confirmed ownership or written permission for these targets. A removed target asks for confirmation again before its next scan."), height: 30);
        return Stack(g);
    }

    private Control BuildEngine()
    {
        var info = new EtchedGroup("Scan Engine");
        var sheet = new PropertySheet { KeyWidth = 110 };
        sheet.SetRows(new List<(string, string, Color?)>
        {
            ("Engine", "TryZ engine 1.0 (live)", Theme.Ok),
            ("Probes", "ICMP echo, TCP connect, banners, TLS, HTTP", null),
            ("Runtime", $".NET {Environment.Version}", null),
        });
        info.Add(null, sheet, height: 52);

        var discovery = new EtchedGroup("Host Discovery");
        _assumeUp = discovery.Add(null, new SkinCheck("Treat all hosts as up (skip discovery)", _settings.AssumeHostsUp), height: 17);
        discovery.Add(null, Note("Use this when the targets block ping and common ports. Every address in range is port scanned."), height: 30);

        var nvd = new EtchedGroup("CVE Lookup (NIST NVD)");
        nvd.LabelWidth = 80;
        _nvd = nvd.Add(null, new SkinCheck("Look up identified product versions in the NVD", _settings.EnableNvd), height: 17);
        _nvdKey = nvd.Add("API key", new TextField(cue: "Optional NVD API key") { Mono = true });
        _nvdKey.Value = _settings.NvdApiKey ?? string.Empty;
        _nvdKey.Edit.UseSystemPasswordChar = true;
        nvd.Add(null, Note("Without a key the NVD allows about 5 requests per 30 seconds; with a key about 50. Lookups send product names and versions to services.nvd.nist.gov."), height: 44);
        return Stack(info, discovery, nvd);
    }

    private Control BuildCrawler()
    {
        var g = new EtchedGroup("Web Crawler");
        g.LabelWidth = 110;
        _crawlPages = g.Add("Max pages", new SkinSpin(Math.Clamp(_settings.CrawlMaxPages, 1, 100_000), 1, 100_000, 100), width: 90);
        _crawlDepth = g.Add("Max depth", new SkinSpin(Math.Clamp(_settings.CrawlMaxDepth, 1, 50), 1, 50), width: 90);
        _robots = g.Add(null, new SkinCheck("Respect robots.txt", _settings.RespectRobots), height: 17);

        var http = new EtchedGroup("HTTP Client");
        http.LabelWidth = 80;
        _userAgent = http.Add("User-Agent", new TextField(cue: "User-Agent header sent with every HTTP request") { Mono = true });
        _userAgent.Value = _settings.UserAgent ?? string.Empty;
        http.Add(null, Note("The Quick Audit profile limits the crawl to 200 pages."), height: 17);

        var dns = new EtchedGroup("DNS Names");
        _takeover = dns.Add(null, new SkinCheck("Check names seen during the scan for dangling CNAME records", _settings.CheckTakeover), height: 17);
        dns.Add(null, Note("Covers typed host names, certificate names and links found by the crawler. A CNAME that points at an unclaimed cloud resource can be taken over by anyone."), height: 44);
        return Stack(g, http, dns);
    }

    private Control BuildUdp()
    {
        var g = new EtchedGroup("UDP Service Probes");
        _udp = g.Add(null, new SkinCheck("Probe common UDP services after the TCP sweep", _settings.UdpScan), height: 17);
        g.Add(null, Note("Sends a protocol-correct request to each port (DNS, SNMP, NTP, SSDP and NetBIOS), so a reply proves the service is there. Ports that stay silent are reported as open|filtered only in the log. Not used by the Web Only profile."), height: 58);
        return Stack(g);
    }

    private Control BuildIntel()
    {
        var g = new EtchedGroup("Exploitation Data");
        _intel = g.Add(null, new SkinCheck("Annotate CVE findings with CISA KEV and FIRST EPSS data", _settings.EnableThreatIntel), height: 17);
        g.Add(null, Note("KEV is cached in memory for 24 hours and cleared on exit. EPSS requests send only CVE IDs to api.first.org; no host data is sent."), height: 44);
        return Stack(g);
    }

    private Control BuildRules()
    {
        var g = new EtchedGroup("Custom Rule Files");
        g.LabelWidth = 60;
        _customRules = g.Add(null, new SkinCheck("Load rule files (*.json, *.yaml) in addition to the built-in rules", _settings.UseCustomRules), height: 17);
        _rulesDir = g.Add("Folder", new TextField(cue: Engine.ScanOptions.DefaultRulesDirectory) { Mono = true });
        _rulesDir.Value = _settings.RulesDirectory ?? string.Empty;
        g.Add(null, Note("Rules are read when a scan starts. Files that fail to parse are skipped and reported in the activity log with the line number."), height: 30);
        return Stack(g);
    }

    private Control BuildLogging()
    {
        var g = new EtchedGroup("Activity Log");
        _autoscroll = g.Add(null, new SkinCheck("Follow new lines automatically", _settings.LogAutoscroll), height: 17);
        _debugLines = g.Add(null, new SkinCheck("Show debug lines (per-probe errors and timeouts)", _settings.LogDebug), height: 17);
        return Stack(g);
    }

    private Control BuildReports()
    {
        var g = new EtchedGroup("Report Defaults");
        g.LabelWidth = 90;
        _footer = g.Add("Footer line", new TextField(cue: "Optional footer text, e.g. assessor and engagement"));
        _footer.Value = _settings.ReportAuthorLine;
        g.Add(null, Note("The footer appears on report pages and in exported HTML reports."), height: 17);
        return Stack(g);
    }

    private static void RefreshList(SkinList list, List<string> items, IconId icon) =>
        list.SetItems(items.Select(t => new ListRow(t, icon)).ToList());

    private void ShowPage()
    {
        foreach (var (item, page) in _pages)
            page.Visible = ReferenceEquals(item, _tree.SelectedItem);
        _pageTitle.Caption = _tree.SelectedItem?.Text ?? string.Empty;
        PerformLayout();
        Invalidate();
    }

    public void SelectPage(int index) => _tree.SelectedItem = _pages.Keys.ElementAt(index);

    private bool Apply()
    {
        if (_connectTimeout.Value <= 0 || _readTimeout.Value <= 0) return false;
        _settings.ShowSplash = _splash.Checked;
        _settings.ConfirmStop = _confirm.Checked;
        _settings.LogAutoscroll = _autoscroll.Checked;
        _settings.LogDebug = _debugLines.Checked;
        _settings.DefaultThreads = _threads.Value;
        _settings.DefaultProfile = Math.Max(0, _profile.SelectedIndex);
        _settings.Retries = _retries.Value;
        _settings.CustomPortSelection = Math.Max(0, Array.FindIndex(_portRadios, r => r.Checked));
        _settings.ConnectTimeoutMs = _connectTimeout.Value;
        _settings.ReadTimeoutMs = _readTimeout.Value;
        _settings.MaxRequestsPerSecond = _rps.Value;
        _settings.AutoBackoff = _backoff.Checked;
        _settings.Exclusions = _exclusions.ToList();
        _settings.AuthorizedTargets = _authorized.ToList();
        _settings.AssumeHostsUp = _assumeUp.Checked;
        _settings.EnableNvd = _nvd.Checked;
        _settings.NvdApiKey = _nvdKey.Value.Trim();
        _settings.CrawlMaxPages = _crawlPages.Value;
        _settings.CrawlMaxDepth = _crawlDepth.Value;
        _settings.RespectRobots = _robots.Checked;
        _settings.UserAgent = _userAgent.Value.Trim();
        _settings.UdpScan = _udp.Checked;
        _settings.EnableThreatIntel = _intel.Checked;
        _settings.CheckTakeover = _takeover.Checked;
        _settings.UseCustomRules = _customRules.Checked;
        _settings.RulesDirectory = _rulesDir.Value.Trim();
        _settings.ReportAuthorLine = _footer.Value;
        _settings.Save();
        return true;
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = DialogBody;
        int treeW = Px(164);
        _tree.SetBounds(b.X + Px(8), b.Y + Px(8), treeW, b.Height - Px(16));
        int x = _tree.Right + Px(10);
        int w = b.Right - x - Px(10);
        _pageTitle.SetBounds(x, b.Y + Px(8), w, Px(17));
        foreach (var page in _pages.Values)
            page.SetBounds(x, b.Y + Px(30), w, b.Height - Px(38));
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var b = DialogBody;
        int x = _tree.Right + Px(10);
        Draw.EtchH(e.Graphics, x, b.Right - Px(10), b.Y + Px(26));
    }
}

internal sealed class StackPanel : SkinPanel
{
    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int y = 0;
        foreach (Control c in Controls)
        {
            int h = c is EtchedGroup g ? Px(g.PreferredLogicalHeight) : c.Height;
            c.SetBounds(0, y, Width, h);
            y += h + Px(8);
        }
    }
}
