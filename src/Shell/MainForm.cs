using System.Net;
using System.Text;
using System.Threading.Channels;
using TryZ.Data;
using TryZ.Engine;
using TryZ.Views;

namespace TryZ.Shell;

internal sealed class SkinMenuStrip : MenuStrip
{
    private const int WM_NCHITTEST = 0x0084;
    private const int HTTRANSPARENT = -1;

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_NCHITTEST && FindForm() is FrameForm frame && frame.IsInResizeBand(m.LParam))
        {
            m.Result = HTTRANSPARENT;
            return;
        }
        base.WndProc(ref m);
    }
}

internal sealed class MainForm : FrameForm, IShell
{
    private readonly AppSettings _settings;
    private readonly Session _session = new();
    private readonly ScanEngine _engine = new();
    private readonly Timer _uiTimer = new() { Interval = 66 };
    private readonly SkinMenuStrip _menu = new();
    private readonly Toolbar _toolbar = new();
    private readonly TargetBar _targetBar;
    private readonly Navigator _nav = new();
    private readonly SkinPanel _center = new() { BackColor = Theme.Panel };
    private readonly ModuleView[] _modules;
    private readonly PortAuditView _portAudit;
    private readonly WorkbenchView _workbench;
    private readonly TabHost _dock = new();
    private readonly LogView _log = new();
    private readonly GridView _dockFindings = new() { EmptyText = "No findings recorded." };
    private readonly RowSet<Finding> _dockFindingRows;
    private readonly GridView _dockTasks = new() { EmptyText = "Task queue is empty." };
    private readonly RowSet<TaskItem> _dockTaskRows;
    private readonly SplitBox _mainSplit;
    private readonly StatusPanel _status = new();
    private readonly ToolbarItem _tbNew, _tbOpen, _tbSave, _tbStart, _tbPause, _tbStop, _tbReport, _tbOptions;
    private readonly List<ToolStripMenuItem> _moduleItems = new();
    private readonly List<ToolStripMenuItem> _profileItems = new();
    private readonly List<ToolStripMenuItem> _dockTabItems = new();
    private ToolStripMenuItem _miStart = null!, _miPause = null!, _miStop = null!, _miDock = null!, _miFollow = null!;
    private CancellationTokenSource? _consumer;
    private string? _sessionPath;
    private ModuleView? _active;
    private int _lastFindingsTab = -1;
    private int _lastTaskTab = -1;

    public MainForm(AppSettings settings) : base(true, true)
    {
        _settings = settings;
        Caption.Title = "TryZ Security Suite  -  Session: untitled.tzs";
        Text = "TryZ Security Suite";
        SetMinimumLogical(980, 640);

        _menu.Renderer = SkinRenderer.Instance;
        _menu.GripStyle = ToolStripGripStyle.Hidden;
        _menu.Padding = new Padding(2, 1, 0, 1);
        _menu.AutoSize = false;
        _menu.Dock = DockStyle.None;
        BuildMenu();

        _tbNew = _toolbar.Add("New", IconId.New, NewSession, "New session (Ctrl+N)");
        _tbOpen = _toolbar.Add("Open", IconId.Open, OpenSession, "Open a saved session (Ctrl+O)");
        _tbSave = _toolbar.Add("Save", IconId.Save, SaveSession, "Save the session (Ctrl+S)");
        _toolbar.AddSeparator();
        _tbStart = _toolbar.Add("Start", IconId.Start, StartOrResume, "Start or resume the scan (F5)");
        _tbPause = _toolbar.Add("Pause", IconId.Pause, PauseScan, "Pause the scan (F6)");
        _tbStop = _toolbar.Add("Stop", IconId.Stop, StopScan, "Stop the scan (Esc)");
        _toolbar.AddSeparator();
        _tbReport = _toolbar.Add("Report", IconId.Report, () => NavigateTo(6), "Open the Reports module (Ctrl+7)");
        _toolbar.AddSeparator();
        _tbOptions = _toolbar.Add("Options", IconId.Options, ShowOptions, "Preferences");

        _targetBar = new TargetBar(settings);
        _targetBar.StartClicked += (_, _) => StartOrResume();
        _targetBar.FilterChanged += (_, _) => ApplyFilter();

        var overview = new OverviewView(this);
        var discovery = new DiscoveryView(this);
        _portAudit = new PortAuditView(this);
        var vulnerability = new VulnerabilityView(this);
        var crawler = new CrawlerView(this);
        _workbench = new WorkbenchView(this);
        var reports = new ReportsView(this);
        var remediation = new RemediationView(this);
        var compare = new CompareView(this);
        // Indexes are persisted (LastModule) and used by Ctrl+1..9, so new modules are appended.
        _modules = new ModuleView[] { overview, discovery, _portAudit, vulnerability, crawler, _workbench, reports, remediation, compare };
        foreach (var m in _modules)
        {
            m.Visible = false;
            _center.Controls.Add(m);
        }
        _center.Layout += (_, _) => _active?.SetBounds(0, 0, _center.Width, _center.Height);

        _log.Attach(_session.Log);
        _log.AutoFollow = settings.LogAutoscroll;
        _log.FollowChanged += (_, _) => _dock.SetTitle(0, _log.Following ? "Activity Log" : "Activity Log (autoscroll paused)");
        _dockFindingRows = Schemas.Findings(_session.Findings);
        _dockFindings.Source = _dockFindingRows;
        _dockFindings.RowActivated += (_, _) => NavigateTo(3);
        _dockTaskRows = Schemas.Tasks(_session.Tasks);
        _dockTasks.Source = _dockTaskRows;
        _dock.AddPage("Activity Log", IconId.Log, _log);
        _dock.AddPage("Findings", IconId.Findings, _dockFindings);
        _dock.AddPage("Task Queue", IconId.Queue, _dockTasks);
        _dock.SelectedIndex = Math.Clamp(settings.DockTab, 0, 2);
        _dock.SelectedChanged += (_, _) =>
        {
            for (int i = 0; i < _dockTabItems.Count; i++) _dockTabItems[i].Checked = i == _dock.SelectedIndex;
            SyncDock();
        };

        _mainSplit = new SplitBox(false, _center, _dock, Math.Clamp(settings.DockHeight, 100, 500), fixSecond: true)
        {
            MinFirst = 280,
            MinSecond = 90,
        };
        _mainSplit.CollapseSecond = !settings.DockVisible;

        Controls.Add(_menu);
        Controls.Add(_toolbar);
        Controls.Add(_targetBar);
        Controls.Add(_nav);
        Controls.Add(_mainSplit);
        Controls.Add(_status);
        MainMenuStrip = _menu;

        _nav.SelectedChanged += (_, _) => Activate(_nav.SelectedModule);
        _engine.StateChanged += (_, _) => UpdateCommandState();
        _uiTimer.Tick += (_, _) => SyncUi();

        ApplyMenuDpi();
        RestorePlacement();
        Activate(Math.Clamp(settings.LastModule, 0, _modules.Length - 1));
        _nav.SelectedModule = Math.Clamp(settings.LastModule, 0, _modules.Length - 1);
        _miFollow.Checked = settings.LogAutoscroll;
        UpdateCommandState();
    }

    public Session Session => _session;
    public AppSettings Settings => _settings;
    public bool PersistOnClose { get; set; } = true;

#if DEBUG
    public ScanEngine Engine => _engine;
    public ModuleView[] Modules => _modules;
    public TabHost DockHost => _dock;
    public SkinMenuStrip MenuBar => _menu;
    public TargetBar Target => _targetBar;
#endif

    private void RestorePlacement()
    {
        int w = _settings.WindowWidth > 0 ? _settings.WindowWidth : Px(1240);
        int h = _settings.WindowHeight > 0 ? _settings.WindowHeight : Px(780);
        var bounds = new Rectangle(_settings.WindowX, _settings.WindowY, w, h);
        bool visible = _settings.WindowX != int.MinValue
            && Screen.AllScreens.Any(s => s.WorkingArea.IntersectsWith(Rectangle.Inflate(bounds, -40, -40)));
        if (visible)
        {
            StartPosition = FormStartPosition.Manual;
            Bounds = bounds;
        }
        else
        {
            StartPosition = FormStartPosition.CenterScreen;
            Size = new Size(w, h);
        }
        if (_settings.Maximized) WindowState = FormWindowState.Maximized;
    }

#if DEBUG
    public void SetCaptureBounds(Size logical)
    {
        StartPosition = FormStartPosition.Manual;
        WindowState = FormWindowState.Normal;
        var area = Screen.PrimaryScreen!.WorkingArea;
        Bounds = new Rectangle(area.X + 8, area.Y + 8, Px(logical.Width), Px(logical.Height));
    }
#endif

    private ToolStripMenuItem MenuItem(ToolStripMenuItem parent, string text, IconId icon, Action action, Keys keys = Keys.None, string? display = null)
    {
        var item = new ToolStripMenuItem(text) { Tag = icon, ForeColor = Theme.Text };
        if (keys != Keys.None) item.ShortcutKeys = keys;
        if (display != null) item.ShortcutKeyDisplayString = display;
        item.Click += (_, _) => action();
        parent.DropDownItems.Add(item);
        return item;
    }

    private ToolStripMenuItem TopMenu(string text)
    {
        var item = new ToolStripMenuItem(text) { ForeColor = Theme.Text };
        item.DropDown.BackColor = Theme.Panel;
        item.DropDown.ForeColor = Theme.Text;
        _menu.Items.Add(item);
        return item;
    }

    private void BuildMenu()
    {
        var file = TopMenu("&File");
        MenuItem(file, "&New Session", IconId.New, NewSession, Keys.Control | Keys.N);
        MenuItem(file, "&Open Session...", IconId.Open, OpenSession, Keys.Control | Keys.O);
        MenuItem(file, "&Save Session", IconId.Save, SaveSession, Keys.Control | Keys.S);
        MenuItem(file, "Save Session &As...", IconId.SaveAs, SaveSessionAs, Keys.Control | Keys.Shift | Keys.S);
        file.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(file, "&Export Findings (CSV)...", IconId.Export, () => ExportReport(ExportFormat.Csv), Keys.Control | Keys.E);
        file.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(file, "E&xit", IconId.Exit, Close, Keys.None, "Alt+F4");

        var session = TopMenu("&Session");
        MenuItem(session, "Session &Properties...", IconId.Properties, ShowSessionProperties);
        session.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(session, "Clear Activity &Log", IconId.Clear, () =>
        {
            _session.Log.Clear();
            SyncDock();
        });
        MenuItem(session, "Clear &Filter", IconId.Filter, () => _targetBar.ClearFilter(), Keys.Control | Keys.Shift | Keys.F);

        var scan = TopMenu("S&can");
        _miStart = MenuItem(scan, "&Start", IconId.Start, StartOrResume, Keys.F5);
        _miPause = MenuItem(scan, "&Pause", IconId.Pause, PauseScan, Keys.F6);
        _miStop = MenuItem(scan, "S&top", IconId.Stop, StopScan, Keys.None, "Esc");
        scan.DropDownItems.Add(new ToolStripSeparator());
        var profile = MenuItem(scan, "P&rofile", IconId.None, () => { });
        for (int i = 0; i < ScanOptions.ProfileNames.Length; i++)
        {
            int index = i;
            var item = MenuItem(profile, ScanOptions.ProfileNames[i], IconId.None, () => _targetBar.ProfileIndex = index);
            _profileItems.Add(item);
        }
        profile.DropDownOpening += (_, _) =>
        {
            for (int i = 0; i < _profileItems.Count; i++) _profileItems[i].Checked = i == _targetBar.ProfileIndex;
        };

        var tools = TopMenu("&Tools");
        MenuItem(tools, "HTTP &Workbench", IconId.Workbench, () => NavigateTo(5));
        MenuItem(tools, "&Find in Grid", IconId.Filter, () => _targetBar.FocusFilter(), Keys.Control | Keys.F);
        tools.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(tools, "&Options...", IconId.Options, ShowOptions);

        var reportsMenu = TopMenu("&Reports");
        MenuItem(reportsMenu, "&View Report", IconId.Report, () => NavigateTo(6), Keys.Control | Keys.R);
        MenuItem(reportsMenu, "&Export HTML Report...", IconId.Export, () => ExportReport(ExportFormat.Html), Keys.Control | Keys.Shift | Keys.E);
        MenuItem(reportsMenu, "Export &PDF Report...", IconId.Export, () => ExportReport(ExportFormat.Pdf));
        MenuItem(reportsMenu, "Export &Markdown Report...", IconId.Export, () => ExportReport(ExportFormat.Markdown));
        reportsMenu.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(reportsMenu, "Export Findings &CSV...", IconId.Export, () => ExportReport(ExportFormat.Csv));
        MenuItem(reportsMenu, "Export Findings &JSON...", IconId.Export, () => ExportReport(ExportFormat.Json));
        MenuItem(reportsMenu, "Export &SARIF 2.1.0...", IconId.Export, () => ExportReport(ExportFormat.Sarif));
        reportsMenu.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(reportsMenu, "&Remediation Plan", IconId.Remediation, () => NavigateTo(7));
        MenuItem(reportsMenu, "Compare with &Baseline...", IconId.Compare, () => NavigateTo(8), Keys.Control | Keys.B);

        var view = TopMenu("&View");
        string[] names = { "Overview", "Discovery", "Port Audit", "Vulnerability Audit", "Web Crawler", "HTTP Workbench", "Reports", "Remediation Plan", "Scan Compare" };
        IconId[] icons = { IconId.Overview, IconId.Discovery, IconId.PortAudit, IconId.Vulnerability, IconId.Crawler, IconId.Workbench, IconId.Reports, IconId.Remediation, IconId.Compare };
        for (int i = 0; i < names.Length; i++)
        {
            int index = i;
            _moduleItems.Add(MenuItem(view, names[i], icons[i], () => NavigateTo(index), Keys.Control | (Keys.D1 + i)));
        }
        view.DropDownItems.Add(new ToolStripSeparator());
        _miDock = MenuItem(view, "Bottom &Dock", IconId.None, ToggleDock, Keys.F8);
        _miDock.Checked = _settings.DockVisible;
        string[] tabs = { "Activity Log", "Findings", "Task Queue" };
        for (int i = 0; i < tabs.Length; i++)
        {
            int index = i;
            _dockTabItems.Add(MenuItem(view, tabs[i], IconId.None, () => ShowDockTab(index), Keys.Alt | (Keys.D1 + i)));
        }
        _dockTabItems[Math.Clamp(_settings.DockTab, 0, 2)].Checked = true;
        view.DropDownItems.Add(new ToolStripSeparator());
        _miFollow = MenuItem(view, "Follow Log &Tail", IconId.None, () =>
        {
            _miFollow.Checked = !_miFollow.Checked;
            _settings.LogAutoscroll = _miFollow.Checked;
            _log.AutoFollow = _miFollow.Checked;
            if (_miFollow.Checked) _log.Follow();
        });

        var help = TopMenu("&Help");
        MenuItem(help, "&Contents", IconId.Help, ShowHelp, Keys.F1);
        MenuItem(help, "&Keyboard Shortcuts", IconId.Keyboard, ShowShortcuts);
        help.DropDownItems.Add(new ToolStripSeparator());
        MenuItem(help, "&About TryZ...", IconId.About, ShowAbout);
    }

    private void ApplyMenuDpi()
    {
        var font = Theme.Ui(Dpi);
        _menu.Font = font;
        int icon = Px(16);
        _menu.ImageScalingSize = new Size(icon, icon);
        foreach (ToolStripItem top in _menu.Items) ApplyMenuDpi(top, font, icon);
    }

    private void ApplyMenuDpi(ToolStripItem item, Font font, int icon)
    {
        item.Font = font;
        if (item is not ToolStripMenuItem m) return;
        if (m.Tag is IconId id && id != IconId.None) m.Image = Icons.Get(id, icon);
        if (m.HasDropDownItems)
        {
            m.DropDown.Font = font;
            ((ToolStripDropDownMenu)m.DropDown).ImageScalingSize = new Size(icon, icon);
            foreach (ToolStripItem child in m.DropDownItems) ApplyMenuDpi(child, font, icon);
        }
        if (m.Owner is MenuStrip) m.Padding = new Padding(Px(6), 0, Px(6), 0);
    }

    protected override void OnDpiApplied()
    {
        ApplyMenuDpi();
        foreach (Control c in Controls)
            if (c is SkinControl s) s.RefreshDpi();
    }

#if DEBUG
    public void ApplyOverrideDpi()
    {
        OnDpiApplied();
        ApplyMinimum();
        PerformLayout();
    }
#endif

    protected override int HitTestExtra(Point client)
    {
        if (WindowState != FormWindowState.Normal) return 0;
        var grip = _status.GripRect;
        grip.Offset(_status.Location);
        return grip.Contains(client) ? Native.HTBOTTOMRIGHT : 0;
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        if (_targetBar == null) return;
        var c = ContentBounds;
        int y = c.Top;
        int menuH = Px(21);
        _menu.SetBounds(c.Left, y, c.Width, menuH);
        y += menuH;
        int toolH = Px(Toolbar.LogicalHeight);
        _toolbar.SetBounds(c.Left, y, c.Width, toolH);
        y += toolH;
        int targetH = Px(TargetBar.LogicalHeight);
        _targetBar.SetBounds(c.Left, y, c.Width, targetH);
        y += targetH;
        int statusH = Px(StatusPanel.LogicalHeight);
        _status.SetBounds(c.Left, c.Bottom - statusH, c.Width, statusH);
        int navW = Px(190);
        int bodyH = c.Bottom - statusH - y;
        _nav.SetBounds(c.Left, y, navW, bodyH);
        _mainSplit.SetBounds(c.Left + navW, y, c.Width - navW, bodyH);
    }

    private void Activate(int index)
    {
        var next = _modules[index];
        if (ReferenceEquals(_active, next)) return;
        _active = next;
        next.SetBounds(0, 0, _center.Width, _center.Height);
        next.SyncData();
        next.Visible = true;
        foreach (var m in _modules)
            if (!ReferenceEquals(m, next)) m.Visible = false;
        for (int i = 0; i < _moduleItems.Count; i++) _moduleItems[i].Checked = i == index;
        _settings.LastModule = index;
    }

#if DEBUG
    public void PerformCommand(string name)
    {
        switch (name)
        {
            case "Pause": PauseScan(); break;
            case "Stop": StopScan(); break;
            case "New": NewSession(); break;
        }
    }
#endif

    public void NavigateTo(int module) => _nav.SelectedModule = module;

    public void OpenInWorkbench(string method, string url)
    {
        _workbench.Load(method, url);
        NavigateTo(5);
    }

    public void SelectHostInPortAudit(string ip)
    {
        NavigateTo(2);
        _portAudit.SelectHost(ip);
    }

    private void ShowDockTab(int index)
    {
        if (_mainSplit.CollapseSecond) ToggleDock();
        _dock.SelectedIndex = index;
    }

    private void ToggleDock()
    {
        _mainSplit.CollapseSecond = !_mainSplit.CollapseSecond;
        _miDock.Checked = !_mainSplit.CollapseSecond;
        _settings.DockVisible = _miDock.Checked;
    }

    public void LogUser(string source, string text)
    {
        _session.AddLog(LogLevel.Notice, source, text);
    }

    public void Notify(string title, string text, IconId icon = IconId.InfoMark) => MessageDialog.Show(this, title, text, icon);

    public void ShowAbout()
    {
        using var dlg = new AboutDialog();
        dlg.ShowDialog(this);
    }

    private void ShowOptions()
    {
        using var dlg = new OptionsDialog(_settings);
        if (dlg.ShowDialog(this) == DialogResult.OK) _miFollow.Checked = _settings.LogAutoscroll;
        ApplyLogPrefs();
    }

    private void ApplyLogPrefs()
    {
        _log.AutoFollow = _settings.LogAutoscroll;
        if (_settings.LogAutoscroll) _log.Follow();
        _session.Dirty = true;
    }

    private void ShowHelp() => Notify("Help",
        "Enter a target (IP, CIDR, range, host name or URL), pick a profile and press F5. "
        + "TryZ discovers live hosts, scans TCP ports, identifies services, checks TLS and HTTP configuration, crawls web sites and lists findings. "
        + "Scan only systems you own or are authorized to test. Save sessions with Ctrl+S; export reports from the Reports menu.", IconId.Help);

    public void UseCustomProfile() => _targetBar.ProfileIndex = ScanOptions.ProfileNames.Length - 1;

    private void ShowSessionProperties() => Notify("Session Properties",
        $"Name: {_session.Name}\nTarget: {(_session.Target.Length > 0 ? _session.Target : "(none)")}\nProfile: {(_session.Profile.Length > 0 ? _session.Profile : "(none)")}\nHosts: {_session.Hosts.Items.Count}   Services: {_session.Ports.Items.Count}   URLs: {_session.Urls.Items.Count:N0}\nFindings: {_session.FindingCount}", IconId.Properties);

    private void ShowShortcuts() => Notify("Keyboard Shortcuts",
        "F5 Start or resume, F6 Pause, Esc Stop\nCtrl+1 to Ctrl+7 Modules, Ctrl+F Filter\nAlt+1 to Alt+3 Dock tabs, F8 Dock\nCtrl+N New, Ctrl+O Open, Ctrl+S Save\nCtrl+C Copy the selected row", IconId.Keyboard);

    private void NewSession()
    {
        if (_engine.State is ScanState.Running or ScanState.Paused && _settings.ConfirmStop
            && !MessageDialog.Ask(this, "New Session", "A scan is in progress. Stop it and clear the session?"))
            return;
        _consumer?.Cancel();
        _engine.Reset();
        _session.Clear();
        _sessionPath = null;
        _targetBar.ClearFilter();
        SetSessionTitle();
        SyncUi(force: true);
    }

    private void SetSessionTitle() => Caption.Title = $"TryZ Security Suite  -  Session: {_session.Name}";

    public void StartOrResume()
    {
        if (_engine.State == ScanState.Paused)
        {
            _engine.Resume();
            _session.AddLog(LogLevel.Notice, "engine", "Scan resumed");
            return;
        }
        if (_engine.State == ScanState.Running) return;
        string target = _targetBar.TargetText.Trim();
        if (target.Length == 0)
        {
            Notify("Target", "Enter a target: an IP address, CIDR block, address range, host name or URL.", IconId.Warning);
            return;
        }
        if (!TargetParser.TryValidate(target, out string error))
        {
            Notify("Target", error, IconId.Warning);
            return;
        }
        if (!IsAuthorized(target))
        {
            using var dlg = new AuthorizationDialog(target);
            if (dlg.ShowDialog(this) != DialogResult.OK) return;
            _settings.AuthorizedTargets.Add(target);
            _settings.Save();
            _session.AddLog(LogLevel.Notice, "scope", $"Authorization confirmed by the user for target {target}");
        }
        BeginRun(target);
    }

    /// <summary>True when the user already confirmed authorization for this exact target, or it only covers this machine.</summary>
    private bool IsAuthorized(string target) =>
        IsLoopbackTarget(target) || _settings.AuthorizedTargets.Any(t => string.Equals(t.Trim(), target, StringComparison.OrdinalIgnoreCase));

    /// <summary>True when every item of the target text is a loopback address, loopback range or localhost.</summary>
    internal static bool IsLoopbackTarget(string target)
    {
        var parts = target.Split(new[] { ',', ';', ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0) return false;
        foreach (var raw in parts)
        {
            string item = raw.Trim();
            if (item.Contains("://", StringComparison.Ordinal) && Uri.TryCreate(item, UriKind.Absolute, out var uri) && uri.Host.Length > 0)
                item = uri.Host.Trim('[', ']');
            if (item.Equals("localhost", StringComparison.OrdinalIgnoreCase) || item.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase)) continue;
            int slash = item.IndexOf('/');
            if (slash >= 0)
            {
                if (!int.TryParse(item[(slash + 1)..], out int prefix)) return false;
                if (!IPAddress.TryParse(item[..slash], out var net) || !IPAddress.IsLoopback(net)) return false;
                bool v4 = net.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
                if (v4 ? prefix < 8 : prefix < 128) return false;
                continue;
            }
            int dash = item.IndexOf('-');
            if (dash > 0)
            {
                string first = item[..dash], last = item[(dash + 1)..];
                if (!IPAddress.TryParse(first, out var lo) || !IPAddress.IsLoopback(lo)) return false;
                if (IPAddress.TryParse(last, out var hi))
                {
                    if (!IPAddress.IsLoopback(hi)) return false;
                }
                else if (!int.TryParse(last, out _))
                {
                    return false;
                }
                continue;
            }
            if (!IPAddress.TryParse(item, out var addr) || !IPAddress.IsLoopback(addr)) return false;
        }
        return true;
    }

    /// <summary>Starts a real scan of <paramref name="target"/> with the toolbar profile and thread count. Callers handle authorization.</summary>
    public void BeginRun(string target)
    {
        _consumer?.Cancel();
        _session.ResetResults();
        int profile = Math.Clamp(_targetBar.ProfileIndex, 0, ScanOptions.ProfileNames.Length - 1);
        int threads = _targetBar.Threads;
        _session.Target = target;
        _session.Profile = ScanOptions.ProfileNames[profile];
        _session.Threads = threads;
        _session.StartedAt = DateTime.Now;
        _settings.LastTarget = target;
        _targetBar.RefreshRecent(_settings);
        var options = ScanOptions.From(_settings, profile, threads);
        var reader = _engine.Start(new ScanRequest(target, profile, threads, options));
        _consumer = new CancellationTokenSource();
        _ = ConsumeAsync(reader, _consumer.Token);
    }

    private void PauseScan()
    {
        if (_engine.State != ScanState.Running) return;
        _engine.Pause();
        _session.AddLog(LogLevel.Notice, "engine", "Scan paused");
    }

    // ---------------------------------------------------------------- session files and reports

    private const string SessionFilter = "TryZ session (*.tzs)|*.tzs|All files (*.*)|*.*";

    private void SaveSession()
    {
        if (_sessionPath == null) SaveSessionAs();
        else SaveSessionTo(_sessionPath);
    }

    private void SaveSessionAs()
    {
        using var dlg = new SaveFileDialog
        {
            Title = "Save Session",
            Filter = SessionFilter,
            DefaultExt = "tzs",
            AddExtension = true,
            OverwritePrompt = true,
            FileName = _session.Name != "untitled.tzs" ? _session.Name : $"tryz-{SafeName(_session.Target)}-{DateTime.Now:yyyyMMdd-HHmm}.tzs",
        };
        if (dlg.ShowDialog(this) == DialogResult.OK) SaveSessionTo(dlg.FileName);
    }

    public bool SaveSessionTo(string path)
    {
        try
        {
            SessionFile.Write(path, _session.ToFile());
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            Notify("Save Session", $"The session could not be saved to {path}: {ex.Message}", IconId.Warning);
            return false;
        }
        _sessionPath = path;
        _session.Name = Path.GetFileName(path);
        SetSessionTitle();
        _session.AddLog(LogLevel.Ok, "session", $"Session saved to {path}");
        return true;
    }

    private void OpenSession()
    {
        if (_engine.State is ScanState.Running or ScanState.Paused
            && !MessageDialog.Ask(this, "Open Session", "A scan is in progress. Stop it and open another session?"))
            return;
        using var dlg = new OpenFileDialog
        {
            Title = "Open Session",
            Filter = SessionFilter,
            CheckFileExists = true,
            Multiselect = false,
        };
        if (dlg.ShowDialog(this) == DialogResult.OK) OpenSessionFrom(dlg.FileName);
    }

    public bool OpenSessionFrom(string path)
    {
        SessionFile file;
        try
        {
            file = SessionFile.Read(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException)
        {
            Notify("Open Session", $"The session could not be opened: {ex.Message}", IconId.Warning);
            return false;
        }
        _consumer?.Cancel();
        _engine.Reset();
        _session.LoadFrom(file, Path.GetFileName(path));
        _session.AddLog(LogLevel.Ok, "session", $"Session loaded from {path}: {file.Hosts.Count} host(s), {file.Ports.Count} service(s), {file.Findings.Count} finding(s), {file.Urls.Count} URL(s)");
        _sessionPath = path;
        _targetBar.ClearFilter();
        SetSessionTitle();
        SyncUi(force: true);
        return true;
    }

    public void ExportReport(ExportFormat format, ReportScope? scope = null)
    {
        scope ??= ReportScope.Complete;
        var info = ReportExporter.Describe(format, scope);
        using var dlg = new SaveFileDialog
        {
            Title = $"Export {info.Name}",
            Filter = info.Filter,
            DefaultExt = info.Extension,
            AddExtension = true,
            OverwritePrompt = true,
            FileName = $"tryz-{info.FileTag}-{SafeName(_session.Target)}-{DateTime.Now:yyyyMMdd-HHmm}.{info.Extension}",
        };
        if (dlg.ShowDialog(this) == DialogResult.OK) ExportTo(dlg.FileName, format, scope);
    }

    public bool ExportTo(string path, ExportFormat format, ReportScope? scope = null)
    {
        scope ??= ReportScope.Complete;
        var info = ReportExporter.Describe(format, scope);
        try
        {
            ReportExporter.Write(path, format, _session, _settings, scope);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            Notify("Export", $"The file could not be written: {ex.Message}", IconId.Warning);
            return false;
        }
        _session.AddLog(LogLevel.Ok, "report", $"{info.Name} written to {path}");
        return true;
    }

    private static string SafeName(string text)
    {
        if (text.Length == 0) return "session";
        var sb = new StringBuilder();
        foreach (char c in text)
            sb.Append(char.IsLetterOrDigit(c) || c is '.' or '-' ? c : '_');
        string name = sb.ToString().Trim('_');
        return name.Length == 0 ? "session" : name.Length > 48 ? name[..48] : name;
    }

    private async Task ConsumeAsync(ChannelReader<ScanEvent> reader, CancellationToken token)
    {
        try
        {
            while (await reader.WaitToReadAsync(token))
            {
                int budget = 4000;
                while (budget-- > 0 && !token.IsCancellationRequested && reader.TryRead(out var ev))
                {
                    if (ev is ScanCompleted)
                    {
                        _engine.MarkCompleted();
                        // Tasks still open at this point belong to a phase the engine abandoned (for example after an internal error).
                        _session.CancelOpenTasks();
                        continue;
                    }
                    if (ev is ScanFailed)
                    {
                        _engine.MarkFailed();
                        _session.CancelOpenTasks();
                        _session.Dirty = true;
                        continue;
                    }
                    if (ev is ScanLog { Level: LogLevel.Debug } && !_settings.LogDebug) continue;
                    _session.Apply(ev);
                }
                if (budget <= 0) await Task.Yield();
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void StopScan()
    {
        if (_engine.State is not (ScanState.Running or ScanState.Paused)) return;
        _engine.Stop();
        _consumer?.Cancel();
        _session.CancelOpenTasks();
        _session.AddLog(LogLevel.Warn, "engine", "Scan stopped by user");
    }

    public void ApplyFilter()
    {
        _session.FilterText = _targetBar.FilterText.Trim();
        SyncUi(force: true);
    }

    private void SyncDock()
    {
        _log.Sync(_session.FilterText);
        if (_dockFindingRows.Sync(_session.FilterText)) _dockFindings.Sync();
        if (_dockTaskRows.Sync(_session.FilterText)) _dockTasks.Sync();
        if (_dockFindingRows.Count != _lastFindingsTab)
        {
            _lastFindingsTab = _dockFindingRows.Count;
            _dock.SetTitle(1, $"Findings ({_lastFindingsTab})");
        }
        int running = _session.Tasks.Items.Count(t => t.State == TaskState.Running);
        if (running != _lastTaskTab)
        {
            _lastTaskTab = running;
            _dock.SetTitle(2, $"Task Queue ({running} running)");
        }
    }

    public void SyncUi(bool force = false)
    {
        if (!force && !_session.Dirty) return;
        _session.Dirty = false;
        SyncDock();
        _active?.SyncData();
        var s = _session;
        _nav.SetCount(1, s.Hosts.Items.Count > 0 ? s.Hosts.Items.Count.ToString() : null);
        _nav.SetCount(2, s.Ports.Items.Count > 0 ? s.Ports.Items.Count.ToString() : null);
        _nav.SetCount(3, s.FindingCount > 0 ? s.FindingCount.ToString() : null);
        _nav.SetCount(4, s.Urls.Items.Count > 0 ? FormatCompact(s.Urls.Items.Count) : null);
        _nav.SetSummary(new List<(string, string)>
        {
            ("Target", s.Target.Length > 0 ? s.Target : "-"),
            ("Profile", s.Profile.Length > 0 ? s.Profile : "-"),
            ("Requests", s.TotalRequests.ToString("N0")),
            ("Elapsed", TimeSpan.FromSeconds(s.ElapsedSeconds).ToString(@"mm\:ss")),
        });
        UpdateStatus();
    }

    private static string FormatCompact(int n) => n >= 10_000 ? $"{n / 1000}k" : n.ToString();

    private void UpdateStatus()
    {
        var s = _session;
        string state = _engine.State switch
        {
            ScanState.Running => $"Running: {s.PhaseText}",
            ScanState.Paused => $"Paused: {s.PhaseText}",
            ScanState.Stopped => "Stopped",
            ScanState.Failed => "Failed — see activity log",
            ScanState.Completed => "Completed",
            _ => "Ready",
        };
        _status.SetValues(_engine.State, state,
            $"Threads {s.ActiveThreads}/{(s.Threads > 0 ? s.Threads : _targetBar.Threads)}",
            $"Elapsed {TimeSpan.FromSeconds(s.ElapsedSeconds):mm\\:ss}",
            $"Req/s {s.RequestsPerSecond:0}",
            $"Findings {s.FindingCount}",
            s.Progress);
    }

    private void UpdateCommandState()
    {
        var st = _engine.State;
        bool running = st == ScanState.Running, paused = st == ScanState.Paused;
        _toolbar.SetEnabled(_tbStart, !running);
        _toolbar.SetEnabled(_tbPause, running);
        _toolbar.SetEnabled(_tbStop, running || paused);
        _miStart.Enabled = !running;
        _miPause.Enabled = running;
        _miStop.Enabled = running || paused;
        _miStart.Text = paused ? "Re&sume" : "&Start";
        _targetBar.SetScanState(st);
        UpdateStatus();
    }

    protected override bool ProcessCmdKey(ref Message msg, Keys keyData)
    {
        if (keyData == Keys.Escape && _engine.State is ScanState.Running or ScanState.Paused && Form.ActiveForm == this)
        {
            StopScan();
            return true;
        }
        return base.ProcessCmdKey(ref msg, keyData);
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        _uiTimer.Start();
        ActiveControl = _nav;
        SyncUi(force: true);
    }

    protected override void OnSizeChanged(EventArgs e)
    {
        base.OnSizeChanged(e);
        _status?.Invalidate();
        Caption.Invalidate();
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing && _engine.State is ScanState.Running or ScanState.Paused && _settings.ConfirmStop && PersistOnClose
            && !MessageDialog.Ask(this, "Exit", "A scan is in progress. Stop it and exit?"))
        {
            e.Cancel = true;
            return;
        }
        base.OnFormClosing(e);
        _uiTimer.Stop();
        _consumer?.Cancel();
        _engine.Dispose();
        if (!PersistOnClose) return;
        var bounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
        _settings.WindowX = bounds.X;
        _settings.WindowY = bounds.Y;
        _settings.WindowWidth = bounds.Width;
        _settings.WindowHeight = bounds.Height;
        _settings.Maximized = WindowState == FormWindowState.Maximized;
        _settings.DockHeight = _mainSplit.Position;
        _settings.DockTab = _dock.SelectedIndex;
        _settings.DefaultProfile = _targetBar.ProfileIndex;
        _settings.DefaultThreads = _targetBar.Threads;
        _settings.Save();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _uiTimer.Dispose();
            _consumer?.Dispose();
        }
        base.Dispose(disposing);
    }
}

internal sealed class TargetBar : SkinControl
{
    public const int LogicalHeight = 30;

    private readonly SkinCombo _target = new(editable: true);
    private readonly SkinCombo _profile = new();
    private readonly SkinSpin _threads;
    private readonly SkinButton _start = new("Start", IconId.Start, ButtonLook.Oxblood);
    private readonly TextField _filter = new(IconId.Filter, "Filter all grids and the log");
    private readonly (string Text, Func<Rectangle> Rect)[] _labels;
    private readonly Timer _filterDelay = new() { Interval = 140 };

    public TargetBar(AppSettings settings)
    {
        BackColor = Theme.Hex(0x1A1C1F);
        RefreshRecent(settings);
        _target.Value = settings.LastTarget;
        _profile.AddRange(ScanOptions.ProfileNames);
        _profile.SelectedIndex = Math.Clamp(settings.DefaultProfile, 0, ScanOptions.ProfileNames.Length - 1);
        _threads = new SkinSpin(Math.Clamp(settings.DefaultThreads, 1, 256), 1, 256);
        _threads.BackColor = BackColor;
        _start.BackColor = BackColor;
        _start.Click += (_, _) => StartClicked?.Invoke(this, EventArgs.Empty);
        _filterDelay.Tick += (_, _) =>
        {
            _filterDelay.Stop();
            FilterChanged?.Invoke(this, EventArgs.Empty);
        };
        _filter.Edit.TextChanged += (_, _) =>
        {
            _filterDelay.Stop();
            _filterDelay.Start();
        };
        _target.BackColor = BackColor;
        _profile.BackColor = BackColor;
        Controls.AddRange(new Control[] { _target, _profile, _threads, _start, _filter });
        _labels = new (string, Func<Rectangle>)[]
        {
            ("Target", () => _target.Bounds),
            ("Profile", () => _profile.Bounds),
            ("Threads", () => _threads.Bounds),
            ("Filter", () => _filter.Bounds),
        };
    }

    public event EventHandler? StartClicked;
    public event EventHandler? FilterChanged;

    public string TargetText => _target.Value;
    public string FilterText => _filter.Value;
    public int Threads => _threads.Value;

    public int ProfileIndex
    {
        get => _profile.SelectedIndex;
        set => _profile.SelectedIndex = value;
    }

    /// <summary>Fills the target drop-down with the last target and the targets the user has authorized.</summary>
    public void RefreshRecent(AppSettings settings)
    {
        var recent = new List<string>();
        if (!string.IsNullOrWhiteSpace(settings.LastTarget)) recent.Add(settings.LastTarget.Trim());
        for (int i = settings.AuthorizedTargets.Count - 1; i >= 0; i--)
        {
            string t = settings.AuthorizedTargets[i].Trim();
            if (t.Length > 0 && !recent.Contains(t, StringComparer.OrdinalIgnoreCase)) recent.Add(t);
        }
        string current = _target.Value;
        _target.Items.Clear();
        _target.AddRange(recent.ToArray());
        _target.Value = current;
    }

    public void ClearFilter() => _filter.Value = string.Empty;
    public void FocusFilter() => _filter.Edit.Focus();
#if DEBUG
    public void SetFilterForCapture(string text) => _filter.Value = text;
    public void SetTargetForTest(string text) => _target.Value = text;
    public SkinCombo ProfileCombo => _profile;
#endif

    public void SetScanState(ScanState state)
    {
        bool busy = state is ScanState.Running or ScanState.Paused;
        _target.Enabled = !busy;
        _profile.Enabled = !busy;
        _threads.Enabled = !busy;
        _start.Enabled = state != ScanState.Running;
        _start.Caption = state == ScanState.Paused ? "Resume" : "Start";
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _filterDelay.Dispose();
        base.Dispose(disposing);
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int y = Px(4), h = Height - Px(9);
        int x = Px(6) + Px(38);
        _target.SetBounds(x, y, Px(166), h);
        x = _target.Right + Px(8) + Px(38);
        _profile.SetBounds(x, y, Px(106), h);
        x = _profile.Right + Px(8) + Px(44);
        _threads.SetBounds(x, y, Px(56), h);
        x = _threads.Right + Px(9);
        _start.SetBounds(x, y - Px(1), Px(74), h + Px(2));
        int filterW = Px(190);
        _filter.SetBounds(Width - filterW - Px(6), y, filterW, h);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Gradient(g, ClientRectangle, Theme.Hex(0x131416), Theme.Hex(0x1E2023));
        g.DrawLine(Draw.Pen(Theme.BorderDark), 0, 0, Width, 0);
        g.DrawLine(Draw.Pen(Theme.BorderDark), 0, Height - 2, Width, Height - 2);
        g.DrawLine(Draw.Pen(Theme.EtchLight), 0, Height - 1, Width, Height - 1);
        foreach (var (text, rect) in _labels)
        {
            var b = rect();
            int w = Draw.Measure(text, UiFont) + Px(1);
            Draw.Text(g, text, UiFont, new Rectangle(b.X - w - Px(4), 0, w, Height - Px(1)), Theme.TextDim);
        }
    }
}
