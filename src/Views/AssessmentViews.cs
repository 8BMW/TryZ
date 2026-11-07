using TryZ.Data;
using TryZ.Engine;

namespace TryZ.Views;

internal sealed class LedRow : SkinControl
{
    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int n = Controls.Count;
        if (n == 0) return;
        int gap = Px(5);
        int w = (Width - gap * (n - 1)) / n;
        for (int i = 0; i < n; i++)
            Controls[i].SetBounds(i * (w + gap), 0, i == n - 1 ? Width - i * (w + gap) : w, Height);
    }
}

internal sealed class OverviewView : ModuleView
{
    private readonly EtchedGroup _sevGroup = new("Findings by Severity");
    private readonly EtchedGroup _invGroup = new("Inventory");
    private readonly EtchedGroup _graphGroup = new("Live Throughput");
    private readonly EtchedGroup _targetGroup = new("Target Summary");
    private readonly EtchedGroup _topGroup = new("Top Findings");
    private readonly EtchedGroup _phaseGroup = new("Scan Phases");
    private readonly LedCounter[] _sev;
    private readonly LedCounter _hosts = new("HOSTS", Theme.Brass);
    private readonly LedCounter _ports = new("OPEN PORTS", Theme.Brass);
    private readonly LedCounter _urls = new("URLS", Theme.Brass, 6);
    private readonly GraphView _graph = new();
    private readonly PropertySheet _target = new() { KeyWidth = 84 };
    private readonly GridView _top = new() { EmptyText = "Nothing to rank yet." };
    private readonly RowSet<Finding> _topRows;
    private readonly PhaseList _phases = new();
    private int _samplesSeen;
    private int _samplesGeneration = -1;

    public OverviewView(IShell shell) : base(shell)
    {
        _sev = new[]
        {
            new LedCounter("CRITICAL", Theme.Critical),
            new LedCounter("HIGH", Theme.High),
            new LedCounter("MEDIUM", Theme.Medium),
            new LedCounter("LOW", Theme.Low),
            new LedCounter("INFO", Theme.Hex(0xB4BAC2)),
        };
        var sevRow = new LedRow();
        sevRow.Controls.AddRange(_sev.Cast<Control>().ToArray());
        _sevGroup.SetFill(sevRow);
        var invRow = new LedRow();
        invRow.Controls.AddRange(new Control[] { _hosts, _ports, _urls });
        _invGroup.SetFill(invRow);
        _graphGroup.SetFill(_graph);
        _targetGroup.SetFill(_target);
        _topRows = Schemas.Findings(Session.Findings);
        _topRows.SetSort(0, descending: true);
        _top.Source = _topRows;
        _top.RowActivated += (_, _) => Shell.NavigateTo(3);
        _topGroup.SetFill(_top);
        _phaseGroup.SetFill(_phases);
        Controls.AddRange(new Control[] { _sevGroup, _invGroup, _graphGroup, _targetGroup, _topGroup, _phaseGroup });
    }

    public override string Title => "Overview";
    public override IconId IconKind => IconId.Overview;
    public override string Subtitle => Session.Target.Length > 0 ? $"{Session.Target}  |  {Session.Profile}" : "No scan has run in this session";

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        int gap = Px(5);
        int ledH = Px(84);
        int rightW = Px(290);
        int invW = Px(322);
        _invGroup.SetBounds(b.Right - invW, b.Y, invW, ledH);
        _sevGroup.SetBounds(b.X, b.Y, b.Width - invW - gap, ledH);
        int lowerH = Math.Clamp((b.Height - ledH - gap * 2) / 2, Px(112), Px(186));
        int midY = b.Y + ledH + gap;
        int midH = b.Bottom - midY - lowerH - gap;
        _graphGroup.SetBounds(b.X, midY, b.Width - rightW - gap, midH);
        _targetGroup.SetBounds(b.Right - rightW, midY, rightW, midH);
        int lowY = midY + midH + gap;
        _topGroup.SetBounds(b.X, lowY, b.Width - rightW - gap, lowerH);
        _phaseGroup.SetBounds(b.Right - rightW, lowY, rightW, lowerH);
    }

    public override void SyncData()
    {
        var s = Session;
        for (int i = 0; i < 5; i++) _sev[i].Value = s.SeverityCounts[4 - i];
        _hosts.Value = s.Hosts.Items.Count;
        _ports.Value = s.Ports.Items.Count(p => p.State == "open");
        _urls.Value = s.Urls.Items.Count;

        if (_samplesGeneration != s.SamplesGeneration)
        {
            _samplesGeneration = s.SamplesGeneration;
            _samplesSeen = 0;
            _graph.Clear();
        }
        for (; _samplesSeen < s.Samples.Count; _samplesSeen++)
            _graph.Push(s.Samples[_samplesSeen].RequestsPerSecond, s.Samples[_samplesSeen].LatencyMs);

        _target.SetRows(new List<(string, string, Color?)>
        {
            ("Target", s.Target.Length > 0 ? s.Target : "(none)", null),
            ("Profile", s.Profile.Length > 0 ? s.Profile : "(none)", null),
            ("Worker threads", s.Threads > 0 ? s.Threads.ToString() : "-", null),
            ("Started", s.StartedAt?.ToString("yyyy-MM-dd HH:mm:ss") ?? "-", null),
            ("Elapsed", TimeSpan.FromSeconds(s.ElapsedSeconds).ToString(@"mm\:ss"), null),
            ("Current phase", s.PhaseText, Theme.Brass),
            ("Requests sent", s.TotalRequests.ToString("N0"), null),
            ("Mean latency", s.LatencyMs > 0 ? $"{s.LatencyMs:0} ms" : "-", null),
            ("Hosts audited", s.Hosts.Items.Count(h => h.State == "Audited").ToString(), null),
            ("Engine", "TryZ engine 1.0 (live)", Theme.Ok),
        });

        if (_topRows.Sync(s.FilterText)) _top.Sync();

        var rows = new List<PhaseRow>(5);
        for (int i = 0; i < 5; i++)
        {
            double p = s.PhaseProgress[i];
            rows.Add(new PhaseRow(Session.PhaseNames[i], p, p >= 0.999 ? "done" : p > 0 ? $"{p * 100:0}%" : "queued"));
        }
        _phases.SetRows(rows);
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }
}

internal sealed class DiscoveryView : ModuleView
{
    private readonly GridView _grid = new() { EmptyText = "No hosts discovered. Press F5 to start a scan." };
    private readonly RowSet<HostRecord> _rows;
    private readonly PropertySheet _detail = new() { KeyWidth = 78 };
    private readonly GridView _hostPorts = new() { EmptyText = "Select a host." };
    private readonly RowStore<PortRecord> _detailStore = new();
    private readonly RowSet<PortRecord> _detailRows;
    private readonly SkinCombo _stateFilter = new();
    private readonly SkinCheck _webOnly = new("Web hosts only");
    private readonly SkinLabel _count = new() { TextColor = Theme.TextDim };
    private readonly SkinButton _toPorts = new("Open in Port Audit", IconId.PortAudit);
    private readonly SkinButton _toBench = new("Open in Workbench", IconId.Workbench);
    private readonly SkinLabel _stateLabel = new("State") { TextColor = Theme.TextDim };
    private readonly SkinPanel _left = new();
    private readonly SkinPanel _right = new();
    private readonly EtchedGroup _detailGroup = new("Host Detail");
    private readonly EtchedGroup _portGroup = new("Services");
    private readonly SplitBox _split;

    public DiscoveryView(IShell shell) : base(shell)
    {
        _rows = Schemas.Hosts(Session.Hosts);
        _grid.Source = _rows;
        _grid.SelectionChanged += (_, _) => ShowDetail();
        _grid.RowActivated += (_, _) => OpenPorts();
        _stateFilter.AddRange("All states", "Up", "Scanning", "Audited");
        _stateFilter.SelectedIndex = 0;
        _stateFilter.SelectionChanged += (_, _) => ApplyScope();
        _webOnly.CheckedChanged += (_, _) => ApplyScope();
        _toPorts.Click += (_, _) => OpenPorts();
        _toBench.Click += (_, _) =>
        {
            if (_grid.SelectedItem is HostRecord h) Shell.OpenInWorkbench("GET", WebUrlFor(h));
            else Shell.Notify("Workbench", "Select a host first.");
        };
        _left.Controls.AddRange(new Control[] { _stateLabel, _stateFilter, _webOnly, _count, _grid });
        _left.Layout += (_, _) => LayoutLeft();

        _detailRows = Schemas.Ports(_detailStore);
        _detailRows.Columns[4].Width = 150;
        _hostPorts.Source = _detailRows;
        _detailGroup.SetFill(_detail);
        _portGroup.SetFill(_hostPorts);
        _right.Controls.AddRange(new Control[] { _detailGroup, _portGroup, _toPorts, _toBench });
        _right.Layout += (_, _) => LayoutRight();

        _split = new SplitBox(true, _left, _right, 300, fixSecond: true) { MinFirst = 300, MinSecond = 220 };
        Controls.Add(_split);
    }

    public override string Title => "Discovery";
    public override IconId IconKind => IconId.Discovery;
    public override string Subtitle => $"{Session.Hosts.Items.Count} hosts up  |  reverse names from DNS";

    private void LayoutLeft()
    {
        int h = Px(20);
        _stateLabel.SetBounds(0, Px(1), Px(32), h);
        _stateFilter.SetBounds(Px(34), Px(1), Px(104), h);
        _webOnly.SetBounds(Px(148), Px(1), Px(110), h);
        _count.SetBounds(Px(262), Px(1), Math.Max(0, _left.Width - Px(262)), h);
        _grid.SetBounds(0, Px(25), _left.Width, Math.Max(0, _left.Height - Px(25)));
    }

    private void LayoutRight()
    {
        int w = _right.Width, h = _right.Height;
        int detailH = Px(160);
        int btnH = Px(23);
        _detailGroup.SetBounds(0, 0, w, detailH);
        int btnY = h - btnH;
        int half = (w - Px(4)) / 2;
        _toPorts.SetBounds(0, btnY, half, btnH);
        _toBench.SetBounds(half + Px(4), btnY, w - half - Px(4), btnH);
        _portGroup.SetBounds(0, detailH + Px(4), w, Math.Max(0, btnY - detailH - Px(8)));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    private void ApplyScope()
    {
        string state = _stateFilter.SelectedIndex > 0 ? _stateFilter.Value : string.Empty;
        bool web = _webOnly.Checked;
        var session = Session;
        _rows.SetScope(state.Length == 0 && !web ? null : h =>
            (state.Length == 0 || h.State == state)
            && (!web || session.PortsFor(h.Ip).Any(IsWeb)));
        _grid.Sync();
    }

    private static bool IsWeb(PortRecord p) =>
        p.State == "open" && (p.Service.Contains("http", StringComparison.OrdinalIgnoreCase) || p.Port is 80 or 443 or 8000 or 8080 or 8443);

    private static bool IsTls(PortRecord p) =>
        p.Service.Contains("https", StringComparison.OrdinalIgnoreCase) || p.Service.Contains("ssl", StringComparison.OrdinalIgnoreCase)
        || p.Port is 443 or 8443;

    /// <summary>Best URL for the host's first web service (TLS preferred), falling back to http on port 80.</summary>
    private string WebUrlFor(HostRecord h)
    {
        string name = h.Hostname.Length > 0 && h.Hostname != "-" ? h.Hostname : h.Ip;
        if (name.Contains(':') && !name.StartsWith('[')) name = $"[{name}]";
        var web = Session.PortsFor(h.Ip).Where(IsWeb).OrderByDescending(IsTls).ThenBy(p => p.Port).FirstOrDefault();
        if (web == null) return $"http://{name}/";
        bool tls = IsTls(web);
        bool defaultPort = tls ? web.Port == 443 : web.Port == 80;
        return $"{(tls ? "https" : "http")}://{name}{(defaultPort ? string.Empty : ":" + web.Port)}/";
    }

    private void OpenPorts()
    {
        if (_grid.SelectedItem is HostRecord h) Shell.SelectHostInPortAudit(h.Ip);
        else Shell.NavigateTo(2);
    }

    public override void PrepareForCapture()
    {
        SyncData();
        if (_rows.Count > 2) _grid.SelectRow(2);
    }

    private void ShowDetail()
    {
        _detailStore.Clear();
        if (_grid.SelectedItem is not HostRecord h)
        {
            _detail.SetRows(new List<(string, string, Color?)> { ("Host", "(no selection)", Theme.TextDim) });
            _detailRows.Sync(string.Empty);
            _hostPorts.Sync();
            return;
        }
        _detail.SetRows(new List<(string, string, Color?)>
        {
            ("Address", h.Ip, null),
            ("Hostname", h.Hostname, null),
            ("Role", h.Role, null),
            ("OS guess", h.OsGuess, null),
            ("TTL", h.Ttl.ToString(), null),
            ("Latency", h.LatencyText, null),
            ("Open ports", h.OpenPorts.ToString(), null),
            ("State", h.State, Schemas.HostStateColor(h.State)),
        });
        _detailStore.AddRange(Session.PortsFor(h.Ip));
        _detailRows.Sync(string.Empty);
        _hostPorts.Sync();
    }

    public override void SyncData()
    {
        if (_rows.Sync(Session.FilterText))
        {
            _grid.Sync();
            if (_grid.SelectedItem != null) ShowDetail();
        }
        if (_grid.SelectedItem == null && _detailStore.Items.Count == 0)
            _detail.SetRows(new List<(string, string, Color?)> { ("Host", "(no selection)", Theme.TextDim) });
        _count.Caption = $"{_rows.Count} of {Session.Hosts.Items.Count} shown";
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }
}

internal sealed class PortAuditView : ModuleView
{
    private readonly GridView _hosts = new() { EmptyText = "No hosts." };
    private readonly RowSet<HostRecord> _hostRows;
    private readonly GridView _ports = new() { EmptyText = "No services recorded." };
    private readonly RowSet<PortRecord> _portRows;
    private readonly SkinLabel _portCaption = new("All hosts", true) { TextColor = Theme.Brass };
    private readonly SkinButton _allHosts = new("All Hosts");
    private readonly SkinPanel _center = new();
    private readonly SkinPanel _optionsPanel = new();
    private readonly SkinRadio _top100 = new("Top 100");
    private readonly SkinRadio _top1000 = new("Top 1000");
    private readonly SkinRadio _allPorts = new("All 65535");
    private readonly SkinSpin _rate = new(400, 1, 5000, 10);
    private readonly SkinSpin _timeout = new(1500, 100, 30000, 100);
    private readonly SkinCheck _assumeUp = new("Skip discovery");
    private readonly SkinButton _apply = new("Use as Custom Profile", IconId.Check);
    private readonly SplitBox _split;
    private string? _selectedIp;

    public PortAuditView(IShell shell) : base(shell)
    {
        _hostRows = Schemas.HostsCompact(Session.Hosts);
        _hostRows.SetSort(0, descending: false);
        _hosts.Source = _hostRows;
        _hosts.SelectionChanged += (_, _) =>
        {
            _selectedIp = (_hosts.SelectedItem as HostRecord)?.Ip;
            ApplyScope();
        };

        _portRows = Schemas.Ports(Session.Ports);
        _ports.Source = _portRows;
        _allHosts.Click += (_, _) =>
        {
            _hosts.ClearSelection();
            _selectedIp = null;
            ApplyScope();
        };
        _center.Controls.AddRange(new Control[] { _portCaption, _allHosts, _ports });
        _center.Layout += (_, _) =>
        {
            _portCaption.SetBounds(0, Px(1), Math.Max(0, _center.Width - Px(76)), Px(20));
            _allHosts.SetBounds(_center.Width - Px(72), 0, Px(72), Px(21));
            _ports.SetBounds(0, Px(25), _center.Width, Math.Max(0, _center.Height - Px(25)));
        };

        var technique = new EtchedGroup("Technique");
        technique.Add(null, new SkinLabel("TCP connect() sweep, then banner, TLS and HTTP identification of each open port.") { Wrap = true, TextColor = Theme.TextDim }, height: 44);
        var range = new EtchedGroup("Port Range");
        range.Add(null, _top100, height: 17);
        range.Add(null, _top1000, height: 17);
        range.Add(null, _allPorts, height: 17);
        var pacing = new EtchedGroup("Pacing") { LabelWidth = 62 };
        pacing.Add("Req / s", _rate);
        pacing.Add("Timeout", _timeout);
        var detect = new EtchedGroup("Discovery");
        detect.Add(null, _assumeUp, height: 17);
        LoadOptions();
        var stack = new ScrollStack(technique, range, pacing, detect);
        _optionsPanel.Controls.Add(stack);
        _optionsPanel.Controls.Add(_apply);
        _optionsPanel.Layout += (_, _) =>
        {
            int btnH = Px(23);
            stack.SetBounds(0, 0, _optionsPanel.Width, Math.Max(0, _optionsPanel.Height - btnH - Px(4)));
            _apply.SetBounds(0, _optionsPanel.Height - btnH, _optionsPanel.Width, btnH);
        };
        _apply.Click += (_, _) => ApplyOptions();

        var inner = new SplitBox(true, _center, _optionsPanel, 176, fixSecond: true) { MinFirst = 280, MinSecond = 160 };
        _split = new SplitBox(true, _hosts, inner, 164) { MinFirst = 120, MinSecond = 400 };
        Controls.Add(_split);
    }

    private void LoadOptions()
    {
        var st = Shell.Settings;
        int sel = Math.Clamp(st.CustomPortSelection, 0, 2);
        _top100.Checked = sel == 0;
        _top1000.Checked = sel == 1;
        _allPorts.Checked = sel == 2;
        _rate.Value = Math.Clamp(st.MaxRequestsPerSecond, _rate.Minimum, _rate.Maximum);
        _timeout.Value = Math.Clamp(st.ConnectTimeoutMs, _timeout.Minimum, _timeout.Maximum);
        _assumeUp.Checked = st.AssumeHostsUp;
    }

    private void ApplyOptions()
    {
        var st = Shell.Settings;
        st.CustomPortSelection = _top100.Checked ? 0 : _allPorts.Checked ? 2 : 1;
        st.MaxRequestsPerSecond = _rate.Value;
        st.ConnectTimeoutMs = _timeout.Value;
        st.AssumeHostsUp = _assumeUp.Checked;
        st.Save();
        Shell.UseCustomProfile();
        Shell.LogUser("portaudit", $"Custom profile set: {(st.CustomPortSelection == 0 ? "top 100" : st.CustomPortSelection == 1 ? "top 1000" : "all 65535")} ports, {st.MaxRequestsPerSecond} req/s, connect timeout {st.ConnectTimeoutMs} ms{(st.AssumeHostsUp ? ", discovery skipped" : string.Empty)}");
    }

    public override string Title => "Port Audit";
    public override IconId IconKind => IconId.PortAudit;
    public override string Subtitle => $"{Session.Ports.Items.Count} services on {Session.Hosts.Items.Count} hosts";

    public override void PrepareForCapture()
    {
        SyncData();
        if (_hostRows.Count > 12) _hosts.SelectRow(12);
    }

    public void SelectHost(string ip)
    {
        SyncData();
        for (int i = 0; i < _hostRows.Count; i++)
        {
            if (_hostRows.Rows[i].Ip == ip)
            {
                _hosts.SelectRow(i);
                return;
            }
        }
    }

    private void ApplyScope()
    {
        string? ip = _selectedIp;
        _portRows.SetScope(ip == null ? null : p => p.HostIp == ip);
        _portCaption.Caption = ip == null ? "All hosts" : ip;
        _ports.Sync();
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    public override void SyncData()
    {
        if (_hostRows.Sync(Session.FilterText)) _hosts.Sync();
        if (_portRows.Sync(Session.FilterText)) _ports.Sync();
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }
}

internal sealed class ScrollStack : SkinControl
{
    private readonly EtchedGroup[] _groups;
    private readonly SkinScrollBar _bar = new(false);

    public ScrollStack(params EtchedGroup[] groups)
    {
        _groups = groups;
        Controls.AddRange(groups.Cast<Control>().ToArray());
        Controls.Add(_bar);
        _bar.ValueChanged += (_, _) => PerformLayout();
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int gap = Px(5);
        int content = _groups.Sum(g => Px(g.PreferredLogicalHeight) + gap) - gap;
        bool overflow = content > Height;
        int th = _bar.ThicknessPx;
        _bar.Visible = overflow;
        _bar.SetBounds(Width - th, 0, th, Height);
        _bar.SmallChange = Px(16);
        _bar.SetRange(content, Math.Max(1, Height));
        int w = overflow ? Width - th - Px(2) : Width;
        int y = -_bar.Value;
        foreach (var g in _groups)
        {
            int h = Px(g.PreferredLogicalHeight);
            g.SetBounds(0, y, w, h);
            y += h + gap;
        }
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _bar.Value -= e.Delta / 120 * Px(32);
    }
}

internal sealed class VulnerabilityView : ModuleView
{
    private readonly GridView _grid = new() { EmptyText = "No findings recorded. Press F5 to start a scan." };
    private readonly RowSet<Finding> _rows;
    private readonly SkinCheck[] _sev;
    private readonly SkinButton _confirm = new("Confirm", IconId.Check);
    private readonly SkinButton _falsePositive = new("False Positive");
    private readonly SkinButton _accept = new("Accept Risk");
    private readonly SkinButton _reset = new("Reset");
    private readonly SkinPanel _top = new();
    private readonly TabHost _tabs = new();
    private readonly TextPane _desc = new();
    private readonly CodeView _evidence = new() { ReadOnly = true, Syntax = new HttpSyntax() };
    private readonly TextPane _remedy = new();
    private readonly SplitBox _split;

    public VulnerabilityView(IShell shell) : base(shell)
    {
        _rows = Schemas.Findings(Session.Findings);
        _grid.Source = _rows;
        _grid.SelectionChanged += (_, _) => ShowDetail();
        _sev = new[]
        {
            new SkinCheck("Critical", true), new SkinCheck("High", true), new SkinCheck("Medium", true),
            new SkinCheck("Low", true), new SkinCheck("Info", true),
        };
        foreach (var c in _sev) c.CheckedChanged += (_, _) => ApplyScope();
        _confirm.Click += (_, _) => SetStatus(FindingStatus.Confirmed);
        _falsePositive.Click += (_, _) => SetStatus(FindingStatus.FalsePositive);
        _accept.Click += (_, _) => SetStatus(FindingStatus.Accepted);
        _reset.Click += (_, _) => SetStatus(FindingStatus.New);
        _top.Controls.AddRange(_sev.Cast<Control>().ToArray());
        _top.Controls.AddRange(new Control[] { _confirm, _falsePositive, _accept, _reset, _grid });
        _top.Layout += (_, _) => LayoutTop();

        _tabs.AddPage("Description", IconId.Page, _desc);
        _tabs.AddPage("Evidence", IconId.Script, _evidence);
        _tabs.AddPage("Remediation", IconId.Check, _remedy);

        _split = new SplitBox(false, _top, _tabs, 180, fixSecond: true) { MinFirst = 120, MinSecond = 90 };
        Controls.Add(_split);
        ShowDetail();
    }

    public override string Title => "Vulnerability Audit";
    public override IconId IconKind => IconId.Vulnerability;
    public override string Subtitle => $"{Session.FindingCount} findings  |  {Session.SeverityCounts[4]} critical, {Session.SeverityCounts[3]} high";

    private void LayoutTop()
    {
        int x = 0;
        int[] w = { 62, 50, 62, 48, 48 };
        for (int i = 0; i < _sev.Length; i++)
        {
            _sev[i].SetBounds(x, Px(3), Px(w[i]), Px(17));
            x += Px(w[i] + 4);
        }
        int bw = Px(74);
        int rightX = _top.Width;
        foreach (var b in new[] { _reset, _accept, _falsePositive, _confirm })
        {
            int bwidth = b == _reset ? Px(52) : b == _falsePositive ? Px(90) : b == _confirm ? bw : Px(82);
            rightX -= bwidth;
            b.SetBounds(rightX, 0, bwidth, Px(22));
            rightX -= Px(3);
        }
        _grid.SetBounds(0, Px(26), _top.Width, Math.Max(0, _top.Height - Px(26)));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    private void ApplyScope()
    {
        bool[] on = _sev.Select(c => c.Checked).ToArray();
        _rows.SetScope(f => on[4 - (int)f.Severity]);
        _grid.Sync();
        ShowDetail();
    }

    private void SetStatus(FindingStatus status)
    {
        if (_grid.SelectedItem is not Finding f)
        {
            Shell.Notify("Findings", "Select a finding first.");
            return;
        }
        f.Status = status;
        Session.Findings.Touch();
        Session.Dirty = true;
        Shell.LogUser("audit", $"Finding #{f.Id} marked {f.StatusText}: {f.Title} on {f.Host}:{f.Port}");
        ShowDetail();
    }

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not Finding f)
        {
            _desc.SetBlocks(new() { ("Select a finding to read its description.", false, false) });
            _evidence.Value = string.Empty;
            _remedy.SetBlocks(new() { ("Select a finding to read the suggested remediation.", false, false) });
            return;
        }
        _desc.SetBlocks(new()
        {
            (f.Title, true, false),
            ($"{f.Severity}  |  {f.CweText}  |  {f.Host}:{f.Port}  |  {f.StatusText}", false, true),
            (f.Description, false, false),
        });
        _evidence.Value = f.Evidence;
        _remedy.SetBlocks(new()
        {
            ("Suggested remediation", true, false),
            (f.Remediation, false, false),
        });
    }

    public override void SyncData()
    {
        if (_rows.Sync(Session.FilterText)) _grid.Sync();
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }

    public override void PrepareForCapture()
    {
        SyncData();
        _rows.SetSort(0, descending: true);
        _grid.Sync();
        if (_rows.Count > 0) _grid.SelectRow(0);
    }
}
