using TryZ.Data;

namespace TryZ.Views;

/// <summary>Compare the current observations against a saved session.</summary>
internal sealed class CompareView : ModuleView
{
    private readonly SkinButton _open = new("Choose Baseline...", IconId.Open);
    private readonly SkinButton _clear = new("Clear");
    private readonly SkinLabel _baselineLabel = new("No baseline selected") { TextColor = Theme.Brass };
    private readonly SkinLabel _notice = new("Not observed does not mean fixed: coverage, scope and scan settings may differ.") { TextColor = Theme.TextDim };
    private readonly SkinLabel _summary = new() { TextColor = Theme.TextDim };
    private readonly SkinCombo _kind = new();
    private readonly SkinCombo _change = new();
    private readonly GridView _grid = new() { EmptyText = "Choose a saved session as the baseline." };
    private readonly PropertySheet _details = new() { KeyWidth = 86 };
    private readonly EtchedGroup _changes = new("Observed Changes");
    private readonly EtchedGroup _detailGroup = new("Comparison Detail");
    private readonly RowStore<ComparisonRow> _store = new();
    private readonly RowSet<ComparisonRow> _rows;
    private SessionFile? _baseline;
    private string _baselinePath = string.Empty;
    private (int fg, int fc, int fm, int pg, int pc, int pm) _lastState = (-1, -1, -1, -1, -1, -1);

    public CompareView(IShell shell) : base(shell)
    {
        _rows = new RowSet<ComparisonRow>(_store,
            new Col<ComparisonRow>("Change", 94, r => r.Change) { Color = r => r.Change switch { "New" => Theme.High, "Changed" => Theme.Brass, "Not observed" => Theme.TextDim, _ => Theme.Ok } },
            new Col<ComparisonRow>("Type", 65, r => r.Kind),
            new Col<ComparisonRow>("Host", 128, r => r.Host) { Mono = true },
            new Col<ComparisonRow>("Endpoint", 75, r => r.Endpoint) { Mono = true },
            new Col<ComparisonRow>("Finding / Service", 270, r => r.Name),
            new Col<ComparisonRow>("Baseline", 220, r => r.Before),
            new Col<ComparisonRow>("Current", 220, r => r.After));
        _grid.Source = _rows;
        _grid.SelectionChanged += (_, _) => ShowDetail();
        _kind.AddRange("All types", "Finding", "Service"); _kind.SelectedIndex = 0;
        _change.AddRange("All changes", "New", "Changed", "Not observed", "Unchanged"); _change.SelectedIndex = 0;
        _kind.SelectionChanged += (_, _) => ApplyFilter();
        _change.SelectionChanged += (_, _) => ApplyFilter();
        _open.Click += (_, _) => ChooseBaseline();
        _clear.Click += (_, _) => ClearBaseline();
        _changes.SetFill(_grid);
        _detailGroup.SetFill(_details);
        Controls.AddRange([_open, _clear, _baselineLabel, _notice, _summary, _kind, _change, _changes, _detailGroup]);
        ShowDetail();
    }

    public override string Title => "Scan Compare";
    public override IconId IconKind => IconId.Compare;
    public override string Subtitle => _baseline == null ? "Choose a baseline session" : $"Baseline: {Path.GetFileName(_baselinePath)}";

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        int h = Px(23), gap = Px(5);
        _open.SetBounds(b.X, b.Y, Px(142), h);
        _clear.SetBounds(b.X + Px(147), b.Y, Px(62), h);
        _baselineLabel.SetBounds(b.X + Px(215), b.Y, Math.Max(0, b.Width - Px(215)), h);
        _notice.SetBounds(b.X, b.Y + Px(27), b.Width, Px(20));
        int filtersY = b.Y + Px(50);
        _kind.SetBounds(b.X, filtersY, Px(126), h);
        _change.SetBounds(b.X + Px(131), filtersY, Px(130), h);
        _summary.SetBounds(b.X + Px(268), filtersY, Math.Max(0, b.Width - Px(268)), h);
        int contentY = filtersY + h + gap;
        int detailHeight = Math.Min(Px(150), Math.Max(Px(90), (b.Bottom - contentY) / 3));
        _changes.SetBounds(b.X, contentY, b.Width, Math.Max(0, b.Bottom - contentY - detailHeight - gap));
        _detailGroup.SetBounds(b.X, b.Bottom - detailHeight, b.Width, detailHeight);
    }

    private void ChooseBaseline()
    {
        using var dialog = new OpenFileDialog { Title = "Choose baseline session", Filter = "TryZ session (*.tzs)|*.tzs|All files (*.*)|*.*", CheckFileExists = true, Multiselect = false };
        if (Shell.Settings.LastCompareBaseline.Length > 0)
        {
            string folder = Path.GetDirectoryName(Shell.Settings.LastCompareBaseline) ?? string.Empty;
            if (Directory.Exists(folder)) dialog.InitialDirectory = folder;
        }
        if (dialog.ShowDialog(FindForm()) == DialogResult.OK) LoadBaseline(dialog.FileName);
    }

    internal bool LoadBaseline(string path)
    {
        try
        {
            var loaded = SessionFile.Read(path);
            _baseline = loaded;
            _baselinePath = path;
            Shell.Settings.LastCompareBaseline = path;
            _lastState = (-1, -1, -1, -1, -1, -1);
            Shell.LogUser("compare", $"Baseline loaded: {Path.GetFileName(path)}");
            SyncData();
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException or NotSupportedException or ArgumentException)
        {
            Shell.Notify("Compare", $"The baseline could not be opened: {ex.Message}", IconId.Warning);
            return false;
        }
    }

    private void ClearBaseline()
    {
        _baseline = null; _baselinePath = string.Empty;
        _store.Clear(); _rows.Sync(Session.FilterText); _grid.Sync();
        _baselineLabel.Caption = "No baseline selected";
        _summary.Caption = "";
        _notice.Caption = "Not observed does not mean fixed: coverage, scope and scan settings may differ.";
        ShowDetail();
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }

    private void ApplyFilter()
    {
        string kind = _kind.SelectedIndex > 0 ? _kind.Value : string.Empty;
        string change = _change.SelectedIndex > 0 ? _change.Value : string.Empty;
        _rows.SetScope(r => (kind.Length == 0 || r.Kind == kind) && (change.Length == 0 || r.Change == change));
        _rows.Sync(Session.FilterText);
        _grid.Sync();
        ShowDetail();
        _summary.Caption = $"{_rows.Count} shown / {_store.Items.Count} observations";
    }

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not ComparisonRow item)
        {
            _details.SetRows([("Selection", "Select a row to see baseline and current details.", Theme.TextDim)]);
            return;
        }
        _details.SetRows([
            ("Change", item.Change, null), ("Type", item.Kind, null), ("Host", item.Host, null),
            ("Endpoint", item.Endpoint, null), ("Name", item.Name, null), ("Baseline", item.Before, null), ("Current", item.After, null),
        ]);
    }

    public override void SyncData()
    {
        if (_baseline == null) return;
        var findings = Session.Findings; var ports = Session.Ports;
        var state = (findings.Generation, findings.Items.Count, findings.MutationVersion, ports.Generation, ports.Items.Count, ports.MutationVersion);
        if (_lastState != state)
        {
            _lastState = state;
            var current = new SessionFile
            {
                Findings = findings.Items.Select(f => new FindingDto { Title = f.Title, Host = f.Host, Port = f.Port, Proto = f.Proto, RuleId = f.RuleId, Product = f.Product, Severity = f.Severity }).ToList(),
                Ports = ports.Items.Select(p => new PortDto { HostIp = p.HostIp, Port = p.Port, Proto = p.Proto, State = p.State, Service = p.Service, Banner = p.Banner, Risk = p.Risk }).ToList(),
            };
            _store.Clear(); _store.AddRange(ScanComparison.Build(_baseline, current));
            ApplyFilter();
        }
        else if (_rows.Sync(Session.FilterText)) { _grid.Sync(); _summary.Caption = $"{_rows.Count} shown / {_store.Items.Count} observations"; }
        _baselineLabel.Caption = $"{Path.GetFileName(_baselinePath)}  |  target: {_baseline.Target}  |  profile: {_baseline.Profile}";
        bool targetDiffers = !string.Equals(_baseline.Target?.Trim(), Session.Target?.Trim(), StringComparison.OrdinalIgnoreCase);
        bool profileDiffers = !string.Equals(_baseline.Profile?.Trim(), Session.Profile?.Trim(), StringComparison.OrdinalIgnoreCase);
        _notice.Caption = targetDiffers || profileDiffers
            ? "Target or profile differs. Not observed does not mean fixed; scan coverage may differ."
            : Session.Progress < 0.999
                ? "Current scan is incomplete or not started. Not observed does not mean fixed."
                : "Not observed does not mean fixed: coverage, scope and scan settings may differ.";
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }
}
