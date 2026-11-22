using TryZ.Data;

namespace TryZ.Views;

/// <summary>Ranks current findings using severity and available exploitation data.</summary>
internal sealed class RemediationView : ModuleView
{
    private readonly GridView _grid = new() { EmptyText = "No active findings. Run a scan or include accepted / false-positive findings." };
    private readonly RowSet<Finding> _rows;
    private readonly SkinCheck _includeClosed = new("Include accepted / false positives");
    private readonly SkinLabel _count = new() { TextColor = Theme.TextDim };
    private readonly SkinPanel _top = new();
    private readonly TextPane _detail = new();
    private readonly SplitBox _split;
    private int _lastMutation = -1;
    private int _lastGeneration = -1;

    public RemediationView(IShell shell) : base(shell)
    {
        _rows = new RowSet<Finding>(Session.Findings,
            new Col<Finding>("Score", 55, f => Prioritizer.Evaluate(f).Score.ToString("0"))
            { Compare = (a, b) => Prioritizer.Evaluate(a).Score.CompareTo(Prioritizer.Evaluate(b).Score), Align = HorizontalAlignment.Right, Mono = true },
            new Col<Finding>("Priority", 86, f => Prioritizer.Evaluate(f).TierText)
            { Color = f => PriorityColor(Prioritizer.Evaluate(f).Tier) },
            new Col<Finding>("Finding", 290, f => f.Title),
            new Col<Finding>("Host", 125, f => f.Host) { Mono = true },
            new Col<Finding>("Port", 48, f => f.Port == 0 ? "-" : f.Port.ToString())
            { Compare = (a, b) => a.Port.CompareTo(b.Port), Align = HorizontalAlignment.Right, Mono = true },
            new Col<Finding>("Status", 90, f => f.StatusText));
        _rows.SetSort(0, descending: true);
        _rows.SetScope(IsVisible);
        _grid.Source = _rows;
        _grid.SelectionChanged += (_, _) => ShowDetail();
        _includeClosed.CheckedChanged += (_, _) => { _rows.SetScope(IsVisible); _grid.Sync(); ShowDetail(); UpdateCaption(); };
        _top.Controls.AddRange(new Control[] { _includeClosed, _count, _grid });
        _top.Layout += (_, _) =>
        {
            _includeClosed.SetBounds(0, Px(3), Px(215), Px(18));
            _count.SetBounds(Px(220), Px(3), Math.Max(0, _top.Width - Px(220)), Px(18));
            _grid.SetBounds(0, Px(25), _top.Width, Math.Max(0, _top.Height - Px(25)));
        };
        _split = new SplitBox(false, _top, _detail, 210, fixSecond: true) { MinFirst = 120, MinSecond = 100 };
        Controls.Add(_split);
        ShowDetail();
    }

    public override string Title => "Remediation Plan";
    public override IconId IconKind => IconId.Remediation;
    public override string Subtitle => "Prioritized findings  |  scores are an ordering aid";

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    private bool IsVisible(Finding f) => _includeClosed.Checked || f.Status is not (FindingStatus.Accepted or FindingStatus.FalsePositive);

    private static Color PriorityColor(PriorityTier tier) => tier switch
    {
        PriorityTier.FixNow => Theme.Critical,
        PriorityTier.FixNext => Theme.High,
        PriorityTier.Planned => Theme.Medium,
        _ => Theme.TextDim,
    };

    private void UpdateCaption() => _count.Caption = $"{_rows.Count} shown / {Session.Findings.Items.Count} findings";

    private void ShowDetail()
    {
        if (_grid.SelectedItem is not Finding f)
        {
            ShowPlanOverview();
            return;
        }
        var priority = Prioritizer.Evaluate(f);
        var blocks = new List<(string, bool, bool)>
        {
            (f.Title, true, false),
            ($"{priority.TierText}  |  {priority.Score:0}/100  |  {f.Host}{(f.Port > 0 ? $":{f.Port}" : string.Empty)}  |  {f.StatusText}", false, true),
            ("Why this priority", true, false),
        };
        blocks.AddRange(priority.Reasons.Select(reason => ("• " + reason, false, false)));
        blocks.Add(("Priority is a heuristic; asset importance, local exposure and confidence are not currently supplied. Verify applicability before remediation.", false, false));
        blocks.Add(("Recommended action", true, false));
        blocks.Add((f.Remediation, false, false));
        _detail.SetBlocks(blocks);
    }

    /// <summary>Shown when no single finding is selected: the consolidated remediation plan across the visible findings.</summary>
    private void ShowPlanOverview()
    {
        var plan = RemediationPlan.Build(Session.Findings.Items, _includeClosed.Checked);
        if (plan.Actions.Count == 0)
        {
            _detail.SetBlocks(new() { ("Select a finding to see its priority, reasons and recommended action. No active findings to plan yet.", false, false) });
            return;
        }
        var blocks = new List<(string, bool, bool)>
        {
            ("Remediation plan", true, false),
            ($"{plan.Actions.Count} consolidated action(s) across {plan.FindingsCovered} finding(s)  |  " +
             $"Fix now {plan.TierFindingCounts[(int)PriorityTier.FixNow]}  ·  Fix next {plan.TierFindingCounts[(int)PriorityTier.FixNext]}  ·  " +
             $"Planned {plan.TierFindingCounts[(int)PriorityTier.Planned]}  ·  Monitor {plan.TierFindingCounts[(int)PriorityTier.Monitor]}", false, true),
            ("Select a row for the per-finding rationale, or export the full plan from Reports → Export Remediation Plan.", false, false),
            ("Top actions", true, false),
        };
        foreach (var a in plan.Actions.Take(12))
        {
            blocks.Add(($"{a.Rank}. [{a.Tier switch { PriorityTier.FixNow => "Fix now", PriorityTier.FixNext => "Fix next", PriorityTier.Planned => "Planned", _ => "Monitor" }}] {a.Category}  —  {a.MaxScore:0}/100, {a.FindingCount} finding(s), {a.Hosts.Count} host(s)", false, false));
            blocks.Add(("    " + a.Guidance, false, false));
        }
        _detail.SetBlocks(blocks);
    }

    public override void SyncData()
    {
        // Scope depends on mutable status; enrichment can also alter the ranking and the selected detail.
        var store = Session.Findings;
        if (_lastMutation != store.MutationVersion || _lastGeneration != store.Generation)
        {
            _lastMutation = store.MutationVersion;
            _lastGeneration = store.Generation;
            _rows.SetScope(IsVisible);
            _rows.Sync(Session.FilterText);
            _grid.Sync();
            ShowDetail();
        }
        else if (_rows.Sync(Session.FilterText))
        {
            _grid.Sync();
            ShowDetail();
        }
        UpdateCaption();
    }

    public override void PrepareForCapture()
    {
        SyncData();
        if (_rows.Count > 0) _grid.SelectRow(0);
    }
}
