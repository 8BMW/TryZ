using TryZ.Data;

namespace TryZ.Views;

/// <summary>Ranks current findings using severity, available exploitation data and how much each host matters.</summary>
internal sealed class RemediationView : ModuleView
{
    private readonly GridView _grid = new() { EmptyText = "No active findings. Run a scan or include accepted / false-positive findings." };
    private readonly RowSet<Finding> _rows;
    private readonly SkinCheck _includeClosed = new("Include accepted / false positives");
    private readonly SkinLabel _count = new() { TextColor = Theme.TextDim };
    private readonly SkinLabel _importanceLabel = new("Host importance") { TextColor = Theme.TextDim };
    private readonly SkinCombo _importance = new();
    private readonly SkinPanel _top = new();
    private readonly TextPane _detail = new();
    private readonly SplitBox _split;
    private RemediationPlan? _plan;
    private Dictionary<Finding, PlanItem> _itemOf = new(ReferenceEqualityComparer.Instance);
    private int _lastMutation = -1;
    private int _lastGeneration = -1;
    private int _lastCount = -1;
    private bool _syncingImportance;

    public RemediationView(IShell shell) : base(shell)
    {
        _rows = new RowSet<Finding>(Session.Findings,
            new Col<Finding>("Score", 55, f => Session.PriorityOf(f).Score.ToString("0"))
            { Compare = (a, b) => Session.PriorityOf(a).Score.CompareTo(Session.PriorityOf(b).Score), Align = HorizontalAlignment.Right, Mono = true },
            new Col<Finding>("Priority", 86, f => Session.PriorityOf(f).TierText)
            { Color = f => PriorityColor(Session.PriorityOf(f).Tier) },
            new Col<Finding>("Due", 78, f => DueText(f))
            { Compare = (a, b) => Due(a).CompareTo(Due(b)), Mono = true, Color = f => IsOverdue(f) ? Theme.Critical : Theme.Text },
            new Col<Finding>("Finding", 270, f => f.Title),
            new Col<Finding>("Host", 125, f => f.Host) { Mono = true },
            new Col<Finding>("Port", 48, f => f.Port == 0 ? "-" : f.Port.ToString())
            { Compare = (a, b) => a.Port.CompareTo(b.Port), Align = HorizontalAlignment.Right, Mono = true },
            new Col<Finding>("Status", 90, f => f.StatusText));
        _rows.SetSort(0, descending: true);
        _rows.SetScope(IsVisible);
        _grid.Source = _rows;
        _grid.SelectionChanged += (_, _) => ShowDetail();
        _includeClosed.CheckedChanged += (_, _) => { _rows.SetScope(IsVisible); _grid.Sync(); ShowDetail(); UpdateCaption(); };
        _importance.AddRange(Prioritizer.ImportanceNames);
        _importance.SelectedIndex = (int)AssetImportance.Normal;
        _importance.Enabled = false;
        _importance.SelectionChanged += (_, _) => ImportanceChosen();
        _top.Controls.AddRange(new Control[] { _includeClosed, _count, _importanceLabel, _importance, _grid });
        _top.Layout += (_, _) =>
        {
            int comboW = Px(86), labelW = Px(92);
            int right = _top.Width;
            _importance.SetBounds(Math.Max(0, right - comboW), 0, comboW, Px(21));
            _importanceLabel.SetBounds(Math.Max(0, right - comboW - labelW - Px(4)), Px(3), labelW, Px(18));
            _includeClosed.SetBounds(0, Px(3), Px(215), Px(18));
            _count.SetBounds(Px(220), Px(3), Math.Max(0, right - Px(220) - comboW - labelW - Px(8)), Px(18));
            _grid.SetBounds(0, Px(25), _top.Width, Math.Max(0, _top.Height - Px(25)));
        };
        _split = new SplitBox(false, _top, _detail, 210, fixSecond: true) { MinFirst = 120, MinSecond = 100 };
        Controls.Add(_split);
        RebuildPlan();
        ShowDetail();
    }

    public override string Title => "Remediation Plan";
    public override IconId IconKind => IconId.Remediation;
    public override string Subtitle => _plan is { Items.Count: > 0 } plan
        ? $"{plan.Items.Count} work item(s){(plan.OverdueCount > 0 ? $", {plan.OverdueCount} overdue" : string.Empty)}  |  scores are an ordering aid"
        : "Prioritized findings  |  scores are an ordering aid";

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    private bool IsVisible(Finding f) => _includeClosed.Checked || !RemediationPlan.IsClosed(f);

    private static Color PriorityColor(PriorityTier tier) => tier switch
    {
        PriorityTier.FixNow => Theme.Critical,
        PriorityTier.FixNext => Theme.High,
        PriorityTier.Planned => Theme.Medium,
        _ => Theme.TextDim,
    };

    private DateOnly BaseDate => _plan?.BaseDate ?? DateOnly.FromDateTime(DateTime.Now);

    private DateOnly Due(Finding f) =>
        RemediationPlan.IsClosed(f) ? DateOnly.MaxValue : RemediationPlan.DueFor(f, Session.PriorityOf(f), BaseDate).Due ?? DateOnly.MaxValue;

    private string DueText(Finding f)
    {
        if (RemediationPlan.IsClosed(f)) return "-";
        var due = Due(f);
        return due == DateOnly.MaxValue ? "-" : due.ToString("yyyy-MM-dd");
    }

    private bool IsOverdue(Finding f)
    {
        var due = Due(f);
        return due != DateOnly.MaxValue && due < DateOnly.FromDateTime(DateTime.Now);
    }

    private void RebuildPlan()
    {
        _plan = RemediationPlan.Build(Session);
        _itemOf = new Dictionary<Finding, PlanItem>(ReferenceEqualityComparer.Instance);
        foreach (var item in _plan.Items)
            foreach (var f in item.Findings) _itemOf[f] = item;
    }

    private void UpdateCaption() => _count.Caption = _plan is { Items.Count: > 0 } plan
        ? $"{_rows.Count} shown / {Session.Findings.Items.Count} findings  |  {plan.Items.Count} work item(s)"
        : $"{_rows.Count} shown / {Session.Findings.Items.Count} findings";

    private void ImportanceChosen()
    {
        if (_syncingImportance || _grid.SelectedItem is not Finding f || f.Host.Length == 0) return;
        var value = (AssetImportance)Math.Clamp(_importance.SelectedIndex, 0, Prioritizer.ImportanceNames.Length - 1);
        if (Session.ImportanceOf(f.Host) == value) return;
        Session.SetImportance(f.Host, value);
        Shell.LogUser("plan", $"Host {f.Host} marked {Prioritizer.ImportanceNames[(int)value].ToLowerInvariant()} importance");
        SyncData();
    }

    private void ShowDetail()
    {
        var selected = _grid.SelectedItem as Finding;
        _syncingImportance = true;
        _importance.Enabled = selected is { Host.Length: > 0 };
        _importance.SelectedIndex = (int)(selected != null ? Session.ImportanceOf(selected.Host) : AssetImportance.Normal);
        _syncingImportance = false;

        if (selected is not Finding f)
        {
            _detail.SetBlocks(new() { ("Select a finding to see its priority, target date and recommended action.", false, false) });
            return;
        }
        var priority = Session.PriorityOf(f);
        var blocks = new List<(string, bool, bool)>
        {
            (f.Title, true, false),
            ($"{priority.TierText}  |  {priority.Score:0}/100  |  {f.Host}{(f.Port > 0 ? $":{f.Port}" : string.Empty)}  |  {f.StatusText}", false, true),
            ("Why this priority", true, false),
        };
        blocks.AddRange(priority.Reasons.Select(reason => ("• " + reason, false, false)));

        if (RemediationPlan.IsClosed(f))
            blocks.Add(($"Marked {f.StatusText.ToLowerInvariant()}, so it is left out of the plan and exports.", false, false));
        else
        {
            var (due, basis) = RemediationPlan.DueFor(f, priority, BaseDate);
            blocks.Add(("Target date", true, false));
            string when = due is DateOnly d ? d.ToString("yyyy-MM-dd") + (d < DateOnly.FromDateTime(DateTime.Now) ? "  (overdue)" : string.Empty) : "None";
            blocks.Add(($"{when}  |  {basis}", false, true));
            if (_itemOf.TryGetValue(f, out var item) && item.Endpoints.Count > 1)
            {
                blocks.Add(($"Same fix, work item #{item.Rank}", true, false));
                var others = item.Endpoints.Where(e => !string.Equals(e, RemediationPlan.Endpoint(f), StringComparison.OrdinalIgnoreCase)).ToList();
                blocks.Add(($"Also applies to {others.Count} other endpoint(s): {string.Join(", ", others.Take(12))}{(others.Count > 12 ? $" and {others.Count - 12} more" : string.Empty)}", false, true));
            }
        }
        blocks.Add(("Priority is a heuristic; local exposure is not scored. Set host importance above "
            + "for systems that matter more or less to the business, and verify applicability before remediation.", false, false));
        blocks.Add(("Recommended action", true, false));
        blocks.Add((f.Remediation, false, false));
        _detail.SetBlocks(blocks);
    }

    public override void SyncData()
    {
        // Scope depends on mutable status; enrichment and host importance can also alter the ranking and the selected detail.
        var store = Session.Findings;
        if (_lastMutation != store.MutationVersion || _lastGeneration != store.Generation || _lastCount != store.Items.Count)
        {
            _lastMutation = store.MutationVersion;
            _lastGeneration = store.Generation;
            _lastCount = store.Items.Count;
            RebuildPlan();
            _rows.SetScope(IsVisible);
            _rows.Sync(Session.FilterText);
            _grid.Sync();
            ShowDetail();
            Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
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
