using TryZ.Data;

namespace TryZ.Controls;

internal sealed class LogView : SkinControl
{
    private readonly SkinScrollBar _bar = new(false);
    private readonly List<int> _filtered = new();
    private LogBuffer? _buffer;
    private string _filter = string.Empty;
    private int _consumed;
    private int _generation = -1;
    private bool _follow = true;
    private int _selected = -1;
    private bool _syncing;

    public LogView()
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        BackColor = Theme.Inset;
        _bar.ValueChanged += (_, _) =>
        {
            Invalidate();
            if (_syncing) return;
            SetFollow(_bar.Value >= _bar.MaxValue);
        };
        Controls.Add(_bar);
    }

    public event EventHandler? FollowChanged;

    public bool Following => _follow;
    public bool AutoFollow { get; set; } = true;

    private void SetFollow(bool follow)
    {
        if (_follow == follow) return;
        _follow = follow;
        FollowChanged?.Invoke(this, EventArgs.Empty);
    }

    private void ApplyRange()
    {
        _syncing = true;
        _bar.SetRange(_filtered.Count, VisibleRows);
        if (_follow && AutoFollow) _bar.Value = _bar.MaxValue;
        _syncing = false;
    }

    public void Follow()
    {
        _syncing = true;
        _bar.Value = _bar.MaxValue;
        _syncing = false;
        SetFollow(true);
        Invalidate();
    }

    public void Attach(LogBuffer buffer)
    {
        _buffer = buffer;
        _generation = -1;
        Sync(_filter);
    }

    public void Sync(string filter)
    {
        if (_buffer == null) return;
        if (_generation != _buffer.Generation || filter != _filter)
        {
            _generation = _buffer.Generation;
            _filter = filter;
            _filtered.Clear();
            _consumed = 0;
            _selected = -1;
        }
        int before = _filtered.Count;
        var items = _buffer.Items;
        for (; _consumed < items.Count; _consumed++)
            if (Matches(items[_consumed])) _filtered.Add(_consumed);

        if (before != _filtered.Count || _filtered.Count == 0)
        {
            ApplyRange();
            Invalidate();
        }
    }

    private bool Matches(LogEntry e) => _filter.Length == 0
        || e.Text.Contains(_filter, StringComparison.OrdinalIgnoreCase)
        || e.Source.Contains(_filter, StringComparison.OrdinalIgnoreCase)
        || e.LevelName.Contains(_filter, StringComparison.OrdinalIgnoreCase);

    private int RowHeight => Px(15);
    private int VisibleRows => Math.Max(1, (Height - 2) / RowHeight);

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int w = _bar.ThicknessPx;
        _bar.SetBounds(Width - w - 1, 1, w, Height - 2);
        ApplyRange();
    }

    private static Color LevelColor(LogLevel level) => level switch
    {
        LogLevel.Alert => Theme.Critical,
        LogLevel.Warn => Theme.High,
        LogLevel.Notice => Theme.Brass,
        LogLevel.Ok => Theme.Ok,
        LogLevel.Debug => Theme.Hex(0x5F666E),
        _ => Theme.Low,
    };

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        if (_buffer == null) return;
        var mono = Theme.MonoSmall(Dpi);
        int rowH = RowHeight;
        int charW = Math.Max(1, Draw.Measure("0000000000", mono) / 10);
        int xTime = Px(5);
        int xLevel = xTime + charW * 13;
        int xSource = xLevel + charW * 7;
        int xText = xSource + charW * 11;
        int right = _bar.Left - Px(2);
        int y = 1;
        for (int i = _bar.Value; i < _filtered.Count && y < Height - 1; i++, y += rowH)
        {
            var entry = _buffer.Items[_filtered[i]];
            var row = new Rectangle(1, y, right, rowH);
            if (i == _selected) Draw.Selection(g, row, Focused);
            else if (i % 2 == 1) Draw.Fill(g, row, Theme.InsetAlt);
            Draw.Text(g, entry.TimeText, mono, new Rectangle(xTime, y, xLevel - xTime, rowH), Theme.Hex(0x6C737B));
            Draw.Text(g, entry.LevelName, mono, new Rectangle(xLevel, y, xSource - xLevel, rowH), LevelColor(entry.Level));
            Draw.Text(g, entry.Source, mono, new Rectangle(xSource, y, xText - xSource, rowH), Theme.TextDim);
            Draw.Text(g, entry.Text, mono, new Rectangle(xText, y, right - xText, rowH),
                i == _selected ? Theme.TextBright : entry.Level == LogLevel.Debug ? Theme.Hex(0x70777F) : Theme.Text);
        }
        if (_filtered.Count == 0)
            Draw.Text(g, _filter.Length > 0 ? "No log lines match the filter." : "Idle. Press F5 to start a scan.",
                UiFont, new Rectangle(Px(8), Px(5), Width - Px(30), Px(16)), Theme.TextDim);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _bar.Value -= WheelLines(e);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        int row = (e.Y - 1) / RowHeight + _bar.Value;
        _selected = row < _filtered.Count ? row : -1;
        Invalidate();
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        int page = Math.Max(1, VisibleRows - 1);
        switch (e.KeyCode)
        {
            case Keys.Up: _bar.Value -= 1; break;
            case Keys.Down: _bar.Value += 1; break;
            case Keys.PageUp: _bar.Value -= page; break;
            case Keys.PageDown: _bar.Value += page; break;
            case Keys.Home: _bar.Value = 0; break;
            case Keys.End: Follow(); break;
            case Keys.C when e.Control && _selected >= 0 && _selected < _filtered.Count && _buffer != null:
                var entry = _buffer.Items[_filtered[_selected]];
                Clipboard.SetText($"{entry.TimeText} {entry.LevelName} {entry.Source} {entry.Text}");
                break;
            default: return;
        }
        e.Handled = true;
    }
}
