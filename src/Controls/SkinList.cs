namespace TryZ.Controls;

internal sealed record ListRow(string Text, IconId Icon = IconId.None, object? Tag = null);

internal sealed class SkinList : SkinControl
{
    private readonly SkinScrollBar _bar = new(false);
    private List<ListRow> _rows = new();
    private int _selected = -1;
    private int _hot = -1;

    public SkinList()
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        BackColor = Theme.Inset;
        _bar.ValueChanged += (_, _) => Invalidate();
        Controls.Add(_bar);
    }

    public event EventHandler? SelectionChanged;
    public event EventHandler? ItemChosen;

    public bool HoverSelects { get; set; }
    public IReadOnlyList<ListRow> Rows => _rows;
    public int RowHeightPx => Px(HoverSelects ? 17 : 19);
    private int VisibleRows => Math.Max(1, (Height - 2) / RowHeightPx);

    public int SelectedIndex
    {
        get => _selected;
        set
        {
            int v = _rows.Count == 0 ? -1 : Math.Clamp(value, -1, _rows.Count - 1);
            if (v == _selected) return;
            _selected = v;
            EnsureVisible(v);
            Invalidate();
            SelectionChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public ListRow? SelectedRow => _selected >= 0 && _selected < _rows.Count ? _rows[_selected] : null;

    public void SetItems(List<ListRow> rows)
    {
        _rows = rows;
        _selected = Math.Min(_selected, rows.Count - 1);
        _hot = -1;
        UpdateScroll();
        Invalidate();
    }

    private void EnsureVisible(int row)
    {
        if (row < 0) return;
        if (row < _bar.Value) _bar.Value = row;
        else if (row >= _bar.Value + VisibleRows) _bar.Value = row - VisibleRows + 1;
    }

    private void UpdateScroll()
    {
        _bar.SetRange(_rows.Count, VisibleRows);
        bool show = _rows.Count > VisibleRows;
        _bar.Visible = show;
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int w = _bar.ThicknessPx;
        _bar.SetBounds(Width - w - 1, 1, w, Height - 2);
        UpdateScroll();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        int rowH = RowHeightPx;
        int right = _bar.Visible ? _bar.Left : Width - 1;
        int icon = Px(16);
        bool anyIcon = _rows.Any(r => r.Icon != IconId.None);
        for (int i = _bar.Value, y = 1; i < _rows.Count && y < Height - 1; i++, y += rowH)
        {
            var r = new Rectangle(1, y, right - 1, rowH);
            if (i == _selected) Draw.Selection(g, r, Focused || HoverSelects);
            else if (i == _hot) Draw.Fill(g, r, Theme.Hex(0x1F2125));
            int x = r.X + Px(5);
            if (anyIcon)
            {
                if (_rows[i].Icon != IconId.None)
                    g.DrawImage(Icons.Get(_rows[i].Icon, icon), x, y + (rowH - icon) / 2, icon, icon);
                x += icon + Px(5);
            }
            Draw.Text(g, _rows[i].Text, UiFont, new Rectangle(x, y, r.Right - x - Px(3), rowH),
                i == _selected ? Theme.TextBright : Enabled ? Theme.Text : Theme.TextDisabled);
        }
    }

    private int RowAt(Point p)
    {
        int rowH = RowHeightPx;
        int row = (p.Y - 1) / rowH + _bar.Value;
        return p.Y >= 1 && row < _rows.Count ? row : -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int row = RowAt(e.Location);
        if (row == _hot) return;
        _hot = row;
        if (HoverSelects && row >= 0) _selected = row;
        Invalidate();
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = -1;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        int row = RowAt(e.Location);
        if (row >= 0) SelectedIndex = row;
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        if (HoverSelects && RowAt(e.Location) >= 0) ItemChosen?.Invoke(this, EventArgs.Empty);
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        if (!HoverSelects && RowAt(e.Location) >= 0) ItemChosen?.Invoke(this, EventArgs.Empty);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _bar.Value -= WheelLines(e);
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Up or Keys.Down or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End or Keys.Return || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        int page = Math.Max(1, VisibleRows - 1);
        switch (e.KeyCode)
        {
            case Keys.Up: SelectedIndex = Math.Max(0, _selected - 1); break;
            case Keys.Down: SelectedIndex = _selected + 1; break;
            case Keys.PageUp: SelectedIndex = Math.Max(0, _selected - page); break;
            case Keys.PageDown: SelectedIndex = _selected + page; break;
            case Keys.Home: SelectedIndex = 0; break;
            case Keys.End: SelectedIndex = _rows.Count - 1; break;
            case Keys.Return: ItemChosen?.Invoke(this, EventArgs.Empty); break;
            default: return;
        }
        e.Handled = true;
    }
}
