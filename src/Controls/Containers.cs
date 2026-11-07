namespace TryZ.Controls;

internal sealed class SplitBox : SkinControl
{
    private readonly bool _vertical;
    private Control _first;
    private Control _second;
    private int _position;
    private bool _dragging;
    private int _dragDelta;
    private bool _hot;
    private bool _collapsedSecond;

    public SplitBox(bool vertical, Control first, Control second, int position, bool fixSecond = false)
    {
        _vertical = vertical;
        _first = first;
        _second = second;
        _position = position;
        FixSecond = fixSecond;
        Controls.Add(first);
        Controls.Add(second);
        BackColor = Theme.Window;
    }

    public event EventHandler? SplitterMoved;

    public bool FixSecond { get; }
    public int MinFirst { get; set; } = 80;
    public int MinSecond { get; set; } = 60;

    public int Position
    {
        get => _position;
        set { _position = value; PerformLayout(); Invalidate(); }
    }

    public bool CollapseSecond
    {
        get => _collapsedSecond;
        set
        {
            _collapsedSecond = value;
            _second.Visible = !value;
            PerformLayout();
            Invalidate();
        }
    }

    private int Thickness => Px(6);
    private int Extent => _vertical ? Width : Height;

    private int SplitOffset()
    {
        int total = Extent;
        int pos = FixSecond ? total - Px(_position) - Thickness : Px(_position);
        int max = total - Px(MinSecond) - Thickness;
        return Math.Clamp(pos, Math.Min(Px(MinFirst), Math.Max(0, max)), Math.Max(0, max));
    }

    private Rectangle GripRect()
    {
        int at = SplitOffset();
        return _vertical ? new Rectangle(at, 0, Thickness, Height) : new Rectangle(0, at, Width, Thickness);
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        if (_collapsedSecond)
        {
            _first.SetBounds(0, 0, Width, Height);
            return;
        }
        int at = SplitOffset();
        if (_vertical)
        {
            _first.SetBounds(0, 0, at, Height);
            _second.SetBounds(at + Thickness, 0, Math.Max(0, Width - at - Thickness), Height);
        }
        else
        {
            _first.SetBounds(0, 0, Width, at);
            _second.SetBounds(0, at + Thickness, Width, Math.Max(0, Height - at - Thickness));
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        if (_collapsedSecond) return;
        var g = e.Graphics;
        var r = GripRect();
        if (_vertical)
        {
            Draw.Gradient(g, r, _hot ? Theme.Hex(0x3A3E44) : Theme.Hex(0x2E3135), Theme.Hex(0x1F2125), horizontal: true);
            g.DrawLine(Draw.Pen(Theme.BorderDark), r.Right - 1, r.Y, r.Right - 1, r.Bottom);
        }
        else
        {
            Draw.Gradient(g, r, _hot ? Theme.Hex(0x3A3E44) : Theme.Hex(0x2E3135), Theme.Hex(0x1F2125));
            g.DrawLine(Draw.Pen(Theme.BorderDark), r.X, r.Bottom - 1, r.Right, r.Bottom - 1);
        }
        Draw.GripDots(g, r, !_vertical, 7, Math.Max(1, Px(1)));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_dragging)
        {
            int at = (_vertical ? e.X : e.Y) - _dragDelta;
            int logical = (int)Math.Round((FixSecond ? Extent - at - Thickness : at) * 96f / Dpi);
            _position = Math.Max(0, logical);
            PerformLayout();
            Invalidate();
            Update();
            return;
        }
        bool hot = GripRect().Contains(e.Location);
        if (hot != _hot) { _hot = hot; Invalidate(); }
        Cursor = hot ? (_vertical ? Cursors.VSplit : Cursors.HSplit) : Cursors.Default;
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = false;
        Cursor = Cursors.Default;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left || !GripRect().Contains(e.Location)) return;
        _dragging = true;
        _dragDelta = (_vertical ? e.X : e.Y) - SplitOffset();
        Capture = true;
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        if (!_dragging) return;
        _dragging = false;
        Capture = false;
        _position = (int)Math.Round((FixSecond ? Extent - SplitOffset() - Thickness : SplitOffset()) * 96f / Dpi);
        SplitterMoved?.Invoke(this, EventArgs.Empty);
    }
}

internal sealed class TabHost : SkinControl
{
    private sealed class Page
    {
        public required string Title;
        public required IconId Icon;
        public required Control Content;
        public int Left;
        public int Width;
    }

    private readonly List<Page> _pages = new();
    private int _selected = -1;
    private int _hot = -1;

    public TabHost()
    {
        SetStyle(ControlStyles.Selectable, true);
        BackColor = Theme.Panel;
    }

    public event EventHandler? SelectedChanged;

    public int TabHeight { get; set; } = 21;
    public int PagePadding { get; set; } = 3;

    public int SelectedIndex
    {
        get => _selected;
        set
        {
            if (value < 0 || value >= _pages.Count || value == _selected) return;
            _selected = value;
            for (int i = 0; i < _pages.Count; i++) _pages[i].Content.Visible = i == _selected;
            PerformLayout();
            Invalidate();
            SelectedChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public Control? SelectedContent => _selected >= 0 ? _pages[_selected].Content : null;

    public void AddPage(string title, IconId icon, Control content)
    {
        _pages.Add(new Page { Title = title, Icon = icon, Content = content });
        content.Visible = false;
        Controls.Add(content);
        if (_selected < 0) SelectedIndex = 0;
        PerformLayout();
    }

    public void SetTitle(int index, string title)
    {
        if (_pages[index].Title == title) return;
        _pages[index].Title = title;
        MeasureTabs();
        Invalidate();
    }

    private void MeasureTabs()
    {
        int x = Px(4);
        foreach (var p in _pages)
        {
            int iconW = p.Icon != IconId.None ? Px(19) : 0;
            p.Left = x;
            p.Width = Draw.Measure(p.Title, BoldFont) + iconW + Px(18);
            x += p.Width - 1;
        }
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        MeasureTabs();
        int top = Px(TabHeight);
        int pad = Px(PagePadding);
        SelectedContent?.SetBounds(pad, top + pad, Math.Max(0, Width - pad * 2), Math.Max(0, Height - top - pad * 2));
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        int top = Px(TabHeight);
        var strip = new Rectangle(0, 0, Width, top);
        Draw.Gradient(g, strip, Theme.Hex(0x1A1C1E), Theme.Hex(0x212327));
        Draw.Fill(g, new Rectangle(0, top, Width, Height - top), Theme.Panel);
        g.DrawLine(Draw.Pen(Theme.BorderDark), 0, top - 1, Width, top - 1);
        g.DrawLine(Draw.Pen(Theme.Highlight), 0, top, Width, top);
        for (int i = 0; i < _pages.Count; i++)
            if (i != _selected) PaintTab(g, i, top);
        if (_selected >= 0) PaintTab(g, _selected, top);
    }

    private void PaintTab(Graphics g, int index, int top)
    {
        var p = _pages[index];
        bool selected = index == _selected;
        int y = selected ? Px(2) : Px(4);
        var r = new Rectangle(p.Left, y, p.Width, top - y + (selected ? 1 : -1));
        if (selected)
        {
            Draw.Gradient(g, r, Theme.Hex(0x3C4046), Theme.Panel);
            g.DrawLine(Draw.Pen(Theme.BorderDark), r.X, r.Y, r.X, r.Bottom - 1);
            g.DrawLine(Draw.Pen(Theme.BorderDark), r.Right - 1, r.Y, r.Right - 1, r.Bottom - 1);
            g.DrawLine(Draw.Pen(Theme.BorderDark), r.X, r.Y, r.Right - 1, r.Y);
            Draw.Fill(g, new Rectangle(r.X + 1, r.Y + 1, r.Width - 2, Math.Max(2, Px(2))), Theme.OxbloodBright);
        }
        else
        {
            var c = index == _hot ? Theme.Hex(0x34383D) : Theme.Hex(0x282B2F);
            Draw.Gradient(g, r, c, Theme.Hex(0x1E2023));
            Draw.Frame(g, r, Theme.BorderDark);
            g.DrawLine(Draw.Pen(Theme.Hex(0x3A3E44)), r.X + 1, r.Y + 1, r.Right - 2, r.Y + 1);
        }
        int x = r.X + Px(8);
        if (p.Icon != IconId.None)
        {
            int s = Px(14);
            g.DrawImage(Icons.Get(p.Icon, s, !selected && index != _hot), x, r.Y + (r.Height - s) / 2 + (selected ? 1 : 0), s, s);
            x += Px(19);
        }
        var text = new Rectangle(x, r.Y + (selected ? 1 : 0), r.Right - x - Px(4), r.Height);
        Draw.Text(g, p.Title, selected ? BoldFont : UiFont, text, selected ? Theme.TextBright : Theme.TextDim);
    }

    private int TabAt(Point p)
    {
        if (p.Y >= Px(TabHeight)) return -1;
        for (int i = 0; i < _pages.Count; i++)
            if (p.X >= _pages[i].Left && p.X < _pages[i].Left + _pages[i].Width) return i;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int hot = TabAt(e.Location);
        if (hot != _hot) { _hot = hot; Invalidate(); }
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
        int t = TabAt(e.Location);
        if (t >= 0) SelectedIndex = t;
    }
}

internal class EtchedGroup : SkinControl
{
    private sealed record Row(string? Label, Control[] Items, int[] Widths, int Height);

    private readonly List<Row> _rows = new();
    private Control? _fill;

    public EtchedGroup(string caption)
    {
        Caption = caption;
    }

    public string Caption { get; set; }
    public int LabelWidth { get; set; } = 70;

    private int CaptionHeight => Px(15);
    private int Pad => Px(7);

    public void SetFill(Control c)
    {
        _fill = c;
        Controls.Add(c);
    }

    public T Add<T>(string? label, T control, int width = 0, int height = 20) where T : Control
    {
        _rows.Add(new Row(label, new Control[] { control }, new[] { width }, height));
        Controls.Add(control);
        return control;
    }

    public void AddRow(string? label, int height, params (Control Item, int Width)[] items)
    {
        _rows.Add(new Row(label, items.Select(i => i.Item).ToArray(), items.Select(i => i.Width).ToArray(), height));
        foreach (var (item, _) in items) Controls.Add(item);
    }

    public int PreferredLogicalHeight => 15 + 7 + 3 + _rows.Sum(r => r.Height + 3);

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var inner = new Rectangle(Pad, CaptionHeight + Px(2), Width - Pad * 2, Height - CaptionHeight - Px(2) - Pad + Px(2));
        if (_fill != null)
        {
            _fill.SetBounds(inner.X, inner.Y, inner.Width, inner.Height);
            return;
        }
        int y = inner.Y;
        int gap = Px(5);
        foreach (var row in _rows)
        {
            int h = Px(row.Height);
            int x = inner.X + (row.Label != null ? Px(LabelWidth) : 0);
            int right = inner.Right;
            int fixedTotal = 0, fills = 0;
            for (int i = 0; i < row.Items.Length; i++)
            {
                if (row.Widths[i] > 0) fixedTotal += Px(row.Widths[i]);
                else fills++;
            }
            int fillWidth = fills > 0 ? Math.Max(0, (right - x - fixedTotal - gap * (row.Items.Length - 1)) / fills) : 0;
            for (int i = 0; i < row.Items.Length; i++)
            {
                int w = row.Widths[i] > 0 ? Px(row.Widths[i]) : fillWidth;
                row.Items[i].SetBounds(x, y, Math.Min(w, Math.Max(0, right - x)), h);
                x += w + gap;
            }
            y += h + Px(3);
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        int captionWidth = Draw.Measure(Caption, BoldFont);
        int mid = CaptionHeight / 2;
        var box = new Rectangle(0, mid, Width, Height - mid);
        Draw.EtchedBox(g, box);
        var gap = new Rectangle(Px(7), 0, captionWidth + Px(8), CaptionHeight);
        Draw.Fill(g, gap, BackColor);
        Draw.Text(g, Caption, BoldFont, new Rectangle(gap.X + Px(4), 0, captionWidth + Px(2), CaptionHeight), Theme.Brass);

        var inner = new Rectangle(Pad, CaptionHeight + Px(2), Width - Pad * 2, Height);
        int y = inner.Y;
        foreach (var row in _rows)
        {
            int h = Px(row.Height);
            if (row.Label != null)
                Draw.Text(g, row.Label, UiFont, new Rectangle(inner.X, y, Px(LabelWidth) - Px(4), h), Enabled ? Theme.TextDim : Theme.TextDisabled);
            y += h + Px(3);
        }
    }
}

internal sealed class PropertySheet : SkinControl
{
    private List<(string Key, string Value, Color? Color)> _rows = new();
    private readonly SkinScrollBar _bar = new(false);

    public PropertySheet()
    {
        BackColor = Theme.Inset;
        _bar.ValueChanged += (_, _) => Invalidate();
        Controls.Add(_bar);
    }

    public int KeyWidth { get; set; } = 92;

    public void SetRows(List<(string Key, string Value, Color? Color)> rows)
    {
        if (rows.SequenceEqual(_rows)) return;
        _rows = rows;
        UpdateScroll();
        Invalidate();
    }

    private int RowH => Px(16);
    private int VisibleRowCount => Math.Max(1, (Height - 2) / RowH);

    private void UpdateScroll()
    {
        _bar.SetRange(_rows.Count, VisibleRowCount);
        bool show = _rows.Count > VisibleRowCount;
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
        int keyW = Px(KeyWidth);
        int right = _bar.Visible ? _bar.Left : Width - 1;
        Draw.Fill(g, new Rectangle(1, 1, keyW, Height - 2), Theme.Hex(0x1A1C1F));
        g.DrawLine(Draw.Pen(Theme.Hex(0x212327)), keyW, 1, keyW, Height - 2);
        int y = 1;
        var mono = Theme.MonoSmall(Dpi);
        for (int i = _bar.Value; i < _rows.Count && y + RowH <= Height; i++, y += RowH)
        {
            var (k, v, c) = _rows[i];
            Draw.Text(g, k, UiFont, new Rectangle(Px(5), y, keyW - Px(7), RowH), Theme.TextDim);
            Draw.Text(g, v, mono, new Rectangle(keyW + Px(5), y, right - keyW - Px(8), RowH), c ?? Theme.Text);
            g.DrawLine(Draw.Pen(Theme.Hex(0x1C1E21)), 1, y + RowH - 1, right - 1, y + RowH - 1);
        }
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _bar.Value -= WheelLines(e);
    }
}
