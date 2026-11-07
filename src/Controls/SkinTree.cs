using System.Drawing.Drawing2D;

namespace TryZ.Controls;

internal sealed class TreeItem
{
    public TreeItem(string text, IconId icon = IconId.Folder, object? tag = null)
    {
        Text = text;
        Icon = icon;
        Tag = tag;
    }

    public string Text { get; set; }
    public IconId Icon { get; set; }
    public object? Tag { get; }
    public int Count { get; set; }
    public bool Expanded { get; set; }
    public TreeItem? Parent { get; private set; }
    public List<TreeItem> Children { get; } = new();

    public TreeItem Add(TreeItem child)
    {
        child.Parent = this;
        Children.Add(child);
        return child;
    }

    public int Depth
    {
        get
        {
            int d = 0;
            for (var p = Parent; p != null; p = p.Parent) d++;
            return d;
        }
    }
}

internal sealed class SkinTree : SkinControl
{
    private readonly SkinScrollBar _bar = new(false);
    private readonly List<TreeItem> _roots = new();
    private readonly List<TreeItem> _flat = new();
    private TreeItem? _selected;
    private int _hot = -1;

    public SkinTree()
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        BackColor = Theme.Inset;
        _bar.ValueChanged += (_, _) => Invalidate();
        Controls.Add(_bar);
    }

    public event EventHandler? SelectionChanged;

    public List<TreeItem> Roots => _roots;
    public bool ShowCounts { get; set; }
    public string EmptyText { get; set; } = string.Empty;

    public TreeItem? SelectedItem
    {
        get => _selected;
        set
        {
            if (ReferenceEquals(_selected, value)) return;
            _selected = value;
            for (var p = value?.Parent; p != null; p = p.Parent) p.Expanded = true;
            Rebuild();
            if (value != null)
            {
                int i = _flat.IndexOf(value);
                if (i >= 0 && (i < _bar.Value || i >= _bar.Value + VisibleRows)) _bar.Value = i;
            }
            SelectionChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void Rebuild()
    {
        _flat.Clear();
        foreach (var r in _roots) Flatten(r);
        _bar.SetRange(_flat.Count, VisibleRows);
        bool show = _flat.Count > VisibleRows;
        _bar.Visible = show;
        if (_selected != null && !_flat.Contains(_selected) && !IsAttached(_selected)) _selected = null;
        Invalidate();
    }

    private bool IsAttached(TreeItem item)
    {
        var top = item;
        while (top.Parent != null) top = top.Parent;
        return _roots.Contains(top);
    }

    private void Flatten(TreeItem item)
    {
        _flat.Add(item);
        if (!item.Expanded) return;
        foreach (var c in item.Children) Flatten(c);
    }

    private int RowH => Px(18);
    private int Indent => Px(16);
    private int VisibleRows => Math.Max(1, (Height - 2) / RowH);

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int w = _bar.ThicknessPx;
        _bar.SetBounds(Width - w - 1, 1, w, Height - 2);
        Rebuild();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        if (_flat.Count == 0)
            Draw.Text(g, EmptyText, UiFont, new Rectangle(Px(8), Px(5), Width - Px(16), Px(16)), Theme.TextDim);
        int rowH = RowH;
        int right = _bar.Visible ? _bar.Left : Width - 1;
        int iconSize = Px(16);
        using var dots = new Pen(Theme.Hex(0x4A4F55)) { DashStyle = DashStyle.Dot };
        int y = 1;
        for (int i = _bar.Value; i < _flat.Count && y < Height - 1; i++, y += rowH)
        {
            var item = _flat[i];
            int depth = item.Depth;
            int x = Px(3) + depth * Indent;
            int midY = y + rowH / 2;
            int boxS = Px(9);
            int boxX = x + (Indent - boxS) / 2;

            for (var a = item; a.Parent != null; a = a.Parent)
            {
                int ax = Px(3) + (a.Depth - 1) * Indent + Indent / 2;
                bool last = ReferenceEquals(a.Parent.Children[^1], a);
                if (ReferenceEquals(a, item))
                    g.DrawLine(dots, ax, y, ax, last ? midY : y + rowH);
                else if (!last)
                    g.DrawLine(dots, ax, y, ax, y + rowH);
            }
            if (item.Parent != null) g.DrawLine(dots, x - Indent / 2, midY, x + Indent / 2 - 1, midY);

            if (item.Children.Count > 0)
            {
                var box = new Rectangle(boxX, midY - boxS / 2, boxS, boxS);
                Draw.Gradient(g, box, Theme.Hex(0x3C4046), Theme.Hex(0x24272B));
                Draw.Frame(g, box, Theme.BorderDark);
                g.DrawLine(Draw.Pen(Theme.Text), box.X + 2, midY, box.Right - 3, midY);
                if (!item.Expanded) g.DrawLine(Draw.Pen(Theme.Text), box.X + box.Width / 2, box.Y + 2, box.X + box.Width / 2, box.Bottom - 3);
            }

            int iconX = x + Indent;
            var iconId = item.Icon == IconId.Folder && item.Expanded ? IconId.FolderOpen : item.Icon;
            bool hasIcon = iconId != IconId.None;
            if (hasIcon) g.DrawImage(Icons.Get(iconId, iconSize), iconX, y + (rowH - iconSize) / 2, iconSize, iconSize);
            int textX = iconX + (hasIcon ? iconSize + Px(4) : Px(1));
            int textW = Draw.Measure(item.Text, UiFont) + Px(5);
            var tr = new Rectangle(textX, y, Math.Min(textW, Math.Max(0, right - textX - 1)), rowH);
            bool selected = ReferenceEquals(item, _selected);
            if (selected) Draw.Selection(g, tr, Focused);
            else if (i == _hot) Draw.Fill(g, tr, Theme.Hex(0x212326));
            Draw.Text(g, item.Text, UiFont, new Rectangle(tr.X + Px(2), y, tr.Width - Px(2), rowH), selected ? Theme.TextBright : Theme.Text);
            if (ShowCounts && item.Count > 0)
            {
                string count = item.Count.ToString("N0");
                int cw = Draw.Measure(count, Theme.MonoSmall(Dpi));
                int cx = tr.Right + Px(4);
                if (cx + cw < right - Px(2))
                    Draw.Text(g, count, Theme.MonoSmall(Dpi), new Rectangle(cx, y, cw + 1, rowH), Theme.TextDim);
            }
        }
    }

    private int RowAt(int y)
    {
        int row = (y - 1) / RowH + _bar.Value;
        return y >= 1 && row < _flat.Count ? row : -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int row = RowAt(e.Y);
        if (row != _hot) { _hot = row; Invalidate(); }
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
        int row = RowAt(e.Y);
        if (row < 0) return;
        var item = _flat[row];
        int x = Px(3) + item.Depth * Indent;
        if (item.Children.Count > 0 && e.X >= x && e.X < x + Indent)
        {
            item.Expanded = !item.Expanded;
            Rebuild();
            return;
        }
        SelectedItem = item;
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        int row = RowAt(e.Y);
        if (row < 0) return;
        var item = _flat[row];
        int x = Px(3) + item.Depth * Indent;
        if (e.X >= x + Indent && item.Children.Count > 0)
        {
            item.Expanded = !item.Expanded;
            Rebuild();
        }
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _bar.Value -= WheelLines(e);
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Up or Keys.Down or Keys.Left or Keys.Right or Keys.Home or Keys.End || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        int i = _selected != null ? _flat.IndexOf(_selected) : -1;
        switch (e.KeyCode)
        {
            case Keys.Up when i > 0: SelectedItem = _flat[i - 1]; break;
            case Keys.Down when i < _flat.Count - 1: SelectedItem = _flat[i + 1]; break;
            case Keys.Home when _flat.Count > 0: SelectedItem = _flat[0]; break;
            case Keys.End when _flat.Count > 0: SelectedItem = _flat[^1]; break;
            case Keys.Right when _selected != null && _selected.Children.Count > 0:
                _selected.Expanded = true;
                Rebuild();
                break;
            case Keys.Left when _selected != null:
                if (_selected.Expanded && _selected.Children.Count > 0) { _selected.Expanded = false; Rebuild(); }
                else if (_selected.Parent != null) SelectedItem = _selected.Parent;
                break;
            default: return;
        }
        e.Handled = true;
    }
}
