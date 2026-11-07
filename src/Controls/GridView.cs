using System.Drawing.Drawing2D;
using System.Text;

namespace TryZ.Controls;

internal enum CellKind { Text, Severity, Bar }

internal class GridColumn
{
    public GridColumn(string title, int width, CellKind kind = CellKind.Text)
    {
        Title = title;
        Width = width;
        Kind = kind;
    }

    public string Title { get; }
    public int Width { get; set; }
    public CellKind Kind { get; }
    public HorizontalAlignment Align { get; init; } = HorizontalAlignment.Left;
    public bool Mono { get; init; }
}

internal interface IGridSource
{
    IReadOnlyList<GridColumn> Columns { get; }
    int Count { get; }
    int OrderVersion { get; }
    int SortColumn { get; }
    bool SortDescending { get; }
    string GetText(int row, int col);
    Color? GetColor(int row, int col);
    int GetBar(int row, int col);
    object ItemAt(int row);
    int IndexOf(object item);
    void ToggleSort(int col);
}

internal sealed class GridView : SkinControl
{
    private readonly SkinScrollBar _v = new(false);
    private readonly SkinScrollBar _h = new(true);
    private IGridSource? _source;
    private object? _selectedItem;
    private bool _showH = true;
    private int _selectedRow = -1;
    private int _seenOrder = -1;
    private int _hotRow = -1;
    private int _hotHeader = -1;
    private int _pressedHeader = -1;
    private int _resizeCol = -1;
    private int _resizeStartX;
    private int _resizeStartWidth;

    public GridView()
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        BackColor = Theme.Inset;
        _v.ValueChanged += (_, _) => Invalidate();
        _h.ValueChanged += (_, _) => Invalidate();
        Controls.Add(_v);
        Controls.Add(_h);
    }

    public event EventHandler? SelectionChanged;
    public event EventHandler? RowActivated;

    public string EmptyText { get; set; } = "No rows.";

    public IGridSource? Source
    {
        get => _source;
        set
        {
            _source = value;
            _seenOrder = -1;
            Sync();
        }
    }

    public object? SelectedItem => _selectedItem;
    public int SelectedRow => _selectedRow;

    private int RowHeight => Px(17);
    private int HeaderHeight => Px(20);
    private int BodyTop => HeaderHeight + 1;
    private int BodyWidth => Math.Max(0, Width - 2 - _v.Width);
    private int BodyHeight => Math.Max(0, Height - BodyTop - 1 - (_showH ? _h.Height : 0));
    private int VisibleRows => Math.Max(1, BodyHeight / RowHeight);
    private int ContentWidth => _source == null ? 0 : _source.Columns.Sum(c => Px(c.Width));

    public void Sync()
    {
        if (_source == null)
        {
            UpdateScroll();
            Invalidate();
            return;
        }
        if (_seenOrder != _source.OrderVersion)
        {
            _seenOrder = _source.OrderVersion;
            _selectedRow = _selectedItem == null ? -1 : _source.IndexOf(_selectedItem);
            if (_selectedRow < 0 && _selectedItem != null)
            {
                _selectedItem = null;
                SelectionChanged?.Invoke(this, EventArgs.Empty);
            }
        }
        UpdateScroll();
        Invalidate();
    }

    public void SelectRow(int row, bool notify = true)
    {
        if (_source == null || _source.Count == 0)
        {
            bool had = _selectedItem != null;
            _selectedRow = -1;
            _selectedItem = null;
            if (had && notify) SelectionChanged?.Invoke(this, EventArgs.Empty);
            return;
        }
        row = Math.Clamp(row, 0, _source.Count - 1);
        var item = _source.ItemAt(row);
        bool changed = !ReferenceEquals(item, _selectedItem);
        _selectedRow = row;
        _selectedItem = item;
        EnsureVisible(row);
        Invalidate();
        if (changed && notify) SelectionChanged?.Invoke(this, EventArgs.Empty);
    }

    public void ClearSelection()
    {
        _selectedRow = -1;
        _selectedItem = null;
        Invalidate();
    }

    private void EnsureVisible(int row)
    {
        if (row < _v.Value) _v.Value = row;
        else if (row >= _v.Value + VisibleRows) _v.Value = row - VisibleRows + 1;
    }

    private void UpdateScroll()
    {
        int count = _source?.Count ?? 0;
        int th = _v.ThicknessPx;
        bool showH = ContentWidth > Width - 2 - th;
        if (_showH != showH)
        {
            _showH = showH;
            _h.Visible = showH;
            PositionBars();
        }
        _v.SetRange(count, VisibleRows);
        _h.SetRange(ContentWidth, Math.Max(1, BodyWidth));
    }

    private void PositionBars()
    {
        int th = _v.ThicknessPx;
        int hh = _showH ? th : 0;
        _v.SetBounds(Width - th - 1, 1, th, Height - 2 - hh);
        _h.SetBounds(1, Height - th - 1, Width - 2 - th, th);
        _h.SmallChange = Px(24);
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        PositionBars();
        UpdateScroll();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        if (_showH)
            Draw.Fill(g, new Rectangle(_h.Right, _h.Top, _v.Width, _h.Height), Theme.Panel);
        var bodyClip = new Rectangle(1, BodyTop, BodyWidth, BodyHeight);
        PaintHeader(g);
        if (_source == null) return;

        var saved = g.Clip;
        g.SetClip(bodyClip);
        PaintBody(g, bodyClip);
        g.Clip = saved;
        saved.Dispose();
    }

    private void PaintHeader(Graphics g)
    {
        var header = new Rectangle(1, 1, BodyWidth, HeaderHeight);
        Draw.Gradient(g, header, Theme.Hex(0x3C4046), Theme.Hex(0x282B2F));
        g.DrawLine(Draw.Pen(Theme.Highlight), 1, 1, header.Right - 1, 1);
        g.DrawLine(Draw.Pen(Theme.BorderDark), 1, header.Bottom, header.Right - 1, header.Bottom);
        if (_source == null) return;

        var saved = g.Clip;
        g.SetClip(header);
        int x = 1 - _h.Value;
        var cols = _source.Columns;
        for (int i = 0; i < cols.Count; i++)
        {
            int w = Px(cols[i].Width);
            var r = new Rectangle(x, 1, w, HeaderHeight);
            if (r.Right > 0 && r.X < header.Right)
            {
                if (i == _pressedHeader)
                    Draw.Gradient(g, r, Theme.Hex(0x1E2024), Theme.Hex(0x2C2F33));
                else if (i == _hotHeader)
                    Draw.Gradient(g, r, Theme.Hex(0x4A4F55), Theme.Hex(0x33373C));
                if (i == _source.SortColumn)
                    g.DrawLine(Draw.Pen(Theme.Brass), r.X + 1, r.Bottom - 1, r.Right - 2, r.Bottom - 1);

                var text = new Rectangle(r.X + Px(5), r.Y, w - Px(10) - (i == _source.SortColumn ? Px(10) : 0), r.Height);
                Draw.Engraved(g, cols[i].Title, BoldFont, text, Theme.Text, AlignFlag(cols[i].Align));
                if (i == _source.SortColumn)
                {
                    var tri = new Rectangle(r.Right - Px(13), r.Y, Px(10), r.Height);
                    Draw.Triangle(g, tri, _source.SortDescending ? ArrowDirection.Down : ArrowDirection.Up, Theme.Brass, Px(3));
                }
                g.DrawLine(Draw.Pen(Theme.BorderDark), r.Right - 2, r.Y + 3, r.Right - 2, r.Bottom - 4);
                g.DrawLine(Draw.Pen(Theme.Highlight), r.Right - 1, r.Y + 3, r.Right - 1, r.Bottom - 4);
            }
            x += w;
        }
        g.Clip = saved;
        saved.Dispose();
    }

    private void PaintBody(Graphics g, Rectangle body)
    {
        var src = _source!;
        var cols = src.Columns;
        int rowH = RowHeight;
        int first = _v.Value;
        int count = src.Count;
        bool focused = ContainsFocus;

        int y = body.Y;
        for (int row = first; y < body.Bottom; row++, y += rowH)
        {
            var rowRect = new Rectangle(body.X, y, body.Width, rowH);
            bool exists = row < count;
            bool selected = exists && row == _selectedRow;
            if (selected) Draw.Selection(g, rowRect, focused);
            else if (exists && row == _hotRow) Draw.Fill(g, rowRect, Theme.Hex(0x212326));
            else if (row % 2 == 1) Draw.Fill(g, rowRect, Theme.InsetAlt);
            if (!exists) continue;

            int x = body.X - _h.Value;
            for (int c = 0; c < cols.Count; c++)
            {
                var col = cols[c];
                int w = Px(col.Width);
                if (x + w > body.X && x < body.Right)
                    PaintCell(g, row, c, col, new Rectangle(x, y, w, rowH), selected);
                x += w;
            }
        }

        int vx = body.X - _h.Value;
        foreach (var col in cols)
        {
            vx += Px(col.Width);
            if (vx >= body.X && vx < body.Right)
                g.DrawLine(Draw.Pen(Theme.Hex(0x212327)), vx - 1, body.Y, vx - 1, body.Bottom);
        }

        if (count == 0 && !string.IsNullOrEmpty(EmptyText))
        {
            var r = new Rectangle(body.X + Px(8), body.Y + Px(6), body.Width - Px(16), Px(18));
            Draw.Text(g, EmptyText, UiFont, r, Theme.TextDim);
        }
    }

    private void PaintCell(Graphics g, int row, int c, GridColumn col, Rectangle r, bool selected)
    {
        var src = _source!;
        if (col.Kind == CellKind.Bar)
        {
            PaintBar(g, r, src.GetBar(row, c), src.GetColor(row, c));
            return;
        }
        var text = src.GetText(row, c);
        var color = src.GetColor(row, c) ?? (selected ? Theme.TextBright : Theme.Text);
        int pad = Px(5);
        var tr = new Rectangle(r.X + pad, r.Y, r.Width - pad * 2, r.Height);
        if (col.Kind == CellKind.Severity)
        {
            int s = Px(8);
            var box = new Rectangle(r.X + pad, r.Y + (r.Height - s) / 2, s, s);
            Draw.Gradient(g, box, Theme.Shift(color, 26), Theme.Shift(color, -46));
            Draw.Frame(g, box, Theme.BorderDark);
            tr.X += s + Px(5);
            tr.Width -= s + Px(5);
        }
        var font = col.Mono ? Theme.MonoSmall(Dpi) : UiFont;
        Draw.Text(g, text, font, tr, color, AlignFlag(col.Align));
    }

    private void PaintBar(Graphics g, Rectangle r, int value, Color? color)
    {
        var area = Rectangle.Inflate(r, -Px(4), -Px(4));
        if (area.Width < Px(10) || area.Height <= 0) return;
        Draw.Fill(g, area, Theme.BorderDark);
        int seg = Px(4), gap = Math.Max(1, Px(1));
        int count = area.Width / (seg + gap);
        int lit = (int)Math.Round(count * value / 100.0);
        var c = color ?? Theme.Brass;
        for (int i = 0; i < count; i++)
        {
            var b = new Rectangle(area.X + 1 + i * (seg + gap), area.Y + 1, seg, area.Height - 2);
            if (b.Right >= area.Right) break;
            Draw.Fill(g, b, i < lit ? c : Theme.Hex(0x1D1F22));
        }
    }

    private static TextFormatFlags AlignFlag(HorizontalAlignment a) => a switch
    {
        HorizontalAlignment.Right => TextFormatFlags.Right,
        HorizontalAlignment.Center => TextFormatFlags.HorizontalCenter,
        _ => TextFormatFlags.Left,
    };

    private int ColumnBoundaryAt(int x)
    {
        if (_source == null) return -1;
        int edge = 1 - _h.Value;
        int tolerance = Px(4);
        var cols = _source.Columns;
        for (int i = 0; i < cols.Count; i++)
        {
            edge += Px(cols[i].Width);
            if (Math.Abs(x - edge) <= tolerance) return i;
        }
        return -1;
    }

    private int ColumnAt(int x)
    {
        if (_source == null) return -1;
        int edge = 1 - _h.Value;
        var cols = _source.Columns;
        for (int i = 0; i < cols.Count; i++)
        {
            int w = Px(cols[i].Width);
            if (x >= edge && x < edge + w) return i;
            edge += w;
        }
        return -1;
    }

    private int RowAt(int y)
    {
        if (_source == null || y < BodyTop || y >= BodyTop + BodyHeight) return -1;
        int row = (y - BodyTop) / RowHeight + _v.Value;
        return row < _source.Count ? row : -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_resizeCol >= 0)
        {
            int logical = (int)Math.Round((e.X - _resizeStartX) * 96f / Dpi) + _resizeStartWidth;
            _source!.Columns[_resizeCol].Width = Math.Max(24, logical);
            UpdateScroll();
            Invalidate();
            return;
        }
        bool inHeader = e.Y >= 1 && e.Y < BodyTop;
        Cursor = inHeader && ColumnBoundaryAt(e.X) >= 0 ? Cursors.VSplit : Cursors.Default;
        int hotHeader = inHeader ? ColumnAt(e.X) : -1;
        int hotRow = inHeader ? -1 : RowAt(e.Y);
        if (hotHeader != _hotHeader || hotRow != _hotRow)
        {
            _hotHeader = hotHeader;
            _hotRow = hotRow;
            Invalidate();
        }
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hotHeader = -1;
        _hotRow = -1;
        Cursor = Cursors.Default;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        if (_source == null || e.Button != MouseButtons.Left) return;
        if (e.Y < BodyTop)
        {
            int b = ColumnBoundaryAt(e.X);
            if (b >= 0)
            {
                _resizeCol = b;
                _resizeStartX = e.X;
                _resizeStartWidth = _source.Columns[b].Width;
                Capture = true;
                return;
            }
            _pressedHeader = ColumnAt(e.X);
            Invalidate();
            return;
        }
        int row = RowAt(e.Y);
        if (row >= 0) SelectRow(row);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        if (_resizeCol >= 0)
        {
            _resizeCol = -1;
            Capture = false;
            return;
        }
        if (_pressedHeader >= 0)
        {
            if (ColumnAt(e.X) == _pressedHeader && e.Y < BodyTop && _source != null)
            {
                _source.ToggleSort(_pressedHeader);
                Sync();
                if (_selectedRow >= 0) EnsureVisible(_selectedRow);
            }
            _pressedHeader = -1;
            Invalidate();
        }
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        if (e.Y < BodyTop)
        {
            int b = ColumnBoundaryAt(e.X);
            if (b >= 0) AutoFit(b);
            return;
        }
        if (RowAt(e.Y) >= 0) RowActivated?.Invoke(this, EventArgs.Empty);
    }

    private void AutoFit(int col)
    {
        if (_source == null) return;
        var column = _source.Columns[col];
        int widest = Draw.Measure(column.Title, BoldFont) + Px(24);
        var font = column.Mono ? Theme.MonoSmall(Dpi) : UiFont;
        int end = Math.Min(_source.Count, _v.Value + VisibleRows);
        for (int r = _v.Value; r < end; r++)
            widest = Math.Max(widest, Draw.Measure(_source.GetText(r, col), font) + Px(12));
        column.Width = (int)Math.Ceiling(widest * 96f / Dpi);
        UpdateScroll();
        Invalidate();
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _v.Value -= WheelLines(e);
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) => keyData is Keys.Up or Keys.Down or Keys.Left or Keys.Right
        or Keys.PageUp or Keys.PageDown or Keys.Home or Keys.End || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (_source == null) return;
        int page = Math.Max(1, VisibleRows - 1);
        switch (e.KeyCode)
        {
            case Keys.Up: SelectRow(Math.Max(0, _selectedRow - 1)); break;
            case Keys.Down: SelectRow(_selectedRow + 1); break;
            case Keys.PageUp: SelectRow(Math.Max(0, _selectedRow - page)); break;
            case Keys.PageDown: SelectRow(Math.Max(0, _selectedRow) + page); break;
            case Keys.Home: SelectRow(0); break;
            case Keys.End: SelectRow(_source.Count - 1); break;
            case Keys.Left: _h.Value -= Px(40); break;
            case Keys.Right: _h.Value += Px(40); break;
            case Keys.Return: if (_selectedItem != null) RowActivated?.Invoke(this, EventArgs.Empty); break;
            case Keys.C when e.Control: CopySelected(); break;
            default: return;
        }
        e.Handled = true;
    }

    private void CopySelected()
    {
        if (_source == null || _selectedRow < 0) return;
        var line = new StringBuilder();
        for (int c = 0; c < _source.Columns.Count; c++)
        {
            if (c > 0) line.Append('\t');
            line.Append(_source.GetText(_selectedRow, c));
        }
        Clipboard.SetText(line.ToString());
    }
}
