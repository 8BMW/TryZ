using System.Text;

namespace TryZ.Controls;

internal readonly record struct CodeSpan(int Start, int Length, Color Color);

internal interface ISyntax
{
    void Colorize(IReadOnlyList<string> lines, int lineIndex, List<CodeSpan> output);
}

internal sealed class CodeView : SkinControl
{
    private readonly SkinScrollBar _v = new(false);
    private readonly SkinScrollBar _h = new(true);
    private readonly Timer _blink = new() { Interval = 530 };
    private readonly List<string> _lines = new() { string.Empty };
    private readonly List<CodeSpan> _spans = new();
    private Point _caret;
    private Point _anchor;
    private bool _caretOn = true;
    private bool _dragging;
    private bool _showH = true;

    public CodeView()
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        BackColor = Theme.Inset;
        Cursor = Cursors.IBeam;
        _v.ValueChanged += (_, _) => Invalidate();
        _h.ValueChanged += (_, _) => Invalidate();
        Controls.Add(_v);
        Controls.Add(_h);
        _blink.Tick += (_, _) =>
        {
            _caretOn = !_caretOn;
            Invalidate();
        };
        ContextMenuStrip = BuildMenu();
    }

    public event EventHandler? TextEdited;

    public bool ReadOnly { get; set; }
    public ISyntax? Syntax { get; set; }
    public IReadOnlyList<string> Lines => _lines;

    public string Value
    {
        get => string.Join("\r\n", _lines);
        set
        {
            _lines.Clear();
            _lines.AddRange(value.Replace("\r", string.Empty).Split('\n'));
            _caret = Point.Empty;
            _anchor = Point.Empty;
            _v.Value = 0;
            _h.Value = 0;
            UpdateScroll();
            Invalidate();
        }
    }

    private Font CodeFont => MonoFont;
    private int CharW => Math.Max(1, Draw.Measure("0000000000", CodeFont) / 10);
    private int RowH => Px(15);
    private int Gutter => Px(32);
    private int VisibleRows => Math.Max(1, (Height - 2 - (_showH ? _h.Height : 0)) / RowH);
    private int TextLeft => Gutter + Px(5);

    private ContextMenuStrip BuildMenu()
    {
        var menu = new SkinContextMenu();
        var cut = menu.AddItem("Cut", IconId.None, CutSelection);
        var copy = menu.AddItem("Copy", IconId.Copy, CopySelection);
        var paste = menu.AddItem("Paste", IconId.None, PasteClipboard);
        menu.Items.Add(new ToolStripSeparator());
        menu.AddItem("Select All", IconId.None, SelectAll);
        menu.Opening += (_, _) =>
        {
            cut.Enabled = !ReadOnly && HasSelection;
            copy.Enabled = HasSelection;
            paste.Enabled = !ReadOnly;
        };
        return menu;
    }

    private void UpdateScroll()
    {
        int longest = _lines.Count == 0 ? 0 : _lines.Max(l => l.Length);
        int content = longest * CharW + TextLeft + Px(12);
        int th = _v.ThicknessPx;
        bool showH = content > Width - th - 2;
        _showH = showH;
        _h.Visible = showH;
        _v.SetBounds(Width - th - 1, 1, th, Height - 2 - (showH ? th : 0));
        _h.SetBounds(1, Height - th - 1, Width - 2 - th, th);
        _h.SmallChange = CharW * 4;
        _v.SetRange(_lines.Count, VisibleRows);
        _h.SetRange(content, Math.Max(1, Width - th - 2));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        UpdateScroll();
    }

    private bool HasSelection => _caret != _anchor;

    private (Point Start, Point End) Selection()
    {
        bool forward = _anchor.Y < _caret.Y || (_anchor.Y == _caret.Y && _anchor.X <= _caret.X);
        return forward ? (_anchor, _caret) : (_caret, _anchor);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        var font = CodeFont;
        int cw = CharW, rowH = RowH;
        int right = _v.Left;
        int bottom = _showH ? _h.Top : Height - 1;

        var gutter = new Rectangle(1, 1, Gutter - 1, bottom - 1);
        Draw.Fill(g, gutter, Theme.Hex(0x191B1E));
        g.DrawLine(Draw.Pen(Theme.Hex(0x2A2D31)), Gutter, 1, Gutter, bottom - 1);

        var saved = g.Clip;
        g.SetClip(new Rectangle(1, 1, right - 1, bottom - 1));
        var (selStart, selEnd) = Selection();
        int y = 1;
        for (int i = _v.Value; i < _lines.Count && y < bottom; i++, y += rowH)
        {
            Draw.Text(g, (i + 1).ToString(), Theme.MonoSmall(Dpi), new Rectangle(1, y, Gutter - Px(5), rowH), Theme.Hex(0x565C63), TextFormatFlags.Right);
            string line = _lines[i];
            int x0 = TextLeft - _h.Value;
            var clip = new Rectangle(Gutter + 1, y, right - Gutter - 1, rowH);

            if (HasSelection && i >= selStart.Y && i <= selEnd.Y)
            {
                int a = i == selStart.Y ? selStart.X : 0;
                int b = i == selEnd.Y ? selEnd.X : line.Length + 1;
                var sel = Rectangle.Intersect(clip, new Rectangle(x0 + a * cw, y, (b - a) * cw, rowH));
                Draw.Selection(g, sel, Focused);
            }
            else if (i == _caret.Y && Focused && !ReadOnly)
            {
                Draw.Fill(g, clip, Theme.Hex(0x191B1E));
            }

            g.SetClip(clip);
            _spans.Clear();
            Syntax?.Colorize(_lines, i, _spans);
            if (_spans.Count == 0) DrawRun(g, font, line, 0, line.Length, x0, y, cw, rowH, Theme.Text);
            else
            {
                int at = 0;
                foreach (var s in _spans)
                {
                    if (s.Start > at) DrawRun(g, font, line, at, s.Start - at, x0, y, cw, rowH, Theme.Text);
                    DrawRun(g, font, line, s.Start, s.Length, x0, y, cw, rowH, s.Color);
                    at = s.Start + s.Length;
                }
                if (at < line.Length) DrawRun(g, font, line, at, line.Length - at, x0, y, cw, rowH, Theme.Text);
            }
            if (i == _caret.Y && Focused && !ReadOnly && _caretOn)
                g.FillRectangle(Draw.Brush(Theme.Brass), x0 + _caret.X * cw, y + 1, Math.Max(1, Px(1)), rowH - 2);
            g.SetClip(new Rectangle(1, 1, right - 1, bottom - 1));
        }
        g.Clip = saved;
        saved.Dispose();
        if (_showH) Draw.Fill(g, new Rectangle(_h.Right, _h.Top, _v.Width, _h.Height), Theme.Panel);
    }

    private static void DrawRun(Graphics g, Font font, string line, int start, int len, int x0, int y, int cw, int rowH, Color color)
    {
        if (len <= 0) return;
        string text = line.Substring(start, len);
        TextRenderer.DrawText(g, text, font, new Rectangle(x0 + start * cw, y, len * cw + cw, rowH), color,
            TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine | TextFormatFlags.VerticalCenter | TextFormatFlags.PreserveGraphicsClipping);
    }

    private Point PointAt(Point p)
    {
        int row = Math.Clamp((p.Y - 1) / RowH + _v.Value, 0, _lines.Count - 1);
        int col = (p.X - TextLeft + _h.Value + CharW / 2) / CharW;
        return new Point(Math.Clamp(col, 0, _lines[row].Length), row);
    }

    private void Touch(bool extend)
    {
        if (!extend) _anchor = _caret;
        _caretOn = true;
        if (Focused) _blink.Stop();
        if (Focused) _blink.Start();
        if (_caret.Y < _v.Value) _v.Value = _caret.Y;
        else if (_caret.Y >= _v.Value + VisibleRows) _v.Value = _caret.Y - VisibleRows + 1;
        int cx = _caret.X * CharW;
        int viewW = Math.Max(CharW, _v.Left - TextLeft - CharW);
        if (cx < _h.Value) _h.Value = cx;
        else if (cx > _h.Value + viewW) _h.Value = cx - viewW;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        if (e.Button != MouseButtons.Left) return;
        _caret = PointAt(e.Location);
        Touch(ModifierKeys.HasFlag(Keys.Shift));
        _dragging = true;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (!_dragging) return;
        _caret = PointAt(e.Location);
        Touch(true);
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        _dragging = false;
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _v.Value -= WheelLines(e);
    }

    protected override void OnGotFocus(EventArgs e)
    {
        base.OnGotFocus(e);
        if (!ReadOnly) _blink.Start();
        Invalidate();
    }

    protected override void OnLostFocus(EventArgs e)
    {
        base.OnLostFocus(e);
        _blink.Stop();
        Invalidate();
    }

    protected override bool IsInputKey(Keys keyData)
    {
        var k = keyData & Keys.KeyCode;
        return k is Keys.Up or Keys.Down or Keys.Left or Keys.Right or Keys.Home or Keys.End or Keys.PageUp or Keys.PageDown
            or Keys.Return or Keys.Tab || base.IsInputKey(keyData);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        bool shift = e.Shift;
        switch (e.KeyCode)
        {
            case Keys.Left:
                if (_caret.X > 0) _caret.X--;
                else if (_caret.Y > 0) { _caret.Y--; _caret.X = _lines[_caret.Y].Length; }
                Touch(shift);
                break;
            case Keys.Right:
                if (_caret.X < _lines[_caret.Y].Length) _caret.X++;
                else if (_caret.Y < _lines.Count - 1) { _caret.Y++; _caret.X = 0; }
                Touch(shift);
                break;
            case Keys.Up: MoveRow(-1, shift); break;
            case Keys.Down: MoveRow(1, shift); break;
            case Keys.PageUp: MoveRow(-Math.Max(1, VisibleRows - 1), shift); break;
            case Keys.PageDown: MoveRow(Math.Max(1, VisibleRows - 1), shift); break;
            case Keys.Home:
                if (e.Control) _caret.Y = 0;
                _caret.X = 0;
                Touch(shift);
                break;
            case Keys.End:
                if (e.Control) _caret.Y = _lines.Count - 1;
                _caret.X = _lines[_caret.Y].Length;
                Touch(shift);
                break;
            case Keys.Back when !ReadOnly: Backspace(); break;
            case Keys.Delete when !ReadOnly: DeleteForward(); break;
            case Keys.Return when !ReadOnly: Insert("\n"); break;
            case Keys.Tab when !ReadOnly: Insert("    "); break;
            case Keys.A when e.Control: SelectAll(); break;
            case Keys.C when e.Control: CopySelection(); break;
            case Keys.X when e.Control: CutSelection(); break;
            case Keys.V when e.Control: PasteClipboard(); break;
            default: return;
        }
        e.Handled = true;
        e.SuppressKeyPress = true;
    }

    protected override void OnKeyPress(KeyPressEventArgs e)
    {
        base.OnKeyPress(e);
        if (ReadOnly || char.IsControl(e.KeyChar)) return;
        Insert(e.KeyChar.ToString());
        e.Handled = true;
    }

    private void MoveRow(int delta, bool extend)
    {
        _caret.Y = Math.Clamp(_caret.Y + delta, 0, _lines.Count - 1);
        _caret.X = Math.Min(_caret.X, _lines[_caret.Y].Length);
        Touch(extend);
    }

    private void SelectAll()
    {
        _anchor = Point.Empty;
        _caret = new Point(_lines[^1].Length, _lines.Count - 1);
        Invalidate();
    }

    private string SelectedText()
    {
        var (s, e) = Selection();
        if (s.Y == e.Y) return _lines[s.Y].Substring(s.X, e.X - s.X);
        var sb = new StringBuilder(_lines[s.Y][s.X..]);
        for (int i = s.Y + 1; i < e.Y; i++) sb.Append("\r\n").Append(_lines[i]);
        sb.Append("\r\n").Append(_lines[e.Y][..e.X]);
        return sb.ToString();
    }

    private void CopySelection()
    {
        if (HasSelection) Clipboard.SetText(SelectedText());
    }

    private void CutSelection()
    {
        if (!HasSelection || ReadOnly) return;
        CopySelection();
        DeleteSelection();
        Edited();
    }

    private void PasteClipboard()
    {
        if (!ReadOnly && Clipboard.ContainsText()) Insert(Clipboard.GetText());
    }

    private void DeleteSelection()
    {
        if (!HasSelection) return;
        var (s, e) = Selection();
        string merged = _lines[s.Y][..s.X] + _lines[e.Y][e.X..];
        _lines.RemoveRange(s.Y, e.Y - s.Y + 1);
        _lines.Insert(s.Y, merged);
        _caret = s;
        _anchor = s;
    }

    private void Insert(string text)
    {
        DeleteSelection();
        var parts = text.Replace("\r", string.Empty).Split('\n');
        string line = _lines[_caret.Y];
        string head = line[.._caret.X], tail = line[_caret.X..];
        if (parts.Length == 1)
        {
            _lines[_caret.Y] = head + parts[0] + tail;
            _caret.X += parts[0].Length;
        }
        else
        {
            _lines[_caret.Y] = head + parts[0];
            for (int i = 1; i < parts.Length - 1; i++) _lines.Insert(_caret.Y + i, parts[i]);
            _lines.Insert(_caret.Y + parts.Length - 1, parts[^1] + tail);
            _caret.Y += parts.Length - 1;
            _caret.X = parts[^1].Length;
        }
        Edited();
    }

    private void Backspace()
    {
        if (HasSelection) { DeleteSelection(); Edited(); return; }
        if (_caret.X > 0)
        {
            _lines[_caret.Y] = _lines[_caret.Y].Remove(_caret.X - 1, 1);
            _caret.X--;
        }
        else if (_caret.Y > 0)
        {
            int len = _lines[_caret.Y - 1].Length;
            _lines[_caret.Y - 1] += _lines[_caret.Y];
            _lines.RemoveAt(_caret.Y);
            _caret = new Point(len, _caret.Y - 1);
        }
        Edited();
    }

    private void DeleteForward()
    {
        if (HasSelection) { DeleteSelection(); Edited(); return; }
        string line = _lines[_caret.Y];
        if (_caret.X < line.Length) _lines[_caret.Y] = line.Remove(_caret.X, 1);
        else if (_caret.Y < _lines.Count - 1)
        {
            _lines[_caret.Y] = line + _lines[_caret.Y + 1];
            _lines.RemoveAt(_caret.Y + 1);
        }
        Edited();
    }

    private void Edited()
    {
        _anchor = _caret;
        UpdateScroll();
        Touch(false);
        TextEdited?.Invoke(this, EventArgs.Empty);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _blink.Dispose();
        base.Dispose(disposing);
    }
}

internal sealed class TextPane : SkinControl
{
    private readonly SkinScrollBar _bar = new(false);
    private List<(string Text, bool Heading, bool Mono)> _blocks = new();
    private int _contentHeight;

    public TextPane()
    {
        BackColor = Theme.Inset;
        _bar.ValueChanged += (_, _) => Invalidate();
        _bar.SmallChange = 16;
        Controls.Add(_bar);
    }

    public void SetBlocks(List<(string Text, bool Heading, bool Mono)> blocks)
    {
        _blocks = blocks;
        _bar.Value = 0;
        Measure();
        Invalidate();
    }

    private Font FontFor((string Text, bool Heading, bool Mono) b) => b.Heading ? BoldFont : b.Mono ? Theme.MonoSmall(Dpi) : UiFont;

    private void Measure()
    {
        int width = TextWidth;
        int y = Px(6);
        foreach (var b in _blocks)
            y += Draw.MeasureWrapped(b.Text, FontFor(b), width) + Px(b.Heading ? 3 : 7);
        _contentHeight = y;
        _bar.SetRange(_contentHeight, Math.Max(1, Height - 2));
        bool show = _contentHeight > Height - 2;
        _bar.Visible = show;
    }

    private int TextWidth => Math.Max(10, Width - Px(14) - _bar.ThicknessPx);

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int w = _bar.ThicknessPx;
        _bar.SetBounds(Width - w - 1, 1, w, Height - 2);
        Measure();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        int width = TextWidth;
        int y = Px(6) - _bar.Value;
        var saved = g.Clip;
        g.SetClip(new Rectangle(1, 1, Width - 2, Height - 2));
        foreach (var b in _blocks)
        {
            var font = FontFor(b);
            int h = Draw.MeasureWrapped(b.Text, font, width);
            if (y + h > 0 && y < Height)
                TextRenderer.DrawText(g, b.Text, font, new Rectangle(Px(7), y, width, h), b.Heading ? Theme.Brass : Theme.Text,
                    TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl | TextFormatFlags.PreserveGraphicsClipping);
            y += h + Px(b.Heading ? 3 : 7);
        }
        g.Clip = saved;
        saved.Dispose();
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        _bar.Value -= WheelLines(e) * Px(15);
    }
}
