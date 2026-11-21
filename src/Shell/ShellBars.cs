using TryZ.Data;

namespace TryZ.Shell;

internal sealed class ToolbarItem
{
    public string? Text { get; init; }
    public IconId Icon { get; init; }
    public Action? Action { get; init; }
    public string? Tip { get; init; }
    public bool Enabled { get; set; } = true;
    public bool IsSeparator => Text == null;
    public Rectangle Bounds { get; set; }
}

internal sealed class Toolbar : SkinControl
{
    private readonly List<ToolbarItem> _items = new();
    private readonly SkinTip _tip = new();
    private int _hot = -1;
    private int _pressed = -1;

    public const int LogicalHeight = 34;

    public ToolbarItem Add(string text, IconId icon, Action action, string tip)
    {
        var item = new ToolbarItem { Text = text, Icon = icon, Action = action, Tip = tip };
        _items.Add(item);
        return item;
    }

    public void AddSeparator() => _items.Add(new ToolbarItem());

    public void SetEnabled(ToolbarItem item, bool enabled)
    {
        if (item.Enabled == enabled) return;
        item.Enabled = enabled;
        Invalidate();
    }

    private void Measure()
    {
        int x = Px(4);
        int h = Height;
        foreach (var item in _items)
        {
            if (item.IsSeparator)
            {
                item.Bounds = new Rectangle(x + Px(2), Px(5), Px(2), h - Px(11));
                x += Px(7);
                continue;
            }
            int w = Px(22) + Px(4) + Draw.Measure(item.Text!, UiFont) + Px(10);
            item.Bounds = new Rectangle(x, Px(3), w, h - Px(7));
            x += w + Px(1);
        }
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        Measure();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var r = ClientRectangle;
        Draw.Gloss(g, r, Theme.Hex(0x41454B), Theme.Hex(0x34383D), Theme.Hex(0x2A2D31), Theme.Hex(0x212327));
        g.DrawLine(Draw.Pen(Theme.Hex(0x53585F)), 0, 0, Width, 0);
        Draw.EtchH(g, 0, Width, Height - 2);

        int gripX = Px(1);
        for (int y = Px(6); y < Height - Px(7); y += Px(3) + 1)
        {
            g.FillRectangle(Draw.Brush(Theme.Highlight), gripX, y, Math.Max(1, Px(1)), Math.Max(1, Px(1)));
        }

        int icon = Px(20);
        for (int i = 0; i < _items.Count; i++)
        {
            var item = _items[i];
            var b = item.Bounds;
            if (item.IsSeparator)
            {
                Draw.EtchV(g, b.X, b.Y, b.Bottom);
                continue;
            }
            bool hot = i == _hot && item.Enabled;
            bool pressed = hot && i == _pressed;
            if (pressed)
            {
                Draw.Gradient(g, b, Theme.Hex(0x1B1D20), Theme.Hex(0x2A2D31));
                Draw.Frame(g, b, Theme.BorderDark);
                g.DrawLine(Draw.Pen(Theme.Highlight), b.X + 1, b.Bottom, b.Right - 1, b.Bottom);
            }
            else if (hot)
            {
                Draw.Gloss(g, b, Theme.Hex(0x565B62), Theme.Hex(0x45494F), Theme.Hex(0x383C42), Theme.Hex(0x41454B));
                Draw.Frame(g, b, Theme.BorderDark);
                g.DrawLine(Draw.Pen(Theme.Hex(0x70767E)), b.X + 1, b.Y + 1, b.Right - 2, b.Y + 1);
            }
            int off = pressed ? 1 : 0;
            g.DrawImage(Icons.Get(item.Icon, icon, !item.Enabled), b.X + Px(4) + off, b.Y + (b.Height - icon) / 2 + off, icon, icon);
            var text = new Rectangle(b.X + Px(26) + off, b.Y + off, b.Width - Px(28), b.Height);
            if (item.Enabled) Draw.Engraved(g, item.Text, UiFont, text, Theme.Text);
            else Draw.Text(g, item.Text, UiFont, text, Theme.TextDisabled);
        }
    }

    private int ItemAt(Point p)
    {
        for (int i = 0; i < _items.Count; i++)
            if (!_items[i].IsSeparator && _items[i].Bounds.Contains(p)) return i;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int hot = ItemAt(e.Location);
        if (hot == _hot) return;
        _hot = hot;
        Invalidate();
        if (hot >= 0) _tip.Show(_items[hot].Tip ?? string.Empty, this, _items[hot].Bounds.X, Height + Px(2), 4000);
        else _tip.Hide(this);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = -1;
        _tip.Hide(this);
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        _pressed = ItemAt(e.Location);
        Invalidate();
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        int p = _pressed;
        _pressed = -1;
        Invalidate();
        if (p >= 0 && p == ItemAt(e.Location) && _items[p].Enabled) _items[p].Action?.Invoke();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _tip.Dispose();
        base.Dispose(disposing);
    }
}

internal sealed class SkinTip : ToolTip
{
    public SkinTip()
    {
        OwnerDraw = true;
        BackColor = Theme.Panel;
        ForeColor = Theme.Text;
        Draw += PaintTip;
        Popup += OnPopup;
    }


    private void OnPopup(object? sender, PopupEventArgs e)
    {
        string? text = e.AssociatedControl is { } owner ? GetToolTip(owner) : null;
        int w = TextRenderer.MeasureText(string.IsNullOrEmpty(text) ? "Xg" : text, Theme.Ui(e.AssociatedControl?.DeviceDpi ?? 96)).Width;
        e.ToolTipSize = new Size(Math.Max(e.ToolTipSize.Width, w + 8), e.ToolTipSize.Height);
    }

    private static void PaintTip(object? sender, DrawToolTipEventArgs e)
    {
        var r = e.Bounds;
        TryZ.Visual.Draw.Gradient(e.Graphics, r, Theme.Hex(0x34383D), Theme.Hex(0x1F2125));
        TryZ.Visual.Draw.Frame(e.Graphics, r, Theme.BrassDark);
        TextRenderer.DrawText(e.Graphics, e.ToolTipText, Theme.Ui(e.AssociatedControl?.DeviceDpi ?? 96), r, Theme.Text,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.NoPrefix);
    }
}

internal sealed class StatusPanel : SkinControl
{
    private ScanState _state = ScanState.Idle;
    private string _stateText = "Ready";
    private string _threads = "Threads 0/0";
    private string _elapsed = "Elapsed 00:00";
    private string _rate = "Req/s 0";
    private string _findings = "Findings 0";
    private double _progress;

    public const int LogicalHeight = 22;

    public Rectangle GripRect => new(Width - Px(16), Height - Px(16), Px(16), Px(16));

    public void SetValues(ScanState state, string stateText, string threads, string elapsed, string rate, string findings, double progress)
    {
        if (_state == state && _stateText == stateText && _threads == threads && _elapsed == elapsed
            && _rate == rate && _findings == findings && Math.Abs(_progress - progress) < 0.0005) return;
        _state = state;
        _stateText = stateText;
        _threads = threads;
        _elapsed = elapsed;
        _rate = rate;
        _findings = findings;
        _progress = progress;
        Invalidate();
    }

    protected override void WndProc(ref Message m)
    {
        const int WM_NCHITTEST = 0x0084, HTTRANSPARENT = -1;
        if (m.Msg == WM_NCHITTEST)
        {
            long v = m.LParam.ToInt64();
            var p = PointToClient(new Point((short)(v & 0xFFFF), (short)((v >> 16) & 0xFFFF)));
            if (GripRect.Contains(p) && FindForm()?.WindowState == FormWindowState.Normal)
            {
                m.Result = HTTRANSPARENT;
                return;
            }
        }
        base.WndProc(ref m);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var r = ClientRectangle;
        Draw.Gradient(g, r, Theme.Hex(0x2C2F33), Theme.Hex(0x1F2125));
        g.DrawLine(Draw.Pen(Theme.BorderDark), 0, 0, Width, 0);
        g.DrawLine(Draw.Pen(Theme.Hex(0x3C4046)), 0, 1, Width, 1);

        int right = Width - Px(15);
        int progressW = Px(150);
        int y = Px(3), h = Height - Px(6);
        var font = UiFont;

        var bar = new Rectangle(right - progressW, y, progressW, h);
        SegmentedProgress.PaintBlocks(g, bar, _progress, Theme.Hex(0xE2BE76), Theme.Hex(0x8A6C30), Px(5), Math.Max(1, Px(1)));
        right = bar.X - Px(5);

        right = Cell(g, _findings, Px(76), right, y, h, font, Theme.Text);
        right = Cell(g, _rate, Px(66), right, y, h, font, Theme.Text);
        right = Cell(g, _elapsed, Px(82), right, y, h, font, Theme.Text);
        right = Cell(g, _threads, Px(82), right, y, h, font, Theme.Text);
        bool scanning = _state is ScanState.Running or ScanState.Paused;
        right = Cell(g, scanning ? "Engine: scanning" : "Engine: ready", Px(120), right, y, h, font, scanning ? Theme.Ok : Theme.Brass);

        int led = Px(9);
        var ledRect = new Rectangle(Px(6), (Height - led) / 2, led, led);
        var ledColor = _state switch
        {
            ScanState.Running => Theme.Ok,
            ScanState.Paused => Theme.Medium,
            ScanState.Stopped or ScanState.Failed => Theme.Critical,
            ScanState.Completed => Theme.Low,
            _ => Theme.Hex(0x565C63),
        };
        Draw.Gradient(g, ledRect, Theme.Shift(ledColor, 42), Theme.Shift(ledColor, -60));
        Draw.Frame(g, ledRect, Theme.BorderDark);
        Draw.Text(g, _stateText, font, new Rectangle(ledRect.Right + Px(5), y, Math.Max(0, right - ledRect.Right - Px(8)), h), Theme.Text);

        PaintGrip(g);
    }

    private int Cell(Graphics g, string text, int width, int right, int y, int h, Font font, Color color)
    {
        int x = right - width;
        Draw.Sunken(g, new Rectangle(x, y, width, h), Theme.Hex(0x1C1E21));
        Draw.Text(g, text, font, new Rectangle(x + Px(4), y, width - Px(7), h), color);
        return x - Px(2);
    }

    private void PaintGrip(Graphics g)
    {
        if (FindForm()?.WindowState == FormWindowState.Maximized) return;
        int s = Math.Max(1, Px(1));
        int pitch = s * 4;
        for (int row = 0; row < 3; row++)
        {
            for (int col = 0; col <= row; col++)
            {
                int x = Width - pitch * (col + 1) - s;
                int y = Height - pitch * (3 - row) - s;
                g.FillRectangle(Draw.Brush(Theme.Highlight), x, y, s, s);
                g.FillRectangle(Draw.Brush(Theme.BorderDark), x + s, y + s, s, s);
            }
        }
    }
}

internal sealed class Navigator : SkinControl
{
    private sealed record Entry(int Module, string Title, IconId Icon);

    private readonly (string Group, Entry[] Items)[] _groups =
    {
        ("Assessment", new[]
        {
            new Entry(0, "Overview", IconId.Overview),
            new Entry(1, "Discovery", IconId.Discovery),
            new Entry(2, "Port Audit", IconId.PortAudit),
            new Entry(3, "Vulnerability Audit", IconId.Vulnerability),
            new Entry(7, "Remediation Plan", IconId.Remediation),
        }),
        ("Web Application", new[]
        {
            new Entry(4, "Web Crawler", IconId.Crawler),
            new Entry(5, "HTTP Workbench", IconId.Workbench),
        }),
        ("Output", new[]
        {
            new Entry(6, "Reports", IconId.Reports),
            new Entry(8, "Scan Compare", IconId.Compare),
        }),
    };

    private readonly string[] _counts = new string[9];
    private List<(string Key, string Value)> _summary = new();
    private int _selected;
    private int _hot = -1;

    public Navigator()
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
    }

    public event EventHandler? SelectedChanged;

    public int SelectedModule
    {
        get => _selected;
        set
        {
            if (_selected == value) return;
            _selected = value;
            Invalidate();
            SelectedChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void SetCount(int module, string? text)
    {
        text ??= string.Empty;
        if (_counts[module] == text) return;
        _counts[module] = text;
        Invalidate();
    }

    public void SetSummary(List<(string Key, string Value)> rows)
    {
        if (rows.SequenceEqual(_summary)) return;
        _summary = rows;
        Invalidate();
    }

    private int LogoBand => LogoArt.SizeFor(Dpi).Height + Px(12);
    private int ItemH => Px(23);
    private int GroupH => Px(21);

    private IEnumerable<(Entry Item, Rectangle Bounds)> ItemBounds()
    {
        int y = LogoBand + Px(3);
        foreach (var (_, items) in _groups)
        {
            y += GroupH;
            foreach (var item in items)
            {
                yield return (item, new Rectangle(Px(2), y, Width - Px(5), ItemH));
                y += ItemH;
            }
            y += Px(2);
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Gradient(g, ClientRectangle, Theme.Hex(0x282B2F), Theme.Hex(0x1F2125), horizontal: true);
        g.DrawLine(Draw.Pen(Theme.BorderDark), Width - 1, 0, Width - 1, Height);

        var logoBand = new Rectangle(0, 0, Width - 1, LogoBand);
        Draw.Gradient(g, logoBand, Theme.Hex(0x141517), Theme.Hex(0x1C1E21));
        var logo = LogoArt.Get(Dpi);
        g.DrawImageUnscaled(logo, (Width - 1 - logo.Width) / 2, Px(6));
        Draw.EtchH(g, 0, Width - 2, LogoBand - 2);

        int y = LogoBand + Px(3);
        foreach (var (group, items) in _groups)
        {
            var header = new Rectangle(Px(7), y, Width - Px(14), GroupH);
            int tw = Draw.Measure(group, BoldFont);
            Draw.Text(g, group, BoldFont, new Rectangle(header.X, y + Px(1), tw + 2, GroupH - Px(2)), Theme.Brass);
            int lineY = y + GroupH / 2;
            if (header.X + tw + Px(6) < header.Right)
                Draw.EtchH(g, header.X + tw + Px(6), header.Right, lineY);
            y += GroupH + items.Length * ItemH + Px(2);
        }

        var mono = Theme.MonoSmall(Dpi);
        int iconS = Px(16);
        foreach (var (item, r) in ItemBounds())
        {
            bool selected = item.Module == _selected;
            bool hot = item.Module == _hot;
            if (selected)
            {
                Draw.Selection(g, r);
                Draw.Frame(g, r, Theme.BorderDark);
                Draw.Fill(g, new Rectangle(r.X + 1, r.Y + 1, Math.Max(2, Px(2)), r.Height - 2), Theme.Brass);
            }
            else if (hot)
            {
                Draw.Raised(g, r, ChromeState.Hot);
            }
            g.DrawImage(Icons.Get(item.Icon, iconS), r.X + Px(9), r.Y + (r.Height - iconS) / 2, iconS, iconS);
            int textX = r.X + Px(30);
            string count = _counts[item.Module] ?? string.Empty;
            int cw = count.Length > 0 ? Draw.Measure(count, mono) + Px(5) : 0;
            var color = selected ? Theme.TextBright : Theme.Text;
            if (selected) Draw.Engraved(g, item.Title, BoldFont, new Rectangle(textX, r.Y, r.Right - textX - cw, r.Height), color);
            else Draw.Text(g, item.Title, UiFont, new Rectangle(textX, r.Y, r.Right - textX - cw, r.Height), color);
            if (cw > 0)
                Draw.Text(g, count, mono, new Rectangle(r.Right - cw - Px(1), r.Y, cw, r.Height), selected ? Theme.Brass : Theme.TextDim, TextFormatFlags.Right);
        }

        PaintSummary(g, y);
    }

    private void PaintSummary(Graphics g, int minY)
    {
        if (_summary.Count == 0) return;
        int rowH = Px(15);
        int h = GroupH + rowH * _summary.Count + Px(6);
        int y = Height - h;
        if (y < minY + Px(4)) return;

        int tw = Draw.Measure("Session", BoldFont);
        Draw.Text(g, "Session", BoldFont, new Rectangle(Px(7), y, tw + 2, GroupH - Px(2)), Theme.Brass);
        Draw.EtchH(g, Px(7) + tw + Px(6), Width - Px(8), y + (GroupH - Px(2)) / 2);
        y += GroupH;
        var box = new Rectangle(Px(5), y - Px(1), Width - Px(11), rowH * _summary.Count + Px(3));
        Draw.Sunken(g, box, Theme.Inset);
        var mono = Theme.MonoSmall(Dpi);
        foreach (var (key, value) in _summary)
        {
            Draw.Text(g, key, UiFont, new Rectangle(box.X + Px(4), y, Px(62), rowH), Theme.TextDim);
            Draw.Text(g, value, mono, new Rectangle(box.X + Px(66), y, box.Width - Px(70), rowH), Theme.Text, TextFormatFlags.Right);
            y += rowH;
        }
    }

    private int ModuleAt(Point p)
    {
        foreach (var (item, r) in ItemBounds())
            if (r.Contains(p)) return item.Module;
        return -1;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int hot = ModuleAt(e.Location);
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
        int m = ModuleAt(e.Location);
        if (m >= 0) SelectedModule = m;
    }

    protected override bool IsInputKey(Keys keyData) => keyData is Keys.Up or Keys.Down || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.KeyCode == Keys.Up && _selected > 0) SelectedModule = _selected - 1;
        else if (e.KeyCode == Keys.Down && _selected < 6) SelectedModule = _selected + 1;
    }
}
