using System.Drawing.Drawing2D;

namespace TryZ.Controls;

internal sealed class SegmentedProgress : SkinControl
{
    private double _value;

    public double Value
    {
        get => _value;
        set
        {
            double v = Math.Clamp(value, 0, 1);
            if (Math.Abs(v - _value) < 0.0005) return;
            _value = v;
            Invalidate();
        }
    }

    public Color LitTop { get; set; } = Theme.Hex(0xD6423A);
    public Color LitBottom { get; set; } = Theme.Hex(0x7A1818);

    protected override void OnPaint(PaintEventArgs e) =>
        PaintBlocks(e.Graphics, ClientRectangle, _value, LitTop, LitBottom, Px(5), Math.Max(1, Px(1)));

    public static void PaintBlocks(Graphics g, Rectangle r, double value, Color top, Color bottom, int segment, int gap)
    {
        Draw.Sunken(g, r, Theme.Hex(0x0D0E10));
        var area = Rectangle.Inflate(r, -2, -2);
        if (area.Width <= 0 || area.Height <= 0) return;
        int pitch = segment + gap;
        int count = (area.Width + gap) / pitch;
        int lit = (int)Math.Floor(count * value + 0.0001);
        using var litBrush = new LinearGradientBrush(new Rectangle(area.X, area.Y - 1, area.Width, area.Height + 2), top, bottom, LinearGradientMode.Vertical);
        var dark = Draw.Brush(Theme.Hex(0x1C1E21));
        for (int i = 0; i < count; i++)
        {
            var b = new Rectangle(area.X + i * pitch, area.Y, segment, area.Height);
            g.FillRectangle(i < lit ? litBrush : dark, b);
        }
    }
}

internal sealed class LedCounter : SkinControl
{
    private static readonly byte[] Segments =
    {
        0b0111111, 0b0000110, 0b1011011, 0b1001111, 0b1100110,
        0b1101101, 0b1111101, 0b0000111, 0b1111111, 0b1101111,
    };

    private readonly int _digits;
    private int _value;

    public LedCounter(string caption, Color color, int digits = 3)
    {
        Caption = caption;
        LitColor = color;
        _digits = digits;
    }

    public string Caption { get; }
    public Color LitColor { get; }

    public int Value
    {
        get => _value;
        set
        {
            if (_value == value) return;
            _value = value;
            Invalidate();
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Fill(g, ClientRectangle, BackColor);
        int labelH = Px(13);
        Draw.Text(g, Caption, Theme.UiSmall(Dpi), new Rectangle(0, 0, Width, labelH), Theme.TextDim, TextFormatFlags.HorizontalCenter);

        var bezel = new Rectangle(0, labelH + 1, Width, Height - labelH - 1);
        Draw.Gradient(g, bezel, Theme.Hex(0x101113), Theme.Hex(0x2E3135));
        Draw.Frame(g, bezel, Theme.BorderDark);
        g.DrawLine(Draw.Pen(Theme.EtchLight), bezel.X + 1, bezel.Bottom, bezel.Right, bezel.Bottom);
        var glass = Rectangle.Inflate(bezel, -Px(3), -Px(3));
        Draw.Fill(g, glass, Theme.Hex(0x0A0B0C));
        Draw.Frame(g, glass, Theme.Hex(0x030304));

        int digitH = glass.Height - Px(6);
        int digitW = Math.Min((glass.Width - Px(6)) / _digits - Px(2), digitH * 5 / 9);
        if (digitW <= 2) return;
        int total = _digits * digitW + (_digits - 1) * Px(2);
        int x = glass.X + (glass.Width - total) / 2;
        int y = glass.Y + Px(3);

        var unlit = Color.FromArgb(LitColor.R / 7 + 8, LitColor.G / 7 + 8, LitColor.B / 7 + 8);
        string text = Math.Min(_value, (int)Math.Pow(10, _digits) - 1).ToString().PadLeft(_digits, ' ');
        var mode = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        for (int i = 0; i < _digits; i++)
        {
            byte mask = text[i] == ' ' ? (byte)0 : Segments[text[i] - '0'];
            PaintDigit(g, new RectangleF(x, y, digitW, digitH), mask, LitColor, unlit);
            x += digitW + Px(2);
        }
        g.SmoothingMode = mode;

        var sheen = new Rectangle(glass.X + 1, glass.Y + 1, glass.Width - 2, glass.Height / 3);
        using var gloss = new LinearGradientBrush(new Rectangle(sheen.X, sheen.Y - 1, sheen.Width, sheen.Height + 2),
            Color.FromArgb(26, 255, 255, 255), Color.FromArgb(0, 255, 255, 255), LinearGradientMode.Vertical);
        g.FillRectangle(gloss, sheen);
    }

    private static void PaintDigit(Graphics g, RectangleF r, byte mask, Color lit, Color unlit)
    {
        float t = Math.Max(1.5f, r.Width * 0.2f);
        float gap = t * 0.14f;
        float l = r.X, rt = r.Right, top = r.Y, bot = r.Bottom, mid = r.Y + r.Height / 2;
        (PointF A, PointF B)[] segs =
        {
            (new PointF(l + t / 2, top + t / 2), new PointF(rt - t / 2, top + t / 2)),
            (new PointF(rt - t / 2, top + t / 2), new PointF(rt - t / 2, mid)),
            (new PointF(rt - t / 2, mid), new PointF(rt - t / 2, bot - t / 2)),
            (new PointF(l + t / 2, bot - t / 2), new PointF(rt - t / 2, bot - t / 2)),
            (new PointF(l + t / 2, mid), new PointF(l + t / 2, bot - t / 2)),
            (new PointF(l + t / 2, top + t / 2), new PointF(l + t / 2, mid)),
            (new PointF(l + t / 2, mid), new PointF(rt - t / 2, mid)),
        };
        for (int i = 0; i < 7; i++)
        {
            var (a, b) = segs[i];
            bool on = (mask & (1 << i)) != 0;
            PaintSegment(g, a, b, t, gap, on ? lit : unlit);
        }
    }

    private static void PaintSegment(Graphics g, PointF a, PointF b, float t, float gap, Color c)
    {
        float h = t / 2;
        PointF[] pts;
        if (Math.Abs(a.Y - b.Y) < 0.01f)
        {
            float x1 = a.X + gap, x2 = b.X - gap, y = a.Y;
            pts = new[] { new PointF(x1, y), new PointF(x1 + h, y - h), new PointF(x2 - h, y - h), new PointF(x2, y), new PointF(x2 - h, y + h), new PointF(x1 + h, y + h) };
        }
        else
        {
            float y1 = a.Y + gap, y2 = b.Y - gap, x = a.X;
            pts = new[] { new PointF(x, y1), new PointF(x + h, y1 + h), new PointF(x + h, y2 - h), new PointF(x, y2), new PointF(x - h, y2 - h), new PointF(x - h, y1 + h) };
        }
        g.FillPolygon(Draw.Brush(c), pts);
    }
}

internal sealed class GraphView : SkinControl
{
    private const int Capacity = 240;
    private readonly double[] _primary = new double[Capacity];
    private readonly double[] _secondary = new double[Capacity];
    private int _count;
    private int _head;
    private double _scale = 400;

    public GraphView()
    {
        BackColor = Theme.Hex(0x0A0C0B);
    }

    public string PrimaryLabel { get; set; } = "req/s";
    public string SecondaryLabel { get; set; } = "latency ms";

    public void Clear()
    {
        _count = 0;
        _head = 0;
        _scale = 400;
        Invalidate();
    }

    public void Push(double primary, double secondary)
    {
        _primary[_head] = primary;
        _secondary[_head] = secondary;
        _head = (_head + 1) % Capacity;
        if (_count < Capacity) _count++;
        double peak = 0;
        for (int i = 0; i < _count; i++) peak = Math.Max(peak, _primary[i]);
        double target = Math.Max(400, Math.Ceiling(peak * 1.25 / 100) * 100);
        _scale += (target - _scale) * 0.2;
        Invalidate();
    }

    private double Sample(double[] buffer, int fromNewest) => buffer[(_head - 1 - fromNewest + Capacity * 2) % Capacity];

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Hex(0x0A0C0B));
        int axisW = Px(36);
        var plot = Rectangle.FromLTRB(axisW, Px(5), Width - Px(5), Height - Px(14));
        if (plot.Width <= 10 || plot.Height <= 10) return;

        var minor = Draw.Pen(Theme.Hex(0x171C19));
        var major = Draw.Pen(Theme.Hex(0x263029));
        int cell = Px(24);
        int shift = (_count * Px(3)) % cell;
        for (int x = plot.Right - shift; x > plot.X; x -= cell)
            g.DrawLine((plot.Right - x + shift) % (cell * 4) == 0 ? major : minor, x, plot.Y, x, plot.Bottom);
        var mono = Theme.MonoSmall(Dpi);
        const int hDivisions = 4;
        for (int i = 0; i <= hDivisions; i++)
        {
            int y = plot.Bottom - plot.Height * i / hDivisions;
            g.DrawLine(i == 0 ? major : minor, plot.X, y, plot.Right, y);
            for (int x = plot.X + cell / 2; x < plot.Right; x += cell / 2)
                g.DrawLine(minor, x, y - 1, x, y + 1);
            int value = (int)Math.Round(_scale * i / hDivisions);
            Draw.Text(g, value.ToString(), mono, new Rectangle(0, y - Px(7), axisW - Px(4), Px(14)), Theme.Hex(0x5F6A62), TextFormatFlags.Right);
        }
        g.DrawRectangle(Draw.Pen(Theme.Hex(0x2C3730)), plot);

        Draw.Text(g, "60 s", mono, new Rectangle(plot.X, plot.Bottom + 1, Px(40), Px(13)), Theme.Hex(0x5F6A62));
        Draw.Text(g, "now", mono, new Rectangle(plot.Right - Px(40), plot.Bottom + 1, Px(40), Px(13)), Theme.Hex(0x5F6A62), TextFormatFlags.Right);

        if (_count >= 2)
        {
            var clipSaved = g.Clip;
            g.SetClip(plot);
            var mode = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            Trace(g, plot, _secondary, 250, Theme.Hex(0x57707F), 1f, false);
            Trace(g, plot, _primary, _scale, Theme.Brass, Math.Max(1.2f, Px(1) * 1.3f), true);
            g.SmoothingMode = mode;
            g.Clip = clipSaved;
            clipSaved.Dispose();
        }

        var legendX = plot.X + Px(7);
        var legendY = plot.Y + Px(4);
        g.FillRectangle(Draw.Brush(Theme.Brass), legendX, legendY + Px(5), Px(10), Math.Max(1, Px(2)));
        int w1 = Draw.Measure(PrimaryLabel, mono);
        Draw.Text(g, PrimaryLabel, mono, new Rectangle(legendX + Px(14), legendY, w1 + 2, Px(13)), Theme.Brass);
        int x2 = legendX + Px(14) + w1 + Px(12);
        g.FillRectangle(Draw.Brush(Theme.Hex(0x57707F)), x2, legendY + Px(5), Px(10), Math.Max(1, Px(1)));
        Draw.Text(g, SecondaryLabel, mono, new Rectangle(x2 + Px(14), legendY, Px(90), Px(13)), Theme.Hex(0x7E97A6));

        if (_count > 0)
        {
            string now = $"{Sample(_primary, 0):0}";
            Draw.Text(g, now, Theme.UiBold(Dpi), new Rectangle(plot.Right - Px(66), plot.Y + Px(3), Px(60), Px(14)), Theme.Brass, TextFormatFlags.Right);
        }
    }

    private void Trace(Graphics g, Rectangle plot, double[] data, double scale, Color color, float width, bool phosphor)
    {
        float step = plot.Width / (float)Math.Max(1, Capacity - 1);
        int n = Math.Min(_count, Capacity);
        var pts = new PointF[n];
        for (int i = 0; i < n; i++)
        {
            double v = Sample(data, i);
            pts[i] = new PointF(plot.Right - i * step, plot.Bottom - (float)(Math.Clamp(v / scale, 0, 1) * (plot.Height - 2)));
        }
        if (phosphor)
        {
            using var wide = new Pen(Color.FromArgb(38, color), width + 2.2f) { LineJoin = LineJoin.Round };
            g.DrawLines(wide, pts);
        }
        using var pen = new Pen(color, width) { LineJoin = LineJoin.Round };
        g.DrawLines(pen, pts);
    }
}

internal sealed record PhaseRow(string Name, double Progress, string State);

internal sealed class PhaseList : SkinControl
{
    private List<PhaseRow> _rows = new();

    public PhaseList()
    {
        BackColor = Theme.Inset;
    }

    public void SetRows(List<PhaseRow> rows)
    {
        if (rows.SequenceEqual(_rows)) return;
        _rows = rows;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        if (_rows.Count == 0) return;
        int rowH = Math.Max(Px(12), Math.Min(Px(21), (Height - 4) / _rows.Count));
        int nameW = Px(110), stateW = Px(58);
        int y = 2;
        var mono = Theme.MonoSmall(Dpi);
        foreach (var row in _rows)
        {
            if (y + rowH > Height) break;
            Draw.Text(g, row.Name, UiFont, new Rectangle(Px(6), y, nameW - Px(8), rowH), row.Progress > 0 ? Theme.Text : Theme.TextDim);
            int inset = rowH >= Px(16) ? Px(3) : Px(1);
            var bar = new Rectangle(nameW, y + inset, Math.Max(0, Width - nameW - stateW - Px(6)), rowH - inset * 2);
            bool done = row.Progress >= 0.999;
            SegmentedProgress.PaintBlocks(g, bar, row.Progress,
                done ? Theme.Hex(0x93C47D) : Theme.Hex(0xE2BE76), done ? Theme.Hex(0x4C7F35) : Theme.Hex(0x8A6C30),
                Px(4), Math.Max(1, Px(1)));
            var stateColor = done ? Theme.Ok : row.Progress > 0 ? Theme.Brass : Theme.TextDim;
            Draw.Text(g, row.State, mono, new Rectangle(Width - stateW, y, stateW - Px(5), rowH), stateColor, TextFormatFlags.Right);
            y += rowH;
        }
    }
}
