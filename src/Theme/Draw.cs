using System.Drawing.Drawing2D;

namespace TryZ.Visual;

internal enum ChromeState { Normal, Hot, Pressed, Disabled }

internal static class Draw
{
    public const TextFormatFlags LineFlags =
        TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine |
        TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis | TextFormatFlags.PreserveGraphicsClipping;

    private static readonly Dictionary<Color, Pen> PenCache = new();
    private static readonly Dictionary<Color, SolidBrush> BrushCache = new();

    public static Pen Pen(Color c)
    {
        if (!PenCache.TryGetValue(c, out var p)) PenCache[c] = p = new Pen(c);
        return p;
    }

    public static SolidBrush Brush(Color c)
    {
        if (!BrushCache.TryGetValue(c, out var b)) BrushCache[c] = b = new SolidBrush(c);
        return b;
    }

    public static void ReleaseResources()
    {
        foreach (var p in PenCache.Values) p.Dispose();
        foreach (var b in BrushCache.Values) b.Dispose();
        PenCache.Clear();
        BrushCache.Clear();
    }

    public static void Fill(Graphics g, Rectangle r, Color c)
    {
        if (r.Width > 0 && r.Height > 0) g.FillRectangle(Brush(c), r);
    }

    public static void Gradient(Graphics g, Rectangle r, Color top, Color bottom, bool horizontal = false)
    {
        if (r.Width <= 0 || r.Height <= 0) return;
        using var brush = new LinearGradientBrush(
            new Rectangle(r.X - 1, r.Y - 1, r.Width + 2, r.Height + 2), top, bottom,
            horizontal ? LinearGradientMode.Horizontal : LinearGradientMode.Vertical);
        g.FillRectangle(brush, r);
    }

    public static void Frame(Graphics g, Rectangle r, Color c)
    {
        if (r.Width > 0 && r.Height > 0) g.DrawRectangle(Pen(c), r.X, r.Y, r.Width - 1, r.Height - 1);
    }

    public static void Raised(Graphics g, Rectangle r, ChromeState state = ChromeState.Normal)
    {
        Color top = Theme.RaisedTop, bottom = Theme.RaisedBottom;
        switch (state)
        {
            case ChromeState.Hot:
                top = Theme.Shift(top, 14);
                bottom = Theme.Shift(bottom, 10);
                break;
            case ChromeState.Pressed:
                top = Theme.Shift(Theme.RaisedBottom, -10);
                bottom = Theme.Shift(Theme.RaisedTop, -6);
                break;
            case ChromeState.Disabled:
                top = Theme.Shift(top, -10);
                bottom = Theme.Shift(bottom, -4);
                break;
        }
        Gradient(g, r, top, bottom);
        Frame(g, r, Theme.BorderDark);
        if (state == ChromeState.Pressed) return;
        var hi = state == ChromeState.Disabled ? Theme.Shift(Theme.Highlight, -22) : Theme.Highlight;
        if (state == ChromeState.Hot) hi = Theme.Shift(hi, 18);
        g.DrawLine(Pen(hi), r.X + 1, r.Y + 1, r.Right - 2, r.Y + 1);
        g.DrawLine(Pen(Theme.Shift(hi, -18)), r.X + 1, r.Y + 2, r.X + 1, r.Bottom - 2);
    }

    public static void Sunken(Graphics g, Rectangle r, Color fill)
    {
        Fill(g, r, fill);
        g.DrawLine(Pen(Theme.BorderDark), r.X, r.Y, r.Right - 1, r.Y);
        g.DrawLine(Pen(Theme.BorderDark), r.X, r.Y, r.X, r.Bottom - 1);
        g.DrawLine(Pen(Theme.EtchLight), r.X + 1, r.Bottom - 1, r.Right - 1, r.Bottom - 1);
        g.DrawLine(Pen(Theme.EtchLight), r.Right - 1, r.Y + 1, r.Right - 1, r.Bottom - 1);
        g.DrawLine(Pen(Theme.Shift(fill, -8)), r.X + 1, r.Y + 1, r.Right - 2, r.Y + 1);
    }

    public static void EtchH(Graphics g, int x1, int x2, int y)
    {
        g.DrawLine(Pen(Theme.EtchDark), x1, y, x2, y);
        g.DrawLine(Pen(Theme.EtchLight), x1, y + 1, x2, y + 1);
    }

    public static void EtchV(Graphics g, int x, int y1, int y2)
    {
        g.DrawLine(Pen(Theme.EtchDark), x, y1, x, y2);
        g.DrawLine(Pen(Theme.EtchLight), x + 1, y1, x + 1, y2);
    }

    public static void EtchedBox(Graphics g, Rectangle r)
    {
        var dark = new Rectangle(r.X, r.Y, r.Width - 1, r.Height - 1);
        var light = new Rectangle(r.X + 1, r.Y + 1, r.Width - 1, r.Height - 1);
        Frame(g, light, Theme.EtchLight);
        Frame(g, dark, Theme.EtchDark);
    }

    public static void Gloss(Graphics g, Rectangle r, Color top, Color midHi, Color midLo, Color bottom)
    {
        int mid = r.Y + r.Height * 9 / 20;
        Gradient(g, new Rectangle(r.X, r.Y, r.Width, mid - r.Y), top, midHi);
        Gradient(g, new Rectangle(r.X, mid, r.Width, r.Bottom - mid), midLo, bottom);
    }

    public static void Selection(Graphics g, Rectangle r, bool active = true)
    {
        if (active)
        {
            Gradient(g, r, Theme.SelectionTop, Theme.SelectionBottom);
            g.DrawLine(Pen(Theme.Shift(Theme.SelectionTop, 26)), r.X, r.Y, r.Right - 1, r.Y);
            g.DrawLine(Pen(Theme.Shift(Theme.SelectionBottom, -22)), r.X, r.Bottom - 1, r.Right - 1, r.Bottom - 1);
        }
        else
        {
            Gradient(g, r, Theme.Hex(0x3A2424), Theme.Hex(0x2C1C1C));
        }
    }

    public static void GripDots(Graphics g, Rectangle r, bool horizontalRun, int count, int scale)
    {
        int step = 4 * scale;
        int size = Math.Max(1, scale);
        int cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2;
        for (int i = 0; i < count; i++)
        {
            int off = (i - count / 2) * step;
            int x = horizontalRun ? cx + off : cx - size;
            int y = horizontalRun ? cy - size : cy + off;
            g.FillRectangle(Brush(Theme.Highlight), x, y, size, size);
            g.FillRectangle(Brush(Theme.BorderDark), x + size, y + size, size, size);
        }
    }

    public static void Triangle(Graphics g, Rectangle r, ArrowDirection dir, Color c, int size)
    {
        int cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2;
        int half = size;
        var mode = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.None;
        var brush = Brush(c);
        for (int i = 0; i <= half; i++)
        {
            int len = (half - i) * 2 + 1;
            switch (dir)
            {
                case ArrowDirection.Down:
                    g.FillRectangle(brush, cx - (half - i), cy - half / 2 + i, len, 1);
                    break;
                case ArrowDirection.Up:
                    g.FillRectangle(brush, cx - (half - i), cy + half / 2 - i, len, 1);
                    break;
                case ArrowDirection.Right:
                    g.FillRectangle(brush, cx - half / 2 + i, cy - (half - i), 1, len);
                    break;
                case ArrowDirection.Left:
                    g.FillRectangle(brush, cx + half / 2 - i, cy - (half - i), 1, len);
                    break;
            }
        }
        g.SmoothingMode = mode;
    }

    public static void Text(Graphics g, string? text, Font font, Rectangle r, Color c,
        TextFormatFlags extra = TextFormatFlags.Default)
    {
        if (string.IsNullOrEmpty(text) || r.Width <= 0 || r.Height <= 0) return;
        TextRenderer.DrawText(g, text, font, r, c, LineFlags | extra);
    }

    public static void Engraved(Graphics g, string? text, Font font, Rectangle r, Color c,
        TextFormatFlags extra = TextFormatFlags.Default)
    {
        var shadow = r;
        shadow.Offset(0, 1);
        Text(g, text, font, shadow, Theme.BorderDark, extra);
        Text(g, text, font, r, c, extra);
    }

    public static int Measure(string text, Font font) =>
        TextRenderer.MeasureText(text, font, Size.Empty, TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.SingleLine).Width;

    public static int MeasureWrapped(string text, Font font, int width) =>
        TextRenderer.MeasureText(text, font, new Size(width, int.MaxValue),
            TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl).Height;
}
