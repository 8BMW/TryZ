using System.Drawing.Drawing2D;
using System.Drawing.Imaging;
using System.Reflection;
using System.Text;

namespace TryZ.Visual;

internal static class LogoArt
{
    private const float CellWidth = 3.4f;
    private const float CellHeight = 6.2f;
    private const int Supersample = 5;
    private const int SwordColumnStart = 36;

    private static readonly Lazy<string[]> Art = new(LoadArt);
    private static readonly Dictionary<int, Bitmap> Cache = new();

    private static string[] LoadArt()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("TryZ.logo.txt")
            ?? throw new InvalidOperationException("logo resource missing");
        using var reader = new StreamReader(stream, Encoding.UTF8);
        var lines = reader.ReadToEnd().Replace("\r", string.Empty).Split('\n').ToList();
        while (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
        return lines.ToArray();
    }

    private static int Indent => Art.Value.Where(l => l.Trim().Length > 0)
        .Min(l => l.Length - l.TrimStart().Length);

    private static int Columns => Art.Value.Max(l => l.Length) - Indent;
    private static int Rows => Art.Value.Length;

    public static Size SizeFor(int dpi) => new(
        (int)Math.Ceiling(Columns * CellWidth * dpi / 96f),
        (int)Math.Ceiling(Rows * CellHeight * dpi / 96f));

    public static Bitmap Get(int dpi)
    {
        if (!Cache.TryGetValue(dpi, out var bmp)) Cache[dpi] = bmp = Render(dpi);
        return bmp;
    }

    public static void ReleaseResources()
    {
        foreach (var b in Cache.Values) b.Dispose();
        Cache.Clear();
    }

    private static Bitmap Render(int dpi)
    {
        var size = SizeFor(dpi);
        float scale = dpi / 96f;
        float cw = CellWidth * scale * Supersample;
        float ch = CellHeight * scale * Supersample;

        using var knight = new GraphicsPath(FillMode.Winding);
        using var blocks = new GraphicsPath(FillMode.Winding);
        using var shadow = new GraphicsPath(FillMode.Winding);
        using var sword = new GraphicsPath(FillMode.Winding);
        using var rule = new GraphicsPath(FillMode.Winding);

        using var consolas = new FontFamily("Consolas");
        float em = cw / 0.55f;
        float squash = ch / (em * 1.1709f);
        using var format = new StringFormat(StringFormat.GenericTypographic);
        var art = Art.Value;
        int indent = Indent;

        for (int row = 0; row < art.Length; row++)
        {
            string line = art[row];
            bool ruleLine = line.Contains("=====");
            for (int col = 0; col < line.Length; col++)
            {
                char c = line[col];
                if (c == ' ') continue;
                float x = (col - indent) * cw, y = row * ch;
                if (c == '█')
                {
                    blocks.AddRectangle(SnappedCell(col - indent, row, cw, ch));
                }
                else if (c >= '═' && c <= '╬')
                {
                    var cell = SnappedCell(col - indent, row, cw, ch);
                    AddBoxGlyph(shadow, c, cell.X, cell.Y, cell.Width, cell.Height, scale);
                }
                else
                {
                    var target = ClassifyAscii(line, col, ruleLine, knight, sword, rule);
                    AddTextGlyph(target, c, consolas, em, squash, x, y, format);
                }
            }
        }

        using var hires = new Bitmap(size.Width * Supersample, size.Height * Supersample, PixelFormat.Format32bppPArgb);
        using (var g = Graphics.FromImage(hires))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float total = art.Length * ch;
            float knightSpan = 13 * ch;
            FillStroked(g, knight, Theme.Hex(0x8D96A3), Theme.Hex(0xD6DBE2), knightSpan, 0.52f * scale * Supersample);
            FillStroked(g, sword, Theme.Hex(0x9AA5B1), Theme.Hex(0xC4CCD5), total, 0.42f * scale * Supersample);
            FillStroked(g, shadow, Theme.Hex(0x7E6936), Theme.Hex(0x665229), total, 0f);
            FillStroked(g, blocks, Theme.Hex(0xE03A2E), Theme.Hex(0x7E1616), blocksBounds: true);
            FillStroked(g, rule, Theme.Brass, Theme.Brass, total, 0.3f * scale * Supersample);
        }

        var result = new Bitmap(size.Width, size.Height, PixelFormat.Format32bppPArgb);
        using (var g = Graphics.FromImage(result))
        {
            g.InterpolationMode = InterpolationMode.HighQualityBilinear;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.CompositingQuality = CompositingQuality.HighQuality;
            g.DrawImage(hires, new Rectangle(Point.Empty, size), 0, 0, hires.Width, hires.Height, GraphicsUnit.Pixel);
        }
        return result;
    }

    private static GraphicsPath ClassifyAscii(string line, int col, bool ruleLine,
        GraphicsPath knight, GraphicsPath sword, GraphicsPath rule)
    {
        char c = line[col];
        if (ruleLine && c == '=') return rule;
        if (col >= SwordColumnStart)
        {
            bool pipePair = c == '|' && ((col > 0 && line[col - 1] == '|') || (col + 1 < line.Length && line[col + 1] == '|'));
            if (pipePair || c == '[' || c == ']') return sword;
        }
        return knight;
    }

    private static void AddTextGlyph(GraphicsPath target, char c, FontFamily family, float em, float squash,
        float x, float y, StringFormat format)
    {
        using var glyph = new GraphicsPath();
        glyph.AddString(c.ToString(), family, (int)FontStyle.Regular, em, PointF.Empty, format);
        using var m = new Matrix();
        m.Translate(x, y);
        m.Scale(1f, squash);
        glyph.Transform(m);
        target.AddPath(glyph, false);
    }

    private static RectangleF SnappedCell(int col, int row, float cw, float ch)
    {
        static float S(float v) => MathF.Round(v / Supersample) * Supersample;
        float x0 = S(col * cw), y0 = S(row * ch);
        return RectangleF.FromLTRB(x0, y0, S((col + 1) * cw), S((row + 1) * ch));
    }

    private static void AddBoxGlyph(GraphicsPath target, char c, float x, float y, float w, float h, float scale)
    {
        float px = Supersample;
        float S(float v) => MathF.Round(v / px) * px;
        float tx = Math.Max(1, MathF.Round(scale * 0.8f)) * px, ty = tx;
        float vx1 = x + S(w * 0.10f), vx2 = x + S(w * 0.60f);
        float hy1 = y + S(h * 0.22f), hy2 = y + S(h * 0.60f);
        float r = x + w, b = y + h;

        void Rect(float x0, float y0, float x1, float y1) =>
            target.AddRectangle(new RectangleF(x0, y0, Math.Max(0.1f, x1 - x0), Math.Max(0.1f, y1 - y0)));

        switch (c)
        {
            case '═':
                Rect(x, hy1, r, hy1 + ty);
                Rect(x, hy2, r, hy2 + ty);
                break;
            case '║':
                Rect(vx1, y, vx1 + tx, b);
                Rect(vx2, y, vx2 + tx, b);
                break;
            case '╔':
                Rect(vx1, hy1, r, hy1 + ty);
                Rect(vx1, hy1, vx1 + tx, b);
                Rect(vx2, hy2, r, hy2 + ty);
                Rect(vx2, hy2, vx2 + tx, b);
                break;
            case '╗':
                Rect(x, hy1, vx2 + tx, hy1 + ty);
                Rect(vx2, hy1, vx2 + tx, b);
                Rect(x, hy2, vx1 + tx, hy2 + ty);
                Rect(vx1, hy2, vx1 + tx, b);
                break;
            case '╚':
                Rect(vx1, y, vx1 + tx, hy2 + ty);
                Rect(vx1, hy2, r, hy2 + ty);
                Rect(vx2, y, vx2 + tx, hy1 + ty);
                Rect(vx2, hy1, r, hy1 + ty);
                break;
            case '╝':
                Rect(vx2, y, vx2 + tx, hy2 + ty);
                Rect(x, hy2, vx2 + tx, hy2 + ty);
                Rect(vx1, y, vx1 + tx, hy1 + ty);
                Rect(x, hy1, vx1 + tx, hy1 + ty);
                break;
            default:
                Rect(x, hy1, r, hy1 + ty);
                break;
        }
    }

    private static void FillStroked(Graphics g, GraphicsPath path, Color top, Color bottom, float total, float stroke)
    {
        if (path.PointCount == 0) return;
        using var brush = new LinearGradientBrush(new RectangleF(0, -1, 10, total + 2), top, bottom, LinearGradientMode.Vertical);
        g.FillPath(brush, path);
        if (stroke > 0)
        {
            using var pen = new Pen(brush, stroke) { LineJoin = LineJoin.Round };
            g.DrawPath(pen, path);
        }
    }

    private static void FillStroked(Graphics g, GraphicsPath path, Color top, Color bottom, bool blocksBounds)
    {
        if (path.PointCount == 0 || !blocksBounds) return;
        var bounds = path.GetBounds();
        bounds.Inflate(0, 1);
        using var brush = new LinearGradientBrush(bounds, top, bottom, LinearGradientMode.Vertical);
        g.FillPath(brush, path);
    }
}
