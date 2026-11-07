using System.Drawing.Drawing2D;
using System.Drawing.Imaging;

namespace TryZ.Visual;

internal enum IconId
{
    None, New, Open, Save, SaveAs, Start, Pause, Stop, Report, Options,
    Overview, Discovery, PortAudit, Vulnerability, Crawler, Workbench, Reports,
    Folder, FolderOpen, Page, Script, Image, Host, Globe, Filter, Exit, Help, About,
    Export, Clear, Copy, Send, Prev, Next, ZoomIn, ZoomOut, Warning, InfoMark, ErrorMark,
    Log, Findings, Queue, Check, Properties, Keyboard,
}

internal static class Icons
{
    private static readonly Dictionary<(IconId, int, bool), Bitmap> Cache = new();
    private static readonly Color Ink = Theme.Hex(0x15171A);

    public static Bitmap Get(IconId id, int size, bool disabled = false)
    {
        var key = (id, size, disabled);
        if (Cache.TryGetValue(key, out var bmp)) return bmp;
        bmp = new Bitmap(size, size, PixelFormat.Format32bppPArgb);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.PixelOffsetMode = PixelOffsetMode.HighQuality;
            g.ScaleTransform(size / 16f, size / 16f);
            Paint(g, id);
        }
        if (disabled) bmp = Desaturate(bmp);
        Cache[key] = bmp;
        return bmp;
    }

    public static void ReleaseResources()
    {
        foreach (var b in Cache.Values) b.Dispose();
        Cache.Clear();
    }

    private static Bitmap Desaturate(Bitmap source)
    {
        var result = new Bitmap(source.Width, source.Height, PixelFormat.Format32bppPArgb);
        using (var g = Graphics.FromImage(result))
        using (var attr = new ImageAttributes())
        {
            float a = 0.30f, b = 0.59f, c = 0.11f;
            attr.SetColorMatrix(new ColorMatrix(new[]
            {
                new[] { a, a, a, 0f, 0f },
                new[] { b, b, b, 0f, 0f },
                new[] { c, c, c, 0f, 0f },
                new[] { 0f, 0f, 0f, 0.42f, 0f },
                new[] { 0f, 0f, 0f, 0f, 1f },
            }));
            g.DrawImage(source, new Rectangle(0, 0, source.Width, source.Height), 0, 0, source.Width, source.Height, GraphicsUnit.Pixel, attr);
        }
        source.Dispose();
        return result;
    }

    private static PointF P(float x, float y) => new(x, y);

    private static void Poly(Graphics g, Color top, Color bottom, params PointF[] pts)
    {
        using var path = new GraphicsPath();
        path.AddPolygon(pts);
        FillPath(g, path, top, bottom);
    }

    private static void FillPath(Graphics g, GraphicsPath path, Color top, Color bottom, Color? outline = null)
    {
        var b = path.GetBounds();
        b.Inflate(0.01f, 0.5f);
        using (var brush = new LinearGradientBrush(b, top, bottom, LinearGradientMode.Vertical))
            g.FillPath(brush, path);
        using var pen = new Pen(outline ?? Ink, 0.75f) { LineJoin = LineJoin.Round };
        g.DrawPath(pen, path);
    }

    private static void Box(Graphics g, Color top, Color bottom, float x, float y, float w, float h)
    {
        using var path = new GraphicsPath();
        path.AddRectangle(new RectangleF(x, y, w, h));
        FillPath(g, path, top, bottom);
    }

    private static void Circle(Graphics g, Color top, Color bottom, float x, float y, float w, float h)
    {
        using var path = new GraphicsPath();
        path.AddEllipse(x, y, w, h);
        FillPath(g, path, top, bottom);
    }

    private static void Line(Graphics g, Color c, float width, float x1, float y1, float x2, float y2)
    {
        using var pen = new Pen(c, width) { StartCap = LineCap.Round, EndCap = LineCap.Round };
        g.DrawLine(pen, x1, y1, x2, y2);
    }

    private static void Sheet(Graphics g, float x = 3f, float w = 10f)
    {
        float r = x + w;
        Poly(g, Theme.Hex(0xF0EEE6), Theme.Hex(0xB7B4A8), P(x, 1), P(r - 3.5f, 1), P(r, 4.5f), P(r, 15), P(x, 15));
        Poly(g, Theme.Hex(0xFFFFFF), Theme.Hex(0xA8A598), P(r - 3.5f, 1), P(r, 4.5f), P(r - 3.5f, 4.5f));
    }

    private static void TextLines(Graphics g, float x, float x2, float y, int n, float step = 2f)
    {
        for (int i = 0; i < n; i++) Line(g, Theme.Hex(0x6A6E76), 0.8f, x, y + i * step, x2, y + i * step);
    }

    private static void Paint(Graphics g, IconId id)
    {
        Color brassTop = Theme.Hex(0xE8CC88), brassBot = Theme.Hex(0x96753A);
        Color steelTop = Theme.Hex(0xD6DBE2), steelBot = Theme.Hex(0x737C88);
        Color bloodTop = Theme.Hex(0xD8423A), bloodBot = Theme.Hex(0x6D1717);
        Color greenTop = Theme.Hex(0xA4D38A), greenBot = Theme.Hex(0x4C7F35);
        Color blueTop = Theme.Hex(0x9CC8EE), blueBot = Theme.Hex(0x35628E);

        switch (id)
        {
            case IconId.New:
                Sheet(g);
                Line(g, Theme.Hex(0xC8A45C), 1.1f, 11.5f, 10f, 11.5f, 14f);
                Line(g, Theme.Hex(0xC8A45C), 1.1f, 9.5f, 12f, 13.5f, 12f);
                break;
            case IconId.Open:
            case IconId.FolderOpen:
                Poly(g, brassBot, Theme.Hex(0x6E5428), P(1, 4), P(5.5f, 4), P(7, 5.5f), P(13, 5.5f), P(13, 13.5f), P(1, 13.5f));
                Poly(g, brassTop, brassBot, P(3.5f, 7.5f), P(15.2f, 7.5f), P(13, 13.5f), P(1, 13.5f));
                break;
            case IconId.Folder:
                Poly(g, brassTop, brassBot, P(1, 3.5f), P(6, 3.5f), P(7.5f, 5), P(15, 5), P(15, 13.5f), P(1, 13.5f));
                Line(g, Theme.Hex(0xF4E2B4), 0.7f, 2f, 6.2f, 14f, 6.2f);
                break;
            case IconId.Save:
            case IconId.SaveAs:
                Poly(g, Theme.Hex(0x7E9AB8), Theme.Hex(0x31465E), P(1.5f, 1.5f), P(12.5f, 1.5f), P(14.5f, 3.5f), P(14.5f, 14.5f), P(1.5f, 14.5f));
                Box(g, Theme.Hex(0xF2F2EC), Theme.Hex(0xC4C4BA), 4, 1.5f, 8, 5.5f);
                Line(g, Theme.Hex(0x8A8E94), 0.7f, 5f, 3.2f, 11f, 3.2f);
                Box(g, Theme.Hex(0x4A4F55), Theme.Hex(0x24272B), 4.5f, 9.5f, 7, 5);
                Box(g, steelTop, steelBot, 8.5f, 10.5f, 1.8f, 3);
                if (id == IconId.SaveAs) Line(g, brassTop, 1.4f, 11f, 13.5f, 14.5f, 9.5f);
                break;
            case IconId.Start:
                Poly(g, greenTop, greenBot, P(3.5f, 1.8f), P(13.8f, 8), P(3.5f, 14.2f));
                Line(g, Theme.Hex(0xD8F0C4), 0.7f, 4.6f, 3.8f, 9.5f, 6.8f);
                break;
            case IconId.Pause:
                Box(g, brassTop, brassBot, 3, 2, 3.8f, 12);
                Box(g, brassTop, brassBot, 9.2f, 2, 3.8f, 12);
                break;
            case IconId.Stop:
                Box(g, bloodTop, bloodBot, 2.5f, 2.5f, 11, 11);
                Line(g, Theme.Hex(0xF2A09A), 0.7f, 3.6f, 3.7f, 12.3f, 3.7f);
                break;
            case IconId.Report:
                Sheet(g);
                Box(g, bloodTop, bloodBot, 5, 10, 1.6f, 3.5f);
                Box(g, brassTop, brassBot, 7.3f, 7.5f, 1.6f, 6);
                Box(g, steelTop, steelBot, 9.6f, 9, 1.6f, 4.5f);
                TextLines(g, 5, 8, 3.5f, 2);
                break;
            case IconId.Reports:
                Poly(g, Theme.Hex(0xBDBAAE), Theme.Hex(0x8C897E), P(5.5f, 1), P(14, 1), P(14, 12), P(5.5f, 12));
                Sheet(g, 2f, 9.5f);
                TextLines(g, 3.8f, 9.2f, 6.5f, 4);
                Box(g, bloodTop, bloodBot, 3.8f, 3f, 3f, 1.8f);
                break;
            case IconId.Options:
                Gear(g, 8f, 8f, 7f, 4.9f, steelTop, steelBot);
                break;
            case IconId.Overview:
                Box(g, Theme.Hex(0x4A4F55), Theme.Hex(0x1E2024), 1, 2, 14, 11);
                Box(g, Theme.Hex(0x0E0F11), Theme.Hex(0x14161A), 2.5f, 3.5f, 11, 8);
                Box(g, bloodTop, bloodBot, 3.8f, 8, 1.8f, 2.8f);
                Box(g, brassTop, brassBot, 6.4f, 5.5f, 1.8f, 5.3f);
                Box(g, greenTop, greenBot, 9, 6.8f, 1.8f, 4);
                Line(g, steelBot, 1.2f, 5f, 14.8f, 11f, 14.8f);
                break;
            case IconId.Discovery:
                Circle(g, Theme.Hex(0x2C3A32), Theme.Hex(0x10160F), 1, 1, 14, 14);
                using (var ring = new Pen(Theme.Hex(0x7FB069), 0.6f))
                {
                    g.DrawEllipse(ring, 4, 4, 8, 8);
                    g.DrawLine(ring, 8, 1.5f, 8, 14.5f);
                    g.DrawLine(ring, 1.5f, 8, 14.5f, 8);
                }
                Poly(g, Theme.Hex(0xBEE6A6), Theme.Hex(0x4C7F35), P(8, 8), P(13.8f, 4.5f), P(14.6f, 8));
                Circle(g, brassTop, brassBot, 4.6f, 4.6f, 2.2f, 2.2f);
                break;
            case IconId.PortAudit:
                Box(g, steelTop, steelBot, 1.5f, 3, 13, 10);
                Poly(g, Theme.Hex(0x24272B), Theme.Hex(0x0E0F11), P(4, 5.5f), P(12, 5.5f), P(12, 10), P(10.5f, 10), P(10.5f, 11.5f), P(5.5f, 11.5f), P(5.5f, 10), P(4, 10));
                for (int i = 0; i < 4; i++) Line(g, brassTop, 0.8f, 5.6f + i * 1.6f, 6.5f, 5.6f + i * 1.6f, 8.4f);
                break;
            case IconId.Vulnerability:
                using (var path = new GraphicsPath())
                {
                    path.AddBezier(P(8, 1), P(10, 2.5f), P(12.5f, 3), P(14, 3));
                    path.AddBezier(P(14, 3), P(14.2f, 9), P(12, 12.8f), P(8, 15));
                    path.AddBezier(P(8, 15), P(4, 12.8f), P(1.8f, 9), P(2, 3));
                    path.AddBezier(P(2, 3), P(3.5f, 3), P(6, 2.5f), P(8, 1));
                    FillPath(g, path, bloodTop, bloodBot);
                }
                Line(g, Theme.Hex(0xF2DFA8), 1.7f, 8, 4.6f, 8, 8.8f);
                Line(g, Theme.Hex(0xF2DFA8), 1.8f, 8, 11.5f, 8, 11.6f);
                break;
            case IconId.Crawler:
            case IconId.Globe:
                Circle(g, blueTop, blueBot, 1, 1, 14, 14);
                using (var mer = new Pen(Theme.Hex(0xE2EEF8), 0.65f))
                {
                    g.DrawEllipse(mer, 4.6f, 1, 6.8f, 14);
                    g.DrawLine(mer, 8, 1, 8, 15);
                    g.DrawLine(mer, 1, 8, 15, 8);
                    g.DrawArc(mer, 2, -2.5f, 12, 8, 30, 120);
                    g.DrawArc(mer, 2, 10.5f, 12, 8, 210, 120);
                }
                break;
            case IconId.Workbench:
                Box(g, Theme.Hex(0x4A4F55), Theme.Hex(0x2A2D31), 1, 1.5f, 14, 13);
                Box(g, Theme.Hex(0x0E0F11), Theme.Hex(0x14161A), 2.2f, 4.5f, 11.6f, 8.8f);
                Line(g, Theme.Hex(0xC8A45C), 0.9f, 2.5f, 3f, 5f, 3f);
                Poly(g, greenTop, greenBot, P(3.5f, 6.2f), P(9, 6.2f), P(9, 5), P(12.5f, 7), P(9, 9), P(9, 7.8f), P(3.5f, 7.8f));
                Poly(g, bloodTop, bloodBot, P(12.5f, 10), P(7, 10), P(7, 8.8f), P(3.5f, 10.8f), P(7, 12.8f), P(7, 11.6f), P(12.5f, 11.6f));
                break;
            case IconId.Page:
                Sheet(g);
                TextLines(g, 5, 11, 7, 4);
                break;
            case IconId.Script:
                Sheet(g);
                Line(g, Theme.Hex(0x3A6E9A), 1f, 7f, 7.5f, 5f, 9.5f);
                Line(g, Theme.Hex(0x3A6E9A), 1f, 5f, 9.5f, 7f, 11.5f);
                Line(g, Theme.Hex(0x3A6E9A), 1f, 9f, 7.5f, 11f, 9.5f);
                Line(g, Theme.Hex(0x3A6E9A), 1f, 11f, 9.5f, 9f, 11.5f);
                break;
            case IconId.Image:
                Sheet(g);
                Box(g, blueTop, blueBot, 4.8f, 7, 6.4f, 5.5f);
                Poly(g, greenTop, greenBot, P(4.8f, 12.5f), P(7.5f, 9), P(11.2f, 12.5f));
                break;
            case IconId.Host:
                Box(g, steelTop, steelBot, 3, 1, 10, 14);
                Box(g, Theme.Hex(0x24272B), Theme.Hex(0x121315), 4.5f, 2.8f, 7, 2);
                Box(g, Theme.Hex(0x24272B), Theme.Hex(0x121315), 4.5f, 6f, 7, 2);
                Circle(g, greenTop, greenBot, 5, 10.8f, 1.8f, 1.8f);
                Line(g, Ink, 0.8f, 8f, 11.7f, 11.2f, 11.7f);
                break;
            case IconId.Filter:
                Poly(g, steelTop, steelBot, P(1.5f, 2), P(14.5f, 2), P(9.5f, 8), P(9.5f, 13.5f), P(6.5f, 15), P(6.5f, 8));
                break;
            case IconId.Exit:
                Box(g, Theme.Hex(0x8A6A3C), Theme.Hex(0x4A3518), 2, 1.5f, 8, 13);
                Circle(g, brassTop, brassBot, 7.4f, 7.4f, 1.4f, 1.4f);
                Poly(g, bloodTop, bloodBot, P(9, 6.6f), P(12, 6.6f), P(12, 4.6f), P(15.3f, 8), P(12, 11.4f), P(12, 9.4f), P(9, 9.4f));
                break;
            case IconId.Help:
                Circle(g, blueTop, blueBot, 1, 1, 14, 14);
                using (var q = new Pen(Theme.Hex(0xF4F8FC), 1.6f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
                {
                    g.DrawArc(q, 5.4f, 3.6f, 5.2f, 5f, 170, 240);
                    g.DrawLine(q, 8.8f, 8.3f, 8, 9.6f);
                    g.DrawLine(q, 8, 12, 8, 12.1f);
                }
                break;
            case IconId.About:
            case IconId.InfoMark:
                Circle(g, blueTop, blueBot, 1, 1, 14, 14);
                Line(g, Theme.Hex(0xF4F8FC), 1.8f, 8, 7.4f, 8, 11.8f);
                Line(g, Theme.Hex(0xF4F8FC), 2f, 8, 4.4f, 8, 4.5f);
                break;
            case IconId.Warning:
                Poly(g, brassTop, Theme.Hex(0xB07C20), P(8, 1.2f), P(15.2f, 14.5f), P(0.8f, 14.5f));
                Line(g, Ink, 1.6f, 8, 5.6f, 8, 10);
                Line(g, Ink, 1.7f, 8, 12.4f, 8, 12.5f);
                break;
            case IconId.ErrorMark:
                Circle(g, bloodTop, bloodBot, 1, 1, 14, 14);
                Line(g, Theme.Hex(0xF8ECEA), 1.8f, 5, 5, 11, 11);
                Line(g, Theme.Hex(0xF8ECEA), 1.8f, 11, 5, 5, 11);
                break;
            case IconId.Export:
                Sheet(g, 2f, 9.5f);
                Poly(g, greenTop, greenBot, P(6, 8), P(10.5f, 8), P(10.5f, 5.8f), P(15, 9.5f), P(10.5f, 13.2f), P(10.5f, 11), P(6, 11));
                break;
            case IconId.Clear:
                Sheet(g);
                Line(g, Theme.Hex(0xB32A24), 1.8f, 5.5f, 6.5f, 10.5f, 12.5f);
                Line(g, Theme.Hex(0xB32A24), 1.8f, 10.5f, 6.5f, 5.5f, 12.5f);
                break;
            case IconId.Copy:
                Poly(g, Theme.Hex(0xD6D3C8), Theme.Hex(0x98958A), P(1.5f, 1), P(9, 1), P(9, 11), P(1.5f, 11));
                Poly(g, Theme.Hex(0xF4F2EA), Theme.Hex(0xBDBAAE), P(6, 5), P(14.5f, 5), P(14.5f, 15), P(6, 15));
                TextLines(g, 7.5f, 13, 7.2f, 3, 2.2f);
                break;
            case IconId.Send:
            case IconId.Next:
                Poly(g, greenTop, greenBot, P(1.5f, 6), P(8.5f, 6), P(8.5f, 2.5f), P(14.5f, 8), P(8.5f, 13.5f), P(8.5f, 10), P(1.5f, 10));
                break;
            case IconId.Prev:
                Poly(g, greenTop, greenBot, P(14.5f, 6), P(7.5f, 6), P(7.5f, 2.5f), P(1.5f, 8), P(7.5f, 13.5f), P(7.5f, 10), P(14.5f, 10));
                break;
            case IconId.ZoomIn:
            case IconId.ZoomOut:
                Line(g, brassBot, 2.6f, 10.5f, 10.5f, 14.2f, 14.2f);
                Circle(g, Theme.Hex(0xD8E8F4), Theme.Hex(0x7EA4C6), 1.2f, 1.2f, 10, 10);
                Line(g, Ink, 1.2f, 3.8f, 6.2f, 8.6f, 6.2f);
                if (id == IconId.ZoomIn) Line(g, Ink, 1.2f, 6.2f, 3.8f, 6.2f, 8.6f);
                break;
            case IconId.Log:
                Sheet(g);
                Line(g, Theme.Hex(0xB32A24), 0.9f, 5, 6.5f, 6.4f, 6.5f);
                Line(g, Theme.Hex(0x6A6E76), 0.9f, 7.4f, 6.5f, 11, 6.5f);
                Line(g, Theme.Hex(0xC8A45C), 0.9f, 5, 9f, 6.4f, 9f);
                Line(g, Theme.Hex(0x6A6E76), 0.9f, 7.4f, 9f, 11, 9f);
                Line(g, Theme.Hex(0x4C7F35), 0.9f, 5, 11.5f, 6.4f, 11.5f);
                Line(g, Theme.Hex(0x6A6E76), 0.9f, 7.4f, 11.5f, 11, 11.5f);
                break;
            case IconId.Findings:
                Poly(g, brassTop, Theme.Hex(0xB07C20), P(8, 1.2f), P(15.2f, 14.5f), P(0.8f, 14.5f));
                Line(g, Ink, 1.6f, 8, 5.6f, 8, 10);
                Line(g, Ink, 1.7f, 8, 12.4f, 8, 12.5f);
                break;
            case IconId.Queue:
                Box(g, steelTop, steelBot, 2, 2, 12, 3);
                Box(g, brassTop, brassBot, 2, 6.5f, 12, 3);
                Box(g, steelTop, steelBot, 2, 11, 12, 3);
                break;
            case IconId.Check:
                using (var pen = new Pen(Theme.Hex(0x7FB069), 2.4f) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round })
                    g.DrawLines(pen, new[] { P(2.5f, 8.5f), P(6.5f, 12.5f), P(13.5f, 3.5f) });
                break;
            case IconId.Properties:
                Box(g, Theme.Hex(0xF0EEE6), Theme.Hex(0xB7B4A8), 2, 1.5f, 12, 13);
                Box(g, bloodTop, bloodBot, 2, 1.5f, 12, 2.5f);
                TextLines(g, 4, 12, 6.5f, 4);
                break;
            case IconId.Keyboard:
                Box(g, steelTop, steelBot, 0.8f, 4, 14.4f, 9);
                for (int row = 0; row < 2; row++)
                    for (int col = 0; col < 5; col++)
                        g.FillRectangle(Draw.Brush(Theme.Hex(0x24272B)), 2.2f + col * 2.4f, 5.6f + row * 2.2f, 1.6f, 1.4f);
                g.FillRectangle(Draw.Brush(Theme.Hex(0x24272B)), 4.4f, 10.2f, 7f, 1.4f);
                break;
        }
    }

    private static void Gear(Graphics g, float cx, float cy, float outer, float inner, Color top, Color bottom)
    {
        const int teeth = 8;
        var pts = new List<PointF>();
        for (int i = 0; i < teeth; i++)
        {
            double a = i * Math.PI * 2 / teeth;
            double w = Math.PI / teeth * 0.52;
            pts.Add(Polar(cx, cy, inner, a - w * 1.5));
            pts.Add(Polar(cx, cy, outer, a - w * 0.8));
            pts.Add(Polar(cx, cy, outer, a + w * 0.8));
            pts.Add(Polar(cx, cy, inner, a + w * 1.5));
        }
        using var path = new GraphicsPath();
        path.AddPolygon(pts.ToArray());
        path.AddEllipse(cx - 2.2f, cy - 2.2f, 4.4f, 4.4f);
        FillPath(g, path, top, bottom);
    }

    private static PointF Polar(float cx, float cy, float r, double a) =>
        new(cx + (float)(Math.Cos(a) * r), cy + (float)(Math.Sin(a) * r));
}
