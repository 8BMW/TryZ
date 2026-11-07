namespace TryZ.Visual;

internal enum Severity { Info, Low, Medium, High, Critical }

internal static class Theme
{
    public static readonly Color Window = Hex(0x1B1D20);
    public static readonly Color Panel = Hex(0x24272B);
    public static readonly Color RaisedTop = Hex(0x34383D);
    public static readonly Color RaisedBottom = Hex(0x25282C);
    public static readonly Color Inset = Hex(0x121315);
    public static readonly Color InsetAlt = Hex(0x17191C);
    public static readonly Color BorderDark = Hex(0x08090A);
    public static readonly Color Highlight = Hex(0x4A4F55);
    public static readonly Color EtchLight = Hex(0x383C42);
    public static readonly Color EtchDark = Hex(0x0F1012);
    public static readonly Color Text = Hex(0xC9CDD2);
    public static readonly Color TextDim = Hex(0x8A9098);
    public static readonly Color TextDisabled = Hex(0x5A5F66);
    public static readonly Color TextBright = Hex(0xECEEF0);
    public static readonly Color Oxblood = Hex(0x8E1C1C);
    public static readonly Color OxbloodBright = Hex(0xB32A24);
    public static readonly Color Brass = Hex(0xC8A45C);
    public static readonly Color BrassDark = Hex(0x7A6434);
    public static readonly Color SelectionTop = Hex(0x6D1717);
    public static readonly Color SelectionBottom = Hex(0x4D1010);
    public static readonly Color Steel = Hex(0xA9B3BE);

    public static readonly Color Critical = Hex(0xE0483E);
    public static readonly Color High = Hex(0xE08A3C);
    public static readonly Color Medium = Hex(0xD9C04F);
    public static readonly Color Low = Hex(0x6FA8D8);
    public static readonly Color Info = Hex(0x8A9098);
    public static readonly Color Ok = Hex(0x7FB069);

    public static int? DpiOverride { get; set; }

    private static readonly Dictionary<(string Face, float Px, FontStyle Style, int Dpi), Font> Fonts = new();

    public static Color Hex(int rgb) => Color.FromArgb((rgb >> 16) & 255, (rgb >> 8) & 255, rgb & 255);

    public static Color Shift(Color c, int delta) => Color.FromArgb(
        c.A,
        Math.Clamp(c.R + delta, 0, 255),
        Math.Clamp(c.G + delta, 0, 255),
        Math.Clamp(c.B + delta, 0, 255));

    public static Color SeverityColor(Severity s) => s switch
    {
        Severity.Critical => Critical,
        Severity.High => High,
        Severity.Medium => Medium,
        Severity.Low => Low,
        _ => Info,
    };

    public static int DpiOf(Control c) => DpiOverride ?? (c.IsHandleCreated ? c.DeviceDpi : DefaultDpi(c));

    private static int DefaultDpi(Control c)
    {
        var form = c.FindForm();
        return form != null ? form.DeviceDpi : c.DeviceDpi;
    }

    public static int Scale(float logical, int dpi) => (int)Math.Round(logical * dpi / 96f);

    public static Font Ui(int dpi) => GetFont("Tahoma", 11f, FontStyle.Regular, dpi);
    public static Font UiBold(int dpi) => GetFont("Tahoma", 11f, FontStyle.Bold, dpi);
    public static Font UiSmall(int dpi) => GetFont("Tahoma", 10f, FontStyle.Regular, dpi);
    public static Font UiLarge(int dpi) => GetFont("Tahoma", 16f, FontStyle.Bold, dpi);
    public static Font Mono(int dpi) => GetFont("Consolas", 12f, FontStyle.Regular, dpi);
    public static Font MonoSmall(int dpi) => GetFont("Consolas", 11f, FontStyle.Regular, dpi);

    private static Font GetFont(string face, float px, FontStyle style, int dpi)
    {
        var key = (face, px, style, dpi);
        if (!Fonts.TryGetValue(key, out var font))
        {
            font = new Font(face, (float)Math.Round(px * dpi / 96f), style, GraphicsUnit.Pixel);
            Fonts[key] = font;
        }
        return font;
    }

    public static void ReleaseResources()
    {
        foreach (var f in Fonts.Values) f.Dispose();
        Fonts.Clear();
        Draw.ReleaseResources();
        Icons.ReleaseResources();
        LogoArt.ReleaseResources();
    }
}
