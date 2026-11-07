using TryZ.Shell;

namespace TryZ.Controls;

internal class SkinControl : Control
{
    private const int WM_NCHITTEST = 0x0084;
    private const int HTTRANSPARENT = -1;

    public SkinControl()
    {
        SetStyle(ControlStyles.UserPaint | ControlStyles.AllPaintingInWmPaint |
                 ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
        SetStyle(ControlStyles.Selectable, false);
        BackColor = Theme.Panel;
        ForeColor = Theme.Text;
        TabStop = false;
    }

    protected int Dpi => Theme.DpiOf(this);
    protected int Px(float logical) => Theme.Scale(logical, Dpi);
    protected Font UiFont => Theme.Ui(Dpi);
    protected Font BoldFont => Theme.UiBold(Dpi);
    protected Font MonoFont => Theme.Mono(Dpi);

    public void RefreshDpi()
    {
        OnDpiRefresh();
        foreach (Control c in Controls)
            if (c is SkinControl s) s.RefreshDpi();
        PerformLayout();
        Invalidate();
    }

    protected virtual void OnDpiRefresh() { }

    protected override void OnDpiChangedAfterParent(EventArgs e)
    {
        base.OnDpiChangedAfterParent(e);
        OnDpiRefresh();
        PerformLayout();
        Invalidate();
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_NCHITTEST && FindForm() is FrameForm frame && frame.IsInResizeBand(m.LParam))
        {
            m.Result = HTTRANSPARENT;
            return;
        }
        base.WndProc(ref m);
    }

    protected static int WheelLines(MouseEventArgs e) => e.Delta / 120 * Math.Max(1, SystemInformation.MouseWheelScrollLines);
}

internal class SkinPanel : SkinControl
{
    private bool _etchBottom;

    public bool EtchBottom
    {
        get => _etchBottom;
        set { _etchBottom = value; Invalidate(); }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        if (_etchBottom) Draw.EtchH(e.Graphics, 0, Width, Height - 2);
    }
}

internal sealed class SkinLabel : SkinControl
{
    private string _text = string.Empty;
    private Color _color = Theme.Text;
    private bool _bold;
    private bool _mono;
    private bool _wrap;
    private TextFormatFlags _align = TextFormatFlags.Left;

    public SkinLabel(string text = "", bool bold = false)
    {
        _text = text;
        _bold = bold;
        SetStyle(ControlStyles.StandardClick | ControlStyles.StandardDoubleClick, false);
    }

    public string Caption
    {
        get => _text;
        set { if (_text != value) { _text = value; Invalidate(); } }
    }

    public Color TextColor
    {
        get => _color;
        set { if (_color != value) { _color = value; Invalidate(); } }
    }

    public bool Bold { get => _bold; set { _bold = value; Invalidate(); } }
    public bool Mono { get => _mono; set { _mono = value; Invalidate(); } }
    public bool Wrap { get => _wrap; set { _wrap = value; Invalidate(); } }
    public TextFormatFlags Alignment { get => _align; set { _align = value; Invalidate(); } }

    public int WrappedHeight(int width) => Draw.MeasureWrapped(_text, UiFont, width);

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        var font = _mono ? MonoFont : _bold ? BoldFont : UiFont;
        var color = Enabled ? _color : Theme.TextDisabled;
        if (_wrap)
        {
            TextRenderer.DrawText(e.Graphics, _text, font, ClientRectangle, color,
                TextFormatFlags.NoPrefix | TextFormatFlags.NoPadding | TextFormatFlags.WordBreak | TextFormatFlags.TextBoxControl);
        }
        else
        {
            Draw.Text(e.Graphics, _text, font, ClientRectangle, color, _align);
        }
    }
}

internal sealed class IconBox : SkinControl
{
    private readonly IconId _icon;
    private readonly int _logical;

    public IconBox(IconId icon, int logicalSize)
    {
        _icon = icon;
        _logical = logicalSize;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);
        int s = Px(_logical);
        e.Graphics.DrawImage(Icons.Get(_icon, s), (Width - s) / 2, (Height - s) / 2, s, s);
    }
}
