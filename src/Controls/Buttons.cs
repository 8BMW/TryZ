using System.Drawing.Drawing2D;

namespace TryZ.Controls;

internal enum ButtonLook { Standard, Oxblood, Flat }

internal sealed class SkinButton : SkinControl, IButtonControl
{
    private bool _hot;
    private bool _pressed;
    private bool _default;
    private string _caption;
    private DialogResult _result;
    private IconId _icon;

    public SkinButton(string caption, IconId icon = IconId.None, ButtonLook look = ButtonLook.Standard)
    {
        _caption = caption;
        _icon = icon;
        Look = look;
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
    }

    public ButtonLook Look { get; set; }

    public string Caption
    {
        get => _caption;
        set { _caption = value; Invalidate(); }
    }

    public IconId Icon
    {
        get => _icon;
        set { _icon = value; Invalidate(); }
    }

    public DialogResult DialogResult
    {
        get => _result;
        set => _result = value;
    }

    public void NotifyDefault(bool value)
    {
        _default = value;
        Invalidate();
    }

    public void PerformClick()
    {
        if (Enabled) OnClick(EventArgs.Empty);
    }

    protected override void OnClick(EventArgs e)
    {
        if (_result != DialogResult.None && FindForm() is { } form) form.DialogResult = _result;
        base.OnClick(e);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Fill(g, ClientRectangle, BackColor);
        var state = !Enabled ? ChromeState.Disabled : _pressed && _hot ? ChromeState.Pressed : _hot ? ChromeState.Hot : ChromeState.Normal;
        var r = ClientRectangle;
        if (Look == ButtonLook.Oxblood) PaintOxblood(g, r, state);
        else Draw.Raised(g, r, state);

        if (_default && Enabled) Draw.Frame(g, Rectangle.Inflate(r, -1, -1), Theme.BrassDark);

        int iconSize = Px(16);
        bool hasIcon = _icon != IconId.None;
        var font = Look == ButtonLook.Oxblood ? BoldFont : UiFont;
        int textWidth = Draw.Measure(_caption, font);
        int total = textWidth + (hasIcon ? iconSize + Px(5) : 0);
        int x = (Width - total) / 2 + (state == ChromeState.Pressed ? 1 : 0);
        int yOff = state == ChromeState.Pressed ? 1 : 0;
        if (hasIcon)
        {
            g.DrawImage(Icons.Get(_icon, iconSize, !Enabled), x, (Height - iconSize) / 2 + yOff, iconSize, iconSize);
            x += iconSize + Px(5);
        }
        var color = !Enabled ? Theme.TextDisabled : Look == ButtonLook.Oxblood ? Theme.TextBright : Theme.Text;
        var textRect = new Rectangle(x, yOff, Math.Max(0, Width - x), Height);
        if (Look == ButtonLook.Oxblood && Enabled) Draw.Engraved(g, _caption, font, textRect, color);
        else Draw.Text(g, _caption, font, textRect, color);

        if (Focused && ShowFocusCues)
        {
            var f = Rectangle.Inflate(r, -3, -3);
            using var pen = new Pen(Theme.TextDim) { DashStyle = DashStyle.Dot };
            g.DrawRectangle(pen, f.X, f.Y, f.Width - 1, f.Height - 1);
        }
    }

    private static void PaintOxblood(Graphics g, Rectangle r, ChromeState state)
    {
        Color top = Theme.Hex(0xC2403A), hi = Theme.Hex(0x9E2622), lo = Theme.Oxblood, bottom = Theme.Hex(0x651414);
        switch (state)
        {
            case ChromeState.Hot:
                top = Theme.Hex(0xD6534C); hi = Theme.Hex(0xB2302B); lo = Theme.Hex(0xA02120); bottom = Theme.Hex(0x761818);
                break;
            case ChromeState.Pressed:
                top = Theme.Hex(0x561010); hi = Theme.Hex(0x6D1717); lo = Theme.Hex(0x761818); bottom = Theme.Hex(0x8E1C1C);
                break;
            case ChromeState.Disabled:
                top = Theme.Hex(0x4C3030); hi = Theme.Hex(0x402828); lo = Theme.Hex(0x3A2222); bottom = Theme.Hex(0x2E1C1C);
                break;
        }
        Draw.Gloss(g, r, top, hi, lo, bottom);
        Draw.Frame(g, r, Theme.BorderDark);
        if (state is ChromeState.Normal or ChromeState.Hot)
            g.DrawLine(Draw.Pen(Theme.Hex(0xE07A72)), r.X + 1, r.Y + 1, r.Right - 2, r.Y + 1);
    }

    protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); _hot = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hot = false; Invalidate(); }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left) return;
        _pressed = true;
        Focus();
        Invalidate();
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        _pressed = false;
        Invalidate();
    }

    protected override void OnEnabledChanged(EventArgs e)
    {
        base.OnEnabledChanged(e);
        Invalidate();
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) => keyData is Keys.Space or Keys.Return || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.KeyCode is Keys.Space or Keys.Return) { PerformClick(); e.Handled = true; }
    }
}

internal class SkinCheck : SkinControl
{
    private bool _checked;
    private bool _hot;
    private string _caption;

    public SkinCheck(string caption, bool isChecked = false)
    {
        _caption = caption;
        _checked = isChecked;
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
    }

    public event EventHandler? CheckedChanged;

    public string Caption { get => _caption; set { _caption = value; Invalidate(); } }

    public bool Checked
    {
        get => _checked;
        set
        {
            if (_checked == value) return;
            _checked = value;
            Invalidate();
            CheckedChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Fill(g, ClientRectangle, BackColor);
        int s = Px(13);
        var box = new Rectangle(0, (Height - s) / 2, s, s);
        Draw.Sunken(g, box, Enabled ? (_hot ? Theme.Hex(0x1C1E21) : Theme.Inset) : Theme.Panel);
        if (_checked)
        {
            var mode = g.SmoothingMode;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            float k = s / 13f;
            using var pen = new Pen(Enabled ? Theme.Brass : Theme.TextDisabled, 1.8f * k) { LineJoin = LineJoin.Miter };
            g.DrawLines(pen, new[]
            {
                new PointF(box.X + 3f * k, box.Y + 6.5f * k),
                new PointF(box.X + 5.5f * k, box.Y + 9f * k),
                new PointF(box.X + 10f * k, box.Y + 3.5f * k),
            });
            g.SmoothingMode = mode;
        }
        var r = new Rectangle(s + Px(5), 0, Width - s - Px(5), Height);
        Draw.Text(g, _caption, UiFont, r, Enabled ? Theme.Text : Theme.TextDisabled);
        if (Focused && ShowFocusCues)
        {
            using var pen = new Pen(Theme.TextDim) { DashStyle = DashStyle.Dot };
            int w = Math.Min(Draw.Measure(_caption, UiFont) + 2, r.Width - 1);
            g.DrawRectangle(pen, r.X - 1, 0, w, Height - 1);
        }
    }

    protected override void OnClick(EventArgs e)
    {
        base.OnClick(e);
        Toggle();
    }

    protected virtual void Toggle() => Checked = !Checked;

    protected override void OnMouseEnter(EventArgs e) { base.OnMouseEnter(e); _hot = true; Invalidate(); }
    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); _hot = false; Invalidate(); }
    protected override void OnMouseDown(MouseEventArgs e) { base.OnMouseDown(e); Focus(); }
    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }
    protected override void OnEnabledChanged(EventArgs e) { base.OnEnabledChanged(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) => keyData == Keys.Space || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.KeyCode == Keys.Space) Toggle();
    }
}

internal sealed class SkinRadio : SkinCheck
{
    public SkinRadio(string caption, bool isChecked = false) : base(caption, isChecked) { }

    protected override void Toggle()
    {
        if (Checked) return;
        if (Parent != null)
            foreach (Control c in Parent.Controls)
                if (c is SkinRadio r && r != this) r.Checked = false;
        Checked = true;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Fill(g, ClientRectangle, BackColor);
        int s = Px(13);
        var box = new Rectangle(0, (Height - s) / 2, s - 1, s - 1);
        var mode = g.SmoothingMode;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.FillEllipse(Draw.Brush(Enabled ? Theme.Inset : Theme.Panel), box);
        using (var dark = new Pen(Theme.BorderDark))
            g.DrawArc(dark, box, 135, 180);
        using (var light = new Pen(Theme.EtchLight))
            g.DrawArc(light, box, 315, 180);
        if (Checked)
        {
            var dot = Rectangle.Inflate(box, -Px(3), -Px(3));
            using var brush = new LinearGradientBrush(Rectangle.Inflate(dot, 1, 1), Theme.Hex(0xE8CC88), Theme.Hex(0x96753A), LinearGradientMode.Vertical);
            g.FillEllipse(Enabled ? brush : Draw.Brush(Theme.TextDisabled), dot);
        }
        g.SmoothingMode = mode;
        Draw.Text(g, Caption, UiFont, new Rectangle(s + Px(5), 0, Width - s - Px(5), Height), Enabled ? Theme.Text : Theme.TextDisabled);
    }
}
