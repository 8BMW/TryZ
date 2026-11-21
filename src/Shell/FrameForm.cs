using System.Reflection;
using System.Runtime.InteropServices;

namespace TryZ.Shell;

internal static class Native
{
    public const int WM_NCCALCSIZE = 0x0083;
    public const int WM_NCHITTEST = 0x0084;
    public const int WM_NCMOUSEMOVE = 0x00A0;
    public const int WM_NCLBUTTONDOWN = 0x00A1;
    public const int WM_NCLBUTTONUP = 0x00A2;
    public const int WM_NCLBUTTONDBLCLK = 0x00A3;
    public const int WM_NCMOUSELEAVE = 0x02A2;
    public const int WM_SYSCOMMAND = 0x0112;

    public const int HTCLIENT = 1;
    public const int HTCAPTION = 2;
    public const int HTMAXBUTTON = 9;
    public const int HTLEFT = 10;
    public const int HTRIGHT = 11;
    public const int HTTOP = 12;
    public const int HTTOPLEFT = 13;
    public const int HTTOPRIGHT = 14;
    public const int HTBOTTOM = 15;
    public const int HTBOTTOMLEFT = 16;
    public const int HTBOTTOMRIGHT = 17;

    public const int SC_MINIMIZE = 0xF020;
    public const int SC_MAXIMIZE = 0xF030;
    public const int SC_CLOSE = 0xF060;
    public const int SC_RESTORE = 0xF120;

    public const uint TME_LEAVE = 0x2;
    public const uint TME_NONCLIENT = 0x10;
    public const int DWMWA_WINDOW_CORNER_PREFERENCE = 33;
    public const int DWMWA_BORDER_COLOR = 34;
    public const int DWMWCP_DONOTROUND = 1;

    public const uint SWP_NOSIZE = 0x1, SWP_NOMOVE = 0x2, SWP_NOZORDER = 0x4, SWP_NOACTIVATE = 0x10, SWP_FRAMECHANGED = 0x20;

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left, Top, Right, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MARGINS
    {
        public int Left, Right, Top, Bottom;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TRACKMOUSEEVENT
    {
        public uint cbSize;
        public uint dwFlags;
        public IntPtr hwndTrack;
        public uint dwHoverTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct MONITORINFO
    {
        public int cbSize;
        public RECT rcMonitor;
        public RECT rcWork;
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct APPBARDATA
    {
        public uint cbSize;
        public IntPtr hWnd;
        public uint uCallbackMessage;
        public uint uEdge;
        public RECT rc;
        public IntPtr lParam;
    }

    [DllImport("user32.dll")]
    public static extern bool IsZoomed(IntPtr hwnd);

    [DllImport("user32.dll")]
    public static extern IntPtr MonitorFromWindow(IntPtr hwnd, uint flags);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern bool GetMonitorInfo(IntPtr monitor, ref MONITORINFO info);

    [DllImport("user32.dll")]
    public static extern bool SetWindowPos(IntPtr hwnd, IntPtr after, int x, int y, int cx, int cy, uint flags);

    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(IntPtr hwnd, int msg, IntPtr wParam, IntPtr lParam);

    [DllImport("user32.dll")]
    public static extern bool TrackMouseEvent(ref TRACKMOUSEEVENT tme);

    [DllImport("dwmapi.dll")]
    public static extern int DwmExtendFrameIntoClientArea(IntPtr hwnd, ref MARGINS margins);

    [DllImport("dwmapi.dll")]
    public static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int value, int size);

    [DllImport("shell32.dll")]
    public static extern UIntPtr SHAppBarMessage(uint message, ref APPBARDATA data);

    public static bool TaskbarAutoHides()
    {
        const uint ABM_GETSTATE = 4;
        const uint ABS_AUTOHIDE = 1;
        var data = new APPBARDATA { cbSize = (uint)Marshal.SizeOf<APPBARDATA>() };
        return ((uint)SHAppBarMessage(ABM_GETSTATE, ref data) & ABS_AUTOHIDE) != 0;
    }
}

internal class FrameForm : Form
{
    private static Icon? _appIcon;
    private readonly bool _resizable;
    private Size _minimumLogical = new(200, 100);
    private bool _trackingNc;

    protected FrameForm(bool resizable, bool minMax)
    {
        Caption = new TitleBar(minMax);
        _resizable = resizable;
        AutoScaleMode = AutoScaleMode.None;
        FormBorderStyle = resizable ? FormBorderStyle.Sizable : FormBorderStyle.FixedSingle;
        MaximizeBox = resizable;
        MinimizeBox = minMax;
        DoubleBuffered = true;
        BackColor = Theme.Window;
        ForeColor = Theme.Text;
        KeyPreview = true;
        SetStyle(ControlStyles.ResizeRedraw | ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint, true);
        Icon = AppIcon;
        Controls.Add(Caption);
    }

    public static Icon AppIcon
    {
        get
        {
            if (_appIcon == null)
            {
                using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("TryZ.tryz.ico")
                    ?? throw new InvalidOperationException("icon resource missing");
                _appIcon = new Icon(stream);
            }
            return _appIcon;
        }
    }

    public TitleBar Caption { get; }

    protected int Dpi => Theme.DpiOf(this);
    protected int Px(float logical) => Theme.Scale(logical, Dpi);
    protected int BorderInset => WindowState == FormWindowState.Maximized ? 0 : 2;

    protected Rectangle ContentBounds
    {
        get
        {
            int b = BorderInset;
            int top = b + Px(TitleBar.LogicalHeight);
            return Rectangle.FromLTRB(b, top, ClientSize.Width - b, ClientSize.Height - b);
        }
    }

    protected void SetMinimumLogical(int w, int h)
    {
        _minimumLogical = new Size(w, h);
        ApplyMinimum();
    }

    protected void ApplyMinimum() =>
        MinimumSize = new Size(Px(_minimumLogical.Width), Px(_minimumLogical.Height));

    protected virtual int HitTestExtra(Point client) => 0;

    public bool IsInResizeBand(IntPtr lParam)
    {
        if (!_resizable || WindowState != FormWindowState.Normal) return false;
        var p = ScreenPoint(lParam);
        var b = Bounds;
        int band = Px(4);
        return b.Contains(p) && (p.X < b.Left + band || p.X >= b.Right - band || p.Y < b.Top + band || p.Y >= b.Bottom - band);
    }

    private static Point ScreenPoint(IntPtr lParam)
    {
        long v = lParam.ToInt64();
        return new Point((short)(v & 0xFFFF), (short)((v >> 16) & 0xFFFF));
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        int corner = Native.DWMWCP_DONOTROUND;
        Native.DwmSetWindowAttribute(Handle, Native.DWMWA_WINDOW_CORNER_PREFERENCE, ref corner, sizeof(int));
        int border = ColorTranslator.ToWin32(Theme.BorderDark);
        Native.DwmSetWindowAttribute(Handle, Native.DWMWA_BORDER_COLOR, ref border, sizeof(int));
        var margins = new Native.MARGINS { Left = 0, Right = 0, Top = 1, Bottom = 0 };
        Native.DwmExtendFrameIntoClientArea(Handle, ref margins);
        Native.SetWindowPos(Handle, IntPtr.Zero, 0, 0, 0, 0,
            Native.SWP_NOMOVE | Native.SWP_NOSIZE | Native.SWP_NOZORDER | Native.SWP_NOACTIVATE | Native.SWP_FRAMECHANGED);
    }

    protected override void WndProc(ref Message m)
    {
        switch (m.Msg)
        {
            case Native.WM_NCCALCSIZE:
                HandleNcCalcSize(ref m);
                return;
            case Native.WM_NCHITTEST:
                m.Result = HitTest(ScreenPoint(m.LParam));
                return;
            case Native.WM_NCMOUSEMOVE:
                Caption.SetMaxNcState((int)m.WParam == Native.HTMAXBUTTON, false);
                if (!_trackingNc)
                {
                    var tme = new Native.TRACKMOUSEEVENT
                    {
                        cbSize = (uint)Marshal.SizeOf<Native.TRACKMOUSEEVENT>(),
                        dwFlags = Native.TME_LEAVE | Native.TME_NONCLIENT,
                        hwndTrack = Handle,
                    };
                    _trackingNc = Native.TrackMouseEvent(ref tme);
                }
                break;
            case Native.WM_NCMOUSELEAVE:
                _trackingNc = false;
                Caption.SetMaxNcState(false, false);
                break;
            case Native.WM_NCLBUTTONDOWN when (int)m.WParam == Native.HTMAXBUTTON:
            case Native.WM_NCLBUTTONDBLCLK when (int)m.WParam == Native.HTMAXBUTTON:
                Caption.SetMaxNcState(true, true);
                m.Result = IntPtr.Zero;
                return;
            case Native.WM_NCLBUTTONUP when (int)m.WParam == Native.HTMAXBUTTON:
                Caption.SetMaxNcState(true, false);
                ToggleMaximize();
                m.Result = IntPtr.Zero;
                return;
        }
        base.WndProc(ref m);
    }

    public void ToggleMaximize()
    {
        int cmd = WindowState == FormWindowState.Maximized ? Native.SC_RESTORE : Native.SC_MAXIMIZE;
        Native.SendMessage(Handle, Native.WM_SYSCOMMAND, (IntPtr)cmd, IntPtr.Zero);
    }

    private void HandleNcCalcSize(ref Message m)
    {
        if (m.WParam != IntPtr.Zero && Native.IsZoomed(Handle))
        {
            var info = new Native.MONITORINFO { cbSize = Marshal.SizeOf<Native.MONITORINFO>() };
            if (Native.GetMonitorInfo(Native.MonitorFromWindow(Handle, 2), ref info))
            {
                var rect = info.rcWork;
                if (Native.TaskbarAutoHides() && rect.Bottom == info.rcMonitor.Bottom) rect.Bottom -= 1;
                Marshal.StructureToPtr(rect, m.LParam, false);
            }
        }
        m.Result = IntPtr.Zero;
    }

    private IntPtr HitTest(Point screen)
    {
        if (_resizable && WindowState == FormWindowState.Normal)
        {
            var b = Bounds;
            int band = Px(4), corner = Px(10);
            bool left = screen.X < b.Left + band, right = screen.X >= b.Right - band;
            bool top = screen.Y < b.Top + band, bottom = screen.Y >= b.Bottom - band;
            bool cl = screen.X < b.Left + corner, cr = screen.X >= b.Right - corner;
            bool ct = screen.Y < b.Top + corner, cb = screen.Y >= b.Bottom - corner;
            if ((left && ct) || (top && cl)) return Native.HTTOPLEFT;
            if ((right && ct) || (top && cr)) return Native.HTTOPRIGHT;
            if ((left && cb) || (bottom && cl)) return Native.HTBOTTOMLEFT;
            if ((right && cb) || (bottom && cr)) return Native.HTBOTTOMRIGHT;
            if (left) return Native.HTLEFT;
            if (right) return Native.HTRIGHT;
            if (top) return Native.HTTOP;
            if (bottom) return Native.HTBOTTOM;
        }
        var client = PointToClient(screen);
        int extra = HitTestExtra(client);
        if (extra != 0) return extra;
        if (Caption.Bounds.Contains(client))
        {
            var inner = new Point(client.X - Caption.Left, client.Y - Caption.Top);
            if (_resizable && Caption.MaxButtonRect.Contains(inner)) return Native.HTMAXBUTTON;
            return Native.HTCAPTION;
        }
        return Native.HTCLIENT;
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        int b = BorderInset;
        Caption.SetBounds(b, b, ClientSize.Width - b * 2, Px(TitleBar.LogicalHeight));
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Fill(g, ClientRectangle, Theme.Window);
        if (WindowState == FormWindowState.Maximized) return;
        var r = ClientRectangle;
        Draw.Frame(g, r, Theme.BorderDark);
        Draw.Frame(g, Rectangle.Inflate(r, -1, -1), Theme.Hex(0x3C4046));
    }

    protected override void OnSizeChanged(EventArgs e)
    {
        base.OnSizeChanged(e);
        PerformLayout();
        Invalidate();
    }

    protected override void OnActivated(EventArgs e)
    {
        base.OnActivated(e);
        Caption.Active = true;
    }

    protected override void OnDeactivate(EventArgs e)
    {
        base.OnDeactivate(e);
        Caption.Active = false;
    }

    protected override void OnDpiChanged(DpiChangedEventArgs e)
    {
        base.OnDpiChanged(e);
        ApplyMinimum();
        OnDpiApplied();
        PerformLayout();
        Invalidate(true);
    }

    protected virtual void OnDpiApplied() { }
}

internal sealed class TitleBar : SkinControl
{
    public const int LogicalHeight = 24;
    private const int HTTRANSPARENT = -1;

    private enum Btn { None, Min, Max, Close }

    private readonly bool _minMax;
    private Btn _hot;
    private Btn _pressed;
    private bool _maxNcHot;
    private bool _maxNcPressed;
    private bool _active = true;
    private string _title = string.Empty;
    private Icon? _smallIcon;

    public TitleBar(bool minMax)
    {
        _minMax = minMax;
        BackColor = Theme.Panel;
    }

    public string Title
    {
        get => _title;
        set { _title = value; Invalidate(); }
    }

    public bool Active
    {
        get => _active;
        set { _active = value; Invalidate(); }
    }

    private int CloseW => Px(42);
    private int SideW => Px(26);
    private int BtnH => Px(19);

    private Rectangle CloseRect => new(Width - CloseW - Px(5), 0, CloseW, BtnH);
    public Rectangle MaxButtonRect => _minMax ? new Rectangle(CloseRect.X - SideW + 1, 0, SideW, BtnH) : Rectangle.Empty;
    private Rectangle MinRect => _minMax ? new Rectangle(MaxButtonRect.X - SideW + 1, 0, SideW, BtnH) : Rectangle.Empty;

    public void SetMaxNcState(bool hot, bool pressed)
    {
        if (_maxNcHot == hot && _maxNcPressed == pressed) return;
        _maxNcHot = hot;
        _maxNcPressed = pressed;
        Invalidate();
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == Native.WM_NCHITTEST)
        {
            long v = m.LParam.ToInt64();
            var p = PointToClient(new Point((short)(v & 0xFFFF), (short)((v >> 16) & 0xFFFF)));
            if (!CloseRect.Contains(p) && !MinRect.Contains(p))
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
        if (_active)
            Draw.Gloss(g, r, Theme.Hex(0x43474D), Theme.Hex(0x33373C), Theme.Hex(0x2A2D31), Theme.Hex(0x212327));
        else
            Draw.Gradient(g, r, Theme.Hex(0x2E3135), Theme.Hex(0x212327));
        g.DrawLine(Draw.Pen(_active ? Theme.Hex(0x5A6068) : Theme.Hex(0x3A3E44)), 0, 0, Width, 0);
        g.DrawLine(Draw.Pen(Theme.BorderDark), 0, Height - 1, Width, Height - 1);

        int icon = Px(16);
        if (_smallIcon == null || _smallIcon.Width != icon)
        {
            _smallIcon?.Dispose();
            _smallIcon = new Icon(FrameForm.AppIcon, icon, icon);
        }
        g.DrawIcon(_smallIcon, new Rectangle(Px(5), (Height - icon) / 2, icon, icon));

        int left = Px(5) + icon + Px(6);
        int right = (_minMax ? MinRect.X : CloseRect.X) - Px(8);
        var font = UiFont;
        Draw.Engraved(g, _title, font, new Rectangle(left, 0, Math.Max(0, right - left), Height), _active ? Theme.TextBright : Theme.TextDim);

        if (_minMax)
        {
            PaintSide(g, MinRect, Btn.Min);
            PaintSide(g, MaxButtonRect, Btn.Max);
        }
        PaintClose(g);
    }

    private void PaintSide(Graphics g, Rectangle r, Btn b)
    {
        bool hot = _hot == b || (b == Btn.Max && _maxNcHot);
        bool pressed = (_pressed == b && _hot == b) || (b == Btn.Max && _maxNcPressed);
        if (pressed) Draw.Gloss(g, r, Theme.Hex(0x1C1E21), Theme.Hex(0x24272B), Theme.Hex(0x1A1C1F), Theme.Hex(0x2A2D31));
        else if (hot) Draw.Gloss(g, r, Theme.Hex(0x666C74), Theme.Hex(0x4C5157), Theme.Hex(0x3C4046), Theme.Hex(0x4A4F55));
        else Draw.Gloss(g, r, Theme.Hex(0x4D5258), Theme.Hex(0x3A3E44), Theme.Hex(0x2C2F33), Theme.Hex(0x33373C));
        DrawButtonFrame(g, r);
        var glyph = _active ? Theme.TextBright : Theme.TextDim;
        int cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2;
        int w = Px(9), t = Math.Max(1, Px(1));
        if (b == Btn.Min)
        {
            var bar = new Rectangle(cx - w / 2, cy + Px(2), w, t + 1);
            g.FillRectangle(Draw.Brush(Theme.BorderDark), bar.X - 1, bar.Y - 1, bar.Width + 2, bar.Height + 2);
            g.FillRectangle(Draw.Brush(glyph), bar);
        }
        else if (FindForm()?.WindowState == FormWindowState.Maximized)
        {
            int s = Px(7);
            g.DrawRectangle(Draw.Pen(glyph), cx - s / 2 + Px(1), cy - s / 2 - Px(1), s, s);
            var front = new Rectangle(cx - s / 2 - Px(1), cy - s / 2 + Px(1), s, s);
            g.FillRectangle(hot ? Draw.Brush(Theme.Hex(0x4C5157)) : Draw.Brush(Theme.Hex(0x33373C)), front);
            g.DrawRectangle(Draw.Pen(glyph), front);
        }
        else
        {
            int h = Px(8);
            var box = new Rectangle(cx - w / 2, cy - h / 2, w, h);
            g.DrawRectangle(Draw.Pen(Theme.BorderDark), box.X - 1, box.Y - 1, box.Width + 2, box.Height + 2);
            g.DrawRectangle(Draw.Pen(glyph), box);
            g.DrawLine(Draw.Pen(glyph), box.X, box.Y + 1, box.Right, box.Y + 1);
        }
    }

    private void PaintClose(Graphics g)
    {
        var r = CloseRect;
        bool hot = _hot == Btn.Close, pressed = hot && _pressed == Btn.Close;
        if (pressed) Draw.Gloss(g, r, Theme.Hex(0x5A1212), Theme.Hex(0x6D1717), Theme.Hex(0x761818), Theme.Hex(0x8E1C1C));
        else if (hot) Draw.Gloss(g, r, Theme.Hex(0xE8665E), Theme.Hex(0xC8362E), Theme.Hex(0xA82420), Theme.Hex(0xC8362E));
        else if (_active) Draw.Gloss(g, r, Theme.Hex(0xB84C46), Theme.Hex(0x96282A), Theme.Hex(0x7A1818), Theme.Hex(0x8E1C1C));
        else Draw.Gloss(g, r, Theme.Hex(0x5C4444), Theme.Hex(0x4C3434), Theme.Hex(0x3E2A2A), Theme.Hex(0x463030));
        DrawButtonFrame(g, r);
        int cx = r.X + r.Width / 2, cy = r.Y + r.Height / 2, s = Px(4);
        var mode = g.SmoothingMode;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        using (var shadow = new Pen(Theme.Hex(0x2A0808), Px(1) * 3.2f))
        {
            g.DrawLine(shadow, cx - s, cy - s, cx + s, cy + s);
            g.DrawLine(shadow, cx + s, cy - s, cx - s, cy + s);
        }
        using (var pen = new Pen(Theme.TextBright, Px(1) * 1.7f))
        {
            g.DrawLine(pen, cx - s, cy - s, cx + s, cy + s);
            g.DrawLine(pen, cx + s, cy - s, cx - s, cy + s);
        }
        g.SmoothingMode = mode;
    }

    private static void DrawButtonFrame(Graphics g, Rectangle r)
    {
        var dark = Draw.Pen(Theme.BorderDark);
        g.DrawLine(dark, r.X, r.Y, r.X, r.Bottom - 1);
        g.DrawLine(dark, r.Right - 1, r.Y, r.Right - 1, r.Bottom - 1);
        g.DrawLine(dark, r.X, r.Bottom - 1, r.Right - 1, r.Bottom - 1);
        using var hi = new Pen(Color.FromArgb(70, 255, 255, 255));
        g.DrawLine(hi, r.X + 1, r.Y + 1, r.Right - 2, r.Y + 1);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _smallIcon?.Dispose();
        base.Dispose(disposing);
    }

    private Btn At(Point p)
    {
        if (CloseRect.Contains(p)) return Btn.Close;
        if (MinRect.Contains(p)) return Btn.Min;
        return Btn.None;
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var b = At(e.Location);
        if (b != _hot) { _hot = b; Invalidate(); }
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = Btn.None;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        _pressed = At(e.Location);
        Invalidate();
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        var pressed = _pressed;
        _pressed = Btn.None;
        Invalidate();
        if (pressed == Btn.None || At(e.Location) != pressed || FindForm() is not { } form) return;
        int cmd = pressed == Btn.Close ? Native.SC_CLOSE : Native.SC_MINIMIZE;
        Native.SendMessage(form.Handle, Native.WM_SYSCOMMAND, (IntPtr)cmd, IntPtr.Zero);
    }
}
