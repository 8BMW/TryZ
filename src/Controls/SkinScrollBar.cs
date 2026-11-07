namespace TryZ.Controls;

internal sealed class SkinScrollBar : SkinControl
{
    private enum Part { None, ArrowA, ArrowB, TrackA, TrackB, Thumb }

    private readonly bool _horizontal;
    private readonly Timer _repeat = new() { Interval = 300 };
    private int _maximum;
    private int _large = 1;
    private int _value;
    private Part _hot;
    private Part _pressed;
    private int _dragOffset;

    public SkinScrollBar(bool horizontal)
    {
        _horizontal = horizontal;
        BackColor = Theme.Inset;
        _repeat.Tick += OnRepeat;
    }

    public event EventHandler? ValueChanged;

    public int SmallChange { get; set; } = 1;
    public int Maximum => _maximum;
    public int LargeChange => _large;
    public int MaxValue => Math.Max(0, _maximum - _large);

    public int Value
    {
        get => _value;
        set
        {
            int v = Math.Clamp(value, 0, MaxValue);
            if (v == _value) return;
            _value = v;
            Invalidate();
            ValueChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public void SetRange(int maximum, int large)
    {
        _maximum = Math.Max(0, maximum);
        _large = Math.Max(1, large);
        int v = Math.Clamp(_value, 0, MaxValue);
        bool changed = v != _value;
        _value = v;
        Invalidate();
        if (changed) ValueChanged?.Invoke(this, EventArgs.Empty);
    }

    public int ThicknessPx => Px(15);

    private int Length => _horizontal ? Width : Height;
    private int ArrowLength => Math.Min(Px(15), Length / 2);

    private Rectangle ArrowRect(bool first)
    {
        int a = ArrowLength;
        if (_horizontal)
            return first ? new Rectangle(0, 0, a, Height) : new Rectangle(Width - a, 0, a, Height);
        return first ? new Rectangle(0, 0, Width, a) : new Rectangle(0, Height - a, Width, a);
    }

    private (int Pos, int Len) ThumbSpan()
    {
        int track = Length - ArrowLength * 2;
        if (_maximum <= _large || track <= 0) return (0, 0);
        int len = Math.Max(Px(18), (int)((long)track * _large / _maximum));
        len = Math.Min(len, track);
        int range = MaxValue;
        int pos = range == 0 ? 0 : (int)((long)(track - len) * _value / range);
        return (ArrowLength + pos, len);
    }

    private Rectangle ThumbRect()
    {
        var (pos, len) = ThumbSpan();
        if (len == 0) return Rectangle.Empty;
        return _horizontal ? new Rectangle(pos, 0, len, Height) : new Rectangle(0, pos, Width, len);
    }

    private Part HitTest(Point p)
    {
        if (ArrowRect(true).Contains(p)) return Part.ArrowA;
        if (ArrowRect(false).Contains(p)) return Part.ArrowB;
        var thumb = ThumbRect();
        if (thumb.IsEmpty) return Part.None;
        if (thumb.Contains(p)) return Part.Thumb;
        int at = _horizontal ? p.X : p.Y;
        return at < (_horizontal ? thumb.X : thumb.Y) ? Part.TrackA : Part.TrackB;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var client = ClientRectangle;
        if (_horizontal)
        {
            Draw.Gradient(g, client, Theme.Hex(0x0E0F11), Theme.Hex(0x1A1C1F));
            g.DrawLine(Draw.Pen(Theme.BorderDark), 0, 0, Width, 0);
        }
        else
        {
            Draw.Gradient(g, client, Theme.Hex(0x0E0F11), Theme.Hex(0x1A1C1F), horizontal: true);
            g.DrawLine(Draw.Pen(Theme.BorderDark), 0, 0, 0, Height);
        }

        var thumb = ThumbRect();
        bool active = !thumb.IsEmpty && Enabled;
        PaintArrow(g, ArrowRect(true), Part.ArrowA, _horizontal ? ArrowDirection.Left : ArrowDirection.Up, active);
        PaintArrow(g, ArrowRect(false), Part.ArrowB, _horizontal ? ArrowDirection.Right : ArrowDirection.Down, active);

        if (_pressed is Part.TrackA or Part.TrackB && !thumb.IsEmpty && _hot == _pressed)
        {
            var r = _pressed == Part.TrackA
                ? (_horizontal ? Rectangle.FromLTRB(ArrowLength, 0, thumb.X, Height) : Rectangle.FromLTRB(0, ArrowLength, Width, thumb.Y))
                : (_horizontal ? Rectangle.FromLTRB(thumb.Right, 0, Width - ArrowLength, Height) : Rectangle.FromLTRB(0, thumb.Bottom, Width, Height - ArrowLength));
            Draw.Fill(g, r, Theme.Hex(0x301414));
        }

        if (thumb.IsEmpty) return;
        var state = _pressed == Part.Thumb ? ChromeState.Pressed : _hot == Part.Thumb ? ChromeState.Hot : ChromeState.Normal;
        Draw.Raised(g, thumb, state);
        int dots = thumb.Width > Px(24) || thumb.Height > Px(24) ? 3 : 0;
        if (dots > 0) Draw.GripDots(g, thumb, _horizontal, dots, Math.Max(1, Px(1)));
    }

    private void PaintArrow(Graphics g, Rectangle r, Part part, ArrowDirection dir, bool active)
    {
        var state = !active ? ChromeState.Disabled
            : _pressed == part && _hot == part ? ChromeState.Pressed
            : _hot == part ? ChromeState.Hot
            : ChromeState.Normal;
        Draw.Raised(g, r, state);
        Draw.Triangle(g, r, dir, active ? Theme.Text : Theme.TextDisabled, Px(3));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        if (_pressed == Part.Thumb)
        {
            int track = Length - ArrowLength * 2;
            var (_, len) = ThumbSpan();
            int at = (_horizontal ? e.X : e.Y) - ArrowLength - _dragOffset;
            int span = Math.Max(1, track - len);
            Value = (int)((long)at * MaxValue / span);
            return;
        }
        var part = HitTest(e.Location);
        if (part != _hot)
        {
            _hot = part;
            Invalidate();
        }
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = Part.None;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left) return;
        _pressed = HitTest(e.Location);
        _hot = _pressed;
        if (_pressed == Part.Thumb)
        {
            var thumb = ThumbRect();
            _dragOffset = _horizontal ? e.X - thumb.X : e.Y - thumb.Y;
        }
        else if (_pressed != Part.None)
        {
            Step();
            _repeat.Interval = 320;
            _repeat.Start();
        }
        Invalidate();
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        _pressed = Part.None;
        _repeat.Stop();
        _hot = HitTest(e.Location);
        Invalidate();
    }

    private void OnRepeat(object? sender, EventArgs e)
    {
        _repeat.Interval = 45;
        var p = PointToClient(Cursor.Position);
        if (HitTest(p) == _pressed) Step();
    }

    private void Step()
    {
        switch (_pressed)
        {
            case Part.ArrowA: Value -= SmallChange; break;
            case Part.ArrowB: Value += SmallChange; break;
            case Part.TrackA: Value -= _large; break;
            case Part.TrackB: Value += _large; break;
        }
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _repeat.Dispose();
        base.Dispose(disposing);
    }
}
