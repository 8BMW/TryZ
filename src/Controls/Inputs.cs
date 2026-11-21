using System.Runtime.InteropServices;

namespace TryZ.Controls;

internal static class EditSupport
{
    private const int EM_SETCUEBANNER = 0x1501;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, string lParam);

    public static void SetCue(TextBox box, string cue)
    {
        if (box.IsHandleCreated) SendMessage(box.Handle, EM_SETCUEBANNER, (IntPtr)1, cue);
        else box.HandleCreated += (_, _) => SendMessage(box.Handle, EM_SETCUEBANNER, (IntPtr)1, cue);
    }

    public static TextBox CreateEdit()
    {
        var box = new TextBox
        {
            BorderStyle = BorderStyle.None,
            BackColor = Theme.Inset,
            ForeColor = Theme.Text,
            Multiline = false,
        };
        box.ContextMenuStrip = BuildMenu(box);
        return box;
    }

    private static ContextMenuStrip BuildMenu(TextBox box)
    {
        var menu = new SkinContextMenu();
        var cut = menu.AddItem("Cut", IconId.None, () => box.Cut());
        var copy = menu.AddItem("Copy", IconId.Copy, () => box.Copy());
        var paste = menu.AddItem("Paste", IconId.None, () => box.Paste());
        menu.Items.Add(new ToolStripSeparator());
        menu.AddItem("Select All", IconId.None, () => box.SelectAll());
        menu.Opening += (_, _) =>
        {
            cut.Enabled = copy.Enabled = box.SelectionLength > 0;
            paste.Enabled = !box.ReadOnly;
        };
        return menu;
    }
}

internal class TextField : SkinControl
{
    private readonly IconId _icon;

    public TextField(IconId icon = IconId.None, string? cue = null)
    {
        _icon = icon;
        BackColor = Theme.Inset;
        Edit = EditSupport.CreateEdit();
        Edit.Enter += (_, _) => Invalidate();
        Edit.Leave += (_, _) => Invalidate();
        Controls.Add(Edit);
        if (cue != null) EditSupport.SetCue(Edit, cue);
        Cursor = Cursors.IBeam;
    }

    public TextBox Edit { get; }

    public string Value
    {
        get => Edit.Text;
        set => Edit.Text = value;
    }

    public bool Mono { get; set; }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        Edit.Font = Mono ? MonoFont : UiFont;
        int left = Px(4) + (_icon != IconId.None ? Px(17) : 0);
        int h = Edit.PreferredHeight;
        Edit.SetBounds(left, (Height - h) / 2, Math.Max(1, Width - left - Px(4)), h);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        Draw.Sunken(e.Graphics, ClientRectangle, Theme.Inset);
        if (Edit.Focused)
            e.Graphics.DrawLine(Draw.Pen(Theme.BrassDark), 1, Height - 1, Width - 1, Height - 1);
        if (_icon != IconId.None)
        {
            int s = Px(13);
            e.Graphics.DrawImage(Icons.Get(_icon, s, !Enabled), Px(3), (Height - s) / 2, s, s);
        }
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Edit.Focus();
    }
}

internal sealed class SkinSpin : SkinControl
{
    private readonly TextBox _edit;
    private readonly Timer _repeat = new() { Interval = 320 };
    private int _value;
    private int _hot;
    private int _pressed;

    public SkinSpin(int value, int min, int max, int step = 1)
    {
        Minimum = min;
        Maximum = max;
        Step = step;
        value = Math.Clamp(value, min, max);
        _value = value;
        BackColor = Theme.Inset;
        _edit = EditSupport.CreateEdit();
        _edit.TextAlign = HorizontalAlignment.Right;
        _edit.Text = value.ToString();
        _edit.KeyPress += (_, e) =>
        {
            if (!char.IsDigit(e.KeyChar) && !char.IsControl(e.KeyChar)) e.Handled = true;
        };
        _edit.KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.Up) { Value += Step; e.Handled = true; }
            else if (e.KeyCode == Keys.Down) { Value -= Step; e.Handled = true; }
        };
        _edit.Leave += (_, _) => Commit();
        _edit.TextChanged += (_, _) =>
        {
            if (int.TryParse(_edit.Text, out int v) && v >= Minimum && v <= Maximum && v != _value)
            {
                _value = v;
                ValueChanged?.Invoke(this, EventArgs.Empty);
            }
        };
        Controls.Add(_edit);
        _repeat.Tick += (_, _) =>
        {
            _repeat.Interval = 60;
            if (_pressed != 0) Value += _pressed * Step;
        };
    }

    public event EventHandler? ValueChanged;

    public int Minimum { get; }
    public int Maximum { get; }
    public int Step { get; }

    public int Value
    {
        get => _value;
        set
        {
            int v = Math.Clamp(value, Minimum, Maximum);
            if (v == _value && _edit.Text == v.ToString()) return;
            _value = v;
            _edit.Text = v.ToString();
            Invalidate();
            ValueChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private void Commit()
    {
        Value = int.TryParse(_edit.Text, out int v) ? v : _value;
        _edit.Text = _value.ToString();
    }

    private int ButtonWidth => Px(15);
    private Rectangle UpRect => new(Width - ButtonWidth - 1, 1, ButtonWidth, Height / 2 - 1);
    private Rectangle DownRect => new(Width - ButtonWidth - 1, Height / 2, ButtonWidth, Height - Height / 2 - 1);

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        _edit.Font = UiFont;
        int h = _edit.PreferredHeight;
        _edit.SetBounds(Px(3), (Height - h) / 2, Math.Max(1, Width - ButtonWidth - Px(6)), h);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        Draw.Sunken(g, ClientRectangle, Theme.Inset);
        PaintButton(g, UpRect, 1, ArrowDirection.Up);
        PaintButton(g, DownRect, -1, ArrowDirection.Down);
    }

    private void PaintButton(Graphics g, Rectangle r, int dir, ArrowDirection arrow)
    {
        var state = !Enabled ? ChromeState.Disabled : _pressed == dir ? ChromeState.Pressed : _hot == dir ? ChromeState.Hot : ChromeState.Normal;
        Draw.Raised(g, r, state);
        Draw.Triangle(g, r, arrow, Enabled ? Theme.Text : Theme.TextDisabled, Px(2));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        int hot = UpRect.Contains(e.Location) ? 1 : DownRect.Contains(e.Location) ? -1 : 0;
        if (hot != _hot) { _hot = hot; Invalidate(); }
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = 0;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        _pressed = UpRect.Contains(e.Location) ? 1 : DownRect.Contains(e.Location) ? -1 : 0;
        if (_pressed != 0)
        {
            Value += _pressed * Step;
            _repeat.Interval = 320;
            _repeat.Start();
        }
        Invalidate();
    }

    protected override void OnMouseUp(MouseEventArgs e)
    {
        base.OnMouseUp(e);
        _pressed = 0;
        _repeat.Stop();
        Invalidate();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _repeat.Dispose();
        base.Dispose(disposing);
    }
}

internal sealed class SkinCombo : SkinControl
{
    private readonly List<string> _items = new();
    private readonly TextBox? _edit;
    private readonly SkinList _list = new() { HoverSelects = true };
    private readonly ToolStripDropDown _drop;
    private readonly ToolStripControlHost _host;
    private int _selected = -1;
    private bool _hot;
    private DateTime _closedAt;

    public SkinCombo(bool editable = false)
    {
        SetStyle(ControlStyles.Selectable, true);
        TabStop = true;
        BackColor = Theme.Panel;
        if (editable)
        {
            _edit = EditSupport.CreateEdit();
            _edit.TextChanged += (_, _) => TextChangedByUser?.Invoke(this, EventArgs.Empty);
            Controls.Add(_edit);
        }

        _host = new ToolStripControlHost(_list) { Margin = Padding.Empty, Padding = Padding.Empty, AutoSize = false };
        _drop = new ToolStripDropDown
        {
            Padding = Padding.Empty,
            Margin = Padding.Empty,
            AutoSize = false,
            DropShadowEnabled = false,
            Renderer = SkinRenderer.Instance,
        };
        _drop.Items.Add(_host);
        _drop.Closed += (_, _) => { _closedAt = DateTime.UtcNow; Invalidate(); };
        _list.ItemChosen += (_, _) =>
        {
            int idx = _list.SelectedIndex;
            _drop.Close();
            if (idx >= 0) SelectedIndex = idx;
            if (_edit != null) _edit.Focus(); else Focus();
        };
    }

    public event EventHandler? SelectionChanged;
    public event EventHandler? TextChangedByUser;

    public IList<string> Items => _items;

    public int SelectedIndex
    {
        get => _selected;
        set
        {
            int v = _items.Count == 0 ? -1 : Math.Clamp(value, 0, _items.Count - 1);
            if (v == _selected) return;
            _selected = v;
            if (_edit != null && v >= 0) _edit.Text = _items[v];
            Invalidate();
            SelectionChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    public string Value
    {
        get => _edit != null ? _edit.Text : _selected >= 0 ? _items[_selected] : string.Empty;
        set
        {
            int idx = _items.IndexOf(value);
            if (_edit != null) { _edit.Text = value; _selected = idx; }
            else if (idx >= 0) SelectedIndex = idx;
            Invalidate();
        }
    }

    public bool DroppedDown => _drop.Visible;
    public ToolStripDropDown DropDownWindow => _drop;

    public void AddRange(params string[] items) => _items.AddRange(items);

    private int ButtonWidth => Px(17);
    private Rectangle ButtonRect => new(Width - ButtonWidth, 0, ButtonWidth, Height);

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        if (_edit == null) return;
        _edit.Font = UiFont;
        int h = _edit.PreferredHeight;
        _edit.SetBounds(Px(4), (Height - h) / 2, Math.Max(1, Width - ButtonWidth - Px(6)), h);
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var r = ClientRectangle;
        if (_edit != null)
        {
            Draw.Sunken(g, r, Theme.Inset);
        }
        else
        {
            Draw.Sunken(g, r, Enabled ? Theme.Hex(0x1A1C1F) : Theme.Panel);
            Draw.Text(g, Value, UiFont, new Rectangle(Px(5), 0, Width - ButtonWidth - Px(7), Height), Enabled ? Theme.Text : Theme.TextDisabled);
            if (Focused && ShowFocusCues)
                g.DrawRectangle(Draw.Pen(Theme.BrassDark), 2, 2, Width - ButtonWidth - 5, Height - 5);
        }
        var b = ButtonRect;
        var state = !Enabled ? ChromeState.Disabled : _drop.Visible ? ChromeState.Pressed : _hot ? ChromeState.Hot : ChromeState.Normal;
        Draw.Raised(g, b, state);
        Draw.Triangle(g, b, ArrowDirection.Down, Enabled ? Theme.Brass : Theme.TextDisabled, Px(3));
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        bool hot = _edit == null || ButtonRect.Contains(e.Location);
        if (hot != _hot) { _hot = hot; Invalidate(); }
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        base.OnMouseLeave(e);
        _hot = false;
        Invalidate();
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        if (e.Button != MouseButtons.Left) return;
        if (_edit != null && !ButtonRect.Contains(e.Location)) { _edit.Focus(); return; }
        Focus();
        if ((DateTime.UtcNow - _closedAt).TotalMilliseconds > 150) ShowDrop();
    }

    protected override void OnEnabledChanged(EventArgs e)
    {
        base.OnEnabledChanged(e);
        Invalidate();
    }

    protected override void OnGotFocus(EventArgs e) { base.OnGotFocus(e); Invalidate(); }
    protected override void OnLostFocus(EventArgs e) { base.OnLostFocus(e); Invalidate(); }

    protected override bool IsInputKey(Keys keyData) =>
        keyData is Keys.Up or Keys.Down or Keys.F4 or (Keys.Alt | Keys.Down) || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (e.KeyCode == Keys.F4 || (e.Alt && e.KeyCode == Keys.Down)) ShowDrop();
        else if (e.KeyCode == Keys.Up && _selected > 0) SelectedIndex = _selected - 1;
        else if (e.KeyCode == Keys.Down && _selected < _items.Count - 1) SelectedIndex = _selected + 1;
    }

    public void ShowDrop()
    {
        if (_items.Count == 0 || _drop.Visible) return;
        _list.SetItems(_items.Select(s => new ListRow(s)).ToList());
        _list.SelectedIndex = _selected;
        int visible = Math.Min(_items.Count, 12);
        int h = visible * _list.RowHeightPx + 2;
        var size = new Size(Math.Max(Width, Px(80)), h);
        _host.Size = size;
        _list.Size = size;
        _drop.Size = size;
        _drop.Show(this, new Point(0, Height));
        _list.Focus();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) _drop.Dispose();
        base.Dispose(disposing);
    }
}
