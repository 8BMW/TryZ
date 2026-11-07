namespace TryZ.Controls;

internal sealed class SkinRenderer : ToolStripRenderer
{
    public static readonly SkinRenderer Instance = new();

    protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
    {
        var r = new Rectangle(Point.Empty, e.ToolStrip.Size);
        if (e.ToolStrip is ToolStripDropDown)
            Draw.Fill(e.Graphics, r, Theme.Panel);
        else
            Draw.Gradient(e.Graphics, r, Theme.Hex(0x2C2F33), Theme.Hex(0x212327));
    }

    protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
    {
        var r = new Rectangle(Point.Empty, e.ToolStrip.Size);
        if (e.ToolStrip is ToolStripDropDown)
        {
            Draw.Frame(e.Graphics, r, Theme.BorderDark);
            Draw.Frame(e.Graphics, Rectangle.Inflate(r, -1, -1), Theme.Hex(0x3A3E44));
        }
        else
        {
            Draw.EtchH(e.Graphics, 0, r.Width, r.Height - 2);
        }
    }

    protected override void OnRenderImageMargin(ToolStripRenderEventArgs e)
    {
        var r = e.AffectedBounds;
        Draw.Gradient(e.Graphics, r, Theme.Hex(0x2C2F33), Theme.Hex(0x282B2F), horizontal: true);
        Draw.EtchV(e.Graphics, r.Right - 1, r.Y, r.Bottom - 1);
    }

    protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
    {
        var item = e.Item;
        if (!item.Enabled && !item.Selected) return;
        var r = new Rectangle(Point.Empty, item.Size);
        if (item.Pressed && item.OwnerItem == null)
        {
            Draw.Gradient(e.Graphics, r, Theme.Hex(0x161719), Theme.Panel);
            Draw.Frame(e.Graphics, r, Theme.BorderDark);
        }
        else if (item.Selected)
        {
            var s = item.OwnerItem == null ? r : Rectangle.Inflate(r, -2, 0);
            Draw.Selection(e.Graphics, s);
            Draw.Frame(e.Graphics, s, Theme.Hex(0x2C0A0A));
        }
    }

    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
    {
        e.TextColor = !e.Item.Enabled ? Theme.TextDisabled : e.Item.Selected ? Theme.TextBright : Theme.Text;
        if (e.Item.OwnerItem != null && e.TextFormat.HasFlag(TextFormatFlags.Right) && e.Item.Enabled && !e.Item.Selected)
            e.TextColor = Theme.TextDim;
        base.OnRenderItemText(e);
    }

    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e)
    {
        var dpi = e.Item?.Owner is { } strip ? Theme.DpiOf(strip) : 96;
        Draw.Triangle(e.Graphics, e.ArrowRectangle, ArrowDirection.Right, e.Item?.Enabled != false ? Theme.Brass : Theme.TextDisabled, Theme.Scale(3, dpi));
    }

    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
    {
        int y = e.Item.Height / 2 - 1;
        int left = e.Item.Owner is ToolStripDropDownMenu { ShowImageMargin: true } menu ? menu.Padding.Left + e.Item.Height * 0 + Theme.Scale(28, Theme.DpiOf(menu)) : 4;
        Draw.EtchH(e.Graphics, left, e.Item.Width - 4, y);
    }

    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e)
    {
        var r = e.ImageRectangle;
        r.Inflate(1, 1);
        Draw.Sunken(e.Graphics, r, Theme.Inset);
        if (e.Item?.Image != null) return;
        var mode = e.Graphics.SmoothingMode;
        e.Graphics.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        float k = r.Width / 13f;
        using var pen = new Pen(Theme.Brass, 1.8f * k);
        e.Graphics.DrawLines(pen, new[]
        {
            new PointF(r.X + 3f * k, r.Y + 6.5f * k),
            new PointF(r.X + 5.5f * k, r.Y + 9f * k),
            new PointF(r.X + 10f * k, r.Y + 3.5f * k),
        });
        e.Graphics.SmoothingMode = mode;
    }
}

internal sealed class SkinContextMenu : ContextMenuStrip
{
    public SkinContextMenu()
    {
        Renderer = SkinRenderer.Instance;
        ShowImageMargin = true;
        DropShadowEnabled = true;
    }

    public ToolStripMenuItem AddItem(string text, IconId icon, Action action)
    {
        var item = new ToolStripMenuItem(text) { Tag = icon };
        item.Click += (_, _) => action();
        Items.Add(item);
        return item;
    }

    protected override void OnOpening(System.ComponentModel.CancelEventArgs e)
    {
        base.OnOpening(e);
        int dpi = Theme.DpiOf(this);
        Font = Theme.Ui(dpi);
        ImageScalingSize = new Size(Theme.Scale(16, dpi), Theme.Scale(16, dpi));
        foreach (ToolStripItem item in Items)
        {
            if (item is ToolStripMenuItem m)
            {
                m.ForeColor = Theme.Text;
                if (m.Tag is IconId id && id != IconId.None)
                    m.Image = Icons.Get(id, Theme.Scale(16, dpi));
            }
        }
    }
}
