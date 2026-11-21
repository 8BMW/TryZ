using System.Drawing.Drawing2D;
using System.Drawing.Text;
using TryZ.Data;

namespace TryZ.Views;

internal sealed class ReportOptions
{
    public int Template { get; set; }
    public bool Cover { get; set; } = true;
    public bool Severity { get; set; } = true;
    public bool Findings { get; set; }
    public bool Evidence { get; set; }
    public bool Hosts { get; set; }
    public string Footer { get; set; } = string.Empty;

    public ReportScope ToScope() => new()
    {
        Template = (ReportTemplate)Math.Clamp(Template, 0, ReportScope.TemplateNames.Length - 1),
        Cover = Cover, Severity = Severity, Findings = Findings, Evidence = Evidence, Hosts = Hosts,
    };
}

internal sealed class ReportPreview : SkinControl
{
    public const int PageW = 595;
    public const int PageH = 842;

    private readonly SkinScrollBar _v = new(false);
    private readonly SkinScrollBar _h = new(true);
    private readonly Session _session;
    private readonly ReportOptions _options;
    private List<Action<Graphics>> _pages = new();
    private double _zoom = 1.0;
    private int _page;

    public ReportPreview(Session session, ReportOptions options)
    {
        _session = session;
        _options = options;
        BackColor = Theme.Hex(0x2B2E32);
        SetStyle(ControlStyles.Selectable, true);
        _v.ValueChanged += (_, _) => { UpdatePageFromScroll(); Invalidate(); };
        _h.ValueChanged += (_, _) => Invalidate();
        Controls.Add(_v);
        Controls.Add(_h);
        Rebuild();
    }

    public event EventHandler? PageChanged;

    public int PageCount => _pages.Count;
    public int Page => _page;
    public double Zoom
    {
        get => _zoom;
        set { _zoom = Math.Clamp(value, 0.3, 2.0); UpdateScroll(); Invalidate(); }
    }

    public void Rebuild()
    {
        _pages = BuildPages();
        _page = Math.Clamp(_page, 0, Math.Max(0, _pages.Count - 1));
        UpdateScroll();
        Invalidate();
    }

    public void GoTo(int page)
    {
        _page = Math.Clamp(page, 0, Math.Max(0, _pages.Count - 1));
        _v.Value = _page * PagePitch;
        PageChanged?.Invoke(this, EventArgs.Empty);
        Invalidate();
    }

    private int PagePx(int size) => (int)(size * _zoom * Dpi / 96.0);
    private int PagePitch => PagePx(PageH) + Px(18);

    private void UpdatePageFromScroll()
    {
        int p = Math.Clamp((_v.Value + PagePitch / 3) / Math.Max(1, PagePitch), 0, Math.Max(0, _pages.Count - 1));
        if (p != _page)
        {
            _page = p;
            PageChanged?.Invoke(this, EventArgs.Empty);
        }
    }

    private void UpdateScroll()
    {
        int th = _v.ThicknessPx;
        int contentW = PagePx(PageW) + Px(40);
        bool showH = contentW > Width - th - 2;
        _h.Visible = showH;
        int viewH = Height - 2 - (showH ? th : 0);
        _v.SetBounds(Width - th - 1, 1, th, viewH);
        _h.SetBounds(1, Height - th - 1, Width - th - 2, th);
        _v.SmallChange = Px(24);
        _h.SmallChange = Px(24);
        _v.SetRange(_pages.Count * PagePitch + Px(18), Math.Max(1, viewH));
        _h.SetRange(contentW, Math.Max(1, Width - th - 2));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        UpdateScroll();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        var desk = new Rectangle(1, 1, Width - 2, Height - 2);
        Draw.Gradient(g, desk, Theme.Hex(0x34373C), Theme.Hex(0x26292D));
        Draw.Frame(g, ClientRectangle, Theme.BorderDark);

        int th = _v.Width;
        int viewW = Width - th - 2;
        int bottom = _h.Visible ? _h.Top : Height - 1;
        var saved = g.Clip;
        g.SetClip(new Rectangle(1, 1, viewW, bottom - 1));
        int pw = PagePx(PageW), ph = PagePx(PageH);
        int x = Math.Max(Px(20), (viewW - pw) / 2) - _h.Value;
        int y = Px(14) - _v.Value;
        for (int i = 0; i < _pages.Count; i++, y += PagePitch)
        {
            if (y + ph + Px(10) < 0 || y > Height) continue;
            var r = new Rectangle(x, y, pw, ph);
            PaintShadow(g, r);
            g.FillRectangle(Brushes.White, r);
            g.DrawRectangle(Draw.Pen(Theme.Hex(0x101113)), r.X - 1, r.Y - 1, r.Width + 1, r.Height + 1);

            var state = g.Save();
            g.IntersectClip(r);
            g.TranslateTransform(x, y);
            float k = (float)(_zoom * Dpi / 96.0);
            g.ScaleTransform(k, k);
            g.TextRenderingHint = TextRenderingHint.AntiAlias;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            _pages[i](g);
            g.Restore(state);
        }
        g.Clip = saved;
        saved.Dispose();
        if (_h.Visible) Draw.Fill(g, new Rectangle(_h.Right, _h.Top, th, _h.Height), Theme.Panel);
    }

    private void PaintShadow(Graphics g, Rectangle r)
    {
        int steps = Px(7);
        for (int i = steps; i >= 1; i--)
        {
            int alpha = (int)(60.0 * (steps - i + 1) / steps / 1.6);
            using var b = new SolidBrush(Color.FromArgb(alpha, 0, 0, 0));
            var s = new Rectangle(r.X + Px(2) - i + 2, r.Y + Px(3) - i + 2, r.Width + i * 2 - 2, r.Height + i * 2 - 2);
            g.FillRectangle(b, s);
        }
    }

    private List<Action<Graphics>> BuildPages()
    {
        var pages = new List<Action<Graphics>>();
        var s = _session;
        var scope = _options.ToScope();
        string title = scope.Name;
        var findings = scope.SelectFindings(s).OrderByDescending(f => f.Severity).ThenBy(f => Schemas.IpKey(f.Host)).ToList();
        var hosts = s.Hosts.Items.ToList();
        var plan = scope.IncludesPlan ? RemediationPlan.Build(s, findings) : null;
        bool planPages = plan != null && scope.Template == ReportTemplate.Remediation;
        int total = 0;

        if (_options.Cover || _options.Severity) total++;
        const int perPage = 34;
        const int planPerPage = 24;
        int pp = planPages ? Math.Max(1, (int)Math.Ceiling(plan!.Items.Count / (double)planPerPage)) : 0;
        int fp = _options.Findings ? Math.Max(1, (int)Math.Ceiling(findings.Count / (double)(_options.Evidence ? perPage / 2 : perPage))) : 0;
        int hp = _options.Hosts ? Math.Max(1, (int)Math.Ceiling(hosts.Count / 34.0)) : 0;
        total += pp + fp + hp;
        if (total == 0) total = 1;
        int current = 0;

        if (_options.Cover || _options.Severity || (pp == 0 && fp == 0 && hp == 0))
        {
            int n = ++current;
            var top = plan != null && scope.Template == ReportTemplate.Executive ? plan.Items.Take(scope.PlanLimit).ToList() : null;
            pages.Add(g => PaintSummaryPage(g, title, n, total, top, plan));
        }
        for (int i = 0; i < pp; i++)
        {
            int n = ++current;
            var slice = plan!.Items.Skip(i * planPerPage).Take(planPerPage).ToList();
            int first = i;
            pages.Add(g => PaintPlanPage(g, title, plan, slice, first == 0, n, total));
        }
        int chunk = _options.Evidence ? perPage / 2 : perPage;
        for (int i = 0; i < fp; i++)
        {
            int n = ++current;
            var slice = findings.Skip(i * chunk).Take(chunk).ToList();
            int first = i;
            pages.Add(g => PaintFindingsPage(g, title, slice, first == 0, n, total));
        }
        for (int i = 0; i < hp; i++)
        {
            int n = ++current;
            var slice = hosts.Skip(i * 34).Take(34).ToList();
            int first = i;
            pages.Add(g => PaintHostsPage(g, title, slice, first == 0, n, total));
        }
        return pages;
    }

    private static readonly Color Ink = Theme.Hex(0x22242A);
    private static readonly Color Muted = Theme.Hex(0x70757D);
    private static readonly Color RuleC = Theme.Hex(0xC8CBD0);
    private static readonly Color Blood = Theme.Hex(0x8E1C1C);

    private static void Str(Graphics g, string text, Font f, Color c, float x, float y, float w = 0, StringAlignment align = StringAlignment.Near)
    {
        using var brush = new SolidBrush(c);
        using var sf = new StringFormat(StringFormat.GenericTypographic) { Alignment = align, Trimming = StringTrimming.EllipsisCharacter };
        sf.FormatFlags |= StringFormatFlags.NoWrap;
        g.DrawString(text, f, brush, new RectangleF(x, y, w > 0 ? w : 500, 40), sf);
    }

    private void PageFrame(Graphics g, string title, int n, int total)
    {
        using var small = new Font("Tahoma", 7f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var ruleP = new Pen(RuleC, 0.5f);
        Str(g, "TryZ Security Suite", small, Muted, 42, 26);
        Str(g, title, small, Muted, 42, 26, 511, StringAlignment.Far);
        g.DrawLine(ruleP, 42, 37, 553, 37);
        g.DrawLine(ruleP, 42, 806, 553, 806);
        var session = _session;
        string foot = _options.Footer.Length > 0 ? _options.Footer
            : session.Target.Length > 0
                ? $"Assessment of {session.Target}{(session.StartedAt is DateTime at ? ", " + at.ToString("yyyy-MM-dd HH:mm") : string.Empty)}. Confidential."
                : "No scan recorded in this session.";
        Str(g, foot, small, Muted, 42, 811, 430);
        Str(g, $"Page {n} of {total}", small, Muted, 42, 811, 511, StringAlignment.Far);
    }

    private void PaintSummaryPage(Graphics g, string title, int n, int total, List<PlanItem>? top, RemediationPlan? plan)
    {
        var s = _session;
        PageFrame(g, title, n, total);
        using var h1 = new Font("Georgia", 22f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var h2 = new Font("Georgia", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var body = new Font("Tahoma", 8.5f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var bold = new Font("Tahoma", 8.5f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var mono = new Font("Consolas", 8.5f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var ruleP = new Pen(RuleC, 0.5f);

        float y = 58;
        using (var band = new SolidBrush(Blood)) g.FillRectangle(band, 42, y, 5, 44);
        Str(g, title, h1, Ink, 54, y - 2, 490);
        Str(g, $"Session {s.Name}", body, Muted, 54, y + 30, 490);
        y += 62;

        Str(g, "Assessment details", h2, Ink, 42, y);
        y += 20;
        (string, string)[] details =
        {
            ("Target", s.Target.Length > 0 ? s.Target : "(no scan has run)"),
            ("Profile", s.Profile.Length > 0 ? s.Profile : "-"),
            ("Started", s.StartedAt?.ToString("yyyy-MM-dd HH:mm") ?? "-"),
            ("Elapsed", TimeSpan.FromSeconds(s.ElapsedSeconds).ToString(@"mm\:ss")),
            ("Hosts", s.Hosts.Items.Count.ToString()),
            ("Services", s.Ports.Items.Count.ToString()),
            ("URLs crawled", s.Urls.Items.Count.ToString("N0")),
        };
        foreach (var (k, v) in details)
        {
            Str(g, k, body, Muted, 42, y, 100);
            Str(g, v, mono, Ink, 150, y, 400);
            g.DrawLine(ruleP, 42, y + 13, 553, y + 13);
            y += 15;
        }

        y += 18;
        if (_options.Severity)
        {
            Str(g, "Findings by severity", h2, Ink, 42, y);
            y += 22;
            string[] names = { "Critical", "High", "Medium", "Low", "Info" };
            int max = Math.Max(1, s.SeverityCounts.Max());
            for (int i = 0; i < 5; i++)
            {
                int count = s.SeverityCounts[4 - i];
                var c = Theme.SeverityColor((Severity)(4 - i));
                Str(g, names[i], body, Ink, 42, y, 60);
                float len = 340f * count / max;
                using (var back = new SolidBrush(Theme.Hex(0xECEDEF))) g.FillRectangle(back, 105, y, 340, 10);
                if (len > 0)
                {
                    using var bar = new LinearGradientBrush(new RectangleF(105, y - 1, 10, 12), Theme.Shift(c, 14), Theme.Shift(c, -30), LinearGradientMode.Vertical);
                    g.FillRectangle(bar, 105, y, len, 10);
                }
                Str(g, count.ToString(), bold, Ink, 452, y, 40);
                y += 17;
            }
            y += 16;
        }

        Str(g, "Summary", h2, Ink, 42, y);
        y += 20;
        using var wrap = new SolidBrush(Ink);
        int openPorts = s.Ports.Items.Count(p => p.State == "open");
        string text = s.Target.Length == 0
            ? "No scan has run in this session yet. Enter a target and press F5; this page fills in as results arrive."
            : s.FindingCount == 0
                ? $"The assessment of {s.Target} found {s.Hosts.Items.Count} live host(s) with {openPorts} open service(s) and recorded no findings. "
                  + "Absence of findings covers only the checks that ran and does not prove the systems are free of vulnerabilities."
                : $"The assessment of {s.Target} found {s.Hosts.Items.Count} live host(s) with {openPorts} open service(s) and recorded {s.FindingCount} finding(s): "
                  + $"{s.SeverityCounts[4]} critical, {s.SeverityCounts[3]} high, {s.SeverityCounts[2]} medium, {s.SeverityCounts[1]} low and {s.SeverityCounts[0]} informational. "
                  + (s.SeverityCounts[4] + s.SeverityCounts[3] > 0
                      ? "Critical and high severity items should be addressed first."
                      : "No critical or high severity items were identified.");
        g.DrawString(text, body, wrap, new RectangleF(42, y, 511, 80));

        if (top == null || plan == null) return;
        y += 86;
        Str(g, "Top priorities", h2, Ink, 42, y);
        y += 20;
        if (top.Count == 0)
        {
            g.DrawString(plan.Summary(), body, wrap, new RectangleF(42, y, 511, 40));
            return;
        }
        foreach (var item in top)
        {
            Str(g, item.TierText, bold, TierInk(item.Tier), 42, y, 56);
            Str(g, item.Title, body, Ink, 102, y, 300);
            Str(g, item.AffectedText, mono, Muted, 405, y + 1, 90);
            Str(g, item.DueText, mono, item.Overdue ? Blood : Ink, 497, y + 1, 56, StringAlignment.Far);
            g.DrawLine(ruleP, 42, y + 13, 553, y + 13);
            y += 16;
        }
        if (plan.Items.Count > top.Count)
            Str(g, $"{plan.Items.Count - top.Count} more item(s) in the Remediation Plan template.", body, Muted, 42, y + 4, 511);
    }

    private static Color TierInk(PriorityTier tier) => Theme.Shift(Theme.SeverityColor(tier switch
    {
        PriorityTier.FixNow => Severity.Critical,
        PriorityTier.FixNext => Severity.High,
        PriorityTier.Planned => Severity.Medium,
        _ => Severity.Info,
    }), -46);

    private void PaintPlanPage(Graphics g, string title, RemediationPlan plan, List<PlanItem> items, bool first, int n, int total)
    {
        PageFrame(g, title, n, total);
        using var h2 = new Font("Georgia", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var body = new Font("Tahoma", 8f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var bold = new Font("Tahoma", 8f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var mono = new Font("Consolas", 7.5f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var ruleP = new Pen(RuleC, 0.5f);
        using var ink = new SolidBrush(Muted);
        float y = 52;
        Str(g, first ? "Remediation plan" : "Remediation plan, continued", h2, Ink, 42, y);
        y += 20;
        if (first)
        {
            g.DrawString(plan.Summary(), body, ink, new RectangleF(42, y, 511, 24));
            y += 26;
        }
        using (var head = new SolidBrush(Theme.Hex(0x34383D))) g.FillRectangle(head, 42, y, 511, 13);
        float[] xs = { 46, 64, 118, 176, 440 };
        string[] heads = { "#", "Priority", "Target", "Issue and action", "Affected" };
        for (int i = 0; i < xs.Length; i++) Str(g, heads[i], bold, Color.White, xs[i], y + 2, 90);
        y += 15;
        if (items.Count == 0)
        {
            Str(g, "Nothing to plan: no open findings.", body, Muted, 46, y + 2);
            return;
        }
        foreach (var item in items)
        {
            Str(g, item.Rank.ToString(), mono, Muted, xs[0], y + 3, 16);
            Str(g, item.TierText, bold, TierInk(item.Tier), xs[1], y + 2, 52);
            Str(g, $"{item.Score:0}/100", mono, Muted, xs[1], y + 13, 52);
            Str(g, item.DueText, mono, item.Overdue ? Blood : Ink, xs[2], y + 3, 56);
            if (item.Overdue) Str(g, "overdue", bold, Blood, xs[2], y + 13, 56);
            else if (item.Kev) Str(g, "CISA KEV", bold, Blood, xs[2], y + 13, 56);
            Str(g, item.Title, bold, Ink, xs[3], y + 2, 260);
            Str(g, item.Action.Replace('\n', ' '), body, Muted, xs[3], y + 13, 260);
            Str(g, item.AffectedText, mono, Ink, xs[4], y + 3, 112);
            if (item.Endpoints.Count > 1) Str(g, string.Join(", ", item.Hosts), mono, Muted, xs[4], y + 13, 112);
            y += 26;
            g.DrawLine(ruleP, 42, y, 553, y);
            y += 1;
        }
    }

    private void PaintFindingsPage(Graphics g, string title, List<Finding> findings, bool first, int n, int total)
    {
        PageFrame(g, title, n, total);
        using var h2 = new Font("Georgia", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var body = new Font("Tahoma", 8f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var bold = new Font("Tahoma", 8f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var mono = new Font("Consolas", 7.5f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var ruleP = new Pen(RuleC, 0.5f);
        float y = 52;
        Str(g, first ? "Findings register" : "Findings register, continued", h2, Ink, 42, y);
        y += 20;
        using (var head = new SolidBrush(Theme.Hex(0x34383D))) g.FillRectangle(head, 42, y, 511, 13);
        float[] xs = { 46, 94, 340, 420, 470, 514 };
        string[] heads = { "Severity", "Title", "Host", "Port", "CWE", "Status" };
        for (int i = 0; i < xs.Length; i++) Str(g, heads[i], bold, Color.White, xs[i], y + 2, 90);
        y += 15;
        if (findings.Count == 0)
        {
            Str(g, "No findings recorded.", body, Muted, 46, y + 2);
            return;
        }
        foreach (var f in findings)
        {
            Str(g, f.Severity.ToString(), bold, Theme.Shift(Theme.SeverityColor(f.Severity), -46), xs[0], y + 2, 46);
            Str(g, f.Title, body, Ink, xs[1], y + 2, 242);
            Str(g, f.Host, mono, Ink, xs[2], y + 3, 78);
            Str(g, f.Port.ToString(), mono, Ink, xs[3], y + 3, 46);
            Str(g, f.CweText, mono, Ink, xs[4], y + 3, 42);
            Str(g, f.StatusText, body, Muted, xs[5], y + 2, 40);
            y += 15;
            if (_options.Evidence)
            {
                var evidence = f.Evidence.Split('\n');
                Str(g, evidence[0], mono, Muted, xs[1], y, 400);
                if (evidence.Length > 1) Str(g, evidence[^1], mono, Muted, xs[1], y + 11, 400);
                y += 24;
            }
            g.DrawLine(ruleP, 42, y, 553, y);
            y += 1;
        }
    }

    private void PaintHostsPage(Graphics g, string title, List<HostRecord> hosts, bool first, int n, int total)
    {
        PageFrame(g, title, n, total);
        using var h2 = new Font("Georgia", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var body = new Font("Tahoma", 8f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var bold = new Font("Tahoma", 8f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var mono = new Font("Consolas", 7.5f, FontStyle.Regular, GraphicsUnit.Pixel);
        using var ruleP = new Pen(RuleC, 0.5f);
        float y = 52;
        Str(g, first ? "Host inventory" : "Host inventory, continued", h2, Ink, 42, y);
        y += 20;
        using (var head = new SolidBrush(Theme.Hex(0x34383D))) g.FillRectangle(head, 42, y, 511, 13);
        float[] xs = { 46, 130, 250, 395, 450 };
        string[] heads = { "Address", "Hostname", "OS guess", "Open ports", "Role" };
        for (int i = 0; i < xs.Length; i++) Str(g, heads[i], bold, Color.White, xs[i], y + 2, 100);
        y += 15;
        if (hosts.Count == 0) Str(g, "No hosts recorded.", body, Muted, 46, y + 2);
        foreach (var h in hosts)
        {
            Str(g, h.Ip, mono, Ink, xs[0], y + 3, 82);
            Str(g, h.Hostname, body, Ink, xs[1], y + 2, 118);
            Str(g, h.OsGuess, body, Ink, xs[2], y + 2, 142);
            Str(g, h.OpenPorts.ToString(), mono, Ink, xs[3], y + 3, 50);
            Str(g, h.Role, body, Muted, xs[4], y + 2, 102);
            y += 15;
            g.DrawLine(ruleP, 42, y, 553, y);
            y += 1;
        }
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        base.OnMouseWheel(e);
        if ((ModifierKeys & Keys.Control) != 0)
        {
            Zoom += e.Delta > 0 ? 0.1 : -0.1;
            return;
        }
        _v.Value -= e.Delta / 120 * Px(48);
    }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
    }

    protected override bool IsInputKey(Keys keyData) => keyData is Keys.PageUp or Keys.PageDown or Keys.Up or Keys.Down || base.IsInputKey(keyData);

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        switch (e.KeyCode)
        {
            case Keys.PageUp: GoTo(_page - 1); break;
            case Keys.PageDown: GoTo(_page + 1); break;
            case Keys.Up: _v.Value -= Px(48); break;
            case Keys.Down: _v.Value += Px(48); break;
        }
    }
}

internal sealed class ReportsView : ModuleView
{
    public static string[] TemplateNames => ReportScope.TemplateNames;

    private readonly SkinList _templates = new();
    private readonly EtchedGroup _templateGroup = new("Preview Template");
    private readonly EtchedGroup _optionsGroup = new("Preview Sections");
    private readonly EtchedGroup _outputGroup = new("Output") { LabelWidth = 50 };
    private readonly SkinCheck _cover = new("Cover details", true);
    private readonly SkinCheck _severity = new("Severity chart", true);
    private readonly SkinCheck _findings = new("Findings register");
    private readonly SkinCheck _evidence = new("Evidence excerpts");
    private readonly SkinCheck _hosts = new("Host inventory");
    private readonly SkinCombo _format = new();
    private readonly SkinButton _generate = new("Generate", IconId.Report, ButtonLook.Oxblood);
    private readonly SkinButton _export = new("Export...", IconId.Export);
    private readonly ReportOptions _options = new();
    private readonly ReportPreview _preview;
    private readonly SkinButton _prev = new(string.Empty, IconId.Prev);
    private readonly SkinButton _next = new(string.Empty, IconId.Next);
    private readonly SkinButton _zoomOut = new(string.Empty, IconId.ZoomOut);
    private readonly SkinButton _zoomIn = new(string.Empty, IconId.ZoomIn);
    private readonly SkinCombo _zoom = new();
    private readonly SkinPanel _rightPanel = new();
    private readonly SkinPanel _leftPanel = new();
    private readonly SplitBox _split;
    private int _lastFindings = -1;
    private int _lastHosts = -1;
    private int _lastMutation = -1;

    public ReportsView(IShell shell) : base(shell)
    {
        _templates.SetItems(TemplateNames.Select(t => new ListRow(t, IconId.Report)).ToList());
        _templates.SelectedIndex = 0;
        _templates.SelectionChanged += (_, _) => ApplyTemplate();
        _templateGroup.SetFill(_templates);

        _optionsGroup.Add(null, _cover, height: 17);
        _optionsGroup.Add(null, _severity, height: 17);
        _optionsGroup.Add(null, _findings, height: 17);
        _optionsGroup.Add(null, _evidence, height: 17);
        _optionsGroup.Add(null, _hosts, height: 17);
        foreach (var c in new[] { _cover, _severity, _findings, _evidence, _hosts })
            c.CheckedChanged += (_, _) => OptionsChanged();

        _format.AddRange("HTML report", "CSV findings", "PDF report", "Markdown report", "JSON findings", "SARIF 2.1.0");
        _format.SelectedIndex = 0;
        _outputGroup.Add("Format", _format);

        _generate.Click += (_, _) =>
        {
            _preview!.Rebuild();
            Shell.LogUser("report", $"Report view refreshed: {TemplateNames[_options.Template]}");
            UpdatePageLabel();
        };
        // Export what the preview shows: same template, same sections.
        _export.Click += (_, _) => Shell.ExportReport(SelectedFormat, _options.ToScope());

        _leftPanel.Controls.AddRange(new Control[] { _templateGroup, _optionsGroup, _outputGroup, _generate, _export });
        _leftPanel.Layout += (_, _) => LayoutLeft();

        _preview = new ReportPreview(Session, _options);
        _preview.PageChanged += (_, _) => UpdatePageLabel();
        _prev.Click += (_, _) => _preview.GoTo(_preview.Page - 1);
        _next.Click += (_, _) => _preview.GoTo(_preview.Page + 1);
        _zoom.AddRange("50%", "75%", "100%", "125%", "150%");
        _zoom.SelectedIndex = 2;
        _zoom.SelectionChanged += (_, _) => _preview.Zoom = int.Parse(_zoom.Value.TrimEnd('%')) / 100.0;
        _zoomOut.Click += (_, _) => { if (_zoom.SelectedIndex > 0) _zoom.SelectedIndex--; };
        _zoomIn.Click += (_, _) => { if (_zoom.SelectedIndex < _zoom.Items.Count - 1) _zoom.SelectedIndex++; };
        _rightPanel.Controls.AddRange(new Control[] { _prev, _next, _zoomOut, _zoom, _zoomIn, _preview });
        _rightPanel.Layout += (_, _) => LayoutRight();
        _rightPanel.Paint += (_, e) =>
        {
            var r = new Rectangle(0, 0, _rightPanel.Width, Px(27));
            Draw.Gradient(e.Graphics, r, Theme.Hex(0x34383D), Theme.Hex(0x25282C));
            Draw.Frame(e.Graphics, r, Theme.BorderDark);
            e.Graphics.DrawLine(Draw.Pen(Theme.Highlight), 1, 1, r.Width - 2, 1);
            Draw.Engraved(e.Graphics, $"Page {_preview.Page + 1} of {Math.Max(1, _preview.PageCount)}", UiFont, new Rectangle(Px(64), 0, Px(120), r.Height), Theme.Text);
        };

        _split = new SplitBox(true, _leftPanel, _rightPanel, 208) { MinFirst = 180, MinSecond = 360 };
        Controls.Add(_split);
        UpdatePageLabel();
    }

    internal ExportFormat SelectedFormat => _format.SelectedIndex switch
    {
        1 => ExportFormat.Csv,
        2 => ExportFormat.Pdf,
        3 => ExportFormat.Markdown,
        4 => ExportFormat.Json,
        5 => ExportFormat.Sarif,
        _ => ExportFormat.Html,
    };

    internal ReportScope Scope => _options.ToScope();

    public override string Title => "Reports";
    public override IconId IconKind => IconId.Reports;
    public override string Subtitle => $"{TemplateNames[_options.Template]}  |  {Session.FindingCount} findings, {Session.Hosts.Items.Count} hosts";

    private void LayoutLeft()
    {
        int w = _leftPanel.Width, h = _leftPanel.Height;
        int gap = Px(5);
        int optH = Px(_optionsGroup.PreferredLogicalHeight);
        int outH = Px(_outputGroup.PreferredLogicalHeight);
        int btnH = Px(24);
        int tplH = Math.Max(Px(70), h - optH - outH - btnH - gap * 3);
        _templateGroup.SetBounds(0, 0, w, tplH);
        _optionsGroup.SetBounds(0, tplH + gap, w, optH);
        _outputGroup.SetBounds(0, tplH + gap + optH + gap, w, outH);
        int half = (w - Px(4)) / 2;
        _generate.SetBounds(0, h - btnH, half, btnH);
        _export.SetBounds(half + Px(4), h - btnH, w - half - Px(4), btnH);
    }

    private void LayoutRight()
    {
        int y = Px(3), h = Px(21), s = Px(25);
        _prev.SetBounds(Px(4), y, s, h);
        _next.SetBounds(Px(4) + s + Px(2), y, s, h);
        int x = _rightPanel.Width - Px(4) - s;
        _zoomIn.SetBounds(x, y, s, h);
        x -= Px(68);
        _zoom.SetBounds(x, y, Px(66), h);
        x -= s + Px(2);
        _zoomOut.SetBounds(x, y, s, h);
        _preview.SetBounds(0, Px(29), _rightPanel.Width, Math.Max(0, _rightPanel.Height - Px(29)));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    private void ApplyTemplate()
    {
        var preset = ReportScope.For((ReportTemplate)Math.Clamp(_templates.SelectedIndex, 0, TemplateNames.Length - 1));
        _cover.Checked = preset.Cover;
        _severity.Checked = preset.Severity;
        _findings.Checked = preset.Findings;
        _evidence.Checked = preset.Evidence;
        _hosts.Checked = preset.Hosts;
        OptionsChanged();
    }

    private void OptionsChanged()
    {
        _options.Template = Math.Max(0, _templates.SelectedIndex);
        _options.Cover = _cover.Checked;
        _options.Severity = _severity.Checked;
        _options.Findings = _findings.Checked;
        _options.Evidence = _evidence.Checked;
        _options.Hosts = _hosts.Checked;
        _preview.Rebuild();
        UpdatePageLabel();
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }

    private void UpdatePageLabel()
    {
        _rightPanel.Invalidate(new Rectangle(0, 0, _rightPanel.Width, Px(28)));
    }

    public override void SyncData()
    {
        _options.Footer = Shell.Settings.ReportAuthorLine;
        // Status and importance edits reorder the plan without changing any count, so watch the mutation version too.
        if (_lastFindings != Session.FindingCount || _lastHosts != Session.Hosts.Items.Count || _lastMutation != Session.Findings.MutationVersion)
        {
            _lastFindings = Session.FindingCount;
            _lastHosts = Session.Hosts.Items.Count;
            _lastMutation = Session.Findings.MutationVersion;
            _preview.Rebuild();
            UpdatePageLabel();
        }
    }
}
