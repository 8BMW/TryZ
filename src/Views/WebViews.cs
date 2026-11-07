using TryZ.Data;

namespace TryZ.Views;

internal sealed class HttpSyntax : ISyntax
{
    private static readonly Color Method = Theme.Brass;
    private static readonly Color Version = Theme.TextDim;
    private static readonly Color HeaderName = Theme.Low;
    private static readonly Color Tag = Theme.Hex(0x8FB3D0);
    private static readonly Color Attr = Theme.Hex(0xC8A45C);
    private static readonly Color Str = Theme.Hex(0x9CBF84);
    private static readonly Color Comment = Theme.Hex(0x666C74);
    private static readonly Color Num = Theme.Hex(0xD08770);
    private static readonly Color Flag = Theme.High;
    private static readonly HashSet<string> Methods = new() { "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "TRACE", "PATCH" };

    public void Colorize(IReadOnlyList<string> lines, int index, List<CodeSpan> output)
    {
        string line = lines[index];
        if (line.Length == 0) return;

        int blank = -1;
        for (int i = 0; i <= index; i++)
            if (lines[i].Length == 0) { blank = i; break; }
        if (blank >= 0 && blank < index)
        {
            Body(line, output);
            return;
        }

        if (line.StartsWith("HTTP/", StringComparison.Ordinal)) StatusLine(line, output);
        else if (line.StartsWith("$ ", StringComparison.Ordinal)) output.Add(new CodeSpan(0, line.Length, Theme.Brass));
        else if (RequestLine(line, output)) { }
        else Header(line, output);
    }

    private static void StatusLine(string line, List<CodeSpan> output)
    {
        int sp = line.IndexOf(' ');
        if (sp < 0) { output.Add(new CodeSpan(0, line.Length, Version)); return; }
        output.Add(new CodeSpan(0, sp, Version));
        int sp2 = line.IndexOf(' ', sp + 1);
        int end = sp2 < 0 ? line.Length : sp2;
        var color = Theme.Text;
        if (int.TryParse(line.AsSpan(sp + 1, end - sp - 1), out int code)) color = Schemas.StatusColor(code);
        output.Add(new CodeSpan(sp + 1, line.Length - sp - 1, color));
    }

    private static bool RequestLine(string line, List<CodeSpan> output)
    {
        int sp = line.IndexOf(' ');
        if (sp <= 0 || !Methods.Contains(line[..sp])) return false;
        output.Add(new CodeSpan(0, sp, Method));
        int ver = line.LastIndexOf(" HTTP/", StringComparison.Ordinal);
        if (ver > sp) output.Add(new CodeSpan(ver + 1, line.Length - ver - 1, Version));
        return true;
    }

    private static void Header(string line, List<CodeSpan> output)
    {
        int colon = line.IndexOf(':');
        if (colon <= 0) return;
        output.Add(new CodeSpan(0, colon + 1, HeaderName));
        if (line.StartsWith("Set-Cookie", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var attr in new[] { "Secure", "HttpOnly" })
            {
                int at = line.IndexOf(attr, colon, StringComparison.OrdinalIgnoreCase);
                if (at > 0)
                {
                    output.Add(new CodeSpan(at, attr.Length, Flag));
                }
            }
            output.Sort((a, b) => a.Start.CompareTo(b.Start));
        }
    }

    private static void Body(string line, List<CodeSpan> output)
    {
        int i = 0;
        string trimmed = line.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('"') || trimmed.StartsWith('}'))
        {
            Json(line, output);
            return;
        }
        while (i < line.Length)
        {
            if (line[i] != '<') { i++; continue; }
            if (i + 3 < line.Length && line.AsSpan(i).StartsWith("<!--"))
            {
                int close = line.IndexOf("-->", i, StringComparison.Ordinal);
                int stop = close < 0 ? line.Length : close + 3;
                output.Add(new CodeSpan(i, stop - i, Comment));
                i = stop;
                continue;
            }
            int end = line.IndexOf('>', i);
            if (end < 0) end = line.Length - 1;
            Tagged(line, i, end, output);
            i = end + 1;
        }
    }

    private static void Tagged(string line, int start, int end, List<CodeSpan> output)
    {
        int i = start + 1;
        while (i <= end && !char.IsWhiteSpace(line[i]) && line[i] != '>') i++;
        output.Add(new CodeSpan(start, i - start, Tag));
        while (i <= end)
        {
            if (line[i] == '"')
            {
                int q = line.IndexOf('"', i + 1);
                if (q < 0 || q > end) q = end;
                output.Add(new CodeSpan(i, q - i + 1, Str));
                i = q + 1;
            }
            else if (line[i] == '>' || line[i] == '/')
            {
                output.Add(new CodeSpan(i, 1, Tag));
                i++;
            }
            else if (char.IsLetter(line[i]))
            {
                int s = i;
                while (i <= end && (char.IsLetterOrDigit(line[i]) || line[i] is '-' or '_')) i++;
                output.Add(new CodeSpan(s, i - s, Attr));
            }
            else
            {
                i++;
            }
        }
    }

    private static void Json(string line, List<CodeSpan> output)
    {
        int i = 0;
        while (i < line.Length)
        {
            char c = line[i];
            if (c == '"')
            {
                int q = line.IndexOf('"', i + 1);
                if (q < 0) q = line.Length - 1;
                bool key = q + 1 < line.Length && line[q + 1] == ':';
                output.Add(new CodeSpan(i, q - i + 1, key ? HeaderName : Str));
                i = q + 1;
            }
            else if (char.IsDigit(c))
            {
                int s = i;
                while (i < line.Length && char.IsDigit(line[i])) i++;
                output.Add(new CodeSpan(s, i - s, Num));
            }
            else
            {
                i++;
            }
        }
    }
}

internal sealed class CrawlerView : ModuleView
{
    private readonly SkinTree _tree = new() { ShowCounts = true, EmptyText = "No sites crawled yet." };
    private readonly GridView _grid = new() { EmptyText = "No URLs recorded yet." };
    private readonly RowSet<UrlRecord> _rows;
    private readonly Dictionary<string, TreeItem> _nodes = new();
    private readonly SkinPanel _right = new();
    private readonly SkinLabel _scopeLabel = new("Status") { TextColor = Theme.TextDim };
    private readonly SkinCombo _statusFilter = new();
    private readonly SkinCombo _typeFilter = new();
    private readonly SkinLabel _typeLabel = new("Type") { TextColor = Theme.TextDim };
    private readonly SkinLabel _count = new() { TextColor = Theme.TextDim, Alignment = TextFormatFlags.Right, Mono = false };
    private readonly SkinButton _send = new("Send to Workbench", IconId.Workbench);
    private readonly SplitBox _split;
    private int _consumed;
    private int _generation = -1;
    private string? _pathPrefix;

    public CrawlerView(IShell shell) : base(shell)
    {
        _rows = Schemas.Urls(Session.Urls);
        _grid.Source = _rows;
        _grid.RowActivated += (_, _) => SendSelected();
        _send.Click += (_, _) => SendSelected();
        _statusFilter.AddRange("All", "2xx", "3xx", "4xx", "5xx");
        _statusFilter.SelectedIndex = 0;
        _statusFilter.SelectionChanged += (_, _) => ApplyScope();
        _typeFilter.AddRange("All", "text/html", "text/css", "text/plain", "application/json", "application/javascript", "application/xml", "image");
        _typeFilter.SelectedIndex = 0;
        _typeFilter.SelectionChanged += (_, _) => ApplyScope();
        _right.Controls.AddRange(new Control[] { _scopeLabel, _statusFilter, _typeLabel, _typeFilter, _count, _send, _grid });
        _right.Layout += (_, _) => LayoutRight();
        _tree.SelectionChanged += (_, _) =>
        {
            _pathPrefix = _tree.SelectedItem?.Tag as string;
            ApplyScope();
        };
        _split = new SplitBox(true, _tree, _right, 218) { MinFirst = 140, MinSecond = 380 };
        Controls.Add(_split);
    }

    public override string Title => "Web Crawler";
    public override IconId IconKind => IconId.Crawler;
    public override string Subtitle => $"{Session.Urls.Items.Count:N0} URLs across {_tree.Roots.Count} sites";

    private void LayoutRight()
    {
        int h = Px(20);
        _scopeLabel.SetBounds(0, Px(1), Px(36), h);
        _statusFilter.SetBounds(Px(38), Px(1), Px(66), h);
        _typeLabel.SetBounds(Px(112), Px(1), Px(28), h);
        _typeFilter.SetBounds(Px(142), Px(1), Px(140), h);
        int sendW = Px(122);
        _send.SetBounds(_right.Width - sendW, 0, sendW, Px(22));
        _count.SetBounds(Px(288), Px(1), Math.Max(0, _right.Width - sendW - Px(294)), h);
        _grid.SetBounds(0, Px(26), _right.Width, Math.Max(0, _right.Height - Px(26)));
    }

    protected override void OnLayout(LayoutEventArgs e)
    {
        base.OnLayout(e);
        var b = Body;
        _split.SetBounds(b.X, b.Y, b.Width, b.Height);
    }

    private void SendSelected()
    {
        if (_grid.SelectedItem is UrlRecord u) Shell.OpenInWorkbench("GET", u.Url);
        else Shell.Notify("Workbench", "Select a URL first.");
    }

    private void ApplyScope()
    {
        string? prefix = _pathPrefix;
        int band = _statusFilter.SelectedIndex;
        string? type = _typeFilter.SelectedIndex > 0 ? _typeFilter.Value : null;
        _rows.SetScope(prefix == null && band == 0 && type == null ? null : u =>
            (prefix == null || u.Url.StartsWith(prefix, StringComparison.Ordinal))
            && (band == 0 || u.Status / 100 == band + 1)
            && (type == null || u.ContentType.StartsWith(type, StringComparison.OrdinalIgnoreCase)));
        _grid.Sync();
    }

    /// <summary>"scheme://authority" of a crawled URL, used as the site node and as the scope prefix.</summary>
    private static string RootOf(UrlRecord u)
    {
        if (Uri.TryCreate(u.Url, UriKind.Absolute, out var uri)) return $"{uri.Scheme}://{uri.Authority}";
        return "http://" + u.Host;
    }

    private TreeItem Node(string key, string text, IconId icon, TreeItem? parent, string prefix)
    {
        if (_nodes.TryGetValue(key, out var node)) return node;
        node = new TreeItem(text, icon, prefix);
        if (parent != null) parent.Add(node);
        else _tree.Roots.Add(node);
        _nodes[key] = node;
        return node;
    }

    private void ExtendTree()
    {
        var urls = Session.Urls;
        if (_generation != urls.Generation)
        {
            _generation = urls.Generation;
            _consumed = 0;
            _nodes.Clear();
            _tree.Roots.Clear();
            _tree.SelectedItem = null;
            _tree.Rebuild();
        }
        if (_consumed == urls.Items.Count) return;
        bool structural = false;
        for (; _consumed < urls.Items.Count; _consumed++)
        {
            var u = urls.Items[_consumed];
            int before = _nodes.Count;
            string root = RootOf(u);
            var site = Node(root, root, IconId.Globe, null, root + "/");
            site.Count++;
            string path = u.Path;
            int cut = path.IndexOfAny(new[] { '?', '#' });
            if (cut >= 0) path = path[..cut];
            var parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string prefix = root;
            var parent = site;
            int folders = Math.Min(2, parts.Length - 1);
            for (int i = 0; i < folders; i++)
            {
                prefix += "/" + parts[i];
                string key = root + "|" + string.Join('/', parts, 0, i + 1);
                parent = Node(key, parts[i], IconId.Folder, parent, prefix + "/");
                parent.Count++;
            }
            structural |= _nodes.Count != before;
            if (before == 0) site.Expanded = true;
        }
        foreach (var root in _tree.Roots) root.Expanded |= root.Children.Count > 0 && root.Children.Count <= 8 && _tree.Roots.IndexOf(root) == 0;
        if (structural) _tree.Rebuild();
        else _tree.Invalidate();
    }

    public override void SyncData()
    {
        ExtendTree();
        if (_rows.Sync(Session.FilterText)) _grid.Sync();
        _count.Caption = $"{_rows.Count:N0} of {Session.Urls.Items.Count:N0} shown";
        Invalidate(new Rectangle(0, 0, Width, HeaderHeight));
    }
}

