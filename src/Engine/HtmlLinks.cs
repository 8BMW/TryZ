using System.Net;
using System.Text.RegularExpressions;
using System.Xml;

namespace TryZ.Engine;

/// <summary>One HTML form as seen by the crawler's passive checks.</summary>
internal sealed class HtmlForm
{
    public string Action { get; init; } = string.Empty;
    public string Method { get; init; } = "get";
    public bool HasPassword { get; init; }
    /// <summary>True when at least one password input does not disable autocomplete (form- or field-level).</summary>
    public bool PasswordAutocomplete { get; init; }
    /// <summary>True when a hidden input with a name that looks like an anti-CSRF token is present.</summary>
    public bool HasCsrfToken { get; init; }
    /// <summary>Submittable fields (input/textarea/select) as name → default value, excluding file and submit inputs.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Fields { get; init; } = Array.Empty<KeyValuePair<string, string>>();
}

/// <summary>A tag reference the crawler cares about for mixed-content checks.</summary>
internal readonly record struct ActiveRef(string Tag, string Url);

/// <summary>
/// Dependency-free link, form and sitemap extraction. Regex based tokenizer tuned for real-world, often malformed HTML:
/// attribute values may be double, single or un-quoted, entities are decoded, and script/style bodies are scanned separately.
/// </summary>
internal static partial class HtmlLinks
{
    private const RegexOptions Opts = RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;

    [GeneratedRegex(@"<(?<tag>[a-zA-Z][a-zA-Z0-9:\-]*)(?<attrs>(?:\s+[^\s""'>/=]+(?:\s*=\s*(?:""[^""]*""|'[^']*'|[^\s>]+))?)*)\s*/?>", Opts, 2000)]
    private static partial Regex TagRegex();

    [GeneratedRegex(@"(?<name>[^\s""'>/=]+)(?:\s*=\s*(?:""(?<v>[^""]*)""|'(?<v>[^']*)'|(?<v>[^\s>]+)))?", Opts, 2000)]
    private static partial Regex AttrRegex();

    [GeneratedRegex(@"<script\b[^>]*>(?<body>.*?)</script\s*>", Opts | RegexOptions.Singleline, 2000)]
    private static partial Regex ScriptBlockRegex();

    [GeneratedRegex(@"<style\b[^>]*>(?<body>.*?)</style\s*>", Opts | RegexOptions.Singleline, 2000)]
    private static partial Regex StyleBlockRegex();

    [GeneratedRegex(@"<form\b(?<attrs>[^>]*)>(?<body>.*?)(?:</form\s*>|(?=<form\b)|$)", Opts | RegexOptions.Singleline, 2000)]
    private static partial Regex FormRegex();

    [GeneratedRegex(@"<input\b(?<attrs>[^>]*)>", Opts, 2000)]
    private static partial Regex InputRegex();

    [GeneratedRegex(@"<textarea\b(?<attrs>[^>]*)>", Opts, 2000)]
    private static partial Regex TextAreaRegex();

    [GeneratedRegex(@"<select\b(?<attrs>[^>]*)>", Opts, 2000)]
    private static partial Regex SelectRegex();

    /// <summary>String literals in JS that look like site paths: start with a single '/', no whitespace or quotes inside.</summary>
    [GeneratedRegex(@"(?<q>[""'`])(?<p>/(?!/)[A-Za-z0-9_\-.~%!$&+,;=:@/]*[A-Za-z0-9_\-~%/](?:\?[A-Za-z0-9_\-.~%!$&+,;=:@/?]*)?)\k<q>", RegexOptions.CultureInvariant, 2000)]
    private static partial Regex JsPathRegex();

    [GeneratedRegex(@"url\(\s*(?:""(?<u>[^""]+)""|'(?<u>[^']+)'|(?<u>[^'"")\s]+))\s*\)", Opts, 2000)]
    private static partial Regex CssUrlRegex();

    [GeneratedRegex(@"^\s*\d*(?:\.\d+)?\s*[;,]?\s*url\s*=\s*['""]?(?<u>[^'""]+)", Opts)]
    private static partial Regex MetaRefreshRegex();

    private static readonly HashSet<string> UrlAttributes = new(StringComparer.OrdinalIgnoreCase)
    {
        "href", "src", "action", "data-src", "data-href", "data-url", "formaction", "poster", "background", "cite", "longdesc", "manifest", "codebase", "data",
    };

    private static readonly HashSet<string> SkipTags = new(StringComparer.OrdinalIgnoreCase) { "!doctype" };

    // ---------------------------------------------------------------- attributes

    public static Dictionary<string, string> ParseAttributes(string attrs)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in AttrRegex().Matches(attrs))
        {
            string name = m.Groups["name"].Value;
            if (map.ContainsKey(name)) continue; // first occurrence wins, like browsers
            map[name] = m.Groups["v"].Success ? WebUtility.HtmlDecode(m.Groups["v"].Value) : string.Empty;
        }
        return map;
    }

    // ---------------------------------------------------------------- links

    /// <summary>
    /// Extracts raw link strings from an HTML document. <paramref name="baseHref"/> receives the document's &lt;base href&gt; if any.
    /// <paramref name="active"/> receives script/iframe/embed/object/link-stylesheet references for mixed-content checks.
    /// </summary>
    public static List<string> FromHtml(string html, out string? baseHref, List<ActiveRef>? active)
    {
        var links = new List<string>();
        baseHref = null;
        foreach (Match m in TagRegex().Matches(html))
        {
            string tag = m.Groups["tag"].Value;
            if (SkipTags.Contains(tag)) continue;
            string attrText = m.Groups["attrs"].Value;
            if (attrText.Length == 0) continue;
            var attrs = ParseAttributes(attrText);

            foreach (var (name, value) in attrs)
            {
                if (value.Length == 0) continue;
                if (UrlAttributes.Contains(name))
                {
                    if (name.Equals("data", StringComparison.OrdinalIgnoreCase) && !tag.Equals("object", StringComparison.OrdinalIgnoreCase)) continue;
                    links.Add(value);
                }
                else if (name.Equals("srcset", StringComparison.OrdinalIgnoreCase) || name.Equals("data-srcset", StringComparison.OrdinalIgnoreCase)
                    || name.Equals("imagesrcset", StringComparison.OrdinalIgnoreCase))
                {
                    links.AddRange(ParseSrcset(value));
                }
                else if (name.Equals("style", StringComparison.OrdinalIgnoreCase))
                {
                    links.AddRange(FromCss(value));
                }
            }

            if (tag.Equals("base", StringComparison.OrdinalIgnoreCase) && baseHref == null && attrs.TryGetValue("href", out var b) && b.Length > 0)
                baseHref = b.Trim();

            if (tag.Equals("meta", StringComparison.OrdinalIgnoreCase)
                && attrs.TryGetValue("http-equiv", out var equiv) && equiv.Trim().Equals("refresh", StringComparison.OrdinalIgnoreCase)
                && attrs.TryGetValue("content", out var content))
            {
                var r = MetaRefreshRegex().Match(content);
                if (r.Success) links.Add(r.Groups["u"].Value.Trim());
            }

            if (active != null)
            {
                string? url = null;
                if (tag.Equals("script", StringComparison.OrdinalIgnoreCase) || tag.Equals("iframe", StringComparison.OrdinalIgnoreCase)
                    || tag.Equals("frame", StringComparison.OrdinalIgnoreCase) || tag.Equals("embed", StringComparison.OrdinalIgnoreCase))
                    attrs.TryGetValue("src", out url);
                else if (tag.Equals("object", StringComparison.OrdinalIgnoreCase))
                    attrs.TryGetValue("data", out url);
                else if (tag.Equals("link", StringComparison.OrdinalIgnoreCase)
                    && attrs.TryGetValue("rel", out var rel) && rel.Contains("stylesheet", StringComparison.OrdinalIgnoreCase))
                    attrs.TryGetValue("href", out url);
                if (!string.IsNullOrWhiteSpace(url)) active.Add(new ActiveRef(tag.ToLowerInvariant(), url.Trim()));
            }
        }

        foreach (Match s in ScriptBlockRegex().Matches(html))
            links.AddRange(FromScript(s.Groups["body"].Value));
        foreach (Match s in StyleBlockRegex().Matches(html))
            links.AddRange(FromCss(s.Groups["body"].Value));
        return links;
    }

    /// <summary>Path-like string literals in JavaScript or JSON.</summary>
    public static IEnumerable<string> FromScript(string js)
    {
        foreach (Match m in JsPathRegex().Matches(js))
        {
            string p = m.Groups["p"].Value;
            if (p.Length < 2 || p.Length > 512) continue;
            if (!p.Any(char.IsLetter)) continue;
            // skip regex literals and comment-like fragments
            if (p.StartsWith("/*", StringComparison.Ordinal)) continue;
            yield return p;
        }
    }

    public static IEnumerable<string> FromCss(string css)
    {
        foreach (Match m in CssUrlRegex().Matches(css))
        {
            string u = m.Groups["u"].Value.Trim();
            if (!u.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) yield return u;
        }
    }

    public static IEnumerable<string> ParseSrcset(string srcset)
    {
        foreach (var part in srcset.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            int sp = part.IndexOfAny(new[] { ' ', '\t', '\n', '\r' });
            string url = sp > 0 ? part[..sp] : part;
            if (url.Length > 0 && !url.StartsWith("data:", StringComparison.OrdinalIgnoreCase)) yield return url;
        }
    }

    // ---------------------------------------------------------------- forms

    public static List<HtmlForm> Forms(string html)
    {
        var forms = new List<HtmlForm>();
        foreach (Match f in FormRegex().Matches(html))
        {
            var fa = ParseAttributes(f.Groups["attrs"].Value);
            bool formAcOff = fa.TryGetValue("autocomplete", out var fac) && IsAutocompleteOff(fac);
            bool hasPassword = false, passwordAc = false, token = false;
            var fields = new List<KeyValuePair<string, string>>();
            foreach (Match i in InputRegex().Matches(f.Groups["body"].Value))
            {
                var ia = ParseAttributes(i.Groups["attrs"].Value);
                string type = ia.TryGetValue("type", out var t) ? t.Trim().ToLowerInvariant() : "text";
                ia.TryGetValue("name", out var fname);
                ia.TryGetValue("value", out var fval);
                if (type == "password")
                {
                    hasPassword = true;
                    bool off = ia.TryGetValue("autocomplete", out var iac) ? IsAutocompleteOff(iac) : formAcOff;
                    if (!off) passwordAc = true;
                }
                else if (type == "hidden" && fname != null && LooksLikeCsrfName(fname) && fval is { Length: >= 8 })
                {
                    token = true;
                }
                // Collect submittable fields for active fuzzing; skip valueless submit/button/file/image inputs.
                if (!string.IsNullOrEmpty(fname) && type is not ("submit" or "button" or "reset" or "file" or "image"))
                    fields.Add(new(fname!, fval ?? string.Empty));
            }
            // <textarea name=...> and <select name=...> are submittable too.
            foreach (Match ta in TextAreaRegex().Matches(f.Groups["body"].Value))
                if (ParseAttributes(ta.Groups["attrs"].Value).TryGetValue("name", out var tn) && tn.Length > 0)
                    fields.Add(new(tn, string.Empty));
            foreach (Match se in SelectRegex().Matches(f.Groups["body"].Value))
                if (ParseAttributes(se.Groups["attrs"].Value).TryGetValue("name", out var sn) && sn.Length > 0)
                    fields.Add(new(sn, string.Empty));
            forms.Add(new HtmlForm
            {
                Action = fa.TryGetValue("action", out var a) ? a.Trim() : string.Empty,
                Method = fa.TryGetValue("method", out var meth) && meth.Trim().Length > 0 ? meth.Trim().ToLowerInvariant() : "get",
                HasPassword = hasPassword,
                PasswordAutocomplete = passwordAc,
                HasCsrfToken = token,
                Fields = fields,
            });
        }
        return forms;
    }

    private static bool IsAutocompleteOff(string v)
    {
        v = v.Trim().ToLowerInvariant();
        return v is "off" or "new-password" or "false";
    }

    private static bool LooksLikeCsrfName(string name)
    {
        string n = name.ToLowerInvariant();
        return n.Contains("csrf") || n.Contains("xsrf") || n.Contains("token") || n.Contains("nonce") || n.Contains("authenticity")
            || n is "__requestverificationtoken" or "_wpnonce" or "form_key" or "__viewstategenerator" or "__eventvalidation";
    }

    // ---------------------------------------------------------------- robots / sitemap

    /// <summary>Parses robots.txt: Disallow/Allow rules for "User-agent: *" and every Sitemap: line.</summary>
    public static (List<string> Disallow, List<string> Allow, List<string> Sitemaps) ParseRobots(string text)
    {
        var disallow = new List<string>();
        var allow = new List<string>();
        var sitemaps = new List<string>();
        bool inStar = false, lastWasAgent = false;
        foreach (var raw in text.Split('\n'))
        {
            string line = raw;
            int hash = line.IndexOf('#');
            if (hash >= 0) line = line[..hash];
            line = line.Trim();
            if (line.Length == 0) continue;
            int colon = line.IndexOf(':');
            if (colon <= 0) continue;
            string key = line[..colon].Trim().ToLowerInvariant();
            string value = line[(colon + 1)..].Trim();
            switch (key)
            {
                case "user-agent":
                    bool star = value == "*";
                    inStar = lastWasAgent ? inStar || star : star;
                    lastWasAgent = true;
                    continue;
                case "disallow":
                    if (inStar && value.Length > 0) disallow.Add(value);
                    break;
                case "allow":
                    if (inStar && value.Length > 0) allow.Add(value);
                    break;
                case "sitemap":
                    if (value.Length > 0) sitemaps.Add(value);
                    break;
            }
            lastWasAgent = false;
        }
        return (disallow, allow, sitemaps);
    }

    /// <summary>Robots rule match supporting '*' wildcards and '$' end anchors (Google/RFC 9309 semantics).</summary>
    public static bool RobotsMatch(string rule, string pathAndQuery)
    {
        bool anchored = rule.EndsWith('$');
        if (anchored) rule = rule[..^1];
        if (!rule.Contains('*'))
            return anchored ? pathAndQuery == rule : pathAndQuery.StartsWith(rule, StringComparison.Ordinal);
        string pattern = "^" + Regex.Escape(rule).Replace(@"\*", ".*") + (anchored ? "$" : string.Empty);
        try
        {
            return Regex.IsMatch(pathAndQuery, pattern, RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(50));
        }
        catch (RegexMatchTimeoutException)
        {
            return false;
        }
    }

    /// <summary>Parses a sitemap (urlset or sitemapindex). DTDs are prohibited; malformed XML yields what was read so far.</summary>
    public static (List<string> Pages, List<string> Indexes) ParseSitemap(string xml, int max)
    {
        var pages = new List<string>();
        var indexes = new List<string>();
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null,
            IgnoreComments = true,
            IgnoreWhitespace = true,
            MaxCharactersInDocument = 20_000_000,
        };
        try
        {
            using var sr = new StringReader(xml);
            using var reader = XmlReader.Create(sr, settings);
            bool inSitemap = false;
            while (reader.Read() && pages.Count + indexes.Count < max)
            {
                if (reader.NodeType == XmlNodeType.Element)
                {
                    if (reader.LocalName.Equals("sitemap", StringComparison.OrdinalIgnoreCase)) inSitemap = true;
                    else if (reader.LocalName.Equals("url", StringComparison.OrdinalIgnoreCase)) inSitemap = false;
                    else if (reader.LocalName.Equals("loc", StringComparison.OrdinalIgnoreCase))
                    {
                        string loc = reader.ReadElementContentAsString().Trim();
                        if (loc.Length > 0) (inSitemap ? indexes : pages).Add(loc);
                    }
                }
                else if (reader.NodeType == XmlNodeType.EndElement && reader.LocalName.Equals("sitemap", StringComparison.OrdinalIgnoreCase))
                {
                    inSitemap = false;
                }
            }
        }
        catch (XmlException)
        {
            // keep whatever was parsed before the error
        }
        return (pages, indexes);
    }
}
