#if DEBUG
using System.Diagnostics;
using TryZ.Data;
using TryZ.Shell;
using TryZ.Views;

namespace TryZ.Capture;

/// <summary>
/// End-to-end self test (TryZ.exe --selftest). Runs a real scan of 127.0.0.1 against a local test web site on port 8080
/// and checks the window, the scan lifecycle, session files, exports and the HTTP workbench. Results go to selftest.txt.
/// </summary>
internal static class SelfTest
{
    private static readonly List<string> Report = new();
    private static int _failures;

    private static void Check(string name, bool ok, string detail = "")
    {
        if (!ok) _failures++;
        Report.Add($"{(ok ? "PASS" : "FAIL")}  {name}{(detail.Length > 0 ? "  (" + detail + ")" : string.Empty)}");
    }

    private static void Note(string text) => Report.Add($"NOTE  {text}");

    /// <summary>Counts CSV records (quoted fields may contain line breaks, e.g. multi-line evidence).</summary>
    private static int CsvRecords(string path)
    {
        if (!File.Exists(path)) return 0;
        string text = File.ReadAllText(path);
        int records = 0;
        bool quoted = false;
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] == '"') quoted = !quoted;
            else if (!quoted && text[i] == '\n') records++;
        }
        return records;
    }

    public static int Run()
    {
        // Settings live only in memory: the test never writes the user's settings file.
        var settings = new AppSettings { ShowSplash = false, ConfirmStop = false, DefaultProfile = 0, DefaultThreads = 64, LastTarget = "127.0.0.1" };
        using var form = new MainForm(settings) { PersistOnClose = false };
        form.Shown += async (_, _) =>
        {
            try
            {
                await Exercise(form);
            }
            catch (Exception ex)
            {
                Check("exception", false, ex.ToString());
            }
            File.WriteAllLines(Path.Combine(AppContext.BaseDirectory, "selftest.txt"), Report);
            form.Close();
        };
        Application.Run(form);
        return _failures == 0 ? 0 : 1;
    }

    private static async Task Pump(int ms)
    {
        var end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end)
        {
            Application.DoEvents();
            await Task.Delay(10);
        }
    }

    private static async Task PumpUntil(Func<bool> done, TimeSpan limit)
    {
        var end = DateTime.UtcNow + limit;
        while (!done() && DateTime.UtcNow < end) await Pump(50);
    }

    private static IntPtr HitAt(Form form, int x, int y) =>
        Native.SendMessage(form.Handle, Native.WM_NCHITTEST, IntPtr.Zero, (IntPtr)((y << 16) | (x & 0xFFFF)));

    private static async Task Exercise(MainForm form)
    {
        await Pump(200);
        var b = form.Bounds;
        Check("hit left edge", (int)HitAt(form, b.Left + 1, b.Top + 300) == Native.HTLEFT);
        Check("hit right edge", (int)HitAt(form, b.Right - 2, b.Top + 300) == Native.HTRIGHT);
        Check("hit bottom edge", (int)HitAt(form, b.Left + 300, b.Bottom - 2) == Native.HTBOTTOM);
        Check("hit corner", (int)HitAt(form, b.Right - 2, b.Bottom - 2) == Native.HTBOTTOMRIGHT);
        Check("hit caption", (int)HitAt(form, b.Left + 300, b.Top + 12) == Native.HTCAPTION);
        Check("hit client", (int)HitAt(form, b.Left + 400, b.Top + 200) == Native.HTCLIENT);
        Check("default size", form.Width == Theme.Scale(1240, form.DeviceDpi) && form.Height == Theme.Scale(780, form.DeviceDpi), $"{form.Size}");
        Check("minimum size", form.MinimumSize == new Size(Theme.Scale(980, form.DeviceDpi), Theme.Scale(640, form.DeviceDpi)), $"{form.MinimumSize}");

        form.WindowState = FormWindowState.Maximized;
        await Pump(300);
        var work = Screen.FromControl(form).WorkingArea;
        var clientScreen = form.RectangleToScreen(form.ClientRectangle);
        Check("maximized client equals work area", clientScreen == work, $"client {clientScreen}, work {work}");
        form.WindowState = FormWindowState.Normal;
        await Pump(300);
        Check("restored size", form.Width == b.Width && form.Height == b.Height, $"{form.Size}");

        CheckAuthorizationGate();

        using var site = TestSite.TryStartAny();
        if (site == null)
        {
            Check("test site started", false, $"ports {string.Join(", ", TestSite.CandidatePorts)} are all in use");
            return;
        }
        int sitePort = site.Port;
        Note($"test site listening on 127.0.0.1:{sitePort}");

        // ---------------------------------------------------------------- real scan of the loopback address
        var engine = form.Engine;
        form.Target.ProfileIndex = 0;
        form.BeginRun("127.0.0.1");
        await Pump(400);
        Check("running after start", engine.State == ScanState.Running, engine.State.ToString());
        form.PerformCommand("Pause");
        Check("paused", engine.State == ScanState.Paused, engine.State.ToString());
        await Pump(300);
        double at = form.Session.ElapsedSeconds;
        await Pump(700);
        Check("paused clock holds", Math.Abs(form.Session.ElapsedSeconds - at) < 0.6, $"{at:0.00} -> {form.Session.ElapsedSeconds:0.00}");
        form.StartOrResume();
        Check("resumed", engine.State == ScanState.Running, engine.State.ToString());

        for (int i = 0; i < 7; i++)
        {
            form.NavigateTo(i);
            await Pump(40);
            Check($"module {i} active", form.Modules[i].Visible);
        }

        var sw = Stopwatch.StartNew();
        await PumpUntil(() => engine.State != ScanState.Running, TimeSpan.FromSeconds(120));
        await Pump(400);
        var s = form.Session;
        Check("completes within 120 s", engine.State == ScanState.Completed, $"{engine.State} after {sw.Elapsed.TotalSeconds:0.0} s");
        Check("progress 100%", Math.Abs(s.Progress - 1) < 0.001, s.Progress.ToString("0.000"));
        Check("at least one host", s.Hosts.Items.Count >= 1, s.Hosts.Items.Count.ToString());
        var web = s.Ports.Items.FirstOrDefault(p => p.Port == sitePort && p.State == "open");
        Check($"port {sitePort} open", web != null, string.Join(", ", s.Ports.Items.Select(p => $"{p.Port}/{p.Service}")));
        Check($"port {sitePort} identified as http", web != null && web.Service.Contains("http", StringComparison.OrdinalIgnoreCase), web?.Service ?? "-");
        Check("crawler recorded at least 3 URLs", s.Urls.Items.Count >= 3, $"{s.Urls.Items.Count} URLs");
        Check("at least one finding", s.FindingCount >= 1, $"{s.FindingCount} findings: {string.Join("; ", s.Findings.Items.Take(6).Select(f => f.Title))}");
        Check("test site received requests", site.Requests > 0, site.Requests.ToString());
        Check("log has engine lines", s.Log.Items.Any(l => l.Source == "engine"), s.Log.Items.Count.ToString());
        Check("no simulation wording in log", !s.Log.Items.Any(l => l.Text.Contains("simulat", StringComparison.OrdinalIgnoreCase)));

        sw.Restart();
        var rows = Schemas.Urls(s.Urls);
        rows.Sync("docs");
        Check("URL filter", rows.Count <= s.Urls.Items.Count, $"{sw.ElapsedMilliseconds} ms, {rows.Count} rows");

        form.Target.SetFilterForCapture("127.0.0.1");
        await Pump(300);
        Check("live filter applied", form.Session.FilterText == "127.0.0.1");
        form.Target.ClearFilter();
        await Pump(300);

        await CheckWorkbench(form, sitePort);
        CheckFiles(form);

        await ExerciseControls(form);

        int clicked = 0;
        var closer = new Timer { Interval = 40 };
        closer.Tick += (_, _) =>
        {
            foreach (var open in Application.OpenForms.Cast<Form>().ToArray())
                if (open != form && open is SkinDialog) open.Close();
        };
        closer.Start();
        foreach (var item in AllItems(form.MenuBar.Items))
        {
            if (item.HasDropDownItems || !item.Enabled || SkipInMenuTest(item.Text ?? string.Empty)) continue;
            item.PerformClick();
            clicked++;
            await Pump(25);
        }
        closer.Stop();
        closer.Dispose();
        Check("all menu commands ran", clicked > 20, $"{clicked} items");

        form.BeginRun("127.0.0.1");
        await Pump(300);
        form.PerformCommand("Stop");
        Check("stopped", engine.State == ScanState.Stopped, engine.State.ToString());
        form.PerformCommand("New");
        await Pump(100);
        Check("new clears session", form.Session.Hosts.Items.Count == 0 && form.Session.Urls.Items.Count == 0 && form.Session.Log.Items.Count == 0);
        Check("idle after new", engine.State == ScanState.Idle);
    }

    /// <summary>Menu items that open modal file dialogs or start network activity are exercised separately.</summary>
    private static bool SkipInMenuTest(string text) =>
        text is "E&xit" or "&Start" or "Re&sume"
        || text.Contains("Session", StringComparison.Ordinal) && !text.Contains("Properties", StringComparison.Ordinal) && !text.StartsWith("&New", StringComparison.Ordinal)
        || text.Contains("Export", StringComparison.Ordinal);

    private static void CheckAuthorizationGate()
    {
        Check("loopback 127.0.0.1 skips authorization", MainForm.IsLoopbackTarget("127.0.0.1"));
        Check("localhost skips authorization", MainForm.IsLoopbackTarget("localhost"));
        Check("loopback URL skips authorization", MainForm.IsLoopbackTarget("http://127.0.0.1:8080/"));
        Check("::1 skips authorization", MainForm.IsLoopbackTarget("::1"));
        Check("remote address needs authorization", !MainForm.IsLoopbackTarget("10.0.0.1"));
        Check("wide CIDR needs authorization", !MainForm.IsLoopbackTarget("127.0.0.0/1"));
        Check("mixed list needs authorization", !MainForm.IsLoopbackTarget("127.0.0.1, 192.168.1.1"));
        using var dlg = new AuthorizationDialog("192.168.1.0/24");
        Check("authorization start disabled until confirmed", !dlg.StartButton.Enabled);
        dlg.ConfirmBox.Checked = true;
        Check("authorization start enabled after confirming", dlg.StartButton.Enabled);
        dlg.ConfirmBox.Checked = false;
        Check("authorization start disabled again", !dlg.StartButton.Enabled);
    }

    private static async Task CheckWorkbench(MainForm form, int sitePort)
    {
        var bench = form.Modules.OfType<WorkbenchView>().Single();
        form.OpenInWorkbench("GET", $"http://127.0.0.1:{sitePort}/");
        await Pump(100);
        Check("workbench request built from URL", bench.RequestText.StartsWith("GET / HTTP/1.1", StringComparison.Ordinal)
            && bench.RequestText.Contains($"Host: 127.0.0.1:{sitePort}", StringComparison.Ordinal), bench.RequestText.Split('\r')[0]);
        var send = bench.SendForTestAsync();
        await PumpUntil(() => send.IsCompleted, TimeSpan.FromSeconds(20));
        Check("workbench send completes", send.IsCompleted);
        Check("workbench shows raw response", bench.ResponseText.StartsWith("HTTP/1.", StringComparison.Ordinal), bench.ResponseText.Split('\r')[0]);
        Check("workbench stats caption", bench.StatsText.Contains("bytes", StringComparison.Ordinal) && bench.StatsText.Contains("ms", StringComparison.Ordinal), bench.StatsText);

        bench.UrlText = "http://127.0.0.1:1/";
        await Pump(50);
        send = bench.SendForTestAsync();
        await PumpUntil(() => send.IsCompleted, TimeSpan.FromSeconds(20));
        Check("workbench reports connection failure", send.IsCompleted && !bench.ResponseText.StartsWith("HTTP/", StringComparison.Ordinal), bench.StatsText);
    }

    private static void CheckFiles(MainForm form)
    {
        var s = form.Session;
        string dir = Path.Combine(Path.GetTempPath(), "tryz-selftest");
        Directory.CreateDirectory(dir);
        string sessionPath = Path.Combine(dir, "selftest.tzs");
        int hosts = s.Hosts.Items.Count, ports = s.Ports.Items.Count, findings = s.FindingCount, urls = s.Urls.Items.Count;
        if (findings > 0) s.Findings.Items[0].Status = FindingStatus.Confirmed;
        Check("session saves", form.SaveSessionTo(sessionPath) && File.Exists(sessionPath));
        form.PerformCommand("New");
        Check("session cleared before reload", s.Hosts.Items.Count == 0);
        Check("session opens", form.OpenSessionFrom(sessionPath));
        Check("session round trip counts", s.Hosts.Items.Count == hosts && s.Ports.Items.Count == ports && s.FindingCount == findings && s.Urls.Items.Count == urls,
            $"{s.Hosts.Items.Count}/{hosts} hosts, {s.Ports.Items.Count}/{ports} ports, {s.FindingCount}/{findings} findings, {s.Urls.Items.Count}/{urls} urls");
        Check("session round trip keeps finding status", findings == 0 || s.Findings.Items[0].Status == FindingStatus.Confirmed);
        Check("session round trip keeps target", s.Target == "127.0.0.1", s.Target);

        string html = Path.Combine(dir, "report.html");
        string csv = Path.Combine(dir, "findings.csv");
        Check("html report exports", form.ExportTo(html, ExportFormat.Html) && File.ReadAllText(html).Contains("Executive summary", StringComparison.Ordinal));
        Check("csv exports", form.ExportTo(csv, ExportFormat.Csv) && CsvRecords(csv) == findings + 1, $"{CsvRecords(csv)} records for {findings} findings");
    }

    private const int WM_LBUTTONDOWN = 0x201, WM_LBUTTONUP = 0x202, WM_MOUSEMOVE = 0x200, WM_KEYDOWN = 0x100;

    private static void Click(Control c, int x, int y)
    {
        var lp = (IntPtr)((y << 16) | (x & 0xFFFF));
        Native.SendMessage(c.Handle, WM_MOUSEMOVE, IntPtr.Zero, lp);
        Native.SendMessage(c.Handle, WM_LBUTTONDOWN, (IntPtr)1, lp);
        Native.SendMessage(c.Handle, WM_LBUTTONUP, IntPtr.Zero, lp);
    }

    private static async Task ExerciseControls(MainForm form)
    {
        var combo = form.Target.ProfileCombo;
        await Pump(50);
        Check("profile combo enabled when idle", combo.Enabled);
        int before = combo.SelectedIndex;
        Click(combo, combo.Width - 4, combo.Height / 2);
        await Pump(120);
        bool opened = combo.DroppedDown;
        Check("combo opens on click", opened);
        var list = combo.ListForTest;
        int rowY = list.RowHeightPx * ((before + 1) % 4) + list.RowHeightPx / 2;
        Click(list, 20, rowY);
        await Pump(120);
        Check("combo item picks", combo.SelectedIndex == (before + 1) % 4 && !combo.DroppedDown, combo.SelectedIndex.ToString());
        combo.SelectedIndex = before;

        form.NavigateTo(4);
        await Pump(100);
        var grids = Descendants(form.Modules[4]).OfType<GridView>().ToList();
        Check("crawler grid found", grids.Count == 1);
        var grid = grids[0];
        var src = grid.Source!;
        if (src.Count < 2) { Check("crawler grid has rows", false, src.Count.ToString()); return; }
        grid.Focus();
        int sortBefore = src.SortColumn;
        Click(grid, Theme.Scale(30, form.DeviceDpi), Theme.Scale(8, form.DeviceDpi));
        Check("header click sorts", src.SortColumn == 0 && sortBefore != 0, src.SortColumn.ToString());
        Click(grid, Theme.Scale(30, form.DeviceDpi), Theme.Scale(40, form.DeviceDpi));
        Check("row click selects", grid.SelectedRow >= 0, grid.SelectedRow.ToString());
        int row = grid.SelectedRow;
        Native.SendMessage(grid.Handle, WM_KEYDOWN, (IntPtr)Keys.Down, IntPtr.Zero);
        Check("arrow key moves selection", grid.SelectedRow == row + 1, grid.SelectedRow.ToString());

        var dock = form.DockHost;
        Click(dock, Theme.Scale(120, form.DeviceDpi), Theme.Scale(12, form.DeviceDpi));
        Check("tab click switches", dock.SelectedIndex == 1, dock.SelectedIndex.ToString());
        dock.SelectedIndex = 0;

        foreach (var view in form.Modules)
        {
            view.SetBounds(view.Left, view.Top, view.Width, view.Height);
            foreach (var check in Descendants(view).OfType<SkinCheck>().Where(c => c is not SkinRadio).Take(2))
            {
                bool state = check.Checked;
                if (!check.IsHandleCreated) continue;
                Click(check, 4, 4);
                check.Checked = state;
            }
        }
        await Pump(100);
    }

    private static IEnumerable<Control> Descendants(Control root)
    {
        foreach (Control c in root.Controls)
        {
            yield return c;
            foreach (var d in Descendants(c)) yield return d;
        }
    }

    private static IEnumerable<ToolStripMenuItem> AllItems(ToolStripItemCollection items)
    {
        foreach (ToolStripItem i in items)
        {
            if (i is not ToolStripMenuItem m) continue;
            yield return m;
            foreach (var c in AllItems(m.DropDownItems)) yield return c;
        }
    }
}
#endif
