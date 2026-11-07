#if DEBUG
using System.Drawing.Imaging;
using TryZ.Data;
using TryZ.Shell;

namespace TryZ.Capture;

internal sealed record CaptureOptions(string Directory, Size LogicalSize, int? DpiOverride, string Target, string? Filter)
{
    public static CaptureOptions? Parse(string[] args)
    {
        int at = Array.IndexOf(args, "--capture");
        if (at < 0 || at + 1 >= args.Length) return null;
        var size = new Size(1240, 780);
        int? dpi = null;
        string target = "127.0.0.1";
        string? filter = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--size" && i + 1 < args.Length)
            {
                var parts = args[i + 1].Split('x');
                size = new Size(int.Parse(parts[0]), int.Parse(parts[1]));
            }
            else if (args[i] == "--dpi-test" && i + 1 < args.Length) dpi = int.Parse(args[i + 1]) * 96 / 100;
            else if (args[i] == "--target" && i + 1 < args.Length) target = args[i + 1];
            else if (args[i] == "--filter" && i + 1 < args.Length) filter = args[i + 1];
        }
        return new CaptureOptions(args[at + 1], size, dpi, target, filter);
    }
}

internal static class CaptureRunner
{
    private const uint PW_RENDERFULLCONTENT = 2;
    private static readonly string[] ModuleFiles = { "1-overview", "2-discovery", "3-port-audit", "4-vulnerability", "5-crawler", "6-workbench", "7-reports" };

    public static int Run(CaptureOptions options)
    {
        Theme.DpiOverride = options.DpiOverride;
        Directory.CreateDirectory(options.Directory);
        var settings = new AppSettings { ShowSplash = false, LastModule = 0, DefaultProfile = 0, DefaultThreads = 64, DockHeight = 170, LastTarget = options.Target };
        using var form = new MainForm(settings) { PersistOnClose = false };
        if (options.DpiOverride != null) form.ApplyOverrideDpi();
        form.SetCaptureBounds(options.LogicalSize);
        int exit = 0;
        form.Shown += async (_, _) =>
        {
            try
            {
                await RunAsync(form, options);
            }
            catch (Exception ex)
            {
                File.WriteAllText(Path.Combine(options.Directory, "capture-error.txt"), ex.ToString());
                exit = 1;
            }
            finally
            {
                form.Close();
            }
        };
        Application.Run(form);
        return exit;
    }

    private static async Task Settle(int ms = 220)
    {
        var end = DateTime.UtcNow.AddMilliseconds(ms);
        while (DateTime.UtcNow < end)
        {
            Application.DoEvents();
            await Task.Delay(15);
        }
    }

    private static async Task RunAsync(MainForm form, CaptureOptions o)
    {
        SaveLogoZoom(o);
        form.SyncUi(force: true);
        await Settle(250);
        Save(form, Path.Combine(o.Directory, "0-idle.png"));
        await Settle(200);
        // A local test site gives the loopback scan a web service to identify, audit and crawl.
        using var site = o.Target == "127.0.0.1" ? TestSite.TryStartAny() : null;
        // Capture runs have no authorization prompt, so they are limited to loopback targets.
        if (!MainForm.IsLoopbackTarget(o.Target))
            throw new InvalidOperationException($"Capture target {o.Target} is not a loopback address; capture runs scan only this machine.");
        form.BeginRun(o.Target);
        await Settle(1500);
        form.SyncUi(force: true);
        Save(form, Path.Combine(o.Directory, "0-running.png"));
        var deadline = DateTime.UtcNow.AddSeconds(120);
        while (form.Engine.State == ScanState.Running && DateTime.UtcNow < deadline)
            await Settle(100);
        await Settle(400);
        form.SyncUi(force: true);
        if (o.Filter != null) form.Target.SetFilterForCapture(o.Filter);

        if (site != null) form.OpenInWorkbench("GET", $"http://127.0.0.1:{site.Port}/");
        foreach (var m in form.Modules) m.PrepareForCapture();
        await Settle(1500);
        for (int i = 0; i < form.Modules.Length; i++)
        {
            form.NavigateTo(i);
            form.SyncUi(force: true);
            await Settle();
            Save(form, Path.Combine(o.Directory, ModuleFiles[i] + ".png"));
        }

        form.NavigateTo(0);
        form.DockHost.SelectedIndex = 2;
        await Settle();
        Save(form, Path.Combine(o.Directory, "8-dock-tasks.png"));
        form.DockHost.SelectedIndex = 1;
        await Settle();
        Save(form, Path.Combine(o.Directory, "8-dock-findings.png"));
        form.DockHost.SelectedIndex = 0;

        await CaptureMenu(form, o);
        await CaptureCombo(form, o);
        await CaptureDialog(form, new OptionsDialog(form.Settings), Path.Combine(o.Directory, "9-options.png"));
        var exclusions = new OptionsDialog(form.Settings);
        exclusions.SelectPage(3);
        await CaptureDialog(form, exclusions, Path.Combine(o.Directory, "9-options-exclusions.png"));
        await CaptureDialog(form, new AboutDialog(), Path.Combine(o.Directory, "10-about.png"));
        var engine = new OptionsDialog(form.Settings);
        engine.SelectPage(5);
        await CaptureDialog(form, engine, Path.Combine(o.Directory, "9-options-engine.png"));
        await CaptureDialog(form, new AuthorizationDialog("192.168.1.0/24"), Path.Combine(o.Directory, "10-authorization.png"));
        await CaptureDialog(form, MessageDialog.ForCapture("Target", "Enter a target: an IP address, CIDR block, address range, host name or URL.", IconId.Warning),
            Path.Combine(o.Directory, "11-message.png"));

        var splash = new SplashForm(1000, 0.72);
        splash.Show();
        await Settle();
        Save(splash, Path.Combine(o.Directory, "12-splash.png"));
        splash.Close();
        splash.Dispose();
    }

    private static void SaveLogoZoom(CaptureOptions o)
    {
        var logo = LogoArt.Get(o.DpiOverride ?? 96);
        int k = 5;
        using var big = new Bitmap(logo.Width * k, logo.Height * k);
        using var g = Graphics.FromImage(big);
        g.Clear(Theme.Hex(0x141517));
        g.InterpolationMode = System.Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
        g.PixelOffsetMode = System.Drawing.Drawing2D.PixelOffsetMode.Half;
        g.DrawImage(logo, new Rectangle(0, 0, big.Width, big.Height));
        big.Save(Path.Combine(o.Directory, "logo-zoom.png"), ImageFormat.Png);
    }

    private static async Task CaptureMenu(MainForm form, CaptureOptions o)
    {
        var scan = (ToolStripMenuItem)form.MenuBar.Items[2];
        scan.DropDown.AutoClose = false;
        scan.ShowDropDown();
        await Settle();
        using var main = Grab(form);
        Overlay(main, form, scan.DropDown);
        main.Save(Path.Combine(o.Directory, "13-menu-scan.png"), ImageFormat.Png);
        scan.DropDown.AutoClose = true;
        scan.HideDropDown();
        await Settle(80);

        var view = (ToolStripMenuItem)form.MenuBar.Items[5];
        view.DropDown.AutoClose = false;
        view.ShowDropDown();
        await Settle();
        using var main2 = Grab(form);
        Overlay(main2, form, view.DropDown);
        main2.Save(Path.Combine(o.Directory, "13-menu-view.png"), ImageFormat.Png);
        view.DropDown.AutoClose = true;
        view.HideDropDown();
        await Settle(80);
    }

    private static async Task CaptureCombo(MainForm form, CaptureOptions o)
    {
        var combo = form.Target.ProfileCombo;
        combo.Enabled = true;
        combo.DropDownWindow.AutoClose = false;
        combo.ShowDrop();
        await Settle();
        using var main = Grab(form);
        Overlay(main, form, combo.DropDownWindow);
        main.Save(Path.Combine(o.Directory, "14-combo.png"), ImageFormat.Png);
        combo.DropDownWindow.AutoClose = true;
        combo.DropDownWindow.Close();
        combo.Enabled = false;
        await Settle(80);
    }

    private static async Task CaptureDialog(Form owner, Form dialog, string path)
    {
        dialog.StartPosition = FormStartPosition.Manual;
        dialog.Show(owner);
        dialog.Location = new Point(owner.Left + (owner.Width - dialog.Width) / 2, owner.Top + (owner.Height - dialog.Height) / 2);
        await Settle(260);
        Save(dialog, path);
        dialog.Close();
        dialog.Dispose();
        await Settle(60);
    }

    private static void Overlay(Bitmap target, Form owner, Control popup)
    {
        using var over = Grab(popup);
        using var g = Graphics.FromImage(target);
        var at = popup.Bounds.Location;
        g.DrawImageUnscaled(over, at.X - owner.Left, at.Y - owner.Top);
    }

    private static void Save(Control window, string path)
    {
        using var bmp = Grab(window);
        bmp.Save(path, ImageFormat.Png);
    }

    private static Bitmap Grab(Control window)
    {
        var size = window.Size;
        var bmp = new Bitmap(size.Width, size.Height, PixelFormat.Format32bppRgb);
        using var g = Graphics.FromImage(bmp);
        var hdc = g.GetHdc();
        try
        {
            Native.PrintWindow(window.Handle, hdc, PW_RENDERFULLCONTENT);
        }
        finally
        {
            g.ReleaseHdc(hdc);
        }
        return bmp;
    }
}
#endif
