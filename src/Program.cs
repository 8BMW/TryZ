using TryZ.Data;
using TryZ.Shell;

namespace TryZ;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        ApplicationConfiguration.Initialize();
        try
        {
#if DEBUG
            if (args.Contains("--selftest")) return TryZ.Capture.SelfTest.Run();
            var capture = TryZ.Capture.CaptureOptions.Parse(args);
            if (capture != null) return TryZ.Capture.CaptureRunner.Run(capture);
#endif
            var settings = AppSettings.Load();
            if (settings.ShowSplash)
            {
                using var splash = new SplashForm();
                Application.Run(splash);
            }
            using var form = new MainForm(settings);
            Application.Run(form);
            return 0;
        }
        finally
        {
            Theme.ReleaseResources();
        }
    }
}
