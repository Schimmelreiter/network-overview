using NetworkOverview.Core;
using NetworkOverview.Core.Localization;

namespace NetworkOverview;

internal static class Program
{
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length == 3 && args[0] == "--render-demo")
        {
            Demo.Render(args[1], args[2]);
            return;
        }
        ApplicationConfiguration.Initialize();
#pragma warning disable WFO5001 // dark mode API is marked experimental in WinForms
        Application.SetColorMode(SystemColorMode.System);
#pragma warning restore WFO5001
        var cfg = AppConfig.Load();
        L.SetLanguage(cfg.Language);
        Application.Run(new MainForm(cfg));
    }
}
