using Microsoft.Win32;

namespace NetworkOverview;

/// <summary>Colors for the map, following the Windows app mode (light/dark).</summary>
public sealed class Theme
{
    public bool Dark { get; private init; }
    public Color Background { get; private init; }
    public Color Text { get; private init; }
    public Color SubText { get; private init; }
    public Color Line { get; private init; }
    public Color SelectionFill { get; private init; }
    public Color SelectionBorder { get; private init; }
    public Color Outline { get; private init; }
    public Color DeviceBody1 { get; private init; }
    public Color DeviceBody2 { get; private init; }
    public Color Screen1 { get; private init; }
    public Color Screen2 { get; private init; }
    public Color ScreenGrey1 { get; private init; }
    public Color ScreenGrey2 { get; private init; }
    public Color Fabric { get; private init; }
    public Color Accent { get; private init; }
    public Color Signal { get; private init; }
    public Color Led { get; private init; }

    public static bool SystemUsesDarkMode()
    {
        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
            return key?.GetValue("AppsUseLightTheme") is int v && v == 0;
        }
        catch (Exception) { return false; }
    }

    public static Theme Current() => SystemUsesDarkMode() ? DarkTheme : LightTheme;

    public static readonly Theme LightTheme = new()
    {
        Dark = false,
        Background = Color.White,
        Text = Color.Black,
        SubText = Color.FromArgb(105, 105, 105),
        Line = Color.FromArgb(165, 198, 140),
        SelectionFill = Color.FromArgb(229, 243, 255),
        SelectionBorder = Color.FromArgb(153, 209, 255),
        Outline = Color.FromArgb(80, 80, 80),
        DeviceBody1 = Color.FromArgb(245, 245, 245),
        DeviceBody2 = Color.FromArgb(175, 175, 175),
        Screen1 = Color.FromArgb(205, 232, 255),
        Screen2 = Color.FromArgb(25, 85, 195),
        ScreenGrey1 = Color.FromArgb(240, 240, 240),
        ScreenGrey2 = Color.FromArgb(160, 160, 160),
        Fabric = Color.FromArgb(214, 214, 210),
        Accent = Color.FromArgb(0, 170, 220),
        Signal = Color.FromArgb(60, 170, 60),
        Led = Color.FromArgb(40, 200, 40),
    };

    public static readonly Theme DarkTheme = new()
    {
        Dark = true,
        Background = Color.FromArgb(32, 32, 32),
        Text = Color.FromArgb(235, 235, 235),
        SubText = Color.FromArgb(165, 165, 165),
        Line = Color.FromArgb(112, 160, 92),
        SelectionFill = Color.FromArgb(40, 62, 90),
        SelectionBorder = Color.FromArgb(70, 120, 180),
        Outline = Color.FromArgb(150, 150, 150),
        DeviceBody1 = Color.FromArgb(120, 120, 124),
        DeviceBody2 = Color.FromArgb(70, 70, 74),
        Screen1 = Color.FromArgb(120, 180, 240),
        Screen2 = Color.FromArgb(20, 60, 150),
        ScreenGrey1 = Color.FromArgb(150, 150, 150),
        ScreenGrey2 = Color.FromArgb(90, 90, 90),
        Fabric = Color.FromArgb(150, 150, 146),
        Accent = Color.FromArgb(0, 190, 240),
        Signal = Color.FromArgb(90, 200, 90),
        Led = Color.FromArgb(60, 220, 60),
    };
}
