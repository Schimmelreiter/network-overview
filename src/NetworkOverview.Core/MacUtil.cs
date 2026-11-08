using System.Globalization;
using System.Net;

namespace NetworkOverview.Core;

public static class MacUtil
{
    /// <summary>Normalizes any MAC notation to lower-case "aa:bb:cc:dd:ee:ff"; returns "" if invalid.</summary>
    public static string Normalize(string? mac)
    {
        if (string.IsNullOrEmpty(mac)) return "";
        var hex = new string(mac.Where(Uri.IsHexDigit).ToArray()).ToLowerInvariant();
        if (hex.Length != 12) return "";
        return string.Join(":", Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2)));
    }

    public static bool IsUsable(string mac) =>
        mac.Length == 17 && mac != "00:00:00:00:00:00" && mac != "ff:ff:ff:ff:ff:ff"
        && !mac.StartsWith("01:00:5e") && !mac.StartsWith("33:33");

    /// <summary>Locally administered (randomized/private) address?</summary>
    public static bool IsLocallyAdministered(string mac) =>
        mac.Length >= 2 && (Convert.ToInt32(mac[..2], 16) & 0x02) != 0;

    /// <summary>Same physical device? BSSIDs often differ from the LAN MAC in the locally-administered
    /// bit of the first octet and/or the last few counts.</summary>
    public static bool SameDevice(string a, string b)
    {
        if (a.Length != 17 || b.Length != 17) return false;
        if (a == b) return true;
        var x = a.Split(':'); var y = b.Split(':');
        int x0 = Convert.ToInt32(x[0], 16) | 2, y0 = Convert.ToInt32(y[0], 16) | 2;
        if (x0 != y0 || x[1] != y[1] || x[2] != y[2]) return false;
        int xv = Convert.ToInt32(x[3] + x[4] + x[5], 16), yv = Convert.ToInt32(y[3] + y[4] + y[5], 16);
        return Math.Abs(xv - yv) <= 16;
    }

    public static long IpKey(string? ip)
    {
        if (string.IsNullOrEmpty(ip) || !IPAddress.TryParse(ip, out var a)) return long.MaxValue;
        var b = a.GetAddressBytes();
        if (b.Length != 4) return long.MaxValue - 1;
        return ((long)b[0] << 24) | ((long)b[1] << 16) | ((long)b[2] << 8) | b[3];
    }

    public static string FormatSpeed(double bps)
    {
        var c = CultureInfo.CurrentCulture;
        if (bps >= 1e9) return (bps / 1e9).ToString("0.#", c) + " Gbit/s";
        if (bps >= 1e6) return (bps / 1e6).ToString("0.#", c) + " Mbit/s";
        if (bps > 0) return (bps / 1e3).ToString("0", c) + " kbit/s";
        return "";
    }
}
