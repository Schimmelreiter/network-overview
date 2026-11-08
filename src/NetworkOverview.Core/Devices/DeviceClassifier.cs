using System.IO.Compression;
using System.Text.RegularExpressions;
using NetworkOverview.Core.Discovery;

namespace NetworkOverview.Core.Devices;

public enum DeviceType
{
    Computer,
    Phone,
    Tablet,
    Printer,
    Tv,
    MediaPlayer,
    Iot,
    Nas,
    EchoDot,
    EchoSpot,
    EchoShow,
    AmazonDevice,
    FireTv,
    GoogleSpeaker,
    GoogleDisplay,
    Chromecast,
    GoogleDevice,
}

/// <summary>Vendor lookup by MAC prefix (IEEE MA-L registry, embedded).</summary>
public static class VendorDb
{
    static Dictionary<int, string>? table;
    static readonly object gate = new();

    static Dictionary<int, string> Table
    {
        get
        {
            lock (gate)
            {
                if (table != null) return table;
                var t = new Dictionary<int, string>(24000);
                using var s = typeof(VendorDb).Assembly.GetManifestResourceStream("NetworkOverview.Core.oui.txt.gz");
                if (s != null)
                {
                    using var gz = new GZipStream(s, CompressionMode.Decompress);
                    using var r = new StreamReader(gz);
                    string? line;
                    while ((line = r.ReadLine()) != null)
                    {
                        int tab = line.IndexOf('\t');
                        if (tab == 6) t[Convert.ToInt32(line[..6], 16)] = line[7..];
                    }
                }
                return table = t;
            }
        }
    }

    /// <summary>Returns the registered vendor or "" (also for randomized/locally administered MACs).</summary>
    public static string Lookup(string mac)
    {
        if (mac.Length != 17 || MacUtil.IsLocallyAdministered(mac)) return "";
        int key = Convert.ToInt32(mac[..2] + mac.Substring(3, 2) + mac.Substring(6, 2), 16);
        return Table.TryGetValue(key, out var v) ? v : "";
    }
}

/// <summary>Determines the device type from vendor, mDNS announcements and names.
/// Order of evidence: mDNS service/model data, then vendor, then the name.</summary>
public static class DeviceClassifier
{
    static bool Has(string? s, string pattern) => s != null && Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase);

    public static DeviceType Classify(string vendor, string? name, MdnsHost? mdns, bool lltdResponder)
    {
        string names = string.Join(" ", new[] { name, mdns?.FriendlyName(), mdns?.HostName }.Where(s => !string.IsNullOrEmpty(s)));
        string model = mdns?.Model() ?? "";
        bool amazon = Has(vendor, @"\bAmazon\b");
        bool google = Has(vendor, @"\bGoogle\b");

        // --- strong evidence from mDNS ---
        if (mdns != null)
        {
            if (mdns.HasType("_googlecast"))
            {
                if (Has(model, @"hub|display|nest\s*hub")) return DeviceType.GoogleDisplay;
                if (Has(model, @"chromecast|google\s*tv|cast")) return DeviceType.Chromecast;
                if (Has(model, @"mini|home|nest\s*audio|speaker")) return DeviceType.GoogleSpeaker;
                if (google) return DeviceType.GoogleSpeaker;
                return DeviceType.MediaPlayer;
            }
            if (mdns.HasType("_amzn-wplay")) return DeviceType.FireTv;
            if (mdns.HasType("_ipp") || mdns.HasType("_printer") || mdns.HasType("_pdl-datastream")) return DeviceType.Printer;
            if (mdns.HasType("_androidtvremote") || Has(model, @"\bTV\b")) return DeviceType.Tv;
            if (mdns.HasType("_esphomelib") || mdns.HasType("_shelly") || mdns.HasType("_hap")) return DeviceType.Iot;
            if (mdns.HasType("_sonos") || mdns.HasType("_spotify-connect") || mdns.HasType("_raop"))
                return Has(model, @"iphone|ipad|mac") ? (Has(model, "ipad") ? DeviceType.Tablet : Has(model, "iphone") ? DeviceType.Phone : DeviceType.Computer) : DeviceType.MediaPlayer;
        }

        // --- Amazon: vendor, then name to tell the models apart ---
        if (amazon || Has(names, @"\b(echo|alexa|fire[-_ ]?tv|amazon)"))
        {
            if (Has(names, @"show")) return DeviceType.EchoShow;
            if (Has(names, @"spot")) return DeviceType.EchoSpot;
            if (Has(names, @"fire|aft[a-z]|stick")) return DeviceType.FireTv;
            if (Has(names, @"echo|alexa|dot")) return DeviceType.EchoDot;
            if (amazon) return DeviceType.AmazonDevice;
        }

        // --- Google ---
        if (google || Has(names, @"google|nest[-_ ]|chromecast"))
        {
            if (Has(names, @"hub|display")) return DeviceType.GoogleDisplay;
            if (Has(names, @"chromecast|google[-_ ]?tv")) return DeviceType.Chromecast;
            if (Has(names, @"mini|home|audio|speaker")) return DeviceType.GoogleSpeaker;
            if (google && !Has(names, @"pixel")) return DeviceType.GoogleDevice;
        }

        // --- other well-known kinds ---
        if (Has(names, @"ipad|\btab\b|galaxy[-_ ]?tab|tablet|\bsm-t\d")) return DeviceType.Tablet;
        if (Has(names, @"iphone|pixel|galaxy|\bnote\s?\d|\bs\d{2}\b|\ba\d{2}s?\b|redmi|xiaomi|huawei|oneplus|android|motorola|\bmoto\b|smartphone|handy|phone"))
            return DeviceType.Phone;
        if (Has(vendor, @"Hewlett Packard|HP Inc|Brother|Seiko Epson|Canon|Kyocera|Lexmark|Xerox|Ricoh") || Has(names, @"printer|drucker|imprimante|impresora|\bmfc|laserjet|officejet|deskjet"))
            return DeviceType.Printer;
        if (Has(vendor, @"Synology|QNAP|Western Digital|Buffalo") || Has(names, @"\bnas\b|diskstation|synology|qnap")) return DeviceType.Nas;
        if (Has(vendor, @"Espressif|Shelly|Tuya|Allterco|Sonoff|Itead|Raspberry") || Has(names, @"esp|shelly|tasmota|sonoff|tuya|zigbee|homematic|\bems\b"))
            return lltdResponder ? DeviceType.Computer : DeviceType.Iot;
        if (Has(vendor, @"Sonos|Roku|Bose") || Has(names, @"sonos|roku|bose")) return DeviceType.MediaPlayer;
        if (Has(names, @"\btv\b|fernseher|bravia|webos|tizen|smart[-_ ]?tv")) return DeviceType.Tv;
        return DeviceType.Computer;
    }
}
