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
    HeatingController,
    Receiver,
    AirConditioner,
    Camera,
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

    public static DeviceType Classify(string vendor, string? name, MdnsHost? mdns, bool lltdResponder, string? upnpModel = null, bool? wireless = null, string? mac = null)
    {
        string names = string.Join(" ", new[] { name, mdns?.FriendlyName(), mdns?.HostName }.Where(s => !string.IsNullOrEmpty(s)));
        string model = string.Join(" ", new[] { mdns?.Model(), upnpModel }.Where(s => !string.IsNullOrEmpty(s)));
        bool amazon = Has(vendor, @"\bAmazon\b");
        bool google = Has(vendor, @"\bGoogle\b");

        // --- strong evidence from mDNS service types ---
        if (mdns != null)
        {
            if (mdns.HasType("_googlecast"))
            {
                if (Has(model, @"hub|display")) return DeviceType.GoogleDisplay;
                if (Has(model, @"chromecast|google\s*tv")) return DeviceType.Chromecast;
                if (Has(model, @"mini|home|nest\s*audio|speaker")) return DeviceType.GoogleSpeaker;
                if (Has(model, @"\bTV\b|bravia|webos")) return DeviceType.Tv;
                return google ? DeviceType.GoogleSpeaker : DeviceType.MediaPlayer;
            }
            if (mdns.HasType("_amzn-wplay")) return DeviceType.FireTv;
            if (mdns.HasType("_ipp") || mdns.HasType("_printer") || mdns.HasType("_pdl-datastream")) return DeviceType.Printer;
        }

        // --- heating (Bosch/Buderus/Junkers and others); checked before generic IoT rules ---
        if (Has(names, @"buderus|junkers|logamatic|easycontrol|\btc100|\bkm[23]00|\bmx300|ems[-_ ]?esp|vaillant|sensonet|viessmann|vitoconnect|wolf[-_ ]?link|heizung|thermostat|chaudi[eè]re|caldera"))
            return DeviceType.HeatingController;

        // --- IP cameras (Tapo, Wansview, ESP32-CAM meter readers, ...) ---
        if (Has(names, @"\bcam\b|\bcam[-_]|[-_]cam\b|kamera|camera|c[aá]mara|cam[eé]ra|webcam|\bipc\b|tapo[-_ ]?c\d|wansview|doorbell|t[üu]rklingel")
            || (Has(vendor, @"^TP-Link") && Has(names, @"\bc[1-5]\d{2}\b")))
            return DeviceType.Camera;

        // --- air conditioners (Wi-Fi adapters often carry the MAC of a module maker, so the name counts too) ---
        if (Has(vendor, @"^(Fujitsu General|GD Midea Air-Conditioning|Gree Electric|Daikin)")
            || Has(names, @"\bklima|aircon|air[-_ ]?condition|airstage|\bfgl\b|daikin|climatiseur|\bclima\b|aire[-_ ]?acondicionado"))
            return DeviceType.AirConditioner;

        // --- TV receivers / set-top boxes (Enigma2 boxes and others: satellite, cable, terrestrial, IPTV) ---
        // Checked before the generic rules: these boxes announce SMB/FTP and run LLTD responders like computers.
        if (Has(vendor, @"^(Marusys|Impex-Sat|Iffu|Dream Property|Xtrend|Edision|AB-COM|Air Digital|TechniSat|Kathrein|HUMAX Co)")
            || Has(names, @"vu\+|vuplus|\b(duo|solo|uno|zero|ultimo)(2|4k|4kse|se)\b|\bultimo|gigablue|\bgb[-_ ]?(quad|ue|trio|ip)|dreambox|\bdm\d{3,4}\b|enigma|zgemma|osmio|\bet\d{4}\b|quadbox|formuler|(?<!av[-_ ]?)receiver|set[-_ ]?top|sat[-_ ]?box"))
            return DeviceType.Receiver;

        // --- Amazon: vendor, then name to tell the models apart ---
        // Echo speakers announce Spotify Connect + Matter with host names like "none.local" or "Android-2.local".
        bool echoLike = mdns != null && mdns.HasType("_spotify-connect") && mdns.HasType("_matter")
                        && Has(mdns.HostName, @"^(none|android)(-\d+)?\.local");
        if (amazon || echoLike || Has(names, @"\b(echo|alexa|fire[-_ ]?tv|amazon)"))
        {
            if (Has(names, @"show")) return DeviceType.EchoShow;
            if (Has(names, @"spot")) return DeviceType.EchoSpot;
            if (Has(names, @"fire|aft[a-z]|stick")) return DeviceType.FireTv;
            if (Has(names, @"echo|alexa|dot") || echoLike) return DeviceType.EchoDot;
            // Echo devices have no Ethernet port: an Amazon device on a cable is a Fire TV with LAN adapter
            if (wireless == false) return DeviceType.FireTv;
            return DeviceType.AmazonDevice;
        }

        // --- Google ---
        if (google || Has(names, @"google|nest[-_ ]|chromecast"))
        {
            if (Has(names, @"hub|display")) return DeviceType.GoogleDisplay;
            if (Has(names, @"chromecast|google[-_ ]?tv")) return DeviceType.Chromecast;
            if (Has(names, @"mini|home|audio|speaker")) return DeviceType.GoogleSpeaker;
            if (google && !Has(names, @"pixel")) return DeviceType.GoogleDevice;
        }

        // --- TVs: after Amazon/Google (Fire TV), before HomeKit/AirPlay, which TVs announce as well ---
        if (Has(names, @"webos|lgwebos|bravia|tizen|smart[-_ ]?tv|\btv\b|fernseher") || Has(model, @"webos|\btv\b|bravia|tizen")
            || (mdns != null && mdns.HasType("_androidtvremote")))
            return DeviceType.Tv;

        // --- weaker mDNS hints ---
        if (mdns != null)
        {
            if (mdns.HasType("_sonos") || mdns.HasType("_spotify-connect") || mdns.HasType("_raop") || mdns.HasType("_airplay"))
            {
                if (Has(model, "iphone")) return DeviceType.Phone;
                if (Has(model, "ipad")) return DeviceType.Tablet;
                if (Has(model, @"mac|imac")) return DeviceType.Computer;
                return DeviceType.MediaPlayer;
            }
            if (mdns.HasType("_esphomelib") || mdns.HasType("_shelly") || mdns.HasType("_hap") || mdns.HasType("_homepilot")
                || (mdns.HasType("_matter") && !mdns.HasType("_home-assistant") && !mdns.HasType("_smb")))
                return DeviceType.Iot;
        }

        // --- other well-known kinds ---
        if (Has(names, @"ipad|\btab\b|galaxy[-_ ]?tab|tablet|\bsm-t\d")) return DeviceType.Tablet;
        if (Has(names, @"iphone|pixel|galaxy|\bnote\s?\d|\bs\d{2}\b|\ba\d{2}s?\b|redmi|xiaomi|huawei|oneplus|android|motorola|\bmoto\b|smartphone|handy|phone"))
            return DeviceType.Phone;
        if (Has(vendor, @"Hewlett Packard|HP Inc|Brother|Seiko Epson|Canon|Kyocera|Lexmark|Xerox|Ricoh") || Has(names, @"printer|drucker|imprimante|impresora|\bmfc|laserjet|officejet|deskjet"))
            return DeviceType.Printer;
        if (Has(vendor, @"Synology|QNAP|Western Digital|Buffalo") || Has(names, @"\bnas\b|diskstation|synology|qnap")) return DeviceType.Nas;
        if (Has(vendor, @"Espressif|Shelly|Tuya|Allterco|Sonoff|Itead") || Has(names, @"\besp|shelly|tasmota|sonoff|tuya|zigbee|homematic|homepilot"))
            return lltdResponder ? DeviceType.Computer : DeviceType.Iot;
        if (Has(vendor, @"Sonos|Roku|Bose|Yamaha|Denon|Harman") || Has(names, @"sonos|roku|bose|yamaha|denon")) return DeviceType.MediaPlayer;
        // --- weak hints: Wi-Fi module makers that are typical for one kind of device ---
        string prefix = mac != null && mac.Length >= 8 ? mac[..8].ToLowerInvariant() : "";
        if (prefix == "3c:e1:a1") return DeviceType.AirConditioner;                 // USI module of the Fujitsu General (FGL) Wi-Fi adapter
        if (Has(vendor, @"^(AltoBeam|SHENZHEN TONG BO WEI)")) return DeviceType.Camera;  // Wi-Fi of Wansview and other IP cameras
        if (prefix == "00:1c:c2" || Has(names, @"dreo|heizl[üu]fter|l[üu]fter|ventilator")) return DeviceType.Iot;  // Dreo fan heaters
        return DeviceType.Computer;
    }
}
