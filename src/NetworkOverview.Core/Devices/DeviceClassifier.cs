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
    Lamp,
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

/// <summary>Everything known about a device that helps to determine its type.</summary>
public sealed class DeviceEvidence
{
    public string Vendor { get; set; } = "";
    public string Mac { get; set; } = "";
    /// <summary>Name given by the user (DHCP/DNS/NetBIOS); only used when <see cref="UseNames"/> is set.</summary>
    public string Name { get; set; } = "";
    public MdnsHost? Mdns { get; set; }
    public SsdpDevice? Ssdp { get; set; }
    public string UpnpModel { get; set; } = "";
    public FingerprintInfo? Fingerprint { get; set; }
    public bool Lltd { get; set; }
    public bool? Wireless { get; set; }
    public bool UseNames { get; set; } = true;
}

/// <summary>Result: the type, where it came from (localization key Src_*) and a short detail.</summary>
public readonly record struct Classification(DeviceType Type, string Source, string Detail = "")
{
    /// <summary>Sources based on what the device itself announced or answered (not vendor or name alone).</summary>
    public bool Strong => Source is "Src_Mdns" or "Src_Ssdp" or "Src_Fingerprint";
}

/// <summary>Determines the device type. Order of evidence: what the device announces (mDNS, SSDP/UPnP) or answers
/// (fingerprint: ports, web servers, certificates, discovery protocols), then the vendor of the MAC address.
/// User-given names are only used last, to refine a generic result, and can be switched off.</summary>
public static class DeviceClassifier
{
    static bool Has(string? s, string pattern) => !string.IsNullOrEmpty(s) && Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase);

    /// <summary>Compatibility overload (type only).</summary>
    public static DeviceType Classify(string vendor, string? name, MdnsHost? mdns, bool lltdResponder, string? upnpModel = null, bool? wireless = null, string? mac = null)
        => Classify(new DeviceEvidence
        {
            Vendor = vendor, Name = name ?? "", Mdns = mdns, Lltd = lltdResponder, UpnpModel = upnpModel ?? "", Wireless = wireless, Mac = mac ?? "",
        }).Type;

    public static Classification Classify(DeviceEvidence e)
    {
        var c = Evidence(e);
        if (!e.UseNames) return c;
        // names only refine generic results
        if (c.Type == DeviceType.Computer && c.Source != "Src_Fingerprint" || c.Type is DeviceType.Iot or DeviceType.AmazonDevice or DeviceType.GoogleDevice)
        {
            var n = ByName(Names(e), c.Type, e.Wireless);
            if (n != null) return new Classification(n.Value, "Src_Name");
        }
        return c;
    }

    static string Names(DeviceEvidence e) =>
        string.Join(" ", new[] { e.Name, e.Mdns?.FriendlyName(), e.Mdns?.HostName }.Where(s => !string.IsNullOrEmpty(s)));

    static Classification Evidence(DeviceEvidence e)
    {
        var mdns = e.Mdns;
        var fp = e.Fingerprint;
        var ssdp = e.Ssdp;
        string vendor = e.Vendor;
        string model = string.Join(" ", new[] { mdns?.Model(), e.UpnpModel, ssdp?.Model }.Where(s => !string.IsNullOrEmpty(s)));
        string names = e.UseNames ? Names(e) : "";
        bool amazon = Has(vendor, @"\bAmazon\b");
        bool google = Has(vendor, @"\bGoogle\b");
        string prefix = e.Mac.Length >= 8 ? e.Mac[..8].ToLowerInvariant() : "";
        Classification R(DeviceType t, string src, string detail = "") => new(t, src, detail);

        // --- 1. what the device announces via mDNS ---
        if (mdns != null)
        {
            if (mdns.HasType("_googlecast"))
            {
                if (Has(model, @"hub|display")) return R(DeviceType.GoogleDisplay, "Src_Mdns", "Google Cast");
                if (Has(model, @"chromecast|google\s*tv")) return R(DeviceType.Chromecast, "Src_Mdns", "Google Cast");
                if (Has(model, @"mini|home|nest\s*audio|speaker")) return R(DeviceType.GoogleSpeaker, "Src_Mdns", "Google Cast");
                if (Has(model, @"\bTV\b|bravia|webos")) return R(DeviceType.Tv, "Src_Mdns", "Google Cast");
                return R(google ? DeviceType.GoogleSpeaker : DeviceType.MediaPlayer, "Src_Mdns", "Google Cast");
            }
            if (mdns.HasType("_amzn-wplay")) return R(DeviceType.FireTv, "Src_Mdns", "_amzn-wplay");
            if (mdns.HasType("_ipp") || mdns.HasType("_printer") || mdns.HasType("_pdl-datastream")) return R(DeviceType.Printer, "Src_Mdns", "IPP/LPD");
            if (mdns.HasType("_e2stream")) return R(DeviceType.Receiver, "Src_Mdns", "Enigma2");
        }

        // --- 2. what the device answers (fingerprint) and SSDP identifiers ---
        bool fireTvSsdp = ssdp != null && ssdp.Usns.Any(u => Has(u, @"FIRETV|-AMAZOAFT|AFT[A-Z]{1,4}-"));
        if (fireTvSsdp) return R(DeviceType.FireTv, "Src_Ssdp", "Fire TV");
        if (fp != null)
        {
            if (fp.Realm("OpenWebif")) return R(DeviceType.Receiver, "Src_Fingerprint", "OpenWebif");
            if (fp.Onvif) return R(DeviceType.Camera, "Src_Fingerprint", "ONVIF");
            if (fp.Cert(@"O=TPRI\b") && (fp.Has(554) || fp.Has(2020))) return R(DeviceType.Camera, "Src_Fingerprint", "Tapo");
            if (fp.Server("^ems-esp") || fp.Banner("EMS-ESP")) return R(DeviceType.HeatingController, "Src_Fingerprint", "EMS-ESP");
            if (fp.MagicHomeModel.Length > 0) return R(DeviceType.Lamp, "Src_Fingerprint", "Magic Home");
        }

        // --- 3. Amazon: Echo or Fire TV ---
        // Echo speakers announce Spotify Connect + Matter with host names like "none.local" or "Android-2.local".
        bool echoLike = mdns != null && mdns.HasType("_spotify-connect") && mdns.HasType("_matter")
                        && Has(mdns.HostName, @"^(none|android|amazon)(-\d+)?\.local");
        if (amazon || echoLike)
        {
            bool fireTv = fp != null && (fp.Has(9080) || fp.Has(8009));
            bool echo = echoLike || fp != null && (fp.Has(4070) || fp.Has(5541)) && !fireTv;
            if (fireTv) return R(DeviceType.FireTv, "Src_Fingerprint", "Fire TV");
            if (echo)
            {
                // which Echo is not visible on the network: only the name can tell
                if (Has(names, @"show")) return R(DeviceType.EchoShow, "Src_Name", "Echo");
                if (Has(names, @"spot")) return R(DeviceType.EchoSpot, "Src_Name", "Echo");
                return R(DeviceType.EchoDot, echoLike ? "Src_Mdns" : "Src_Fingerprint", "Echo");
            }
            // Echo devices have no Ethernet port: an Amazon device on a cable is a Fire TV with LAN adapter
            if (amazon && e.Wireless == false) return R(DeviceType.FireTv, "Src_Vendor", "Amazon");
            if (amazon) return R(DeviceType.AmazonDevice, "Src_Vendor", "Amazon");
        }

        // --- 4. TVs and media devices by their UPnP/mDNS model ---
        if (Has(model, @"webos|\btv\b|bravia|tizen") || mdns != null && mdns.HasType("_androidtvremote")
            || ssdp != null && Has(ssdp.Manufacturer, "Samsung") && Has(ssdp.DeviceType + " " + ssdp.Server, @"MediaRenderer|dial|tizen|tv"))
            return R(DeviceType.Tv, mdns != null && Has(mdns.Model(), @"webos|\btv\b|bravia|tizen") ? "Src_Mdns" : "Src_Ssdp");
        if (mdns != null)
        {
            if (mdns.HasType("_sonos") || mdns.HasType("_spotify-connect") || mdns.HasType("_raop") || mdns.HasType("_airplay"))
            {
                if (Has(model, "iphone")) return R(DeviceType.Phone, "Src_Mdns");
                if (Has(model, "ipad")) return R(DeviceType.Tablet, "Src_Mdns");
                if (Has(model, @"mac|imac")) return R(DeviceType.Computer, "Src_Mdns");
                return R(DeviceType.MediaPlayer, "Src_Mdns", "AirPlay/Spotify");
            }
            if (mdns.HasType("_esphomelib") || mdns.HasType("_shelly") || mdns.HasType("_hap") || mdns.HasType("_homepilot") || mdns.HasType("_everhome")
                || (mdns.HasType("_matter") && !mdns.HasType("_home-assistant") && !mdns.HasType("_smb")))
                return R(DeviceType.Iot, "Src_Mdns");
        }
        if (google) return R(DeviceType.GoogleDevice, "Src_Vendor", "Google");

        // --- 5. vendor of the MAC address (and Wi-Fi modules typical for one kind of device) ---
        if (Has(vendor, @"^(Marusys|Impex-Sat|Iffu|Dream Property|Xtrend|Edision|AB-COM|Air Digital|TechniSat|Kathrein|HUMAX Co)"))
            return R(DeviceType.Receiver, "Src_Vendor");
        if (Has(vendor, @"Hewlett Packard|HP Inc|Brother|Seiko Epson|Canon|Kyocera|Lexmark|Xerox|Ricoh")) return R(DeviceType.Printer, "Src_Vendor");
        if (Has(vendor, @"Synology|QNAP|Western Digital|Buffalo")) return R(DeviceType.Nas, "Src_Vendor");
        if (Has(vendor, @"^(Fujitsu General|GD Midea Air-Conditioning|Gree Electric|Daikin)")) return R(DeviceType.AirConditioner, "Src_Vendor");
        if (prefix == "3c:e1:a1") return R(DeviceType.AirConditioner, "Src_Vendor", "Fujitsu General Wi-Fi");  // USI module of the FGL adapter
        if (Has(vendor, @"^(AltoBeam|SHENZHEN TONG BO WEI)")) return R(DeviceType.Camera, "Src_Vendor", "Wansview Wi-Fi");
        if (Has(vendor, @"Sonos|Roku|Bose|Yamaha|Denon|Harman")) return R(DeviceType.MediaPlayer, "Src_Vendor");

        // --- 6. generic IoT evidence ---
        if (fp != null && fp.Tuya) return R(DeviceType.Iot, "Src_Fingerprint", "Tuya");
        if (fp != null && fp.Has(502) && !e.Lltd) return R(DeviceType.Iot, "Src_Fingerprint", "Modbus");
        if (Has(vendor, @"Espressif|Shelly|Tuya|Allterco|Sonoff|Itead|Zengge"))
            return e.Lltd ? R(DeviceType.Computer, "Src_Lltd") : R(DeviceType.Iot, "Src_Vendor");
        if (prefix is "00:1c:c2" or "7c:fa:80") return R(DeviceType.Iot, "Src_Vendor", "Wi-Fi module");   // Dreo fan heater, Worx Landroid
        if (fp != null && fp.Banner(@"^SSH-") && !fp.Any("dropbear")) return R(DeviceType.Computer, "Src_Fingerprint", "SSH");
        return R(DeviceType.Computer, e.Lltd ? "Src_Lltd" : "Src_Default");
    }

    /// <summary>Type from a user-given name, used to refine a generic result. Cameras are deliberately not detected by name.</summary>
    static DeviceType? ByName(string names, DeviceType current, bool? wireless)
    {
        if (names.Length == 0) return null;
        if (Has(names, @"buderus|junkers|logamatic|easycontrol|\btc100|\bkm[23]00|\bmx300|ems[-_ ]?esp|vaillant|sensonet|viessmann|vitoconnect|wolf[-_ ]?link|heizung|thermostat|chaudi[eè]re|caldera"))
            return DeviceType.HeatingController;
        if (Has(names, @"\bklima|aircon|air[-_ ]?condition|airstage|\bfgl\b|daikin|climatiseur|\bclima\b|aire[-_ ]?acondicionado"))
            return DeviceType.AirConditioner;
        if (current is DeviceType.Iot) return null;   // IoT is only refined to the more specific IoT kinds above
        if (Has(names, @"\b(echo|alexa)\b|\becho[-_ ]"))
            return Has(names, "show") ? DeviceType.EchoShow : Has(names, "spot") ? DeviceType.EchoSpot : DeviceType.EchoDot;
        if (Has(names, @"fire[-_ ]?tv|\baft[a-z]")) return DeviceType.FireTv;
        // Echo devices have no Ethernet port: an "Amazon" device on a cable is a Fire TV with LAN adapter
        if (Has(names, @"\bamazon")) return wireless == false ? DeviceType.FireTv : DeviceType.AmazonDevice;
        if (current is DeviceType.AmazonDevice) return null;
        if (Has(names, @"chromecast|google[-_ ]?tv")) return DeviceType.Chromecast;
        if (Has(names, @"nest[-_ ]?hub|google.*display")) return DeviceType.GoogleDisplay;
        if (Has(names, @"google[-_ ]?(home|mini)|nest[-_ ]?(mini|audio)")) return DeviceType.GoogleSpeaker;
        if (current is DeviceType.GoogleDevice) return null;
        if (Has(names, @"vu\+|vuplus|\b(duo|solo|uno|zero|ultimo)(2|4k|4kse|se)\b|\bultimo|gigablue|\bgb[-_ ]?(quad|ue|trio|ip)|dreambox|\bdm\d{3,4}\b|enigma|zgemma|osmio|\bet\d{4}\b|quadbox|formuler|(?<!av[-_ ]?)receiver|set[-_ ]?top|sat[-_ ]?box"))
            return DeviceType.Receiver;
        if (Has(names, @"webos|lgwebos|bravia|tizen|smart[-_ ]?tv|\btv\b|fernseher")) return DeviceType.Tv;
        if (Has(names, @"ipad|\btab\b|galaxy[-_ ]?tab|tablet|\bsm-t\d")) return DeviceType.Tablet;
        if (Has(names, @"iphone|pixel|galaxy|\bnote\s?\d|\bs\d{2}\b|\ba\d{2}s?\b|redmi|xiaomi|huawei|oneplus|android|motorola|\bmoto\b|smartphone|handy|phone"))
            return DeviceType.Phone;
        if (Has(names, @"printer|drucker|imprimante|impresora|\bmfc|laserjet|officejet|deskjet")) return DeviceType.Printer;
        if (Has(names, @"\bnas\b|diskstation|synology|qnap")) return DeviceType.Nas;
        if (Has(names, @"sonos|roku|bose|yamaha|denon")) return DeviceType.MediaPlayer;
        if (Has(names, @"\besp|shelly|tasmota|sonoff|tuya|zigbee|homematic|homepilot|magic[-_ ]?home|x[-_ ]?sense|rauchmelder|landroid|\bworx|m[äa]h[-_ ]?roboter|mower|dreo|heizl[üu]fter|l[üu]fter|ventilator"))
            return DeviceType.Iot;
        return null;
    }
}
