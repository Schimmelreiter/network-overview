using NetworkOverview.Core.Devices;
using NetworkOverview.Core.Discovery;
using NetworkOverview.Core.Lltd;
using NetworkOverview.Core.Localization;
using NetworkOverview.Core.Platform;

namespace NetworkOverview.Core.Model;

/// <summary>All raw data of one scan.</summary>
public sealed class ScanData
{
    public AdapterInfo Adapter { get; init; } = new();
    public string ComputerName { get; init; } = Environment.MachineName;
    public List<Neighbor> Neighbors { get; init; } = new();
    public List<OpenWrtInfo> OpenWrt { get; init; } = new();
    public List<NsdpDevice> Nsdp { get; init; } = new();
    public List<MdnsHost> Mdns { get; init; } = new();
    public List<SsdpDevice> Ssdp { get; init; } = new();
    public WlanInfo? Wlan { get; init; }
    public List<LltdHost> LltdHosts { get; init; } = new();
    public List<TNode> Tree { get; init; } = new();
    public Dictionary<string, string> ReverseNames { get; init; } = new();
}

/// <summary>Merges LLTD, ARP, OpenWrt, NSDP and mDNS data into one tree rooted at the Internet.</summary>
public static class ModelBuilder
{
    static readonly System.Text.RegularExpressions.Regex WifiPort = new("^(wlan|phy|wl|ra|rai|ath|mesh|wds|sta)", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    public static NetworkModel Build(ScanData d)
    {
        var m = new NetworkModel();
        var ad = d.Adapter;
        var index = new Dictionary<string, string>();      // MAC -> node key
        Node? ByMac(string mac) => mac.Length > 0 && index.TryGetValue(mac, out var k) && m.Contains(k) ? m[k] : null;

        // IPs and names from every source
        var ipByMac = new Dictionary<string, string>();
        var nameByMac = new Dictionary<string, string>();
        foreach (var o in d.OpenWrt.Where(o => o.Ok))
        {
            foreach (var (mac, ip) in o.Arp) ipByMac.TryAdd(mac, ip);
            foreach (var (mac, l) in o.Leases) { ipByMac[mac] = l.IPv4; if (l.Name.Length > 0) nameByMac[mac] = l.Name; }
        }
        var arp = new Dictionary<string, string>();
        foreach (var nb in d.Neighbors) { arp.TryAdd(nb.Mac, nb.IPv4); ipByMac[nb.Mac] = nb.IPv4; }

        // 1. LLTD responders
        foreach (var h in d.LltdHosts)
        {
            var n = m.Add(new Node
            {
                Key = h.Mac, Mac = h.Mac, Lltd = true, Name = h.Name, IPv4 = h.IPv4, IPv6 = h.IPv6,
                Wireless = h.IsWireless, Bssid = h.Bssid, Ssid = h.Ssid, Tlvs = h.Tlvs,
                Medium = MediumName(h.Medium), Speed = h.LinkSpeedBps > 0 ? MacUtil.FormatSpeed(h.LinkSpeedBps) : "",
                Signal = h.HasRssi ? h.Rssi + " dBm" : "",
            });
            index[n.Mac] = n.Key;
        }

        // 2. this computer
        var self = ByMac(ad.Mac);
        if (self == null)
        {
            self = m.Add(new Node { Key = ad.Mac, Mac = ad.Mac, Medium = MediumName(ad.Wireless ? 71u : 6u) });
            index[ad.Mac] = self.Key;
        }
        self.IsSelf = true;
        if (self.Name.Length == 0) self.Name = d.ComputerName;
        if (self.IPv4.Length == 0) self.IPv4 = ad.IPv4;
        if (self.Speed.Length == 0 && ad.SpeedBps > 0) self.Speed = MacUtil.FormatSpeed(ad.SpeedBps);
        if (ad.Wireless)
        {
            self.Wireless = true;
            if (d.Wlan != null)
            {
                if (self.Bssid.Length == 0) self.Bssid = d.Wlan.Bssid;
                if (self.Ssid.Length == 0) self.Ssid = d.Wlan.Ssid;
            }
        }

        // 3. OpenWrt devices
        foreach (var o in d.OpenWrt.Where(o => o.Ok))
        {
            Node? n = null;
            foreach (var mac in o.Interfaces.Values) { n = ByMac(mac); if (n != null) break; }
            n ??= m.Add(new Node { Key = o.MainMac, Mac = o.MainMac });
            n.OpenWrt = o;
            if (o.Name.Length > 0) n.Name = o.Name;
            if (System.Net.IPAddress.TryParse(o.Host, out _)) n.IPv4 = o.Host;
            n.Model = "OpenWrt";
            n.Kind = o.WifiSsid.Count > 0 ? NodeKind.AccessPoint : NodeKind.Router;
            foreach (var mac in o.Interfaces.Values.Distinct())
            {
                if (!n.AltMacs.Contains(mac)) n.AltMacs.Add(mac);
                index.TryAdd(mac, n.Key);
            }
            index[n.Mac] = n.Key;
        }

        // 4. Netgear switches (NSDP)
        foreach (var s in d.Nsdp)
        {
            var mac = MacUtil.Normalize(s.Mac);
            var n = ByMac(mac) ?? m.Add(new Node { Key = mac, Mac = mac });
            index[mac] = n.Key;
            n.Kind = NodeKind.ManagedSwitch; n.Managed = true;
            n.Name = s.Name.Length > 0 ? s.Name : s.Model;
            n.Model = s.Model;
            if (s.IPv4.Length > 0 && s.IPv4 != "0.0.0.0") n.IPv4 = s.IPv4;
            n.Ports = string.Join("  ", s.Ports);
        }

        // 5. further devices from ARP caches and Wi-Fi station lists
        foreach (var mac in arp.Keys.Concat(d.OpenWrt.Where(o => o.Ok).SelectMany(o => o.Stations.Keys)))
        {
            if (index.ContainsKey(mac)) continue;
            m.Add(new Node { Key = mac, Mac = mac });
            index[mac] = mac;
        }
        var other = new HashSet<string>(m.All.Where(n => !n.Lltd && !n.IsSelf && n.OpenWrt == null && !n.Managed).Select(n => n.Key));

        // 6. names, addresses, port info, Wi-Fi data, mDNS
        foreach (var n in m.All)
        {
            if (n.Mac.Length == 0) continue;
            if (n.IPv4.Length == 0 && ipByMac.TryGetValue(n.Mac, out var ip)) n.IPv4 = ip;
            if (n.Name.Length == 0 && nameByMac.TryGetValue(n.Mac, out var nm)) n.Name = nm;
        }
        foreach (var o in d.OpenWrt.Where(o => o.Ok))
        {
            var owNode = ByMac(o.MainMac);
            string dev = o.Name.Length > 0 ? o.Name : o.Host;
            foreach (var (mac, port) in o.Fdb)
            {
                var n = ByMac(mac);
                if (n != null && n != owNode && !WifiPort.IsMatch(port)) n.SeenAt.Add($"{dev} : {port}");
            }
            foreach (var (mac, st) in o.Stations)
            {
                var n = ByMac(mac);
                if (n == null || n.OpenWrt != null) continue;    // OpenWrt devices: see repeaters below
                n.Wireless = true;
                if (n.Medium.Length == 0) n.Medium = MediumName(71);
                o.WifiSsid.TryGetValue(st.Interface, out var ssid);
                n.Ssid = ssid ?? "";
                n.Signal = st.Signal + " dBm";
                if (o.Interfaces.TryGetValue(st.Interface, out var bssid)) n.Bssid = bssid;
                if (owNode != null) n.ApKey = owNode.Key;
            }
        }
        // OpenWrt devices connected via Wi-Fi to another OpenWrt AP (repeater / mesh / WDS). With WDS and
        // mesh both sides list each other as stations; the repeater is the one that reaches the gateway
        // through a Wi-Fi port (bridge forwarding table). The station address may differ slightly from the
        // interface addresses (locally administered variants).
        string gwMac = d.Neighbors.FirstOrDefault(nb => ad.Gateway.Length > 0 && nb.IPv4 == ad.Gateway)?.Mac
                       ?? d.OpenWrt.FirstOrDefault(o => o.Ok && o.Host == ad.Gateway)?.MainMac ?? "";
        bool? WifiUplink(OpenWrtInfo o)
        {
            if (gwMac.Length == 0 || o.MainMac == gwMac || o.Interfaces.Values.Contains(gwMac)) return gwMac.Length == 0 ? null : false;
            return o.Fdb.TryGetValue(gwMac, out var port) ? WifiPort.IsMatch(port) : null;
        }
        List<string> MacsOf(OpenWrtInfo o) => o.Interfaces.Values.Append(o.MainMac).Distinct().ToList();
        bool Lists(OpenWrtInfo ap, OpenWrtInfo x) => ap.Stations.Keys.Any(k => MacsOf(x).Any(m => MacUtil.SameDevice(m, k)));
        foreach (var o in d.OpenWrt.Where(o => o.Ok))
        {
            var apNode = ByMac(o.MainMac);
            if (apNode == null) continue;
            foreach (var o2 in d.OpenWrt.Where(x => x.Ok && x != o))
            {
                var rep = ByMac(o2.MainMac);
                if (rep == null || rep == apNode || rep.ApKey.Length > 0 || rep.IsGateway || o2.Host == ad.Gateway) continue;
                var macs = MacsOf(o2);
                var st = o.Stations.FirstOrDefault(kv => macs.Any(m => MacUtil.SameDevice(m, kv.Key)));
                if (st.Key == null) continue;
                bool? upRep = WifiUplink(o2), upAp = WifiUplink(o);
                if (upRep == false) continue;                          // reaches the gateway by cable
                if (upRep == null && (upAp == true || Lists(o2, o))) continue;   // direction unknown
                if (apNode.ApKey == rep.Key) continue;                 // never create a cycle
                rep.Wireless = true;
                rep.Medium = MediumName(71);
                rep.ApKey = apNode.Key;
                o.WifiSsid.TryGetValue(st.Value.Interface, out var ssid);
                rep.Ssid = ssid ?? rep.Ssid;
                rep.Signal = st.Value.Signal + " dBm";
            }
        }
        var mdnsByIp = d.Mdns.GroupBy(h => h.IPv4).ToDictionary(g => g.Key, g => g.First());
        var ssdpByIp = d.Ssdp.Where(x => x.IPv4.Length > 0).GroupBy(x => x.IPv4).ToDictionary(g => g.Key, g => g.First());
        foreach (var n in m.All)
        {
            if (n.Mac.Length > 0) n.Vendor = VendorDb.Lookup(n.Mac);
            if (n.IPv4.Length > 0 && mdnsByIp.TryGetValue(n.IPv4, out var mh))
            {
                if (n.Name.Length == 0) n.Name = mh.FriendlyName() ?? "";
                if (n.Model.Length == 0) n.Model = mh.Model() ?? "";
                n.MdnsServices.AddRange(mh.Services.Select(s => s.Type.Replace(".local", "")).Distinct());
            }
            if (n.IPv4.Length > 0 && ssdpByIp.TryGetValue(n.IPv4, out var sd))
            {
                if (n.Name.Length == 0) n.Name = sd.FriendlyName;
                if (n.Model.Length == 0) n.Model = sd.Model;
                if (n.Vendor.Length == 0) n.Vendor = sd.Manufacturer;
            }
            if (n.Name.Length == 0 && n.IPv4.Length > 0 && d.ReverseNames.TryGetValue(n.IPv4, out var rn)) n.Name = rn;
        }

        // Netgear switches that do not answer NSDP (newer firmware defaults to "web browser only"):
        // recognized by UPnP model or by the vendor of their MAC address.
        foreach (var n in m.All)
        {
            if (n.Lltd || n.IsSelf || n.OpenWrt != null || n.Managed || n.Wireless || n.IPv4 == ad.Gateway) continue;
            ssdpByIp.TryGetValue(n.IPv4, out var sd);
            bool upnpSwitch = sd != null && Has(sd.Manufacturer, "netgear") && Has(sd.ModelName + " " + sd.ModelNumber, @"\b(GS|XS|MS|JGS|GC)\d");
            bool macSwitch = Has(n.Vendor, @"^netgear") && (n.Name.Length == 0 || Has(n.Name, @"switch|\bgs\d|\bxs\d"));
            if (!upnpSwitch && !macSwitch) continue;
            n.Kind = NodeKind.ManagedSwitch;
            n.Managed = true;
            if (n.Name.Length == 0) n.Name = n.Model.Length > 0 ? "Netgear " + n.Model : "Netgear";
        }
        foreach (var n in m.All.Where(n => n.Managed && n.IPv4.Length > 0 && ad.IPv4.Length > 0 && !MacUtil.SameSubnet(n.IPv4, ad.IPv4, ad.Prefix)))
            n.Notes.Add(L.T("IpOutsideNetwork", n.IPv4));

        // 7. gateway + Internet
        Node? gw = null;
        if (ad.Gateway.Length > 0)
        {
            gw = m.All.FirstOrDefault(n => n.IPv4 == ad.Gateway)
                 ?? m.Add(new Node { Key = "#gateway", IPv4 = ad.Gateway, Virtual = true });
            gw.Kind = NodeKind.Gateway; gw.IsGateway = true;
            other.Remove(gw.Key);
            m.Add(new Node { Key = "#internet", Kind = NodeKind.Internet, Name = "Internet", Virtual = true });
        }

        // 8. tree found by the LLTD topology tests
        bool hasTree = d.Tree.Count > 1;
        if (hasTree)
        {
            foreach (var t in d.Tree.Where(t => t.IsSwitch))
                m.Add(new Node
                {
                    Key = "#" + t.Id, Kind = NodeKind.Switch, Name = "Switch", Virtual = true, Inferred = true,
                    Members = t.Members.Count, Parent = string.IsNullOrEmpty(t.Parent) ? null : "#" + t.Parent,
                });
            foreach (var t in d.Tree.Where(t => !t.IsSwitch))
            {
                var n = ByMac(t.Mac);
                if (n != null) { n.Parent = "#" + t.Parent; n.InTree = true; other.Remove(n.Key); }
            }
        }

        // 9. name infrastructure
        foreach (var n in m.All.Where(n => n.Kind == NodeKind.ManagedSwitch).ToList())
        {
            var s = m.ParentOf(n);
            if (s == null || s.Kind != NodeKind.Switch || s.Managed) continue;
            // a switch's management MAC hangs off its own switch fabric: merge both nodes
            s.Name = n.Name; s.Model = n.Model; s.IPv4 = n.IPv4; s.Mac = n.Mac; s.Ports = n.Ports;
            s.Vendor = n.Vendor; s.Virtual = false; s.Managed = true; s.SeenAt.AddRange(n.SeenAt); s.Notes.AddRange(n.Notes);
            foreach (var c in m.ChildrenOf(n.Key).ToList()) c.Parent = s.Key;
            m.Remove(n.Key);
        }
        foreach (var ow in m.All.Where(n => n.OpenWrt != null && m.ParentOf(n) != null).ToList())
        {
            // the internal switch of an OpenWrt device is only detectable if >= 2 of its LAN ports see tree devices
            var ports = new HashSet<string>();
            foreach (var (mac, port) in ow.OpenWrt!.Fdb)
                if (ByMac(mac) is { InTree: true } && !WifiPort.IsMatch(port)) ports.Add(port);
            var s = m.ParentOf(ow)!;
            if (ports.Count >= 2 && s.Kind == NodeKind.Switch && !s.Managed && s.Name == "Switch")
            {
                s.Name = L.T("LanSwitchOf") + " " + ow.Title;
                s.Virtual = false;
            }
        }

        // 10. hang the tree off the gateway
        if (gw != null)
        {
            if (hasTree && gw.Parent != null) Reroot(m, gw.Key);
            else if (hasTree && m.Contains("#S0")) m["#S0"].Parent = gw.Key;
            gw.Parent = "#internet";
        }
        Node? top = null;
        if (hasTree)
        {
            if (gw != null) top = m.ChildrenOf(gw.Key).FirstOrDefault(n => n.Kind == NodeKind.Switch);
            if (top == null && m.Contains("#S0")) top = m["#S0"];
        }

        // 11. wireless devices to their access point
        foreach (var n in m.All.ToList())
        {
            if (!n.Wireless || n.IsGateway || n.Kind is NodeKind.Internet or NodeKind.Switch) continue;
            Node? ap = n.ApKey.Length > 0 && m.Contains(n.ApKey) ? m[n.ApKey] : null;
            if (ap == null && n.Bssid.Length > 0)
                ap = m.All.FirstOrDefault(x => x.Key != n.Key && !x.Wireless &&
                        ((x.Mac.Length > 0 && MacUtil.SameDevice(x.Mac, n.Bssid)) ||
                         x.AltMacs.Any(a => MacUtil.SameDevice(a, n.Bssid)) ||
                         (x.Virtual && x.Kind == NodeKind.AccessPoint && MacUtil.SameDevice(x.Bssid, n.Bssid))));
            if (ap == null)
            {
                var vk = n.Bssid.Length > 0 ? "#ap-" + n.Bssid : "#ap-unknown";
                ap = m.Contains(vk) ? m[vk] : m.Add(new Node
                {
                    Key = vk, Kind = NodeKind.AccessPoint, Virtual = true, Bssid = n.Bssid, Ssid = n.Ssid,
                    Name = L.T("WirelessAccessPoint"),
                });
            }
            if (ap.Key == n.Key) continue;
            if (ap.Kind == NodeKind.Device) { ap.Kind = NodeKind.AccessPoint; other.Remove(ap.Key); }
            if (ap.Ssid.Length == 0) ap.Ssid = n.Ssid;
            ap.HasWifiClients = true;
            n.Parent = ap.Key; n.Dashed = true;
            other.Remove(n.Key);
        }

        // 12. attach the rest (devices without position stay in the "other devices" area)
        bool needSwitch = false;
        foreach (var n in m.All.ToList())
        {
            if (n.Parent != null || n.IsGateway || n.Kind == NodeKind.Internet || other.Contains(n.Key)) continue;
            if (n.Kind == NodeKind.ManagedSwitch && hasTree) continue;
            if (top != null) n.Parent = top.Key;
            else { n.Parent = "#switch"; needSwitch = true; }
        }
        if (needSwitch)
            m.Add(new Node { Key = "#switch", Kind = NodeKind.Switch, Name = "Switch", Virtual = true, Parent = gw?.Key });

        // 13. drop empty or pass-through inferred switches
        bool changed = true;
        while (changed)
        {
            changed = false;
            foreach (var s in m.All.Where(n => n.Kind == NodeKind.Switch && n.Virtual).ToList())
            {
                var kids = m.ChildrenOf(s.Key).ToList();
                if (kids.Count == 0) { m.Remove(s.Key); changed = true; }
                else if (kids.Count == 1 && s.Parent != null && s.Inferred)
                {
                    // a switch with one child is not detectable; it remains when its devices moved to their AP
                    kids[0].Parent = s.Parent; m.Remove(s.Key); changed = true;
                }
            }
        }

        // 14. device types
        foreach (var n in m.All)
        {
            if (n.Kind != NodeKind.Device) continue;
            mdnsByIp.TryGetValue(n.IPv4, out var mh);
            ssdpByIp.TryGetValue(n.IPv4, out var sd);
            n.DeviceType = DeviceClassifier.Classify(n.Vendor, n.Name, mh, n.Lltd, sd?.Model, n.Wireless ? true : n.InTree ? false : null);
        }
        return m;
    }

    static bool Has(string? s, string pattern) => s != null && System.Text.RegularExpressions.Regex.IsMatch(s, pattern, System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    static void Reroot(NetworkModel m, string rootKey)
    {
        var adj = new Dictionary<string, List<string>>();
        void Link(string a, string b)
        {
            if (!adj.TryGetValue(a, out var l)) adj[a] = l = new List<string>();
            l.Add(b);
        }
        foreach (var n in m.All)
            if (n.Parent != null && m.Contains(n.Parent)) { Link(n.Key, n.Parent); Link(n.Parent, n.Key); }
        var seen = new HashSet<string> { rootKey };
        var q = new Queue<string>();
        q.Enqueue(rootKey);
        while (q.Count > 0)
        {
            var u = q.Dequeue();
            if (!adj.TryGetValue(u, out var vs)) continue;
            foreach (var v in vs)
                if (seen.Add(v)) { m[v].Parent = u; q.Enqueue(v); }
        }
    }

    public static string MediumName(uint ifType) => ifType switch
    {
        0 => "",
        6 => "Ethernet",
        71 => L.T("MediumWifi"),
        _ => "ifType " + ifType,
    };
}
