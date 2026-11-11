using NetworkOverview.Core.Devices;
using NetworkOverview.Core.Discovery;

namespace NetworkOverview.Core.Model;

public enum NodeKind
{
    Device,         // end device (computer, phone, speaker, ...)
    Gateway,        // default gateway / router
    AccessPoint,    // wireless access point (incl. OpenWrt APs)
    Router,         // OpenWrt device without Wi-Fi that is not the gateway
    Switch,         // switch (inferred by LLTD or identified via NSDP)
    ManagedSwitch,  // NSDP switch whose position is unknown
    Internet,
}

public sealed class Node
{
    public string Key { get; init; } = "";
    public NodeKind Kind { get; set; } = NodeKind.Device;
    public DeviceType DeviceType { get; set; } = DeviceType.Computer;
    public string Name { get; set; } = "";
    public string IPv4 { get; set; } = "";
    public string IPv6 { get; set; } = "";
    public string Mac { get; set; } = "";
    public List<string> AltMacs { get; } = new();
    public string Vendor { get; set; } = "";
    public string Model { get; set; } = "";
    public bool Lltd { get; set; }
    public bool Virtual { get; set; }
    public bool Inferred { get; set; }
    public bool Managed { get; set; }
    public int Members { get; set; }
    public bool Wireless { get; set; }
    public string Bssid { get; set; } = "";
    public string Ssid { get; set; } = "";
    public string Speed { get; set; } = "";
    public string Signal { get; set; } = "";
    public string Medium { get; set; } = "";
    public string Ports { get; set; } = "";
    public string Tlvs { get; set; } = "";
    public List<string> SeenAt { get; } = new();
    public List<string> MdnsServices { get; } = new();
    public List<string> Notes { get; } = new();
    public string? Parent { get; set; }
    public bool Dashed { get; set; }
    public bool IsSelf { get; set; }
    public bool IsGateway { get; set; }
    public bool HasWifiClients { get; set; }
    public bool InTree { get; set; }
    public string ApKey { get; set; } = "";
    [System.Text.Json.Serialization.JsonIgnore] public OpenWrtInfo? OpenWrt { get; set; }
    /// <summary>How the device type was determined (localization key Src_*) and a short detail.</summary>
    public string Source { get; set; } = "";
    public string SourceDetail { get; set; } = "";
    public string OpenPorts { get; set; } = "";
    public string DhcpVendor { get; set; } = "";
    /// <summary>Video streams offered by the device (e.g. motionEye MJPEG streams).</summary>
    public List<string> Streams { get; } = new();

    // layout
    public float X { get; set; }
    public float Y { get; set; }
    public int Col { get; set; }
    public bool Placed => Y > 0;

    public string Title
    {
        get
        {
            if (Name.Length > 0) return Name;
            return Kind switch
            {
                NodeKind.Gateway => Localization.L.T("Gateway"),
                NodeKind.Switch or NodeKind.ManagedSwitch => "Switch",
                NodeKind.Internet => "Internet",
                NodeKind.AccessPoint => Localization.L.T("WirelessAccessPoint"),
                _ => IPv4.Length > 0 ? IPv4 : Mac,
            };
        }
    }
}

public sealed class NetworkModel
{
    public Dictionary<string, Node> Nodes { get; } = new();
    public List<string> Order { get; } = new();

    public IEnumerable<Node> All => Order.Where(Nodes.ContainsKey).Select(k => Nodes[k]);
    public bool Contains(string? key) => key != null && Nodes.ContainsKey(key);
    public Node this[string key] => Nodes[key];

    public Node Add(Node n)
    {
        if (!Nodes.ContainsKey(n.Key)) Order.Add(n.Key);
        Nodes[n.Key] = n;
        return n;
    }

    public void Remove(string key)
    {
        Nodes.Remove(key);
        Order.Remove(key);
    }

    public Node? ParentOf(Node n) => n.Parent != null && Nodes.TryGetValue(n.Parent, out var p) ? p : null;
    public IEnumerable<Node> ChildrenOf(string key) => All.Where(n => n.Parent == key);
}
