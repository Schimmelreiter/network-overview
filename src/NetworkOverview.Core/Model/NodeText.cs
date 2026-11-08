using NetworkOverview.Core.Localization;

namespace NetworkOverview.Core.Model;

/// <summary>Localized descriptions of nodes for tooltips, details and the device list.</summary>
public static class NodeText
{
    public static string TypeName(Node n) => n.Kind switch
    {
        NodeKind.Gateway => L.T("Gateway"),
        NodeKind.AccessPoint => L.T("Kind_AccessPoint"),
        NodeKind.Router => L.T("Kind_Router"),
        NodeKind.Switch or NodeKind.ManagedSwitch => L.T("Kind_Switch"),
        NodeKind.Internet => "Internet",
        _ => L.T("DT_" + n.DeviceType),
    };

    public static string Details(Node n, NetworkModel m)
    {
        var l = new List<string> { n.Title };
        if (n.IsSelf) l.Add(L.T("ThisComputer"));
        if (n.Kind != NodeKind.Internet) l.Add(L.T("Type", TypeName(n)));
        if (n.Model.Length > 0) l.Add(L.T("Model", n.Model));
        if (n.Vendor.Length > 0) l.Add(L.T("Vendor", n.Vendor));
        if (n.IPv4.Length > 0) l.Add("IPv4: " + n.IPv4);
        if (n.IPv6.Length > 0) l.Add("IPv6: " + n.IPv6);
        if (n.Mac.Length > 0) l.Add("MAC: " + n.Mac);
        if (n.Medium.Length > 0) l.Add(L.T("Medium", n.Medium));
        if (n.Speed.Length > 0) l.Add(L.T("Link", n.Speed));
        if (n.Ssid.Length > 0) l.Add("SSID: " + n.Ssid);
        if (n.Bssid.Length > 0) l.Add("BSSID: " + n.Bssid);
        if (n.Signal.Length > 0) l.Add(L.T("Signal", n.Signal));
        if (n.Ports.Length > 0) l.Add(L.T("Ports", n.Ports));
        foreach (var s in n.SeenAt) l.Add(L.T("SeenAt", s));
        if (n.MdnsServices.Count > 0) l.Add(L.T("Services", string.Join(", ", n.MdnsServices)));
        var p = m.ParentOf(n);
        if (p != null) l.Add(L.T("ConnectedTo", p.Title));
        if (n.Inferred && !n.Managed) l.Add(L.T("InferredSwitch", n.Members));
        else if (n.Virtual && n.Kind != NodeKind.Internet) l.Add(L.T("Inferred"));
        if (!n.Virtual && n.Kind != NodeKind.Switch) l.Add(n.Lltd ? L.T("LltdYes") : L.T("LltdNo"));
        if (n.Tlvs.Length > 0) l.Add("TLVs: " + n.Tlvs);
        return string.Join(Environment.NewLine, l);
    }

    public static string Subtitle(Node n)
    {
        if (n.Kind == NodeKind.AccessPoint && n.Ssid.Length > 0) return n.Ssid;
        if (n.Managed && n.Model.Length > 0 && n.Model != n.Title) return n.Model;
        if (n.IPv4.Length > 0 && n.Title != n.IPv4 && n.Kind is not (NodeKind.Internet or NodeKind.Switch)) return n.IPv4;
        return "";
    }
}
