using System.Drawing.Imaging;
using NetworkOverview.Core;
using NetworkOverview.Core.Devices;
using NetworkOverview.Core.Layout;
using NetworkOverview.Core.Model;

namespace NetworkOverview;

/// <summary>Renders an example network (used for documentation and CI visual checks):
/// NetworkOverview.exe --render-demo light.png dark.png</summary>
internal static class Demo
{
    public static NetworkModel Model()
    {
        var m = new NetworkModel();
        Node Add(string key, string name, string? parent, NodeKind kind = NodeKind.Device, DeviceType type = DeviceType.Computer,
                 string ip = "", bool wifi = false, bool lltd = false)
            => m.Add(new Node { Key = key, Name = name, Parent = parent, Kind = kind, DeviceType = type, IPv4 = ip, Wireless = wifi, Dashed = wifi, Lltd = lltd });

        m.Add(new Node { Key = "#internet", Name = "Internet", Kind = NodeKind.Internet });
        Add("gw", "Link", "#internet", NodeKind.Gateway, ip: "192.168.75.1").HasWifiClients = true;
        var lan = Add("lan", "LAN switch Link", "gw", NodeKind.Switch);
        lan.Inferred = true;
        Add("nas", "Diskstation", "lan", type: DeviceType.Nas, ip: "192.168.75.10", lltd: true);
        var big = Add("big", "Switch", "lan", NodeKind.Switch);
        big.Inferred = true;
        var self = Add("self", "QUATTRO", "big", ip: "192.168.75.60", lltd: true);
        self.IsSelf = true;
        Add("pc2", "WERKSTATT", "big", ip: "192.168.75.61", lltd: true);
        Add("prn", "Brother-MFC", "big", type: DeviceType.Printer, ip: "192.168.75.30");
        var gs = Add("gs1", "Buero", "big", NodeKind.Switch, ip: "192.168.75.3");
        gs.Managed = true; gs.Model = "GS108Ev3";
        Add("ha", "homeassistant", "gs1", type: DeviceType.Computer, ip: "192.168.75.20", lltd: true);
        Add("tv", "Wohnzimmer-TV", "gs1", type: DeviceType.Tv, ip: "192.168.75.40");
        Add("vu", "ultimo4k", "gs1", type: DeviceType.Receiver, ip: "192.168.75.22", lltd: true);
        var ap = Add("ap", "AP-Flur", "big", NodeKind.AccessPoint, ip: "192.168.75.6");
        ap.Ssid = "HomeNet"; ap.HasWifiClients = true;
        Add("show", "Echo-Show-Kueche", "ap", type: DeviceType.EchoShow, ip: "192.168.75.150", wifi: true);
        Add("spot", "Echo-Spot-SZ", "ap", type: DeviceType.EchoSpot, ip: "192.168.75.151", wifi: true);
        Add("fire", "Fire-TV-Stick", "ap", type: DeviceType.FireTv, ip: "192.168.75.152", wifi: true);
        Add("echo", "Echo-WZ", "gw", type: DeviceType.EchoDot, ip: "192.168.75.28", wifi: true);
        Add("note", "Note20-Ultra-von-Silvia", "gw", type: DeviceType.Phone, ip: "192.168.75.101", wifi: true);
        Add("tab", "Galaxy-Tab", "gw", type: DeviceType.Tablet, ip: "192.168.75.110", wifi: true);
        Add("mini", "Google-Home-Mini", "gw", type: DeviceType.GoogleSpeaker, ip: "192.168.75.244", wifi: true);
        Add("hub", "Nest-Hub", "gw", type: DeviceType.GoogleDisplay, ip: "192.168.75.245", wifi: true);
        Add("cc", "Chromecast", "gw", type: DeviceType.Chromecast, ip: "192.168.75.247", wifi: true);
        Add("esp", "ems-esp", "gw", type: DeviceType.HeatingController, ip: "192.168.75.246", wifi: true);
        Add("tc", "Buderus", "gw", type: DeviceType.HeatingController, ip: "192.168.75.248", wifi: true);
        Add("plug", "shelly-plug", "gw", type: DeviceType.Iot, ip: "192.168.75.249", wifi: true);
        Add("unk", "", null, ip: "192.168.75.170");
        Add("unk2", "Sonos-Bad", null, type: DeviceType.MediaPlayer, ip: "192.168.75.171");
        return m;
    }

    public static void Render(string lightPath, string darkPath)
    {
        var m = Model();
        var r = new ScanResult { Model = m, Layout = TreeLayout.Run(m) };
        foreach (var (path, theme) in new[] { (lightPath, Theme.LightTheme), (darkPath, Theme.DarkTheme) })
        {
            using var bmp = new Bitmap((int)r.Layout.Width + 1, (int)r.Layout.Height + 1);
            using (var g = Graphics.FromImage(bmp))
            {
                g.Clear(theme.Background);
                MapView.Render(g, r, theme, null);
            }
            bmp.Save(path, ImageFormat.Png);
        }
    }
}
