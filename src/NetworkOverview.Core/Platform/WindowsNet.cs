using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkOverview.Core.Platform;

public sealed class AdapterInfo
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string Id { get; init; } = "";          // "{GUID}"
    public int Index { get; init; }
    public string Mac { get; init; } = "";
    public string IPv4 { get; init; } = "";
    public int Prefix { get; init; } = 24;
    public string Gateway { get; init; } = "";
    public bool Wireless { get; init; }
    public long SpeedBps { get; init; }
    public string NpcapDevice => @"\Device\NPF_" + Id;
    public override string ToString() => $"{Name} – {(IPv4.Length > 0 ? IPv4 : Description)}";
}

public sealed class Neighbor
{
    public string IPv4 { get; init; } = "";
    public string Mac { get; init; } = "";
}

public sealed class WlanInfo
{
    public string Ssid { get; set; } = "";
    public string Bssid { get; set; } = "";
}

/// <summary>Windows network information (adapters, ARP cache, Wi-Fi) and helpers.</summary>
public static class WindowsNet
{
    /// <summary>Sends a Wake-on-LAN magic packet (UDP 9 and 7) to the broadcast addresses.</summary>
    public static void WakeOnLan(string mac, string localIp, int prefix)
    {
        var m = MacUtil.Normalize(mac).Split(':').Select(x => Convert.ToByte(x, 16)).ToArray();
        if (m.Length != 6) return;
        var packet = new byte[102];
        for (int i = 0; i < 6; i++) packet[i] = 0xFF;
        for (int r = 0; r < 16; r++) Array.Copy(m, 0, packet, 6 + r * 6, 6);
        var targets = new List<System.Net.IPAddress> { System.Net.IPAddress.Broadcast };
        if (localIp.Length > 0)
        {
            var b = System.Net.IPAddress.Parse(localIp).GetAddressBytes();
            uint v = (uint)(b[0] << 24 | b[1] << 16 | b[2] << 8 | b[3]);
            uint bc = v | ~(prefix == 0 ? 0 : uint.MaxValue << (32 - prefix));
            targets.Add(new System.Net.IPAddress(new[] { (byte)(bc >> 24), (byte)(bc >> 16), (byte)(bc >> 8), (byte)bc }));
        }
        using var udp = new System.Net.Sockets.UdpClient(localIp.Length > 0 ? new System.Net.IPEndPoint(System.Net.IPAddress.Parse(localIp), 0) : new System.Net.IPEndPoint(System.Net.IPAddress.Any, 0)) { EnableBroadcast = true };
        foreach (var t in targets)
            foreach (var port in new[] { 9, 7 })
                for (int i = 0; i < 3; i++) udp.Send(packet, packet.Length, new System.Net.IPEndPoint(t, port));
    }

    public static List<AdapterInfo> GetAdapters()
    {
        var list = new List<(AdapterInfo, bool)>();
        foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (ni.OperationalStatus != OperationalStatus.Up) continue;
            if (ni.NetworkInterfaceType is NetworkInterfaceType.Loopback or NetworkInterfaceType.Tunnel) continue;
            var mac = MacUtil.Normalize(ni.GetPhysicalAddress().ToString());
            if (!MacUtil.IsUsable(mac)) continue;
            IPInterfaceProperties props;
            try { props = ni.GetIPProperties(); } catch (NetworkInformationException) { continue; }
            var ua = props.UnicastAddresses.FirstOrDefault(a => a.Address.AddressFamily == AddressFamily.InterNetwork
                                                               && !a.Address.ToString().StartsWith("169.254."));
            var gw = props.GatewayAddresses.FirstOrDefault(g => g.Address.AddressFamily == AddressFamily.InterNetwork
                                                               && !g.Address.Equals(IPAddress.Any));
            int index = 0;
            try { index = props.GetIPv4Properties()?.Index ?? 0; } catch (NetworkInformationException) { }
            var info = new AdapterInfo
            {
                Name = ni.Name,
                Description = ni.Description,
                Id = ni.Id,
                Index = index,
                Mac = mac,
                IPv4 = ua?.Address.ToString() ?? "",
                Prefix = ua?.PrefixLength ?? 24,
                Gateway = gw?.Address.ToString() ?? "",
                Wireless = ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211,
                SpeedBps = ni.Speed,
            };
            list.Add((info, gw != null));
        }
        return list.OrderByDescending(x => x.Item2).ThenByDescending(x => x.Item1.IPv4.Length > 0).ThenBy(x => x.Item1.Name)
                   .Select(x => x.Item1).ToList();
    }

    // ---------------- ARP / neighbor cache (GetIpNetTable2) ----------------
    [DllImport("iphlpapi.dll")]
    static extern int GetIpNetTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll")]
    static extern void FreeMibTable(IntPtr table);

    const int RowSize = 88;           // sizeof(MIB_IPNET_ROW2) on x86/x64/arm64
    const int OffIfIndex = 28, OffPhys = 40, OffPhysLen = 72, OffState = 76;

    public static List<Neighbor> GetNeighbors(int interfaceIndex)
    {
        var res = new List<Neighbor>();
        if (!OperatingSystem.IsWindows()) return res;
        if (GetIpNetTable2(2 /* AF_INET */, out var table) != 0) return res;
        try
        {
            int count = Marshal.ReadInt32(table);
            IntPtr row = table + 8;
            for (int i = 0; i < count; i++, row += RowSize)
            {
                int ifIndex = Marshal.ReadInt32(row, OffIfIndex);
                int state = Marshal.ReadInt32(row, OffState);       // 0 unreachable, 1 incomplete, 2..6 usable
                int len = Marshal.ReadInt32(row, OffPhysLen);
                if (ifIndex != interfaceIndex || state < 2 || len != 6) continue;
                var ip = new IPAddress(new[] { Marshal.ReadByte(row, 4), Marshal.ReadByte(row, 5), Marshal.ReadByte(row, 6), Marshal.ReadByte(row, 7) });
                var macBytes = new byte[6];
                Marshal.Copy(row + OffPhys, macBytes, 0, 6);
                var mac = MacUtil.Normalize(Convert.ToHexString(macBytes));
                if (MacUtil.IsUsable(mac)) res.Add(new Neighbor { IPv4 = ip.ToString(), Mac = mac });
            }
        }
        finally { FreeMibTable(table); }
        return res;
    }

    // ---------------- Wi-Fi (netsh, keys are not localized) ----------------
    public static WlanInfo GetWlanInfo(string interfaceName)
    {
        var res = new WlanInfo();
        try
        {
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
            var psi = new ProcessStartInfo("netsh.exe", "wlan show interfaces")
            {
                UseShellExecute = false, RedirectStandardOutput = true, CreateNoWindow = true,
                StandardOutputEncoding = Encoding.GetEncoding(CultureInfo.CurrentCulture.TextInfo.OEMCodePage),
            };
            using var p = Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            var blocks = new List<(string Name, WlanInfo Info)>();
            foreach (var line in output.Split('\n'))
            {
                Match m;
                if ((m = Regex.Match(line, @"^\s*Name\s*:\s*(.+?)\s*$")).Success) blocks.Add((m.Groups[1].Value, new WlanInfo()));
                else if (blocks.Count > 0 && (m = Regex.Match(line, @"^\s*(AP\s+)?BSSID\s*:\s*(.+?)\s*$")).Success) blocks[^1].Info.Bssid = MacUtil.Normalize(m.Groups[2].Value);
                else if (blocks.Count > 0 && (m = Regex.Match(line, @"^\s*SSID\s*:\s*(.+?)\s*$")).Success) blocks[^1].Info.Ssid = m.Groups[1].Value;
            }
            var b = blocks.FirstOrDefault(x => x.Name == interfaceName);
            if (b.Info == null && blocks.Count > 0) b = blocks[0];
            if (b.Info != null) return b.Info;
        }
        catch (Exception) { }
        return res;
    }

    // ---------------- Ping / DNS ----------------
    public static IEnumerable<string> SubnetHosts(string ip, int prefix)
    {
        if (prefix < 22 || prefix > 30) prefix = 24;
        var b = IPAddress.Parse(ip).GetAddressBytes();
        uint n = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
        uint count = 1u << (32 - prefix);
        uint net = n & ~(count - 1);
        for (uint i = 1; i < count - 1; i++)
        {
            uint v = net + i;
            yield return new IPAddress(new[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v }).ToString();
        }
    }

    public static void PingAll(IEnumerable<string> ips, int waitMs)
    {
        var tasks = new List<Task>();
        foreach (var ip in ips.Distinct())
        {
            var ping = new Ping();
            tasks.Add(ping.SendPingAsync(ip, 600).ContinueWith(_ => ping.Dispose()));
        }
        try { Task.WaitAll(tasks.ToArray(), waitMs); } catch (AggregateException) { }
    }

    public static Dictionary<string, string> ReverseLookup(IEnumerable<string> ips, int waitMs)
    {
        var jobs = ips.Distinct().ToDictionary(ip => ip, ip => Dns.GetHostEntryAsync(ip));
        try { Task.WaitAll(jobs.Values.ToArray<Task>(), waitMs); } catch (AggregateException) { }
        var res = new Dictionary<string, string>();
        foreach (var (ip, t) in jobs)
            if (t.Status == TaskStatus.RanToCompletion && !string.IsNullOrEmpty(t.Result.HostName) && t.Result.HostName != ip)
                res[ip] = t.Result.HostName.Split('.')[0];
        return res;
    }
}
