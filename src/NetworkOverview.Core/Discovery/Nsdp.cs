using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetworkOverview.Core.Discovery;

public sealed class NsdpDevice
{
    public string Mac { get; set; } = "";
    public string Model { get; set; } = "";
    public string Name { get; set; } = "";
    public string IPv4 { get; set; } = "";
    public string Firmware { get; set; } = "";
    public List<string> Ports { get; } = new();
}

/// <summary>NSDP (Netgear Switch Discovery Protocol) as used by ProSAFE Plus / Smart Managed Plus switches.
/// Newer firmware can switch this off ("Switch Management Mode: Web browser only").</summary>
public static class Nsdp
{
    const ushort TlvModel = 0x0001, TlvName = 0x0003, TlvMac = 0x0004, TlvIp = 0x0006, TlvFirmware = 0x000D, TlvPortStatus = 0x0C00;
    static int sequence = Random.Shared.Next(1, 0x7FFF);

    static string Speed(int code) => code switch
    {
        0 => "-",
        1 => "10M/H",
        2 => "10M",
        3 => "100M/H",
        4 => "100M",
        5 => "1G",
        6 => "2.5G",
        7 => "10G",
        _ => "?" + code,
    };

    public static byte[] BuildReadRequest(byte[] hostMac, byte[] deviceMac, IEnumerable<ushort> tlvs)
    {
        var m = new List<byte> { 0x01, 0x01 };                // version 1, read request
        m.AddRange(new byte[6]);                              // result + reserved
        m.AddRange(hostMac);
        m.AddRange(deviceMac);                                // 00:00:00:00:00:00 = all devices
        m.AddRange(new byte[2]);
        int seq = Interlocked.Increment(ref sequence) & 0xFFFF;
        m.Add((byte)(seq >> 8)); m.Add((byte)seq);
        m.AddRange(Encoding.ASCII.GetBytes("NSDP"));
        m.AddRange(new byte[4]);
        foreach (var t in tlvs) { m.Add((byte)(t >> 8)); m.Add((byte)t); m.Add(0); m.Add(0); }
        m.Add(0xFF); m.Add(0xFF); m.Add(0); m.Add(0);
        return m.ToArray();
    }

    /// <summary>Merges a read response into <paramref name="found"/>. Returns the device MAC or null.</summary>
    public static string? ParseResponse(byte[] r, Dictionary<string, NsdpDevice> found)
    {
        if (r.Length < 32 || r[1] != 0x02 || Encoding.ASCII.GetString(r, 24, 4) != "NSDP") return null;
        string mac = MacUtil.Normalize(Convert.ToHexString(r, 14, 6));
        var tlvs = new List<(int Type, byte[] Value)>();
        int i = 32;
        while (i + 4 <= r.Length)
        {
            int t = (r[i] << 8) | r[i + 1];
            int len = (r[i + 2] << 8) | r[i + 3];
            i += 4;
            if (t == 0xFFFF || i + len > r.Length) break;
            tlvs.Add((t, r.AsSpan(i, len).ToArray()));
            i += len;
        }
        var macTlv = tlvs.FirstOrDefault(x => x.Type == TlvMac && x.Value.Length == 6);
        if (macTlv.Value != null) mac = MacUtil.Normalize(Convert.ToHexString(macTlv.Value));
        if (!MacUtil.IsUsable(mac)) return null;
        if (!found.TryGetValue(mac, out var d)) found[mac] = d = new NsdpDevice { Mac = mac };
        bool portsInThisResponse = false;
        foreach (var (t, v) in tlvs)
        {
            switch (t)
            {
                case TlvModel: d.Model = Encoding.ASCII.GetString(v).TrimEnd('\0', ' '); break;
                case TlvName: d.Name = Encoding.ASCII.GetString(v).TrimEnd('\0', ' '); break;
                case TlvIp: if (v.Length == 4) d.IPv4 = new IPAddress(v).ToString(); break;
                case TlvFirmware: d.Firmware = Encoding.ASCII.GetString(v).TrimEnd('\0', ' '); break;
                case TlvPortStatus:
                    if (v.Length >= 2)
                    {
                        if (!portsInThisResponse) { d.Ports.Clear(); portsInThisResponse = true; }
                        d.Ports.Add(v[0] + ":" + Speed(v[1]));
                    }
                    break;
            }
        }
        return mac;
    }

    public static List<NsdpDevice> Discover(string localIp, string localMac, int timeoutMs, Action<string>? log = null)
    {
        var found = new Dictionary<string, NsdpDevice>();
        byte[] host = Convert.FromHexString(localMac.Replace(":", ""));
        foreach (var (src, dst) in new[] { (63321, 63322), (63323, 63324) })
        {
            UdpClient? u = null;
            try
            {
                u = new UdpClient();
                u.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                u.Client.Bind(new IPEndPoint(IPAddress.Parse(localIp), src));
                u.EnableBroadcast = true;
                u.Client.ReceiveTimeout = 150;
                var target = new IPEndPoint(IPAddress.Broadcast, dst);

                // 1. discovery of all devices
                var req = BuildReadRequest(host, new byte[6], new[] { TlvModel, TlvName, TlvMac, TlvIp, TlvFirmware });
                u.Send(req, req.Length, target);
                Receive(u, found, timeoutMs);

                // 2. port status, addressed to each device (some firmware ignores it in the combined request)
                foreach (var d in found.Values.ToList())
                {
                    var p = BuildReadRequest(host, Convert.FromHexString(d.Mac.Replace(":", "")), new[] { TlvPortStatus });
                    u.Send(p, p.Length, target);
                }
                if (found.Count > 0) Receive(u, found, 700);
            }
            catch (SocketException ex) { log?.Invoke($"NSDP {src}->{dst}: {ex.Message}"); }
            finally { u?.Close(); }
        }
        return found.Values.ToList();
    }

    static void Receive(UdpClient u, Dictionary<string, NsdpDevice> found, int ms)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < ms)
        {
            try
            {
                var ep = new IPEndPoint(IPAddress.Any, 0);
                ParseResponse(u.Receive(ref ep), found);
            }
            catch (SocketException) { }
        }
    }
}
