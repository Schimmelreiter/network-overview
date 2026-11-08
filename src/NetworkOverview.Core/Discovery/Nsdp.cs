#nullable disable
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NetworkOverview.Core.Lltd;

// NSDP (Netgear Switch Discovery Protocol) as used by ProSAFE Plus / Smart switches.
namespace NetworkOverview.Core.Discovery
{
    public class NsdpDevice
    {
        public string Mac = "";
        public string Model = "";
        public string Name = "";
        public string IPv4 = "";
        public string Firmware = "";
        public List<string> Ports = new List<string>();
    }

    public static class Nsdp
    {
        static string Speed(int code)
        {
            switch (code)
            {
                case 0: return "-";
                case 1: return "10M/H";
                case 2: return "10M";
                case 3: return "100M/H";
                case 4: return "100M";
                case 5: return "1G";
                case 6: return "2.5G";
                case 7: return "10G";
                default: return "?" + code;
            }
        }

        public static List<NsdpDevice> Discover(string localIp, string localMac, int timeoutMs)
        {
            Dictionary<string, NsdpDevice> found = new Dictionary<string, NsdpDevice>();
            byte[] myMac = Fr.Mac(localMac);
            int[][] ports = new int[][] { new int[] { 63321, 63322 }, new int[] { 63323, 63324 } };
            foreach (int[] pp in ports)
            {
                UdpClient u = null;
                try
                {
                    u = new UdpClient();
                    u.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                    u.Client.Bind(new IPEndPoint(IPAddress.Parse(localIp), pp[0]));
                    u.EnableBroadcast = true;
                    u.Client.ReceiveTimeout = 200;
                    List<byte> m = new List<byte>();
                    m.Add(0x01); m.Add(0x01);                 // version, read request
                    m.AddRange(new byte[6]);                  // result + unknown
                    m.AddRange(myMac);                        // host MAC
                    m.AddRange(new byte[6]);                  // device MAC (all)
                    m.AddRange(new byte[2]);
                    m.Add(0x00); m.Add(0x01);                 // sequence
                    m.AddRange(Encoding.ASCII.GetBytes("NSDP"));
                    m.AddRange(new byte[4]);
                    int[] tlvs = { 0x0001, 0x0003, 0x0004, 0x0006, 0x000D, 0x0C00 };
                    foreach (int t in tlvs) { m.Add((byte)(t >> 8)); m.Add((byte)t); m.Add(0); m.Add(0); }
                    m.Add(0xFF); m.Add(0xFF); m.Add(0); m.Add(0);
                    byte[] req = m.ToArray();
                    u.Send(req, req.Length, new IPEndPoint(IPAddress.Broadcast, pp[1]));
                    Stopwatch sw = Stopwatch.StartNew();
                    while (sw.ElapsedMilliseconds < timeoutMs)
                    {
                        byte[] r;
                        IPEndPoint ep = new IPEndPoint(IPAddress.Any, 0);
                        try { r = u.Receive(ref ep); }
                        catch (SocketException) { continue; }
                        if (r.Length < 32 || r[1] != 0x02) continue;
                        NsdpDevice d = new NsdpDevice();
                        d.Mac = Fr.Str(r, 14);
                        int i = 32;
                        while (i + 4 <= r.Length)
                        {
                            int t = (r[i] << 8) | r[i + 1];
                            int len = (r[i + 2] << 8) | r[i + 3];
                            i += 4;
                            if (t == 0xFFFF) break;
                            if (i + len > r.Length) break;
                            switch (t)
                            {
                                case 0x0001: d.Model = Encoding.ASCII.GetString(r, i, len).TrimEnd('\0', ' '); break;
                                case 0x0003: d.Name = Encoding.ASCII.GetString(r, i, len).TrimEnd('\0', ' '); break;
                                case 0x0004: if (len == 6) d.Mac = Fr.Str(r, i); break;
                                case 0x0006: if (len == 4) d.IPv4 = new IPAddress(Fr.Sub(r, i, 4)).ToString(); break;
                                case 0x000D: d.Firmware = Encoding.ASCII.GetString(r, i, len).TrimEnd('\0', ' '); break;
                                case 0x0C00: if (len >= 2) d.Ports.Add(r[i] + ":" + Speed(r[i + 1])); break;
                            }
                            i += len;
                        }
                        if (d.Mac != "00:00:00:00:00:00") found[d.Mac] = d;
                    }
                }
                catch { }
                finally { if (u != null) u.Close(); }
            }
            return new List<NsdpDevice>(found.Values);
        }
    }
}
