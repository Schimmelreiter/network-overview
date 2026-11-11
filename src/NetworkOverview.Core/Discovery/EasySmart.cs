using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetworkOverview.Core.Discovery;

/// <summary>
/// TP-Link "Easy Smart" switches (TL-SG105E, TL-SG108E, TL-SG116E, ...): discovery via the Easy Smart Configuration
/// Protocol (ESCP) as used by TP-Link's configuration utility. Requests go as UDP broadcast to port 29808, the switches
/// answer by broadcast to port 29809. Packets are RC4-encrypted with a key that is the same in every switch.
/// The discovery needs no login and returns model, name, MAC, IP address, firmware, hardware version and port count.
/// Protocol details: chrisdcmoore.co.uk (ESCP), Pentest Partners, rgl/ansible-collection-tp-link-easy-smart-switch.
/// </summary>
public static class EasySmart
{
    const int SwitchPort = 29808, ClientPort = 29809, HeaderLength = 32;
    const ushort TlvModel = 1, TlvName = 2, TlvMac = 3, TlvIp = 4, TlvFirmware = 7, TlvHardware = 8, TlvPorts = 10;

    // RC4 state after the key schedule (taken from TP-Link's utility); encryption and decryption are the same.
    static readonly byte[] State =
    {
        191, 155, 227, 202, 99, 162, 79, 104, 49, 18, 190, 164, 30, 76, 189, 131, 23, 52, 86, 106, 207, 125, 126, 169,
        196, 28, 172, 58, 188, 132, 160, 3, 36, 120, 144, 168, 12, 231, 116, 44, 41, 97, 108, 213, 42, 198, 32, 148,
        218, 107, 247, 112, 204, 14, 66, 68, 91, 224, 206, 235, 33, 130, 203, 178, 1, 134, 199, 78, 249, 123, 7, 145,
        73, 208, 209, 100, 74, 115, 72, 118, 8, 22, 243, 147, 64, 96, 5, 87, 60, 113, 233, 152, 31, 219, 143, 174,
        232, 153, 245, 158, 254, 70, 170, 75, 77, 215, 211, 59, 71, 133, 214, 157, 151, 6, 46, 81, 94, 136, 166, 210,
        4, 43, 241, 29, 223, 176, 67, 63, 186, 137, 129, 40, 248, 255, 55, 15, 62, 183, 222, 105, 236, 197, 127, 54,
        179, 194, 229, 185, 37, 90, 237, 184, 25, 156, 173, 26, 187, 220, 2, 225, 0, 240, 50, 251, 212, 253, 167, 17,
        193, 205, 177, 21, 181, 246, 82, 226, 38, 101, 163, 182, 242, 92, 20, 11, 95, 13, 230, 16, 121, 124, 109, 195,
        117, 39, 98, 239, 84, 56, 139, 161, 47, 201, 51, 135, 250, 10, 19, 150, 45, 111, 27, 24, 142, 80, 85, 83, 234,
        138, 216, 57, 93, 65, 154, 141, 122, 34, 140, 128, 238, 88, 89, 9, 146, 171, 149, 53, 102, 61, 114, 69, 217,
        175, 103, 228, 35, 180, 252, 200, 192, 165, 159, 221, 244, 110, 119, 48,
    };

    public static byte[] Crypt(byte[] data)
    {
        var s = (byte[])State.Clone();
        var r = (byte[])data.Clone();
        int j = 0;
        for (int k = 0; k < r.Length; k++)
        {
            int i = (k + 1) & 255;
            j = (j + s[i]) & 255;
            (s[i], s[j]) = (s[j], s[i]);
            r[k] ^= s[(s[i] + s[j]) & 255];
        }
        return r;
    }

    /// <summary>Plain (unencrypted) packet: 32-byte header, TLVs, end marker FF FF 00 00.</summary>
    public static byte[] Build(byte opCode, byte[] switchMac, byte[] hostMac, ushort sequence, IEnumerable<(ushort Type, byte[] Value)> tlvs)
    {
        var payload = new List<byte>();
        foreach (var (type, value) in tlvs)
        {
            payload.Add((byte)(type >> 8)); payload.Add((byte)type);
            payload.Add((byte)(value.Length >> 8)); payload.Add((byte)value.Length);
            payload.AddRange(value);
        }
        payload.AddRange(new byte[] { 0xFF, 0xFF, 0x00, 0x00 });
        int len = HeaderLength + payload.Count;
        var p = new byte[HeaderLength];
        p[0] = 1;                                   // version
        p[1] = opCode;                              // 0 = discovery
        Array.Copy(switchMac, 0, p, 2, 6);
        Array.Copy(hostMac, 0, p, 8, 6);
        p[14] = (byte)(sequence >> 8); p[15] = (byte)sequence;
        p[20] = (byte)(len >> 8); p[21] = (byte)len;  // length incl. header
        return p.Concat(payload).ToArray();
    }

    /// <summary>Parses a decrypted discovery answer; null if it is none.</summary>
    public static NsdpDevice? Parse(byte[] p)
    {
        if (p.Length < HeaderLength + 4 || p[0] != 1 || p[1] != 2) return null;     // answer (op code 2)
        var d = new NsdpDevice { Vendor = "TP-Link" };
        string hardware = "";
        int o = HeaderLength;
        while (o + 4 <= p.Length)
        {
            int type = (p[o] << 8) | p[o + 1], len = (p[o + 2] << 8) | p[o + 3];
            if (type == 0xFFFF) break;
            o += 4;
            if (o + len > p.Length) break;
            string Str() => Encoding.ASCII.GetString(p, o, len).Split('\0')[0].Trim();
            switch (type)
            {
                case TlvModel: d.Model = Str(); break;
                case TlvName: d.Name = Str(); break;
                case TlvMac when len == 6: d.Mac = string.Join(":", p.Skip(o).Take(6).Select(b => b.ToString("x2"))); break;
                case TlvIp when len == 4: d.IPv4 = $"{p[o]}.{p[o + 1]}.{p[o + 2]}.{p[o + 3]}"; break;
                case TlvFirmware: d.Firmware = Str(); break;
                case TlvHardware: hardware = Str(); break;
                case TlvPorts when len >= 1: d.PortCount = p[o + len - 1]; break;
            }
            o += len;
        }
        if (d.Mac.Length == 0) d.Mac = string.Join(":", p.Skip(2).Take(6).Select(b => b.ToString("x2")));
        if (hardware.Length > 0 && (d.Model.Length == 0 || hardware.StartsWith(d.Model, StringComparison.OrdinalIgnoreCase))) d.Model = hardware;
        return d;
    }

    public static List<NsdpDevice> Discover(string localIp, string localMac, string broadcast, int timeoutMs, Action<string>? log = null)
    {
        var found = new Dictionary<string, NsdpDevice>();
        var hostMac = MacUtil.Normalize(localMac).Split(':').Select(x => Convert.ToByte(x, 16)).ToArray();
        ushort seq = (ushort)Random.Shared.Next(1, 1000);
        var request = Crypt(Build(0, new byte[6], hostMac, seq, Array.Empty<(ushort, byte[])>()));

        // The switches answer by broadcast to port 29809. Windows delivers broadcasts to a socket bound to the
        // interface address, Linux only to one bound to "any": listen on both, send from the interface address.
        var sockets = new List<Socket>();
        Socket Open(IPAddress addr)
        {
            var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            s.EnableBroadcast = true;
            s.Bind(new IPEndPoint(addr, ClientPort));
            sockets.Add(s);
            return s;
        }
        try
        {
            Socket send;
            try { send = Open(IPAddress.Parse(localIp)); }
            catch (SocketException ex) { log?.Invoke("Easy Smart: port 29809 in use (" + ex.Message + ")"); return new List<NsdpDevice>(); }
            try { Open(IPAddress.Any); } catch (SocketException) { }
            var targets = new List<IPEndPoint> { new(IPAddress.Broadcast, SwitchPort) };
            if (IPAddress.TryParse(broadcast, out var b)) targets.Add(new IPEndPoint(b, SwitchPort));
            var buf = new byte[1500];
            var sw = Stopwatch.StartNew();
            int sent = 0;
            while (sw.ElapsedMilliseconds < timeoutMs)
            {
                if (sent < 2 && sw.ElapsedMilliseconds >= sent * 500)
                {
                    foreach (var t in targets) try { send.SendTo(request, t); } catch (SocketException) { }
                    sent++;
                }
                var ready = sockets.ToList();
                Socket.Select(ready, null, null, 100_000);
                foreach (var s in ready)
                {
                    int n;
                    try { n = s.Receive(buf); } catch (SocketException) { continue; }
                    var plain = Crypt(buf.Take(n).ToArray());
                    var d = Parse(plain);
                    if (d == null || d.Mac.Length == 0 || found.ContainsKey(d.Mac)) continue;
                    found[d.Mac] = d;
                }
            }
        }
        finally { foreach (var s in sockets) s.Dispose(); }
        return found.Values.ToList();
    }
}
