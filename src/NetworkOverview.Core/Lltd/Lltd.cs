using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

#nullable disable
// LLTD (Link Layer Topology Discovery) mapper: discovery and topology tests via Npcap.
// Protocol reference: [MS-LLTD] Link Layer Topology Discovery Protocol.
namespace NetworkOverview.Core.Lltd
{
    // ------------------------------------------------------------------
    //  Data types
    // ------------------------------------------------------------------
    public class LltdHost
    {
        public string Mac = "";
        public string HostId = "";
        public string Name = "";
        public string IPv4 = "";
        public string IPv6 = "";
        public uint Medium = 0;
        public int WirelessMode = -1;
        public string Bssid = "";
        public string Ssid = "";
        public long LinkSpeedBps = 0;
        public int Rssi = 0;
        public bool HasRssi = false;
        public double MaxRateMbps = 0;
        public uint Characteristics = 0;
        public string Uuid = "";
        public string Tlvs = "";
        public bool TopologyCapable = false;
        public bool IsWireless { get { return Medium == 71; } }
        public bool HasMgmtUrl { get { return (Characteristics & 0x10000000u) != 0; } }
    }

    public class EmitDesc
    {
        public byte Type;     // 0 = Train, 1 = Probe
        public byte Pause;    // ms
        public byte[] Src;
        public byte[] Dst;
        public EmitDesc(byte type, byte pause, byte[] src, byte[] dst) { Type = type; Pause = pause; Src = src; Dst = dst; }
    }

    public class RoundResult
    {
        public string C = "";
        public string D = "";
        public bool DIsExtra = false;
        public bool Failed = false;
        public bool Flooded = false;
        public bool Valid = false;
        public bool Confirmed = false;
        // c cannot observe: AtC = every prober not seen at the (reliable) root; measured twice
        public bool Inferred = false;
        public bool TrainRefused = false;
        public List<string> AtC = new List<string>();
        public List<string> AtRoot = new List<string>();
        public List<string> Missing = new List<string>();
    }

    public class TNode
    {
        public string Id = "";
        public bool IsSwitch = false;
        public string Mac = "";
        public string Parent = "";
        public List<string> Members = new List<string>();
    }

    public interface IFrameIO
    {
        void Send(byte[] frame);
        byte[] Receive(int timeoutMs);
        void Close();
    }

    // ------------------------------------------------------------------
    //  Npcap access
    // ------------------------------------------------------------------
    public class PcapIO : IFrameIO
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool SetDllDirectory(string path);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr LoadLibrary(string path);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern IntPtr pcap_open_live(string device, int snaplen, int promisc, int to_ms, StringBuilder errbuf);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_sendpacket(IntPtr p, byte[] buf, int size);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_next_ex(IntPtr p, out IntPtr header, out IntPtr data);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern void pcap_close(IntPtr p);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        static extern int pcap_compile(IntPtr p, IntPtr program, string filter, int optimize, uint netmask);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int pcap_setfilter(IntPtr p, IntPtr program);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern void pcap_freecode(IntPtr program);
        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern IntPtr pcap_geterr(IntPtr p);

        public static string NpcapError = "";
        static bool loaded = false;
        IntPtr p = IntPtr.Zero;

        public static bool IsAvailable()
        {
            if (loaded) return true;
            try
            {
                string sys = Environment.GetFolderPath(Environment.SpecialFolder.System);
                string dir = Path.Combine(sys, "Npcap");
                if (Directory.Exists(dir)) SetDllDirectory(dir);
                if (LoadLibrary("wpcap.dll") == IntPtr.Zero) { NpcapError = "wpcap.dll (Npcap) not found"; return false; }
                loaded = true;
                return true;
            }
            catch (Exception ex) { NpcapError = ex.Message; return false; }
        }

        public PcapIO(string device, bool promisc)
        {
            if (!IsAvailable()) throw new IOException(NpcapError);
            StringBuilder eb = new StringBuilder(1024);
            p = pcap_open_live(device, 1600, promisc ? 1 : 0, 20, eb);
            if (p == IntPtr.Zero) throw new IOException(eb.ToString());
            IntPtr prog = Marshal.AllocHGlobal(32);
            try
            {
                if (pcap_compile(p, prog, "ether proto 0x88d9", 1, 0xFFFFFFFF) == 0)
                {
                    pcap_setfilter(p, prog);
                    pcap_freecode(prog);
                }
            }
            finally { Marshal.FreeHGlobal(prog); }
        }

        public void Send(byte[] f) { if (p != IntPtr.Zero) pcap_sendpacket(p, f, f.Length); }

        public byte[] Receive(int timeoutMs)
        {
            Stopwatch sw = Stopwatch.StartNew();
            do
            {
                IntPtr hdr, data;
                int r = pcap_next_ex(p, out hdr, out data);
                if (r == 1 && hdr != IntPtr.Zero && data != IntPtr.Zero)
                {
                    int caplen = Marshal.ReadInt32(hdr, 8);
                    if (caplen > 0 && caplen <= 65535)
                    {
                        byte[] buf = new byte[caplen];
                        Marshal.Copy(data, buf, 0, caplen);
                        return buf;
                    }
                }
                else if (r < 0) throw new IOException(Marshal.PtrToStringAnsi(pcap_geterr(p)));
            } while (sw.ElapsedMilliseconds < timeoutMs);
            return null;
        }

        public void Close() { if (p != IntPtr.Zero) { pcap_close(p); p = IntPtr.Zero; } }
    }

    // ------------------------------------------------------------------
    //  LLTD frames
    // ------------------------------------------------------------------
    public static class Fr
    {
        public const int TOS_TOPO = 0, TOS_QUICK = 1;
        public const int F_DISCOVER = 0, F_HELLO = 1, F_EMIT = 2, F_TRAIN = 3, F_PROBE = 4, F_ACK = 5,
                         F_QUERY = 6, F_QUERYRESP = 7, F_RESET = 8, F_CHARGE = 9, F_FLAT = 10;
        public static readonly byte[] Bcast = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

        public static byte[] Build(int tos, int fn, byte[] ethDst, byte[] ethSrc, byte[] realDst, byte[] realSrc, int seq, int payloadLen)
        {
            byte[] f = new byte[Math.Max(32 + payloadLen, 60)];
            Buffer.BlockCopy(ethDst, 0, f, 0, 6);
            Buffer.BlockCopy(ethSrc, 0, f, 6, 6);
            f[12] = 0x88; f[13] = 0xD9;
            f[14] = 0x01; f[15] = (byte)tos; f[16] = 0; f[17] = (byte)fn;
            Buffer.BlockCopy(realDst, 0, f, 18, 6);
            Buffer.BlockCopy(realSrc, 0, f, 24, 6);
            f[30] = (byte)(seq >> 8); f[31] = (byte)seq;
            return f;
        }

        public static bool IsLltd(byte[] f) { return f != null && f.Length >= 32 && f[12] == 0x88 && f[13] == 0xD9 && f[14] == 0x01; }
        public static int Seq(byte[] f) { return (f[30] << 8) | f[31]; }

        public static byte[] Mac(string s)
        {
            string h = s.Replace(":", "").Replace("-", "");
            byte[] b = new byte[6];
            for (int i = 0; i < 6; i++) b[i] = Convert.ToByte(h.Substring(i * 2, 2), 16);
            return b;
        }
        public static string Str(byte[] b, int off)
        {
            return BitConverter.ToString(b, off, 6).Replace('-', ':').ToLowerInvariant();
        }
        public static byte[] Sub(byte[] b, int off, int len)
        {
            byte[] r = new byte[len];
            Buffer.BlockCopy(b, off, r, 0, len);
            return r;
        }
        public static uint U32(byte[] b, int i)
        {
            return ((uint)b[i] << 24) | ((uint)b[i + 1] << 16) | ((uint)b[i + 2] << 8) | b[i + 3];
        }
        static string CutZero(string s)
        {
            int z = s.IndexOf('\0');
            return z >= 0 ? s.Substring(0, z) : s;
        }

        public static byte[] Discover(int tos, byte[] me, int xid, int gen, List<byte[]> stations)
        {
            int n = Math.Min(stations.Count, 200);
            byte[] f = Build(tos, F_DISCOVER, Bcast, me, Bcast, me, xid, 4 + 6 * n);
            f[32] = (byte)(gen >> 8); f[33] = (byte)gen;
            f[34] = (byte)(n >> 8); f[35] = (byte)n;
            for (int i = 0; i < n; i++) Buffer.BlockCopy(stations[i], 0, f, 36 + 6 * i, 6);
            return f;
        }

        public static byte[] Emit(byte[] me, byte[] to, int seq, IList<EmitDesc> descs)
        {
            byte[] f = Build(TOS_TOPO, F_EMIT, to, me, to, me, seq, 2 + 14 * descs.Count);
            f[32] = (byte)(descs.Count >> 8); f[33] = (byte)descs.Count;
            for (int i = 0; i < descs.Count; i++)
            {
                int o = 34 + 14 * i;
                f[o] = descs[i].Type;
                f[o + 1] = descs[i].Pause;
                Buffer.BlockCopy(descs[i].Src, 0, f, o + 2, 6);
                Buffer.BlockCopy(descs[i].Dst, 0, f, o + 8, 6);
            }
            return f;
        }

        // Parse a Hello frame (generation and TLVs)
        public static LltdHost ParseHello(byte[] b, out int generation)
        {
            generation = 0;
            if (b.Length < 46) return null;
            generation = (b[32] << 8) | b[33];
            LltdHost h = new LltdHost();
            h.Mac = Str(b, 24);
            List<string> types = new List<string>();
            int i = 46;
            while (i + 2 <= b.Length)
            {
                int t = b[i];
                int len = b[i + 1];
                i += 2;
                if (t == 0) break;
                if (i + len > b.Length) break;
                types.Add(t.ToString("X2"));
                switch (t)
                {
                    case 0x01: if (len == 6) h.HostId = Str(b, i); break;
                    case 0x02: if (len >= 4) h.Characteristics = U32(b, i); break;
                    case 0x03: if (len >= 4) h.Medium = U32(b, i); break;
                    case 0x04: if (len >= 1) h.WirelessMode = b[i]; break;
                    case 0x05: if (len == 6) h.Bssid = Str(b, i); break;
                    case 0x06: h.Ssid = CutZero(Encoding.UTF8.GetString(b, i, len)); break;
                    case 0x07:
                        if (len == 4)
                        {
                            string ip = new IPAddress(Sub(b, i, 4)).ToString();
                            if (ip != "0.0.0.0") h.IPv4 = ip;
                        }
                        break;
                    case 0x08: if (len == 16) h.IPv6 = new IPAddress(Sub(b, i, 16)).ToString(); break;
                    case 0x09: if (len >= 2) h.MaxRateMbps = ((b[i] << 8) | b[i + 1]) * 0.5; break;
                    case 0x0C: if (len >= 4) h.LinkSpeedBps = (long)U32(b, i) * 100L; break;
                    case 0x0D: if (len >= 4) { h.Rssi = unchecked((int)U32(b, i)); h.HasRssi = true; } break;
                    case 0x0F:
                        {
                            string n = CutZero(Encoding.Unicode.GetString(b, i, len - (len % 2))).Trim();
                            if (n.Length > 0) h.Name = n;
                        }
                        break;
                    case 0x12: if (len == 16) h.Uuid = new Guid(Sub(b, i, 16)).ToString(); break;
                }
                i += len;
            }
            h.Tlvs = string.Join(" ", types.ToArray());
            return h;
        }
    }

    // ------------------------------------------------------------------
    //  Mapper: discovery + topology tests (runs on its own thread)
    // ------------------------------------------------------------------
    public class MapperJob
    {
        // Inputs
        public string Device = "";
        public string MyMac = "";
        public bool MyWired = true;
        public bool DoTopology = true;
        public int DiscoverMs = 4500;
        public int MaxSeconds = 900;
        public int LearnPauseMs = 120;
        public List<string> ExtraMacs = new List<string>();
        public List<string> WirelessMacs = new List<string>();
        public List<string> SwitchMacs = new List<string>();     // management addresses of (possible) switches
        public IFrameIO IO = null;

        // Outputs
        public volatile string Progress = "";
        public volatile bool Done = false;
        public volatile bool Cancel = false;
        public volatile int RoundsTotal = 0;
        public volatile int RoundsDone = 0;
        public string Error = "";
        public bool Partial = false;
        public string RootMac = "";
        public List<LltdHost> Hosts = new List<LltdHost>();
        public List<RoundResult> Rounds = new List<RoundResult>();
        public List<TNode> Tree = new List<TNode>();
        public List<string> Log = new List<string>();
        public List<string> NonObservers = new List<string>();
        // switch management address -> responders (and the root) directly attached to that switch,
        // for switches that flood frames addressed to their own management address
        public Dictionary<string, List<string>> FloodHosts = new Dictionary<string, List<string>>();

        // Internal state
        byte[] me;
        string meStr;
        Random rnd = new Random(Guid.NewGuid().GetHashCode());
        Dictionary<string, LltdHost> hosts = new Dictionary<string, LltdHost>();
        List<byte[]> ackTopo = new List<byte[]>();
        List<byte[]> ackQuick = new List<byte[]>();
        int gen = 0;
        int xidTopo = 1, xidQuick = 1;
        Dictionary<string, int> seqs = new Dictionary<string, int>();
        Dictionary<string, DateTime> touched = new Dictionary<string, DateTime>();
        HashSet<string> acks = new HashSet<string>();
        HashSet<string> flats = new HashSet<string>();
        Dictionary<string, byte[]> qresps = new Dictionary<string, byte[]>();
        HashSet<string> mapperSeen = new HashSet<string>();
        HashSet<string> wirelessSet = new HashSet<string>();
        long spoof;
        Stopwatch clock = new Stopwatch();

        public void Start()
        {
            Thread t = new Thread(Run);
            t.IsBackground = true;
            t.Start();
        }

        void L(string s) { lock (Log) { Log.Add(clock.ElapsedMilliseconds.ToString("000000") + " " + s); } }

        public void Run()
        {
            clock.Start();
            try
            {
                me = Fr.Mac(MyMac);
                meStr = Fr.Str(me, 0);
                if (IO == null) IO = new PcapIO(Device, true);
                foreach (string w in WirelessMacs) wirelessSet.Add(w.ToLowerInvariant());
                spoof = 0x000D3AD7F140L + rnd.Next(0x100, 0x200000);

                Progress = "discover";
                DiscoverPhase();
                foreach (LltdHost h in hosts.Values) if (h.IsWireless) wirelessSet.Add(h.Mac);
                Hosts = new List<LltdHost>(hosts.Values);

                if (DoTopology && !Cancel) TopologyPhase();
            }
            catch (Exception ex) { Error = ex.Message; L("ERROR " + ex); }
            finally
            {
                try
                {
                    if (IO != null)
                    {
                        IO.Send(Fr.Build(Fr.TOS_TOPO, Fr.F_RESET, Fr.Bcast, me, Fr.Bcast, me, 0, 0));
                        IO.Send(Fr.Build(Fr.TOS_QUICK, Fr.F_RESET, Fr.Bcast, me, Fr.Bcast, me, 0, 0));
                        IO.Close();
                    }
                }
                catch { }
                Done = true;
            }
        }

        // ---------------- Receive ----------------
        void Process(byte[] f)
        {
            if (!Fr.IsLltd(f)) return;
            int tos = f[15];
            int fn = f[17];
            if (tos > 1) return;
            string rs = Fr.Str(f, 24);
            if (rs == meStr) return;
            int seq = Fr.Seq(f);
            switch (fn)
            {
                case Fr.F_HELLO:
                    {
                        int g;
                        LltdHost h = Fr.ParseHello(f, out g);
                        if (h == null) break;
                        LltdHost old;
                        if (hosts.TryGetValue(h.Mac, out old))
                        {
                            if (h.Tlvs.Length > old.Tlvs.Length) { h.TopologyCapable = old.TopologyCapable; hosts[h.Mac] = h; old = h; }
                        }
                        else { hosts[h.Mac] = h; old = h; L("hello " + h.Mac + " " + h.Name + " tos" + tos); }
                        List<byte[]> list = tos == Fr.TOS_TOPO ? ackTopo : ackQuick;
                        bool found = false;
                        foreach (byte[] m in list) if (Fr.Str(m, 0) == h.Mac) { found = true; break; }
                        if (!found) list.Add(Fr.Mac(h.Mac));
                        if (tos == Fr.TOS_TOPO)
                        {
                            old.TopologyCapable = true;
                            if (gen == 0 && g != 0) gen = g;
                        }
                    }
                    break;
                case Fr.F_ACK: acks.Add(rs + "/" + seq); break;
                case Fr.F_FLAT: flats.Add(rs + "/" + seq); break;
                case Fr.F_QUERYRESP: qresps[rs + "/" + seq] = f; break;
                case Fr.F_PROBE: mapperSeen.Add(rs + "|" + Fr.Str(f, 0)); break;
            }
        }

        void Pump(int ms)
        {
            Stopwatch sw = Stopwatch.StartNew();
            while (true)
            {
                long left = ms - sw.ElapsedMilliseconds;
                if (left <= 0) break;
                byte[] f = IO.Receive((int)Math.Min(left, 20));
                if (f != null) Process(f);
            }
        }

        bool WaitFor(Func<bool> cond, int ms)
        {
            Stopwatch sw = Stopwatch.StartNew();
            while (true)
            {
                if (cond()) return true;
                long left = ms - sw.ElapsedMilliseconds;
                if (left <= 0) return false;
                byte[] f = IO.Receive((int)Math.Min(left, 20));
                if (f != null) Process(f);
            }
        }

        // ---------------- Phase 1: discovery ----------------
        void DiscoverPhase()
        {
            xidTopo = rnd.Next(1, 65535);
            xidQuick = rnd.Next(1, 65535);
            int[] sendAt = { 0, 600, 1400, 2400, 3400 };
            int next = 0;
            Stopwatch sw = Stopwatch.StartNew();
            while (sw.ElapsedMilliseconds < DiscoverMs && !Cancel)
            {
                if (next < sendAt.Length && sw.ElapsedMilliseconds >= sendAt[next])
                {
                    IO.Send(Fr.Discover(Fr.TOS_QUICK, me, xidQuick, 0, ackQuick));
                    if (DoTopology) IO.Send(Fr.Discover(Fr.TOS_TOPO, me, xidTopo, gen, ackTopo));
                    next++;
                }
                Pump(50);
            }
            // Acknowledge all Hellos so responders enter the Command state
            for (int i = 0; i < 2; i++)
            {
                IO.Send(Fr.Discover(Fr.TOS_QUICK, me, xidQuick, 0, ackQuick));
                if (DoTopology) IO.Send(Fr.Discover(Fr.TOS_TOPO, me, xidTopo, gen, ackTopo));
                Pump(150);
            }
            IO.Send(Fr.Build(Fr.TOS_QUICK, Fr.F_RESET, Fr.Bcast, me, Fr.Bcast, me, 0, 0));
            L("discover done: " + hosts.Count + " hosts, gen=" + gen);
        }

        // ---------------- Command helpers ----------------
        int CurSeq(string mac)
        {
            int s;
            if (!seqs.TryGetValue(mac, out s)) { s = rnd.Next(1, 65000); seqs[mac] = s; }
            return s;
        }
        void AdvanceSeq(string mac)
        {
            int s = CurSeq(mac) + 1;
            if (s > 0xFFFF) s = 1;
            seqs[mac] = s;
        }

        byte[] NextSpoof()
        {
            spoof++;
            if (spoof > 0x000D3AFFFFFFL) spoof = 0x000D3AD7F140L + 0x100;
            byte[] b = new byte[6];
            long v = spoof;
            for (int i = 5; i >= 0; i--) { b[i] = (byte)(v & 0xFF); v >>= 8; }
            return b;
        }

        void Charge(string mac, int count)
        {
            byte[] to = Fr.Mac(mac);
            for (int i = 0; i < count; i++) IO.Send(Fr.Build(Fr.TOS_TOPO, Fr.F_CHARGE, to, me, to, me, 0, 28));
            touched[mac] = DateTime.UtcNow;
        }

        // Acknowledged Emit (used for Train frames whose success is otherwise invisible)
        bool EmitAcked(string mac, List<EmitDesc> descs)
        {
            byte[] to = Fr.Mac(mac);
            int pauseSum = 0;
            foreach (EmitDesc d in descs) pauseSum += d.Pause;
            Charge(mac, descs.Count + 1);
            for (int round = 0; round < 2; round++)
            {
                int seq = CurSeq(mac);
                string key = mac + "/" + seq;
                for (int attempt = 0; attempt < 3; attempt++)
                {
                    IO.Send(Fr.Emit(me, to, seq, descs));
                    if (WaitFor(delegate { return acks.Contains(key) || flats.Contains(key); }, 350 + pauseSum))
                    {
                        AdvanceSeq(mac);
                        touched[mac] = DateTime.UtcNow;
                        if (acks.Contains(key)) return true;
                        L("flat from " + mac);
                        Charge(mac, descs.Count + 3);
                        break;
                    }
                }
                if (!flats.Contains(key))
                {
                    // no answer: the responder may still have consumed the sequence number
                    L("emit timeout " + mac + " seq " + seq);
                    AdvanceSeq(mac);
                    Charge(mac, descs.Count + 1);
                }
            }
            return false;
        }

        // Unacknowledged Emit with exactly one entry (carries enough charge itself)
        void EmitSingle(string mac, EmitDesc d)
        {
            byte[] to = Fr.Mac(mac);
            List<EmitDesc> l = new List<EmitDesc>();
            l.Add(d);
            IO.Send(Fr.Emit(me, to, 0, l));
            touched[mac] = DateTime.UtcNow;
        }

        // Returns a responder's sees-list (probe entries) as "realsrc|ethdst"
        List<string> Query(string mac, out bool ok)
        {
            ok = true;
            List<string> res = new List<string>();
            byte[] to = Fr.Mac(mac);
            for (int part = 0; part < 50; part++)
            {
                int seq = CurSeq(mac);
                string key = mac + "/" + seq;
                bool got = false;
                for (int attempt = 0; attempt < 4 && !got; attempt++)
                {
                    IO.Send(Fr.Build(Fr.TOS_TOPO, Fr.F_QUERY, to, me, to, me, seq, 0));
                    got = WaitFor(delegate { return qresps.ContainsKey(key); }, 300);
                }
                if (!got)
                {
                    L("query timeout " + mac + " seq " + seq);
                    AdvanceSeq(mac);
                    ok = false;
                    return res;
                }
                AdvanceSeq(mac);
                touched[mac] = DateTime.UtcNow;
                byte[] f = qresps[key];
                qresps.Remove(key);
                if (f.Length < 34) break;
                int hdr = (f[32] << 8) | f[33];
                bool more = (hdr & 0x8000) != 0;
                int n = hdr & 0x3FFF;
                for (int i = 0; i < n; i++)
                {
                    int o = 34 + 20 * i;
                    if (o + 20 > f.Length) break;
                    int type = (f[o] << 8) | f[o + 1];
                    if (type != 0) continue;
                    res.Add(Fr.Str(f, o + 2) + "|" + Fr.Str(f, o + 14));
                }
                if (!more) break;
            }
            return res;
        }

        void KeepAlive(IEnumerable<string> macs)
        {
            DateTime now = DateTime.UtcNow;
            foreach (string m in macs)
            {
                DateTime t;
                if (!touched.TryGetValue(m, out t) || (now - t).TotalSeconds > 8) Charge(m, 1);
            }
        }

        // ---------------- Phase 2: topology tests ----------------
        //  Test for pair (c,d): X is learned at the root, c sends X->d (switches on the path c..d learn X towards c),
        //  then every other responder a sends a probe to X. If it arrives at c, the path a->root crosses the path c..d.
        RoundResult Round(string root, string c, string d, List<string> probers, List<string> all, bool inferred = false)
        {
            RoundResult rr = new RoundResult();
            rr.C = c; rr.D = d; rr.Inferred = inferred;
            KeepAlive(all);
            byte[] X = NextSpoof();
            string xs = Fr.Str(X, 0);

            // 1. teach X at the root
            if (root == null)
            {
                for (int i = 0; i < 2; i++) IO.Send(Fr.Build(Fr.TOS_TOPO, Fr.F_TRAIN, Fr.Bcast, X, Fr.Bcast, me, 0, 0));
            }
            else
            {
                List<EmitDesc> t = new List<EmitDesc>();
                t.Add(new EmitDesc(0, 0, X, NextSpoof()));
                t.Add(new EmitDesc(0, 5, X, NextSpoof()));
                if (!EmitAcked(root, t)) { rr.Failed = true; return rr; }
            }

            // 2. relearn X along the path c..d
            List<EmitDesc> t2 = new List<EmitDesc>();
            t2.Add(new EmitDesc(0, (byte)LearnPauseMs, X, Fr.Mac(d)));
            t2.Add(new EmitDesc(0, 5, X, Fr.Mac(d)));
            if (!EmitAcked(c, t2)) { rr.Failed = true; rr.TrainRefused = true; return rr; }

            // 3. probes
            HashSet<string> atC = new HashSet<string>();
            HashSet<string> atRoot = new HashSet<string>();
            List<string> pending = new List<string>(probers);
            // inferred: a lost probe would be counted at c, so probes not seen at the root are repeated more often
            for (int attempt = 0; attempt < (inferred ? 4 : 2) && pending.Count > 0; attempt++)
            {
                foreach (string a in pending) EmitSingle(a, new EmitDesc(1, (byte)LearnPauseMs, Fr.Mac(a), X));
                Pump(LearnPauseMs + 250);

                bool ok;
                if (!inferred)
                {
                    foreach (string e in Query(c, out ok))
                    {
                        string[] p = e.Split('|');
                        if (p[1] == xs) atC.Add(p[0]);
                    }
                    if (!ok) { rr.Failed = true; }
                }
                if (root == null)
                {
                    foreach (string e in mapperSeen)
                    {
                        string[] p = e.Split('|');
                        if (p[1] == xs) atRoot.Add(p[0]);
                    }
                }
                else
                {
                    foreach (string e in Query(root, out ok))
                    {
                        string[] p = e.Split('|');
                        if (p[1] == xs) atRoot.Add(p[0]);
                    }
                    if (!ok) { rr.Failed = true; }
                }
                List<string> still = new List<string>();
                foreach (string a in pending) if (!atC.Contains(a) && !atRoot.Contains(a)) still.Add(a);
                pending = still;
            }
            mapperSeen.Clear();
            if (inferred)
            {
                // c cannot report: every probe that did not reach the root went to c
                foreach (string a in probers)
                    if (atRoot.Contains(a)) rr.AtRoot.Add(a); else rr.AtC.Add(a);
                return rr;
            }
            foreach (string a in probers)
            {
                bool inC = atC.Contains(a), inR = atRoot.Contains(a);
                if (inC && inR) { rr.Flooded = true; rr.Missing.Add(a); }
                else if (inC) rr.AtC.Add(a);
                else if (inR) rr.AtRoot.Add(a);
                else rr.Missing.Add(a);
            }
            return rr;
        }

        // Round with plausibility check and retries
        RoundResult RoundChecked(string root, string c, string d, bool extra, List<string> all, bool inferred = false)
        {
            List<string> probers = new List<string>();
            foreach (string m in all) if (m != c && m != (extra ? d : "")) probers.Add(m);
            if (inferred) return RoundCheckedInferred(root, c, d, extra, probers, all);
            RoundResult rr = null;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (Cancel) break;
                rr = Round(root, c, d, probers, all);
                rr.DIsExtra = extra;
                // Control probe: d lies on the path c..d itself, so its probe MUST arrive at c
                rr.Valid = !rr.Failed && !rr.Flooded && rr.Missing.Count == 0 && (extra || rr.AtC.Contains(d));
                L("round c=" + c + " d=" + d + (extra ? " (x)" : "") + " atC=" + rr.AtC.Count + " atRoot=" + rr.AtRoot.Count +
                  " missing=" + rr.Missing.Count + (rr.Flooded ? " FLOOD" : "") + (rr.Valid ? "" : " INVALID") +
                  " C[" + Names(rr.AtC) + "] R[" + Names(rr.AtRoot) + "]");
                if (rr.Valid) break;
            }
            if (rr != null && !extra) rr.AtC.Remove(d);
            return rr;
        }

        // Round with a responder that cannot observe as c. Lost probes would be counted at c and lost
        // training frames would send probes to the root, so every result is measured again with fresh test
        // addresses: it is accepted as soon as two of up to six measurements agree.
        RoundResult RoundCheckedInferred(string root, string c, string d, bool extra, List<string> probers, List<string> all)
        {
            RoundResult rr = null;
            List<RoundResult> seen = new List<RoundResult>();
            int refused = 0;
            for (int attempt = 0; attempt < 6; attempt++)
            {
                if (Cancel) break;
                RoundResult a = Round(root, c, d, probers, all, true);
                a.DIsExtra = extra;
                if (a.TrainRefused && ++refused >= 2) return a;
                if (rr == null) rr = a;
                if (a.Failed) continue;
                // control probe: d lies on the path c..d, so its probe must not arrive at the root
                bool plausible = extra || a.AtC.Contains(d);
                RoundResult match = null;
                if (plausible)
                    foreach (RoundResult b in seen)
                        if (SameSet(a.AtC, b.AtC) && SameSet(a.AtRoot, b.AtRoot)) { match = b; break; }
                a.Valid = match != null;
                L("round c=" + c + " d=" + d + (extra ? " (x)" : "") + " (inferred) atC=" + a.AtC.Count + " atRoot=" + a.AtRoot.Count +
                  (a.Valid ? "" : seen.Count == 0 && plausible ? " (first)" : " INVALID") + " C[" + Names(a.AtC) + "] R[" + Names(a.AtRoot) + "]");
                rr = a;
                if (a.Valid) break;
                if (plausible) seen.Add(a);
            }
            if (rr != null && !extra) rr.AtC.Remove(d);
            return rr;
        }

        string Names(List<string> macs)
        {
            List<string> r = new List<string>();
            foreach (string m in macs)
            {
                LltdHost h;
                r.Add(hosts.TryGetValue(m, out h) && !string.IsNullOrEmpty(h.Name) ? h.Name : m.Substring(9));
            }
            r.Sort(StringComparer.Ordinal);
            return string.Join(",", r.ToArray());
        }

        // An observer whose sees-list stays empty while the probes addressed to it vanish
        // (they were switched to its port, but it did not record them).
        static bool LostAtObserver(RoundResult rr, int probers)
        {
            return rr != null && !rr.Valid && !rr.Flooded && !rr.Failed && rr.AtC.Count == 0 && rr.Missing.Count > 0
                   && rr.Missing.Count * 2 >= probers;
        }

        void TopologyPhase()
        {
            // add every responder found (including quick-discovery-only ones) to the session
            foreach (LltdHost h in hosts.Values)
            {
                bool found = false;
                foreach (byte[] m in ackTopo) if (Fr.Str(m, 0) == h.Mac) { found = true; break; }
                if (!found) ackTopo.Add(Fr.Mac(h.Mac));
            }
            for (int i = 0; i < 2; i++) { IO.Send(Fr.Discover(Fr.TOS_TOPO, me, xidTopo, gen, ackTopo)); Pump(100); }

            List<string> resp = new List<string>();
            foreach (LltdHost h in hosts.Values)
            {
                if (h.Mac == meStr) continue;
                if (Verify(h.Mac)) { resp.Add(h.Mac); h.TopologyCapable = true; }
                else { h.TopologyCapable = false; L("no topology session: " + h.Mac); }
            }
            resp.Sort();
            if (resp.Count == 0) return;

            // Self-test: can a responder observe probes addressed to a foreign (test) address?
            // Responders that cannot are still used as probe senders and destinations, but not as observers.
            List<string> observers = new List<string>();
            foreach (string m in resp)
            {
                if (Cancel) break;
                if (CanObserve(m, resp)) observers.Add(m);
                else { L("cannot observe: " + m); NonObservers.Add(m); }
            }

            string root = null;
            if (!MyWired)
            {
                foreach (string m in observers) if (!wirelessSet.Contains(m)) { root = m; break; }
                if (root == null) { L("no wired root"); return; }
            }
            RootMac = root == null ? meStr : root;

            List<string> all = new List<string>();
            foreach (string m in resp) if (m != root) all.Add(m);
            List<string> wired = new List<string>();
            foreach (string m in all) if (!wirelessSet.Contains(m) && observers.Contains(m)) wired.Add(m);
            // Wired responders that cannot observe still send: with a reliable root (the wired mapper itself
            // or a wired observer) every probe not seen at the root went to c ("inferred" rounds).
            bool reliableRoot = root == null ? MyWired : !wirelessSet.Contains(root) && observers.Contains(root);
            List<string> inferredC = new List<string>();
            if (reliableRoot)
                foreach (string m in all) if (!wirelessSet.Contains(m) && !observers.Contains(m)) inferredC.Add(m);

            List<string[]> plan = new List<string[]>();
            for (int i = 0; i < all.Count; i++)
                for (int j = i + 1; j < all.Count; j++)
                {
                    string a = all[i], b = all[j];
                    if (wired.Contains(a)) plan.Add(new string[] { a, b, "", "" });
                    else if (wired.Contains(b)) plan.Add(new string[] { b, a, "", "" });
                    else if (inferredC.Contains(a)) plan.Add(new string[] { a, b, "", "i" });
                    else if (inferredC.Contains(b)) plan.Add(new string[] { b, a, "", "i" });
                }
            foreach (string x in ExtraMacs)
            {
                string h = x.ToLowerInvariant();
                if (h == meStr || hosts.ContainsKey(h) || wirelessSet.Contains(h)) continue;
                foreach (string c in wired) plan.Add(new string[] { c, h, "x", "" });
                foreach (string c in inferredC) plan.Add(new string[] { c, h, "x", "i" });
            }
            RoundsTotal = plan.Count;
            L("plan: " + plan.Count + " rounds, root=" + RootMac);

            Dictionary<string, int> missCount = new Dictionary<string, int>();
            Dictionary<string, int> lostAt = new Dictionary<string, int>();
            foreach (string[] step in plan)
            {
                if (Cancel || clock.Elapsed.TotalSeconds > MaxSeconds) { Partial = true; break; }
                RoundsDone = RoundsDone + 1;
                Progress = "round";
                bool extra = step[2] == "x", inf = step[3] == "i";
                if (!all.Contains(step[0]) || !(inf ? inferredC : wired).Contains(step[0]) || (!extra && !all.Contains(step[1]))) continue;
                RoundResult rr = RoundChecked(root, step[0], step[1], extra, all, inf);
                if (rr == null) continue;
                if (inf && rr.TrainRefused)
                {
                    // lltd with --observe no (or the old "auto") refuses trains: no inferred rounds for c
                    inferredC.Remove(step[0]);
                    L("cannot train: " + step[0]);
                    continue;
                }
                Rounds.Add(rr);
                if (LostAtObserver(rr, all.Count - 1))
                {
                    // The self-test only checks probes sent by the mapper. A responder that loses probes from
                    // other senders is demoted: its rounds so far are discarded, its later rounds skipped.
                    int lc;
                    lostAt.TryGetValue(step[0], out lc);
                    lostAt[step[0]] = ++lc;
                    if (lc >= 2)
                    {
                        wired.Remove(step[0]);
                        if (!NonObservers.Contains(step[0])) NonObservers.Add(step[0]);
                        Rounds.RemoveAll(delegate (RoundResult x) { return x.C == step[0]; });
                        L("observer demoted: " + step[0] + " (probes from other responders are not recorded)");
                    }
                    continue;    // not the probers' fault: no re-association
                }
                lostAt[step[0]] = 0;
                // re-associate or drop responders that repeatedly fail to send probes
                foreach (string m in new List<string>(all))
                {
                    if (!rr.Missing.Contains(m)) { missCount[m] = 0; continue; }
                    int mc;
                    missCount.TryGetValue(m, out mc);
                    missCount[m] = ++mc;
                    if (mc >= 2)
                    {
                        missCount[m] = 0;
                        if (!Verify(m)) { all.Remove(m); wired.Remove(m); L("dropped " + m); }
                    }
                }
            }

            // Confirm the decisive round per extra device (lost learning frames would otherwise fake a too deep position)
            Dictionary<string, RoundResult> bestX = new Dictionary<string, RoundResult>();
            foreach (RoundResult r in Rounds)
            {
                if (!r.DIsExtra || !r.Valid) continue;
                RoundResult cur;
                if (!bestX.TryGetValue(r.D, out cur) || r.AtC.Count < cur.AtC.Count) bestX[r.D] = r;
            }
            foreach (KeyValuePair<string, RoundResult> kv in bestX)
            {
                if (Cancel || clock.Elapsed.TotalSeconds > MaxSeconds) { Partial = true; break; }
                RoundResult again = RoundChecked(root, kv.Value.C, kv.Key, true, all, kv.Value.Inferred);
                if (again == null) continue;
                if (again.Valid && SameSet(Only(again.AtC, all), Only(kv.Value.AtC, all))) { kv.Value.Confirmed = true; continue; }
                kv.Value.Valid = false;
                Rounds.Add(again);
                L("extra " + kv.Key + " not confirmed");
            }
            // Switches that flood frames to their own management address (Netgear Plus) are found one level
            // too high by the rounds above. A probe to that address reaches exactly the hosts on that switch.
            foreach (string x in ExtraMacs)
            {
                string m = x.ToLowerInvariant();
                if (Cancel || clock.Elapsed.TotalSeconds > MaxSeconds || wired.Count == 0) break;
                if (!SwitchMacs.Exists(delegate (string y) { return y.ToLowerInvariant() == m; })) continue;
                List<string> f = FloodTest(m, wired, all);
                if (f.Count == 0) continue;
                FloodHosts[m] = f;
                L("flood " + m + ": " + Names(f));
            }
            Tree = TopoBuilder.Build(all, RootMac, Rounds, FloodHosts);
        }

        // A responder sends a probe to the management address m. If m's switch floods it, every
        // responder directly attached to that switch records it (and the mapper, if it is attached there).
        // A second probe from one of those hosts also catches the first sender.
        List<string> FloodTest(string m, List<string> senders, List<string> all)
        {
            HashSet<string> seen = new HashSet<string>();
            string s = senders[0];
            for (int pass = 0; pass < 2 && s != null; pass++)
            {
                bool ok;
                foreach (string h in all) if (h != s) Query(h, out ok);     // empty the sees-lists
                mapperSeen.Clear();
                for (int i = 0; i < 2; i++)
                {
                    EmitSingle(s, new EmitDesc(1, (byte)LearnPauseMs, Fr.Mac(s), Fr.Mac(m)));
                    Pump(LearnPauseMs + 150);
                }
                foreach (string h in all)
                {
                    if (h == s) continue;
                    foreach (string e in Query(h, out ok))
                    {
                        string[] p = e.Split('|');
                        if (p[0] == s && p[1] == m) { seen.Add(h); break; }
                    }
                }
                foreach (string e in mapperSeen)
                {
                    string[] p = e.Split('|');
                    if (p[0] == s && p[1] == m) seen.Add(meStr);
                }
                mapperSeen.Clear();
                string next = null;
                foreach (string h in seen) if (h != s && senders.Contains(h)) { next = h; break; }
                if (next == null) break;
                if (pass == 0) seen.Add("?" + s);   // placeholder: s itself is confirmed by the second probe
                s = next;
            }
            List<string> r = new List<string>();
            foreach (string h in seen) if (!h.StartsWith("?")) r.Add(h);
            return r;
        }

        // Checks that a responder is in the session (answers Query); re-associates otherwise
        bool Verify(string mac)
        {
            bool ok;
            for (int i = 0; i < 3; i++)
            {
                Query(mac, out ok);
                if (ok) return true;
                IO.Send(Fr.Discover(Fr.TOS_TOPO, me, xidTopo, gen, ackTopo));
                Pump(150);
            }
            return false;
        }

        static List<string> Only(List<string> a, List<string> keep)
        {
            List<string> r = new List<string>();
            foreach (string x in a) if (keep.Contains(x)) r.Add(x);
            return r;
        }

        // The responder learns a test address X (Train from X), then the mapper sends a probe to X.
        // The probe is switched to the responder's port; it must appear in its sees-list.
        // Self-test like a real round: X is first learned towards the mapper (broadcast Train),
        // then the candidate trains X towards another responder (the helper), and the helper sends
        // a probe to X. The candidate must see it. A probe of the mapper itself is not enough:
        // set-top boxes with an internal switch (DSA, e.g. Vu+ Ultimo4K) see it when X was never
        // learned from the wire, but drop the probes of other responders in every real round.
        // Without another responder the old test (probe from the mapper) is used.
        bool CanObserve(string mac, List<string> resp)
        {
            List<string> helpers = new List<string>();
            foreach (string m in resp) if (m != mac && !wirelessSet.Contains(m)) helpers.Add(m);
            if (helpers.Count == 0) foreach (string m in resp) if (m != mac) helpers.Add(m);
            if (helpers.Count == 0) return CanObserveFromMapper(mac);

            for (int attempt = 0; attempt < 2; attempt++)
            {
                string h = helpers[attempt % helpers.Count];
                byte[] X = NextSpoof();
                string xs = Fr.Str(X, 0);
                for (int i = 0; i < 2; i++) IO.Send(Fr.Build(Fr.TOS_TOPO, Fr.F_TRAIN, Fr.Bcast, X, Fr.Bcast, me, 0, 0));
                List<EmitDesc> t = new List<EmitDesc>();
                t.Add(new EmitDesc(0, (byte)LearnPauseMs, X, Fr.Mac(h)));
                t.Add(new EmitDesc(0, 5, X, Fr.Mac(h)));
                if (!EmitAcked(mac, t)) continue;
                for (int i = 0; i < 2; i++)
                {
                    EmitSingle(h, new EmitDesc(1, (byte)LearnPauseMs, Fr.Mac(h), X));
                    Pump(LearnPauseMs + 100);
                }
                mapperSeen.Clear();
                bool ok;
                foreach (string e in Query(mac, out ok))
                {
                    string[] p = e.Split('|');
                    if (p[0] == h && p[1] == xs) return true;
                }
            }
            return false;
        }

        bool CanObserveFromMapper(string mac)
        {
            for (int attempt = 0; attempt < 2; attempt++)
            {
                byte[] X = NextSpoof();
                string xs = Fr.Str(X, 0);
                List<EmitDesc> t = new List<EmitDesc>();
                t.Add(new EmitDesc(0, 0, X, me));
                t.Add(new EmitDesc(0, 5, X, me));
                if (!EmitAcked(mac, t)) continue;
                Pump(LearnPauseMs);
                for (int i = 0; i < 2; i++) IO.Send(Fr.Build(Fr.TOS_TOPO, Fr.F_PROBE, X, me, X, me, 0, 0));
                Pump(150);
                bool ok;
                foreach (string e in Query(mac, out ok))
                {
                    string[] p = e.Split('|');
                    if (p[0] == meStr && p[1] == xs) return true;
                }
            }
            return false;
        }

        static bool SameSet(List<string> a, List<string> b)
        {
            if (a.Count != b.Count) return false;
            HashSet<string> s = new HashSet<string>(a);
            return s.SetEquals(b);
        }
    }

    // ------------------------------------------------------------------
    //  Derive the tree from the test results
    // ------------------------------------------------------------------
    public static class TopoBuilder
    {
        static string Key(List<string> s)
        {
            List<string> c = new List<string>(s);
            c.Sort();
            return string.Join(",", c.ToArray());
        }

        public static List<TNode> Build(List<string> hostsAll, string rootHost, List<RoundResult> rounds,
                                        Dictionary<string, List<string>> flood = null)
        {
            if (flood == null) flood = new Dictionary<string, List<string>>();
            HashSet<string> U = new HashSet<string>(hostsAll);
            // clusters from responder pairs
            Dictionary<string, List<string>> clusters = new Dictionary<string, List<string>>();
            foreach (RoundResult r in rounds)
            {
                if (!r.Valid || r.DIsExtra) continue;
                List<string> k = new List<string>();
                if (!U.Contains(r.C) || !U.Contains(r.D)) continue;
                k.Add(r.C); k.Add(r.D);
                foreach (string a in r.AtC) if (U.Contains(a)) k.Add(a);
                if (k.Count >= U.Count) continue;
                string key = Key(k);
                if (!clusters.ContainsKey(key)) clusters[key] = k;
            }
            List<List<string>> cand = new List<List<string>>(clusters.Values);
            cand.Sort(delegate (List<string> a, List<string> b) { return b.Count.CompareTo(a.Count); });

            List<HashSet<string>> acc = new List<HashSet<string>>();
            foreach (List<string> k in cand)
            {
                HashSet<string> ks = new HashSet<string>(k);
                bool okL = true;
                foreach (HashSet<string> a in acc)
                {
                    if (ks.IsSubsetOf(a) || !ks.Overlaps(a)) continue;
                    okL = false; break;
                }
                if (okL) acc.Add(ks);
            }

            List<TNode> nodes = new List<TNode>();
            TNode root = new TNode();
            root.Id = "S0"; root.IsSwitch = true; root.Members = new List<string>(U);
            nodes.Add(root);
            List<HashSet<string>> sets = new List<HashSet<string>>();
            sets.Add(U);
            for (int i = 0; i < acc.Count; i++)
            {
                TNode n = new TNode();
                n.Id = "S" + (i + 1); n.IsSwitch = true; n.Members = new List<string>(acc[i]);
                nodes.Add(n);
                sets.Add(acc[i]);
            }
            for (int i = 1; i < nodes.Count; i++) nodes[i].Parent = SmallestContaining(nodes, sets, sets[i], i);
            foreach (string h in hostsAll)
            {
                TNode n = new TNode();
                n.Id = "H:" + h; n.Mac = h;
                HashSet<string> one = new HashSet<string>(); one.Add(h);
                n.Parent = SmallestContaining(nodes, sets, one, -1);
                nodes.Add(n);
            }
            TNode rh = new TNode();
            rh.Id = "H:" + rootHost; rh.Mac = rootHost; rh.Parent = "S0";
            nodes.Add(rh);

            // place additional devices (without LLTD)
            Dictionary<string, List<string>> best = new Dictionary<string, List<string>>();
            foreach (RoundResult r in rounds)
            {
                if (!r.Valid || !r.DIsExtra) continue;
                if (!U.Contains(r.C)) continue;
                List<string> k = new List<string>();
                k.Add(r.C);
                foreach (string a in r.AtC) if (U.Contains(a)) k.Add(a);
                List<string> cur;
                if (!best.TryGetValue(r.D, out cur) || k.Count < cur.Count) best[r.D] = k;
            }
            int extraSw = 0;
            foreach (KeyValuePair<string, List<string>> kv in best)
            {
                if (flood.ContainsKey(kv.Key)) continue;     // placed below
                HashSet<string> R = new HashSet<string>(kv.Value);
                string parent = null;
                for (int i = 0; i < sets.Count; i++)
                {
                    if (nodes[i].IsSwitch && sets[i].SetEquals(R)) { parent = nodes[i].Id; break; }
                }
                if (parent == null)
                {
                    string p = SmallestContaining(nodes, sets, R, -1);
                    // does a new node fit laminarly below p?
                    bool okL = true;
                    for (int i = 0; i < sets.Count; i++)
                    {
                        if (!nodes[i].IsSwitch || nodes[i].Parent != p) continue;
                        if (sets[i].IsSubsetOf(R) || !sets[i].Overlaps(R)) continue;
                        okL = false; break;
                    }
                    if (!okL) parent = p;
                    else
                    {
                        extraSw++;
                        TNode n = new TNode();
                        n.Id = "X" + extraSw; n.IsSwitch = true; n.Members = new List<string>(R); n.Parent = p;
                        int idx = sets.Count;
                        for (int i = 0; i < sets.Count; i++)
                            if (nodes[i].IsSwitch && nodes[i].Parent == p && sets[i].IsSubsetOf(R)) nodes[i].Parent = n.Id;
                        foreach (TNode h in nodes)
                            if (!h.IsSwitch && h.Parent == p && R.Contains(h.Mac)) h.Parent = n.Id;
                        // switch nodes must stay in front (index == set index)
                        nodes.Insert(idx, n);
                        sets.Add(R);
                        parent = n.Id;
                    }
                }
                TNode e = new TNode();
                e.Id = "H:" + kv.Key; e.Mac = kv.Key; e.Parent = parent;
                nodes.Add(e);
            }
            // management address of a flooding switch: the switch is the one its directly attached hosts hang off
            foreach (KeyValuePair<string, List<string>> kv in flood)
            {
                HashSet<string> parents = new HashSet<string>();
                foreach (string h in kv.Value)
                {
                    TNode hn = nodes.Find(delegate (TNode t) { return !t.IsSwitch && t.Mac == h; });
                    if (hn != null) parents.Add(hn.Parent);
                }
                if (parents.Count == 0) continue;
                string parent = null;
                if (parents.Count == 1)
                {
                    foreach (string p in parents) parent = p;
                    // the flooded hosts are only part of that switch's direct hosts: the managed switch sits below it
                    List<string> direct = new List<string>();
                    foreach (TNode t in nodes) if (!t.IsSwitch && t.Parent == parent && (U.Contains(t.Mac) || t.Mac == rootHost)) direct.Add(t.Mac);
                    HashSet<string> fs = new HashSet<string>(kv.Value);
                    bool subset = true;
                    foreach (string h in fs) if (!direct.Contains(h)) subset = false;
                    if (subset && fs.Count < direct.Count)
                    {
                        extraSw++;
                        TNode n = new TNode();
                        HashSet<string> R = new HashSet<string>();
                        foreach (string h in fs) if (U.Contains(h)) R.Add(h);
                        n.Id = "X" + extraSw; n.IsSwitch = true; n.Members = new List<string>(R); n.Parent = parent;
                        foreach (TNode t in nodes) if (!t.IsSwitch && t.Parent == parent && fs.Contains(t.Mac)) t.Parent = n.Id;
                        nodes.Insert(sets.Count, n);
                        sets.Add(R);
                        parent = n.Id;
                    }
                }
                else
                {
                    HashSet<string> F = new HashSet<string>();
                    foreach (string h in kv.Value) if (U.Contains(h)) F.Add(h);
                    parent = parents.Contains("S0") || F.Count == 0 ? "S0" : SmallestContaining(nodes, sets, F, -1);
                }
                nodes.RemoveAll(delegate (TNode t) { return !t.IsSwitch && t.Mac == kv.Key; });
                TNode e = new TNode();
                e.Id = "H:" + kv.Key; e.Mac = kv.Key; e.Parent = parent;
                nodes.Add(e);
            }
            return nodes;
        }

        static string SmallestContaining(List<TNode> nodes, List<HashSet<string>> sets, HashSet<string> s, int self)
        {
            int best = 0;
            for (int i = 1; i < sets.Count; i++)
            {
                if (i == self || !nodes[i].IsSwitch) continue;
                if (sets[i].Count <= s.Count && i != self && sets[i].SetEquals(s)) continue;
                if (s.IsSubsetOf(sets[i]) && sets[i].Count < sets[best].Count) best = i;
            }
            return nodes[best].Id;
        }
    }
}
