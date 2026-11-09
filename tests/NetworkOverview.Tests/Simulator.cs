#nullable disable
using NetworkOverview.Core.Lltd;

// Simulated Ethernet with learning switches, Wi-Fi restrictions and LLTD responders (per [MS-LLTD]).
namespace NetworkOverview.Tests
{
    public class SimNode
    {
        public string Name;
        public bool IsSwitch;
        public bool WirelessAp;          // switch whose wireless ports follow Wi-Fi rules
        public string Mac;               // hosts
        public bool Responder;
        public bool Wireless;            // host attached via Wi-Fi
        public bool Deaf;                // never sees frames addressed to foreign MACs (like a NIC behind an internal switch)
        // Internal switch that learns only from the wire, not from frames the CPU sends (DSA port of a
        // set-top box): a foreign unicast address that was once seen as a source on the wire is
        // forwarded back to the wire and never reaches the CPU.
        public bool EmbeddedSwitch;
        public HashSet<string> WireLearned = new HashSet<string>();
        public int ProbeBudget = -1;     // >= 0: records only this many probes, drops all later ones
        public List<SimNode> Links = new List<SimNode>();
        public Dictionary<string, SimNode> Fdb = new Dictionary<string, SimNode>();
        // responder state
        public bool Command, AckedTopo, AckedQuick;
        public string Mapper = "";
        public int NextSeq = 0;
        public int LastSeq = -1, LastFn = -1; public byte[] LastResp;
        public List<string> Sees = new List<string>();
        public Queue<byte[]> Inbox = new Queue<byte[]>();
    }

    public class SimNet
    {
        public List<SimNode> Nodes = new List<SimNode>();
        public Random Rnd = new Random(7);
        public double Loss = 0.0;
        Queue<object[]> q = new Queue<object[]>();
        public int Delivered = 0;

        public SimNode Switch(string n, bool ap) { SimNode s = new SimNode(); s.Name = n; s.IsSwitch = true; s.WirelessAp = ap; Nodes.Add(s); return s; }
        public SimNode Host(string n, string mac, bool resp, SimNode sw, bool wireless)
        {
            SimNode h = new SimNode(); h.Name = n; h.Mac = mac; h.Responder = resp; h.Wireless = wireless;
            Nodes.Add(h); Link(h, sw); return h;
        }
        public void Link(SimNode a, SimNode b) { a.Links.Add(b); b.Links.Add(a); }

        public void Send(SimNode from, byte[] f)
        {
            if (from.Wireless && Fr.Str(f, 6) != from.Mac) return;   // a Wi-Fi client must not use a foreign source address
            q.Enqueue(new object[] { from, from.Links[0], f });
            Run();
        }

        bool running = false;
        void Run()
        {
            if (running) return;
            running = true;
            while (q.Count > 0)
            {
                object[] e = q.Dequeue();
                SimNode from = (SimNode)e[0], to = (SimNode)e[1];
                byte[] f = (byte[])e[2];
                if (Loss > 0 && Rnd.NextDouble() < Loss) continue;
                string dst = Fr.Str(f, 0), src = Fr.Str(f, 6);
                if (to.IsSwitch)
                {
                    to.Fdb[src] = from;
                    SimNode outp;
                    bool bc = (f[0] & 1) != 0;
                    if (!bc && to.Fdb.TryGetValue(dst, out outp))
                    {
                        if (outp != from) q.Enqueue(new object[] { to, outp, f });
                    }
                    else foreach (SimNode l in to.Links) if (l != from) q.Enqueue(new object[] { to, l, f });
                }
                else
                {
                    bool bc = (f[0] & 1) != 0;
                    if (to.Wireless && !bc && dst != to.Mac) continue;  // Wi-Fi clients only see their own frames
                    if (to.Deaf && !bc && dst != to.Mac) continue;
                    if (to.EmbeddedSwitch)
                    {
                        if (src != to.Mac) to.WireLearned.Add(src);
                        if (!bc && dst != to.Mac && to.WireLearned.Contains(dst)) continue;
                    }
                    Delivered++;
                    if (to.Responder) Respond(to, f);
                    else to.Inbox.Enqueue(f);
                }
            }
            running = false;
        }

        void Reply(SimNode h, int tos, int fn, byte[] ethDst, byte[] realDst, int seq, byte[] payload)
        {
            byte[] me = Fr.Mac(h.Mac);
            byte[] f = Fr.Build(tos, fn, ethDst, me, realDst, me, seq, payload == null ? 0 : payload.Length);
            if (payload != null) Buffer.BlockCopy(payload, 0, f, 32, payload.Length);
            q.Enqueue(new object[] { h, h.Links[0], f });
            if (seq != 0) { h.LastSeq = seq; h.LastFn = fn; h.LastResp = f; }
        }

        bool SeqOk(SimNode h, byte[] f, int respFn)
        {
            int seq = Fr.Seq(f);
            if (seq == 0) return false;
            if (h.LastSeq == seq && h.LastFn == respFn && h.LastResp != null) { q.Enqueue(new object[] { h, h.Links[0], h.LastResp }); return false; }
            if (h.NextSeq != 0 && h.NextSeq != seq) return false;
            h.NextSeq = seq + 1 > 0xFFFF ? 1 : seq + 1;
            h.LastResp = null;
            return true;
        }

        void Respond(SimNode h, byte[] f)
        {
            if (!Fr.IsLltd(f)) return;
            int tos = f[15], fn = f[17];
            string dst = Fr.Str(f, 0);
            string rs = Fr.Str(f, 24);
            bool forMe = dst == h.Mac || (f[0] & 1) != 0;
            byte[] rsb = Fr.Sub(f, 24, 6);
            if (fn == Fr.F_DISCOVER && forMe)
            {
                int n = (f[34] << 8) | f[35];
                bool listed = false;
                for (int i = 0; i < n; i++) if (Fr.Str(f, 36 + 6 * i) == h.Mac) listed = true;
                if (tos == 0)
                {
                    if (listed) { h.AckedTopo = true; h.Command = true; h.Mapper = rs; }
                    else if (!h.AckedTopo) Reply(h, 0, Fr.F_HELLO, Fr.Bcast, Fr.Bcast, 0, Hello(h));
                }
                else
                {
                    if (listed) h.AckedQuick = true;
                    else if (!h.AckedQuick) Reply(h, 1, Fr.F_HELLO, Fr.Bcast, Fr.Bcast, 0, Hello(h));
                }
                return;
            }
            if (fn == Fr.F_RESET && forMe) { if (tos == 0) { h.Command = false; h.AckedTopo = false; h.Sees.Clear(); h.NextSeq = 0; } else h.AckedQuick = false; return; }
            if (!h.Command || tos != 0) return;
            if (fn == Fr.F_PROBE && h.ProbeBudget >= 0 && h.ProbeBudget-- == 0) { h.ProbeBudget = 0; return; }
            if (fn == Fr.F_PROBE) { h.Sees.Add(rs + "|" + Fr.Str(f, 6) + "|" + dst); return; }
            if (!forMe || rs != h.Mapper) return;
            if (fn == Fr.F_CHARGE) { h.LastResp = null; h.LastSeq = -1; return; }
            if (fn == Fr.F_EMIT)
            {
                int seq = Fr.Seq(f);
                if (seq != 0 && !SeqOk(h, f, Fr.F_ACK)) return;
                if (seq == 0) { h.LastResp = null; h.LastSeq = -1; }
                int n = (f[32] << 8) | f[33];
                byte[] me = Fr.Mac(h.Mac);
                for (int i = 0; i < n; i++)
                {
                    int o = 34 + 14 * i;
                    byte[] src = Fr.Sub(f, o + 2, 6), d = Fr.Sub(f, o + 8, 6);
                    byte[] e = Fr.Build(0, f[o] == 0 ? Fr.F_TRAIN : Fr.F_PROBE, d, src, d, me, 0, 0);
                    if (h.Wireless && Fr.Str(src, 0) != h.Mac) continue;
                    q.Enqueue(new object[] { h, h.Links[0], e });
                }
                if (seq != 0) Reply(h, 0, Fr.F_ACK, rsb, rsb, seq, null);
                return;
            }
            if (fn == Fr.F_QUERY)
            {
                int seq = Fr.Seq(f);
                if (!SeqOk(h, f, Fr.F_QUERYRESP)) return;
                int n = Math.Min(h.Sees.Count, 70);
                byte[] p = new byte[2 + 20 * n];
                p[0] = (byte)((n >> 8) | (h.Sees.Count > n ? 0x80 : 0)); p[1] = (byte)n;
                for (int i = 0; i < n; i++)
                {
                    string[] s = h.Sees[i].Split('|');
                    Buffer.BlockCopy(Fr.Mac(s[0]), 0, p, 2 + 20 * i + 2, 6);
                    Buffer.BlockCopy(Fr.Mac(s[1]), 0, p, 2 + 20 * i + 8, 6);
                    Buffer.BlockCopy(Fr.Mac(s[2]), 0, p, 2 + 20 * i + 14, 6);
                }
                h.Sees.RemoveRange(0, n);
                Reply(h, 0, Fr.F_QUERYRESP, rsb, rsb, seq, p);
            }
        }

        byte[] Hello(SimNode h)
        {
            List<byte> p = new List<byte>();
            p.AddRange(new byte[14]);
            p.Add(0x03); p.Add(4); p.Add(0); p.Add(0); p.Add(0); p.Add((byte)(h.Wireless ? 71 : 6));
            byte[] nm = System.Text.Encoding.Unicode.GetBytes(h.Name);
            p.Add(0x0F); p.Add((byte)nm.Length); p.AddRange(nm);
            p.Add(0); p.Add(0);
            return p.ToArray();
        }
    }

    public class SimIO : IFrameIO
    {
        SimNet net; SimNode me;
        public SimIO(SimNet n, SimNode m) { net = n; me = m; }
        public void Send(byte[] f) { net.Send(me, f); }
        public byte[] Receive(int timeoutMs)
        {
            if (me.Inbox.Count > 0) return me.Inbox.Dequeue();
            if (timeoutMs > 0) System.Threading.Thread.Sleep(Math.Min(timeoutMs, 2));
            return null;
        }
        public void Close() { }
    }
}
