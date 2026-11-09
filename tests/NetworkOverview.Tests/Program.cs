using System.Drawing;
using System.Text;
using NetworkOverview.Core;
using NetworkOverview.Core.Devices;
using NetworkOverview.Core.Discovery;
using NetworkOverview.Core.Layout;
using NetworkOverview.Core.Lltd;
using NetworkOverview.Core.Localization;
using NetworkOverview.Core.Model;
using NetworkOverview.Core.Platform;
using NetworkOverview.Tests;

// Minimal dependency-free test runner (NuGet is not required to build or run the tests).
var tests = new List<(string Name, Action Body)>
{
    ("Topology: lossless, wired mapper", () => TopologyTests.Run(0.0, true, 1)),
    ("Topology: 3% loss per hop", () => TopologyTests.Run(0.03, true, 2)),
    ("Topology: wireless mapper uses wired root", () => TopologyTests.Run(0.0, false, 3)),
    ("Topology: responder that cannot observe is not used as observer", TopologyTests.DeafResponder),
    ("Topology: responder behind an internal switch is not used as observer", TopologyTests.EmbeddedSwitchResponder),
    ("Topology: observer that drops probes from other responders is demoted", TopologyTests.PartlyDeafResponder),
    ("Topology: switch that floods frames to its management address", TopologyTests.FloodingManagement),
    ("Model + layout: merge sources, no crossings", ModelTests.MergeAndLayout),
    ("Model: OpenWrt AP connected via Wi-Fi becomes a repeater", ModelTests.WifiRepeater),
    ("Layout: wireless group below wired switch (issue screenshot)", ModelTests.WirelessBelowWired),
    ("mDNS: build and parse packets", MiscTests.MdnsRoundTrip),
    ("OpenWrt: parse script output", MiscTests.OpenWrtParse),
    ("Device classifier", MiscTests.Classifier),
    ("Vendor database", MiscTests.Vendors),
    ("SSDP: headers and device description", MiscTests.SsdpParse),
    ("NSDP: response parsing", MiscTests.NsdpParse),
    ("mDNS model hints", MiscTests.MdnsModels),
    ("Localization complete", MiscTests.Localization),
};

if (args.Length > 0) tests = tests.Where(t => args.Any(a => t.Name.Contains(a, StringComparison.OrdinalIgnoreCase))).ToList();
int failed = 0;
foreach (var (name, body) in tests)
{
    var sw = System.Diagnostics.Stopwatch.StartNew();
    try { body(); Console.WriteLine($"PASS  {name} ({sw.ElapsedMilliseconds} ms)"); }
    catch (Exception ex) { failed++; Console.WriteLine($"FAIL  {name}: {ex.Message}"); Console.WriteLine(ex.StackTrace); }
}
Console.WriteLine(failed == 0 ? $"All {tests.Count} tests passed." : $"{failed} of {tests.Count} tests failed.");
return failed == 0 ? 0 : 1;

static class Assert
{
    public static void True(bool cond, string msg) { if (!cond) throw new Exception(msg); }
    public static void Equal<T>(T expected, T actual, string what)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"{what}: expected '{expected}', got '{actual}'");
    }
}

/// <summary>Network resembling the author's: router, big unmanaged switch, two Netgear switches, OpenWrt AP.</summary>
sealed class TestNet
{
    public SimNet Net = new();
    public Dictionary<string, SimNode> H = new();
    public SimNode R, U, N1, N2, AP;

    public TestNet(double loss, bool mapperWired, int seed, params string[] deaf)
    {
        Net.Loss = loss;
        Net.Rnd = new Random(seed);
        R = Net.Switch("R", false); U = Net.Switch("U", false); N1 = Net.Switch("N1", false); N2 = Net.Switch("N2", false); AP = Net.Switch("AP", true);
        Net.Link(R, U); Net.Link(R, N1); Net.Link(U, N2); Net.Link(U, AP);
        Add("M", "02:00:00:00:00:01", false, mapperWired ? U : AP, !mapperWired);
        Add("GW", "02:00:00:00:00:10", false, R);
        Add("r1", "02:00:00:00:00:11", true, R);
        Add("u1", "02:00:00:00:00:21", true, U);
        Add("u2", "02:00:00:00:00:22", true, U);
        Add("u3", "02:00:00:00:00:23", false, U);
        Add("n1a", "02:00:00:00:00:31", true, N1);
        Add("n1b", "02:00:00:00:00:32", true, N1);
        Add("N1mgmt", "02:00:00:00:00:3f", false, N1);
        Add("n2a", "02:00:00:00:00:41", true, N2);
        Add("N2mgmt", "02:00:00:00:00:4f", false, N2);
        Add("APcpu", "02:00:00:00:00:5f", false, AP);
        Add("apl1", "02:00:00:00:00:51", true, AP);
        Add("w1", "02:00:00:00:00:61", true, AP, true);
        Add("w2", "02:00:00:00:00:62", false, AP, true);
        foreach (var d in deaf) H[d].Deaf = true;
        // let every device talk once so that the switches know it
        double l = Net.Loss; Net.Loss = 0;
        foreach (var h in H.Values) Net.Send(h, Fr.Build(0, Fr.F_TRAIN, Fr.Bcast, Fr.Mac(h.Mac), Fr.Bcast, Fr.Mac(h.Mac), 0, 0));
        Net.Loss = l;
        H["M"].Inbox.Clear();
    }

    void Add(string name, string mac, bool resp, SimNode sw, bool wl = false) => H[name] = Net.Host(name, mac, resp, sw, wl);
    public string Mac(string name) => H[name].Mac;

    public MapperJob Map(bool wired)
    {
        var job = new MapperJob { MyMac = Mac("M"), MyWired = wired, DiscoverMs = 600, LearnPauseMs = 5, IO = new SimIO(Net, H["M"]) };
        foreach (var x in new[] { "GW", "u3", "N1mgmt", "N2mgmt", "APcpu" }) job.ExtraMacs.Add(Mac(x));
        job.WirelessMacs.Add(Mac("w1")); job.WirelessMacs.Add(Mac("w2"));
        job.SwitchMacs.Add(Mac("N1mgmt")); job.SwitchMacs.Add(Mac("N2mgmt"));
        job.Run();
        return job;
    }

    public string Describe(List<TNode> tree)
    {
        var byMac = H.Values.ToDictionary(h => h.Mac, h => h.Name);
        var sb = new StringBuilder();
        void Show(string id, string ind)
        {
            foreach (var t in tree.Where(t => t.Parent == id).OrderBy(t => t.IsSwitch ? 0 : 1).ThenBy(t => t.IsSwitch ? string.Join(",", t.Members.Select(m => byMac[m]).OrderBy(x => x, StringComparer.Ordinal)) : byMac[t.Mac], StringComparer.Ordinal))
            {
                if (t.IsSwitch) { sb.Append(ind).Append('{').Append(string.Join(",", t.Members.Select(m => byMac[m]).OrderBy(x => x, StringComparer.Ordinal))).Append("}\n"); Show(t.Id, ind + "  "); }
                else sb.Append(ind).Append(byMac[t.Mac]).Append('\n');
            }
        }
        Show("S0", "");
        return sb.ToString();
    }
}

static partial class TopologyTests
{
    public static void Run(double loss, bool wired, int seed)
    {
        var t = new TestNet(loss, wired, seed);
        var job = t.Map(wired);
        Assert.True(job.Error.Length == 0, "mapper error: " + job.Error);
        Assert.Equal(8, job.Hosts.Count, "responders found");
        string d = t.Describe(job.Tree);
        string expected = wired
            ? "{apl1,w1}\n  APcpu\n  apl1\n  w1\n{n1a,n1b,r1}\n  {n1a,n1b}\n    N1mgmt\n    n1a\n    n1b\n  GW\n  r1\n{n2a}\n  N2mgmt\n  n2a\nM\nu1\nu2\nu3\n"
            : "{apl1,n2a,u1,u2,w1}\n  {apl1,w1}\n    APcpu\n    apl1\n    w1\n  {n2a}\n    N2mgmt\n    n2a\n  u1\n  u2\n  u3\n{n1a,n1b}\n  N1mgmt\n  n1a\n  n1b\nGW\nr1\n";
        Assert.Equal(expected, d, "tree");
    }
}

static partial class TopologyTests
{
    public static void DeafResponder()
    {
        var t = new TestNet(0.0, true, 4, "u2");
        var job = t.Map(true);
        Assert.True(job.NonObservers.Contains(t.Mac("u2")), "u2 detected as non-observer");
        Assert.True(!job.Rounds.Any(r => r.C == t.Mac("u2")), "u2 never used as observer");
        Assert.True(job.Rounds.All(r => r.Valid || r.Confirmed || r.DIsExtra), "no invalid responder rounds: " +
            string.Join("; ", job.Rounds.Where(r => !r.Valid).Select(r => r.C + "/" + r.D)));
        string expected = "{apl1,w1}\n  APcpu\n  apl1\n  w1\n{n1a,n1b,r1}\n  {n1a,n1b}\n    N1mgmt\n    n1a\n    n1b\n  GW\n  r1\n{n2a}\n  N2mgmt\n  n2a\nM\nu1\nu2\nu3\n";
        Assert.Equal(expected, t.Describe(job.Tree), "tree with deaf responder");
    }

    // Like the Vu+ Ultimo4K: sees probes of the mapper to a fresh test address, but not the probes
    // of other responders in a real round (the internal switch learned X from the wire before).
    public static void EmbeddedSwitchResponder()
    {
        var t = new TestNet(0.0, true, 4);
        t.H["u2"].EmbeddedSwitch = true;
        var job = t.Map(true);
        Assert.True(job.NonObservers.Contains(t.Mac("u2")), "u2 detected as non-observer");
        Assert.True(!job.Rounds.Any(r => r.C == t.Mac("u2")), "u2 never used as observer");
        Assert.True(job.Rounds.All(r => r.Valid || r.Confirmed || r.DIsExtra), "no invalid responder rounds: " +
            string.Join("; ", job.Rounds.Where(r => !r.Valid).Select(r => r.C + "/" + r.D)));
        string expected = "{apl1,w1}\n  APcpu\n  apl1\n  w1\n{n1a,n1b,r1}\n  {n1a,n1b}\n    N1mgmt\n    n1a\n    n1b\n  GW\n  r1\n{n2a}\n  N2mgmt\n  n2a\nM\nu1\nu2\nu3\n";
        Assert.Equal(expected, t.Describe(job.Tree), "tree with embedded-switch responder");
    }

    // Netgear Plus switches flood frames addressed to their own management MAC (GS116Ev2 at Hauke's):
    // without the flood test the management address lands on the parent switch.
    public static void FloodingManagement()
    {
        var t = new TestNet(0.0, true, 6);
        t.N1.FloodMac = t.Mac("N1mgmt");
        t.N2.FloodMac = t.Mac("N2mgmt");
        var job = t.Map(true);
        Assert.True(job.FloodHosts.TryGetValue(t.Mac("N1mgmt"), out var f1) && f1.Count == 2
            && f1.Contains(t.Mac("n1a")) && f1.Contains(t.Mac("n1b")), "N1 flood hosts");
        string expected = "{apl1,w1}\n  APcpu\n  apl1\n  w1\n{n1a,n1b,r1}\n  {n1a,n1b}\n    N1mgmt\n    n1a\n    n1b\n  GW\n  r1\n{n2a}\n  N2mgmt\n  n2a\nM\nu1\nu2\nu3\n";
        Assert.Equal(expected, t.Describe(job.Tree), "tree with flooding switches");
    }

    // Passes the self-test but stops recording probes during the rounds: demoted while mapping.
    public static void PartlyDeafResponder()
    {
        var t = new TestNet(0.0, true, 5);
        t.H["u2"].ProbeBudget = 4;
        var job = t.Map(true);
        Assert.True(job.NonObservers.Contains(t.Mac("u2")), "u2 demoted");
        Assert.True(!job.Rounds.Any(r => r.C == t.Mac("u2")), "u2 rounds discarded");
        string expected = "{apl1,w1}\n  APcpu\n  apl1\n  w1\n{n1a,n1b,r1}\n  {n1a,n1b}\n    N1mgmt\n    n1a\n    n1b\n  GW\n  r1\n{n2a}\n  N2mgmt\n  n2a\nM\nu1\nu2\nu3\n";
        Assert.Equal(expected, t.Describe(job.Tree), "tree with partly deaf responder");
    }
}

static class ModelTests
{
    static ScanData SimData(TestNet t, MapperJob job)
    {
        Neighbor Nb(string n, string ip) => new() { Mac = t.Mac(n), IPv4 = ip };
        var ad = new AdapterInfo { Name = "Ethernet", Mac = t.Mac("M"), IPv4 = "192.168.75.60", Gateway = "192.168.75.1", SpeedBps = 1_000_000_000 };
        var router = new OpenWrtInfo { Target = "root@192.168.75.1", Name = "Link", MainMac = t.Mac("GW") };
        router.Interfaces["br-lan"] = t.Mac("GW");
        router.Fdb[t.Mac("r1")] = "lan1";
        foreach (var x in new[] { "n1a", "n1b", "N1mgmt" }) router.Fdb[t.Mac(x)] = "lan2";
        foreach (var x in new[] { "M", "u1", "u2", "u3", "n2a", "N2mgmt", "APcpu", "apl1", "w1", "w2" }) router.Fdb[t.Mac(x)] = "lan3";
        router.Leases[t.Mac("u3")] = new OpenWrtLease { IPv4 = "192.168.75.23", Name = "drucker" };
        router.Leases[t.Mac("w2")] = new OpenWrtLease { IPv4 = "192.168.75.62", Name = "Echo-WZ" };
        var ap = new OpenWrtInfo { Target = "root@192.168.75.6", Name = "AP-Flur", MainMac = t.Mac("APcpu") };
        ap.Interfaces["br-lan"] = t.Mac("APcpu"); ap.Interfaces["phy0-ap0"] = "02:00:00:00:00:5e"; ap.WifiSsid["phy0-ap0"] = "HomeNet";
        ap.Fdb[t.Mac("apl1")] = "lan1";
        foreach (var x in new[] { "M", "u1", "r1", "GW" }) ap.Fdb[t.Mac(x)] = "wan";
        ap.Stations[t.Mac("w1")] = new OpenWrtStation { Interface = "phy0-ap0", Signal = "-51" };
        ap.Stations[t.Mac("w2")] = new OpenWrtStation { Interface = "phy0-ap0", Signal = "-67" };
        var ns1 = new NsdpDevice { Mac = t.Mac("N1mgmt"), Model = "GS108Ev3", Name = "Buero", IPv4 = "192.168.75.3" };
        ns1.Ports.Add("1:1G");
        var ns2 = new NsdpDevice { Mac = t.Mac("N2mgmt"), Model = "GS105E", IPv4 = "192.168.75.4" };
        return new ScanData
        {
            Adapter = ad, ComputerName = "QUATTRO",
            Neighbors = new() { Nb("GW", "192.168.75.1"), Nb("u3", "192.168.75.23"), Nb("N1mgmt", "192.168.75.3"), Nb("N2mgmt", "192.168.75.4"), Nb("APcpu", "192.168.75.6") },
            OpenWrt = new() { router, ap }, Nsdp = new() { ns1, ns2 }, LltdHosts = job.Hosts, Tree = job.Tree,
        };
    }

    public static void WifiRepeater()
    {
        var ad = new AdapterInfo { Name = "Ethernet", Mac = "02:00:00:00:00:01", IPv4 = "192.168.75.60", Prefix = 24, Gateway = "192.168.75.1" };
        var gw = new OpenWrtInfo { Target = "root@192.168.75.1", Name = "Link", MainMac = "02:00:00:00:00:10" };
        gw.Interfaces["br-lan"] = gw.MainMac;
        var sz = new OpenWrtInfo { Target = "root@192.168.75.6", Name = "WLAN-AP-SZ", MainMac = "80:af:ca:fb:3a:71" };
        sz.Interfaces["br-lan"] = sz.MainMac; sz.Interfaces["phy1-ap0"] = "82:af:ca:fb:3a:73"; sz.WifiSsid["phy1-ap0"] = "HomeNet";
        sz.Stations["82:af:ca:fb:3a:2f"] = new OpenWrtStation { Interface = "phy1-ap0", Signal = "-60" };   // repeater uplink
        sz.Stations["02:00:00:00:00:77"] = new OpenWrtStation { Interface = "phy1-ap0", Signal = "-50" };   // phone
        var ku = new OpenWrtInfo { Target = "root@192.168.75.7", Name = "WLAN-AP-Kueche", MainMac = "80:af:ca:fb:3a:2d" };
        ku.Interfaces["br-lan"] = ku.MainMac; ku.Interfaces["phy1-sta0"] = "80:af:ca:fb:3a:2e"; ku.WifiSsid["phy0-ap0"] = "HomeNet";
        ku.Stations["02:00:00:00:00:88"] = new OpenWrtStation { Interface = "phy0-ap0", Signal = "-40" };
        // WDS/mesh: both sides list each other; only the forwarding table tells the direction
        ku.Stations["82:af:ca:fb:3a:73"] = new OpenWrtStation { Interface = "phy1-sta0", Signal = "-60" };
        ku.Fdb[gw.MainMac] = "phy1-sta0";
        sz.Fdb[gw.MainMac] = "lan1";
        var data = new ScanData
        {
            Adapter = ad, OpenWrt = { gw, sz, ku },
            Neighbors = { new Neighbor { Mac = gw.MainMac, IPv4 = "192.168.75.1" }, new Neighbor { Mac = sz.MainMac, IPv4 = "192.168.75.6" },
                          new Neighbor { Mac = ku.MainMac, IPv4 = "192.168.75.7" } },
        };
        L.SetLanguage("en");
        var m = ModelBuilder.Build(data);
        var k = m.All.First(n => n.Name == "WLAN-AP-Kueche");
        Assert.Equal(m.All.First(n => n.Name == "WLAN-AP-SZ").Key, k.Parent ?? "", "repeater hangs off its AP");
        Assert.True(k.Wireless && k.Dashed, "repeater link is wireless");
        var szn = m.All.First(n => n.Name == "WLAN-AP-SZ");
        Assert.True(!szn.Wireless && szn.Parent != k.Key, "the wired AP is not a repeater of its repeater");
        Assert.Equal("Wi-Fi repeater", NodeText.TypeName(k), "type name");
        Assert.Equal(k.Key, m.All.First(n => n.Mac == "02:00:00:00:00:88").Parent ?? "", "repeater keeps its own clients");
    }

    public static void MergeAndLayout()
    {
        var t = new TestNet(0, true, 1);
        var job = t.Map(true);
        var m = ModelBuilder.Build(SimData(t, job));
        var lay = TreeLayout.Run(m);
        Node N(string name) => m[t.Mac(name)];
        Assert.Equal("#internet", N("GW").Parent, "gateway parent");
        var lanSwitch = m.ParentOf(N("r1"))!;
        Assert.Equal(N("GW").Key, lanSwitch.Parent, "router LAN switch hangs off gateway");
        Assert.True(lanSwitch.Name.Contains("Link"), "router LAN switch named after router: " + lanSwitch.Name);
        var netgear = m.ParentOf(N("n1a"))!;
        Assert.Equal("Buero", netgear.Name, "Netgear merged into inferred switch");
        Assert.True(netgear.Managed, "managed flag");
        Assert.Equal("GS105E", m.ParentOf(N("n2a"))!.Name, "second Netgear");
        Assert.Equal(N("APcpu").Key, N("w1").Parent, "LLTD Wi-Fi client hangs off AP");
        Assert.True(N("w2").Dashed && N("w2").Parent == N("APcpu").Key, "non-LLTD Wi-Fi client via station list");
        Assert.Equal(DeviceType.EchoDot, N("w2").DeviceType, "Echo by name");
        Assert.Equal(NodeKind.AccessPoint, N("APcpu").Kind, "OpenWrt AP kind");
        Assert.True(N("u3").Parent != null, "non-LLTD wired device placed");
        Assert.True(m.All.All(n => n.Placed), "all nodes placed");
        CheckSegments(lay);
    }

    /// <summary>Router with many wireless clients and a wired switch: the case from the issue screenshot.</summary>
    public static void WirelessBelowWired()
    {
        var m = new NetworkModel();
        m.Add(new Node { Key = "#internet", Kind = NodeKind.Internet, Name = "Internet" });
        m.Add(new Node { Key = "gw", Kind = NodeKind.Gateway, IsGateway = true, Name = "Link", IPv4 = "192.168.75.1", Parent = "#internet", HasWifiClients = true });
        for (int i = 0; i < 8; i++)
            m.Add(new Node { Key = "w" + i, Name = "Phone" + i, IPv4 = "192.168.75." + (100 + i), Wireless = true, Dashed = true, Parent = "gw" });
        m.Add(new Node { Key = "sw", Kind = NodeKind.Switch, Name = "Switch", Parent = "gw" });
        m.Add(new Node { Key = "self", Name = "QUATTRO", IsSelf = true, IPv4 = "192.168.75.60", Parent = "sw" });
        m.Add(new Node { Key = "sw2", Kind = NodeKind.Switch, Name = "Switch", Parent = "sw" });
        m.Add(new Node { Key = "pc", Name = "PC", IPv4 = "192.168.75.61", Parent = "sw2" });
        m.Add(new Node { Key = "pc2", Name = "PC2", IPv4 = "192.168.75.62", Parent = "sw2" });
        var lay = TreeLayout.Run(m);
        Assert.True(m["sw"].Y < m["w0"].Y, "wired subtree above wireless clients");
        Assert.True(m["w7"].Y > m["pc2"].Y, "wireless clients last");
        CheckSegments(lay);
        var dashedVertical = lay.Segments.Where(s => s.Dashed && Math.Abs(s.A.X - s.B.X) < 0.5f).ToList();
        Assert.Equal(1, dashedVertical.Count, "exactly one dashed bus segment");
    }

    /// <summary>No two segments may cross, and dashed segments must not overlap (overlapping dashes look solid).</summary>
    public static void CheckSegments(LayoutResult lay)
    {
        var s = lay.Segments;
        for (int i = 0; i < s.Count; i++)
            for (int j = i + 1; j < s.Count; j++)
            {
                if (ProperCross(s[i], s[j])) throw new Exception($"segments cross: {Fmt(s[i])} x {Fmt(s[j])}");
                if (s[i].Dashed && s[j].Dashed && Overlap(s[i], s[j])) throw new Exception($"dashed segments overlap: {Fmt(s[i])} / {Fmt(s[j])}");
                if (s[i].Dashed != s[j].Dashed && Overlap(s[i], s[j])) throw new Exception($"wired and wireless overlap: {Fmt(s[i])} / {Fmt(s[j])}");
            }
    }

    static string Fmt(Segment g) => $"({g.A.X},{g.A.Y})-({g.B.X},{g.B.Y}){(g.Dashed ? " dashed" : "")}";

    static bool IsH(Segment g) => Math.Abs(g.A.Y - g.B.Y) < 0.5f;
    static (float lo, float hi) Range(float a, float b) => (Math.Min(a, b), Math.Max(a, b));

    // a horizontal and a vertical segment crossing strictly inside both (touching endpoints is a junction)
    static bool ProperCross(Segment a, Segment b)
    {
        if (IsH(a) == IsH(b)) return false;
        var h = IsH(a) ? a : b; var v = IsH(a) ? b : a;
        var (hx0, hx1) = Range(h.A.X, h.B.X); var (vy0, vy1) = Range(v.A.Y, v.B.Y);
        float x = v.A.X, y = h.A.Y;
        return x > hx0 + 0.5f && x < hx1 - 0.5f && y > vy0 + 0.5f && y < vy1 - 0.5f;
    }

    // collinear segments sharing more than a point
    static bool Overlap(Segment a, Segment b)
    {
        if (IsH(a) != IsH(b)) return false;
        if (IsH(a))
        {
            if (Math.Abs(a.A.Y - b.A.Y) > 0.5f) return false;
            var (a0, a1) = Range(a.A.X, a.B.X); var (b0, b1) = Range(b.A.X, b.B.X);
            return Math.Min(a1, b1) - Math.Max(a0, b0) > 0.5f;
        }
        if (Math.Abs(a.A.X - b.A.X) > 0.5f) return false;
        var (c0, c1) = Range(a.A.Y, a.B.Y); var (d0, d1) = Range(b.A.Y, b.B.Y);
        return Math.Min(c1, d1) - Math.Max(c0, d0) > 0.5f;
    }
}

static class MiscTests
{
    public static void MdnsRoundTrip()
    {
        // response from 192.168.75.244: Cast device with model and friendly name
        var b = new List<byte> { 0, 0, 0x84, 0, 0, 0, 0, 4, 0, 0, 0, 0 };
        void Name(string n) { foreach (var l in n.Split('.')) { b.Add((byte)l.Length); b.AddRange(Encoding.UTF8.GetBytes(l)); } b.Add(0); }
        void Rr(string n, ushort type, byte[] rdata) { Name(n); b.Add((byte)(type >> 8)); b.Add((byte)type); b.Add(0x80); b.Add(1); b.AddRange(new byte[] { 0, 0, 0, 120 }); b.Add((byte)(rdata.Length >> 8)); b.Add((byte)rdata.Length); b.AddRange(rdata); }
        byte[] N(string n) { var x = new List<byte>(); foreach (var l in n.Split('.')) { x.Add((byte)l.Length); x.AddRange(Encoding.UTF8.GetBytes(l)); } x.Add(0); return x.ToArray(); }
        byte[] Txt(params string[] kv) { var x = new List<byte>(); foreach (var s in kv) { var e = Encoding.UTF8.GetBytes(s); x.Add((byte)e.Length); x.AddRange(e); } return x.ToArray(); }
        Rr("_googlecast._tcp.local", Mdns.TypePtr, N("Google-Home-Mini-abc._googlecast._tcp.local"));
        Rr("Google-Home-Mini-abc._googlecast._tcp.local", Mdns.TypeSrv, new byte[] { 0, 0, 0, 0, 0x1F, 0x49 }.Concat(N("abc.local")).ToArray());
        Rr("Google-Home-Mini-abc._googlecast._tcp.local", Mdns.TypeTxt, Txt("md=Google Home Mini", "fn=Küche"));
        Rr("abc.local", Mdns.TypeA, new byte[] { 192, 168, 75, 244 });
        var recs = Mdns.Parse(b.ToArray(), "192.168.75.244");
        Assert.Equal(4, recs.Count, "records");
        var hosts = Mdns.Assemble(recs);
        Assert.Equal(1, hosts.Count, "hosts");
        Assert.Equal("Google Home Mini", hosts[0].Model(), "model");
        Assert.Equal("Küche", hosts[0].FriendlyName(), "friendly name");
        Assert.Equal(DeviceType.GoogleSpeaker, DeviceClassifier.Classify("", "", hosts[0], false), "cast classification");
        // query packets: compression-free labels
        var q = Mdns.BuildQueries(new List<(string, ushort)> { ("_services._dns-sd._udp.local", Mdns.TypePtr) });
        Assert.Equal(1, q.Count, "one packet");
        int p = 12;
        Assert.Equal("_services._dns-sd._udp.local", Mdns.ReadName(q[0], ref p), "query name");
    }

    public static void OpenWrtParse()
    {
        string output = string.Join("\n",
            "##HOST Link",
            "##IF br-lan 3c:84:6a:aa:bb:01", "##IF lan1 3c:84:6a:aa:bb:01", "##IF lo 00:00:00:00:00:00", "##IF phy0-ap0 3c:84:6a:aa:bb:02",
            "##PORT br-lan lan1 0x1", "##PORT br-lan lan2 0x2", "##PORT br-lan phy0-ap0 0x3",
            "##FDB br-lan 3c 84 6a aa bb 01 01 01 00 00 00 00 00 00 00 00",
            "##FDB br-lan 02 11 22 33 44 55 02 00 0a 00 00 00 00 00 00 00",
            "##WIF phy0-ap0 HomeNet",
            "##STA phy0-ap0 aa:bb:cc:dd:ee:ff -55",
            "##LEASE 1731000000 aa:bb:cc:dd:ee:ff 192.168.75.101 Note20-Ultra-von-Silvia 01:aa",
            "##LEASE 1731000000 02:11:22:33:44:55 192.168.75.20 * *",
            "##ARP 192.168.75.20 02:11:22:33:44:55 br-lan");
        var o = new OpenWrtInfo { Target = "root@192.168.75.1" };
        OpenWrtClient.Parse(output, o);
        Assert.Equal("Link", o.Name, "hostname");
        Assert.Equal("3c:84:6a:aa:bb:01", o.MainMac, "main MAC");
        Assert.Equal("192.168.75.1", o.Host, "host");
        Assert.Equal(1, o.Fdb.Count, "local FDB entry skipped");
        Assert.Equal("lan2", o.Fdb["02:11:22:33:44:55"], "FDB port");
        Assert.Equal("-55", o.Stations["aa:bb:cc:dd:ee:ff"].Signal, "station");
        Assert.Equal("Note20-Ultra-von-Silvia", o.Leases["aa:bb:cc:dd:ee:ff"].Name, "lease name");
        Assert.Equal("", o.Leases["02:11:22:33:44:55"].Name, "lease without name");
        Assert.True(!o.Interfaces.ContainsKey("lo"), "loopback ignored");
    }

    public static void Classifier()
    {
        void C(DeviceType exp, string vendor, string name) => Assert.Equal(exp, DeviceClassifier.Classify(vendor, name, null, false), $"'{name}' / '{vendor}'");
        C(DeviceType.EchoDot, "", "Echo-WZ");
        C(DeviceType.EchoShow, "Amazon Technologies Inc.", "Echo-Show-Kueche");
        C(DeviceType.EchoSpot, "Amazon Technologies Inc.", "echo-spot-sz");
        C(DeviceType.FireTv, "Amazon Technologies Inc.", "Fire-TV-Stick");
        C(DeviceType.AmazonDevice, "Amazon Technologies Inc.", "");
        C(DeviceType.GoogleSpeaker, "Google, Inc.", "Google-Home-Mini");
        C(DeviceType.GoogleDisplay, "Google, Inc.", "Nest-Hub-Kueche");
        C(DeviceType.Chromecast, "Google, Inc.", "Chromecast-WZ");
        C(DeviceType.Phone, "", "Galaxy-Note10-von-Hauke");
        C(DeviceType.Phone, "", "S24-Ultra-von-Hauke");
        C(DeviceType.Phone, "", "A30s-von-Beate");
        C(DeviceType.Phone, "", "Note20-Ultra-von-Silvia");
        C(DeviceType.HeatingController, "Espressif Inc.", "ems-esp");
        C(DeviceType.HeatingController, "ROBERT BOSCH GmbH", "Buderus");
        C(DeviceType.HeatingController, "", "TC100-Wohnzimmer");
        C(DeviceType.Iot, "Espressif Inc.", "shelly-plug");
        C(DeviceType.Tv, "LG Electronics", "LGwebOSTV");
        C(DeviceType.MediaPlayer, "", "Yamaha");
        C(DeviceType.Printer, "Brother Industries, LTD.", "BRW123");
        C(DeviceType.Computer, "", "QUATTRO");
        C(DeviceType.AirConditioner, "", "Klima-SZ");
        C(DeviceType.Camera, "", "Cam-SZ");
        C(DeviceType.Camera, "Espressif Inc.", "Cam-Gaszaehler");
        C(DeviceType.Camera, "TP-Link Systems Inc", "C211");
        C(DeviceType.Camera, "", "wansview-q5");
        C(DeviceType.Computer, "", "Camino-PC");
        DeviceType M(string mac, string name) => DeviceClassifier.Classify(VendorDb.Lookup(mac), name, null, false, null, true, mac);
        Assert.Equal(DeviceType.Camera, M("4c:2f:7b:c7:e4:f5", "Wichs-Cam"), "Wansview (AltoBeam)");
        Assert.Equal(DeviceType.Camera, M("e0:09:bf:67:37:eb", ""), "Wansview (Tong Bo Wei) without name");
        Assert.Equal(DeviceType.AirConditioner, M("3c:e1:a1:9a:62:80", "Klima-Buero"), "Fujitsu General Wi-Fi adapter");
        Assert.Equal(DeviceType.Iot, M("00:1c:c2:b4:d6:c3", "Luefter-Bad"), "Dreo fan heater");
        Assert.Equal(DeviceType.Iot, M("08:65:f0:7c:04:23", "X-Buero-Mitte"), "Zengge smart lamp");
        Assert.Equal(DeviceType.Iot, M("1c:69:20:2e:85:38", "X-Sense-Basis"), "X-Sense base station");
        Assert.Equal(DeviceType.Iot, M("7c:fa:80:17:6f:81", ""), "Worx Landroid without name");
        Assert.Equal(DeviceType.FireTv, DeviceClassifier.Classify("", "Amazon-WZ", null, false, null, false), "wired Amazon device");
        Assert.Equal(DeviceType.AmazonDevice, DeviceClassifier.Classify("", "Amazon-WZ", null, false, null, true), "Amazon device via Wi-Fi");
        C(DeviceType.AirConditioner, "Espressif Inc.", "Klima-WZ");
        C(DeviceType.AirConditioner, "GD Midea Air-Conditioning Equipment Co.,Ltd.", "");
        C(DeviceType.Receiver, "Marusys", "duo2");
        C(DeviceType.Receiver, "Marusys", "ultimo4k");
        C(DeviceType.Receiver, "Impex-Sat GmbH&Co KG", "quad4k");
        C(DeviceType.Receiver, "Iffu", "quadbox");
        C(DeviceType.Receiver, "", "dm920");
        C(DeviceType.Computer, "", "pi-zero");
        C(DeviceType.MediaPlayer, "", "AV-Receiver-Yamaha");
    }

    public static void Vendors()
    {
        Assert.Equal("ROBERT BOSCH GmbH", VendorDb.Lookup("00:60:34:34:15:89"), "Bosch (entry with aligned columns)");
        Assert.Equal("Netgear", VendorDb.Lookup("bc:a5:11:35:49:fb"), "Netgear GS308E");
        Assert.True(VendorDb.Lookup("00:17:32:00:00:01").Contains("\"RISSA\""), "escaped quotes");
        Assert.True(VendorDb.Lookup("00:71:47:12:34:56").Contains("Amazon"), "Amazon OUI");
        Assert.Equal("", VendorDb.Lookup("02:71:47:12:34:56"), "randomized MAC has no vendor");
    }

    public static void SsdpParse()
    {
        var h = Ssdp.ParseHeaders("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nLOCATION: http://192.168.75.30:80/desc.xml\r\nST: upnp:rootdevice\r\n\r\n");
        Assert.Equal("http://192.168.75.30:80/desc.xml", h["location"], "location header");
        var d = new SsdpDevice();
        Ssdp.ParseDescription("""
            <?xml version="1.0"?>
            <root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major></specVersion>
              <device><deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType><friendlyName>Switch-Router</friendlyName>
                <manufacturer>NETGEAR</manufacturer><modelName>GS308E</modelName><modelNumber>GS308E</modelNumber></device></root>
            """, d);
        Assert.Equal("Switch-Router", d.FriendlyName, "friendly name");
        Assert.Equal("GS308E", d.Model, "model without duplicate number");
        Assert.Equal("NETGEAR", d.Manufacturer, "manufacturer");
    }

    public static void NsdpParse()
    {
        var found = new Dictionary<string, NsdpDevice>();
        var r = new List<byte> { 0x01, 0x02, 0, 0, 0, 0, 0, 0 };
        r.AddRange(new byte[] { 0xd8, 0x43, 0xae, 0x43, 0x15, 0x1a });   // host
        r.AddRange(new byte[] { 0x38, 0x94, 0xed, 0x2f, 0x07, 0x7d });   // device
        r.AddRange(new byte[] { 0, 0, 0, 1 });
        r.AddRange(Encoding.ASCII.GetBytes("NSDP"));
        r.AddRange(new byte[4]);
        void Tlv(int t, byte[] v) { r.Add((byte)(t >> 8)); r.Add((byte)t); r.Add((byte)(v.Length >> 8)); r.Add((byte)v.Length); r.AddRange(v); }
        Tlv(0x0001, Encoding.ASCII.GetBytes("GS116Ev2"));
        Tlv(0x0003, Encoding.ASCII.GetBytes("Switch-Recv"));
        Tlv(0x0006, new byte[] { 192, 168, 75, 3 });
        Tlv(0x0C00, new byte[] { 1, 5, 0 });
        Tlv(0x0C00, new byte[] { 2, 0, 0 });
        r.AddRange(new byte[] { 0xFF, 0xFF, 0, 0 });
        Assert.Equal("38:94:ed:2f:07:7d", Nsdp.ParseResponse(r.ToArray(), found), "device MAC");
        var d = found["38:94:ed:2f:07:7d"];
        Assert.Equal("GS116Ev2", d.Model, "model");
        Assert.Equal("Switch-Recv", d.Name, "name");
        Assert.Equal("192.168.75.3", d.IPv4, "ip");
        Assert.Equal("1:1G 2:-", string.Join(" ", d.Ports), "ports");
        var req = Nsdp.BuildReadRequest(new byte[6], new byte[6], new ushort[] { 0x0001 });
        Assert.Equal("NSDP", Encoding.ASCII.GetString(req, 24, 4), "signature");
    }

    public static void MdnsModels()
    {
        MdnsHost H(string ip, string host, params (string Type, string Txt)[] svc)
        {
            var h = new MdnsHost { IPv4 = ip, HostName = host };
            foreach (var (type, txt) in svc)
            {
                var s = new MdnsService { Type = type + ".local", Instance = "x." + type + ".local" };
                foreach (var kv in txt.Split(';', StringSplitOptions.RemoveEmptyEntries)) { var p = kv.Split('='); s.Txt[p[0]] = p.Length > 1 ? p[1] : ""; }
                h.Services.Add(s);
            }
            return h;
        }
        var samba = H("192.168.75.11", "abc.local", ("_smb._tcp", ""), ("_device-info._tcp", "model=MacSamba"), ("_home-assistant._tcp", ""));
        Assert.Equal("Home Assistant", samba.Model(), "MacSamba ignored, Home Assistant shown");
        var yamaha = H("192.168.75.24", "Yamaha.local", ("_raop._tcp", "md=0,1,2"), ("_spotify-connect._tcp", ""));
        Assert.Equal(null, yamaha.Model(), "AirPlay md is not a model");
        Assert.Equal(DeviceType.MediaPlayer, DeviceClassifier.Classify("", "Yamaha", yamaha, false), "Yamaha");
        var lg = H("192.168.75.20", "LGwebOSTV.local", ("_hap._tcp", ""), ("_airplay._tcp", "model=WEBOS"));
        Assert.Equal(DeviceType.Tv, DeviceClassifier.Classify("", "", lg, false), "LG TV with HomeKit");
        var echo = H("192.168.75.28", "Android-2.local", ("_spotify-connect._tcp", ""), ("_matter._tcp", ""));
        Assert.Equal(DeviceType.EchoDot, DeviceClassifier.Classify("", "", echo, false), "Echo via Spotify+Matter");
        var none = H("192.168.75.230", "none.local", ("_spotify-connect._tcp", ""), ("_matter._tcp", ""));
        Assert.Equal(DeviceType.EchoDot, DeviceClassifier.Classify("Amazon Technologies Inc.", "", none, false), "Echo none.local");
        var pilot = H("192.168.75.243", "HomePilot.local", ("_homepilot._tcp", ""));
        Assert.Equal(DeviceType.Iot, DeviceClassifier.Classify("", "", pilot, false), "HomePilot");
        var matter = H("192.168.75.238", "446A58E6BC0C.local", ("_matter._tcp", ""));
        Assert.Equal(DeviceType.Iot, DeviceClassifier.Classify("", "", matter, false), "Matter device");
        var ha = H("192.168.75.10", "himbeere.local", ("_smb._tcp", ""), ("_home-assistant._tcp", ""), ("_matter._tcp", ""));
        Assert.Equal(DeviceType.Computer, DeviceClassifier.Classify("Raspberry Pi Trading Ltd", "himbeere", ha, false), "Home Assistant host");
    }

    public static void Localization()
    {
        foreach (var (key, v) in L.Table)
        {
            Assert.Equal(4, v.Length, "languages for " + key);
            Assert.True(v.All(s => !string.IsNullOrWhiteSpace(s)), "empty translation for " + key);
        }
        foreach (var dt in Enum.GetValues<DeviceType>()) Assert.True(L.Table.ContainsKey("DT_" + dt), "device type name " + dt);
        L.SetLanguage("fr");
        Assert.Equal("Paramètres", L.T("SettingsTitle"), "French");
        L.SetLanguage("es");
        Assert.Equal("Configuración", L.T("SettingsTitle"), "Spanish");
        L.SetLanguage("en");
    }
}
