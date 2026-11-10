using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkOverview.Core.Discovery;

/// <summary>What a device reveals about itself: open ports, banners, web servers, certificates and discovery answers.</summary>
public sealed class FingerprintInfo
{
    public string IPv4 { get; set; } = "";
    public SortedDictionary<int, string> Open { get; } = new();
    public List<string> Servers { get; } = new();      // HTTP "Server" headers
    public List<string> Realms { get; } = new();       // WWW-Authenticate realms
    public List<string> Titles { get; } = new();       // HTML titles
    public List<string> Certs { get; } = new();        // TLS certificate subjects
    public List<string> Banners { get; } = new();      // text sent by the device after connecting
    public bool Onvif { get; set; }
    public string OnvifManufacturer { get; set; } = "";
    public string OnvifModel { get; set; } = "";
    public string MagicHomeModel { get; set; } = "";
    public string TuyaVersion { get; set; } = "";
    public List<string> Streams { get; } = new();      // MJPEG stream URLs (motionEye)

    public bool Has(int port) => Open.ContainsKey(port);
    public bool Tuya => TuyaVersion.Length > 0 || Has(6668);
    public bool Rtsp => Open.TryGetValue(554, out var s) && s.Contains("RTSP/", StringComparison.Ordinal);

    public bool Any(string pattern) =>
        Servers.Concat(Realms).Concat(Titles).Concat(Certs).Concat(Banners).Any(s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase));
    public bool Server(string pattern) => Servers.Any(s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase));
    public bool Realm(string pattern) => Realms.Any(s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase));
    public bool Cert(string pattern) => Certs.Any(s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase));
    public bool Banner(string pattern) => Banners.Any(s => Regex.IsMatch(s, pattern, RegexOptions.IgnoreCase));

    /// <summary>Model text derived from the answers, if any.</summary>
    public string Model()
    {
        if (MagicHomeModel.Length > 0) return "Magic Home " + MagicHomeModel;
        if (Onvif && (OnvifManufacturer.Length > 0 || OnvifModel.Length > 0)) return (OnvifManufacturer + " " + OnvifModel).Trim();
        var ems = Banners.Select(b => Regex.Match(b, @"EMS-ESP version (\S+)")).FirstOrDefault(m => m.Success);
        if (ems != null) return "EMS-ESP " + ems.Groups[1].Value;
        if (Server("^ems-esp")) return "EMS-ESP";
        if (Realm("OpenWebif")) return "Enigma2 (OpenWebif)";
        if (Cert("O=TPRI")) return "TP-Link Tapo";
        return "";
    }
}

/// <summary>
/// Targeted fingerprinting: a short list of telling TCP ports per device (one connection per device at a time),
/// banners / web pages / TLS certificates of the open ones, plus WS-Discovery (ONVIF), Magic Home and Tuya broadcasts.
/// The port list and rules were derived from a full scan of a real home network.
/// </summary>
public static class Fingerprint
{
    public static readonly int[] Ports =
    {
        21, 22, 23, 80, 443, 502, 554, 1883, 2020, 4070, 5541, 5577, 6668, 8001, 8009, 8080, 8443, 8765, 8800, 9080, 55443,
    };
    static readonly HashSet<int> NoBanner = new() { 502, 1883, 2020, 5541, 5577, 6668, 55443 };

    public static Dictionary<string, FingerprintInfo> Run(IPAddress local, string broadcast, IEnumerable<string> ips,
        int timeoutMs, Action<string>? log = null, CancellationToken ct = default, ICollection<string>? magicHomeIps = null)
    {
        var zengge = magicHomeIps ?? Array.Empty<string>();
        var result = new ConcurrentDictionary<string, FingerprintInfo>();
        FingerprintInfo Get(string ip) => result.GetOrAdd(ip, i => new FingerprintInfo { IPv4 = i });
        var targets = ips.Where(i => i.Length > 0 && i != local.ToString()).Distinct().ToList();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        // passive / UDP parts run while the ports are probed
        var udp = new List<Task>
        {
            Task.Run(() => Safe("WS-Discovery", log, () => WsDiscovery(local, Get))),
            Task.Run(() => Safe("Magic Home", log, () => MagicHome(local, broadcast, Get))),
            Task.Run(() => Safe("Tuya", log, () => TuyaListen(6666, Get, cts.Token))),
            Task.Run(() => Safe("Tuya", log, () => TuyaListen(6667, Get, cts.Token))),
        };

        var sem = new SemaphoreSlim(128);
        var lanes = targets.Select(ip => Task.Run(async () =>
        {
            var addr = IPAddress.Parse(ip);
            foreach (var port in Ports)
            {
                if (cts.IsCancellationRequested) return;
                await sem.WaitAsync();
                try { if (await Probe(addr, port, timeoutMs)) lock (Get(ip)) Get(ip).Open[port] = ""; }
                finally { sem.Release(); }
            }
        })).ToArray();
        Task.WaitAll(lanes);

        // banners, web pages, certificates
        var jobs = result.Values.SelectMany(f => f.Open.Keys.Where(p => !NoBanner.Contains(p)).Select(p => (f, p))).ToList();
        var bsem = new SemaphoreSlim(32);
        Task.WaitAll(jobs.Select(j => Task.Run(async () =>
        {
            await bsem.WaitAsync();
            try { await Describe(j.f, j.p, cts.Token); } catch (Exception) { }
            finally { bsem.Release(); }
        })).ToArray());

        // Magic Home: broadcasts over Wi-Fi are easily missed by devices in power-save mode, ask the candidates directly
        var mhCandidates = result.Values.Where(f => f.MagicHomeModel.Length == 0 && (f.Has(5577) || zengge.Contains(f.IPv4))).Select(f => f.IPv4)
            .Concat(zengge.Where(ip => !result.ContainsKey(ip))).Distinct().ToList();
        if (mhCandidates.Count > 0) Safe("Magic Home", log, () => MagicHomeUnicast(local, mhCandidates, Get));

        // motionEye: MJPEG streams on the usual ports
        foreach (var f in result.Values.Where(f => f.Server("motionEye")).ToList())
            Safe("motionEye", log, () => MotionEyeStreams(f, timeoutMs, cts.Token));

        // Tuya devices announce themselves every ~5 s: listen at least 6 s in total
        cts.CancelAfter(TimeSpan.FromSeconds(6));
        try { Task.WaitAll(udp.ToArray()); } catch (AggregateException) { }
        return new Dictionary<string, FingerprintInfo>(result);
    }

    static void Safe(string what, Action<string>? log, Action a)
    {
        try { a(); } catch (Exception ex) { log?.Invoke(what + ": " + ex.Message); }
    }

    // ---------------------------------------------------------------- TCP

    static readonly byte[] NoSynRetransmit = { 0xFF, 0xFF, 0xFE, 0x00 };   // TCP_INITIAL_RTO_PARAMETERS

    static async Task<bool> Probe(IPAddress ip, int port, int timeoutMs)
    {
        using var s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        // Windows retries a SYN answered by RST (about 1 s per closed port); SIO_TCP_INITIAL_RTO switches that off
        if (OperatingSystem.IsWindows()) try { s.IOControl(unchecked((int)0x98000011), NoSynRetransmit, null); } catch (SocketException) { }
        using var cts = new CancellationTokenSource(timeoutMs);
        try { await s.ConnectAsync(ip, port, cts.Token); return true; }
        catch (Exception) { return false; }
    }

    sealed class Http { public string Head = "", Body = "", Cert = ""; }

    static async Task<Stream?> Connect(string host, int port, bool tls, int ms, Http res, CancellationToken ct)
    {
        var c = new TcpClient();
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ms);
        try
        {
            await c.ConnectAsync(host, port, cts.Token);
            Stream st = c.GetStream();
            if (!tls) return st;
            var ssl = new SslStream(st, false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token);
            if (ssl.RemoteCertificate != null) res.Cert = ssl.RemoteCertificate.Subject;
            return ssl;
        }
        catch (Exception) { c.Dispose(); return null; }
    }

    static async Task<int> Read(Stream st, byte[] buf, int off, int ms, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(ms);
        try { return await st.ReadAsync(buf.AsMemory(off), cts.Token); }
        catch (Exception) { return -1; }
    }

    static async Task<Http> Get(string host, int port, string path, bool tls, int ms, CancellationToken ct, int max = 65536)
    {
        var res = new Http();
        var st = await Connect(host, port, tls, ms, res, ct);
        if (st == null) return res;
        await using (st)
        {
            var req = Encoding.ASCII.GetBytes($"GET {path} HTTP/1.0\r\nHost: {host}:{port}\r\nUser-Agent: NetworkOverview\r\nAccept: */*\r\nConnection: close\r\n\r\n");
            try { await st.WriteAsync(req, ct); } catch (Exception) { return res; }
            var buf = new byte[max];
            int len = 0;
            var end = DateTime.UtcNow.AddMilliseconds(ms);
            while (len < buf.Length)
            {
                int left = (int)(end - DateTime.UtcNow).TotalMilliseconds;
                if (left <= 0) break;
                int n = await Read(st, buf, len, left, ct);
                if (n <= 0) break;
                len += n;
                if (max < 65536 && Encoding.ASCII.GetString(buf, 0, len).Contains("\r\n\r\n")) break;
            }
            var text = Encoding.UTF8.GetString(buf, 0, len);
            int split = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            res.Head = split >= 0 ? text[..split] : text;
            res.Body = split >= 0 ? text[split..].Trim() : "";
        }
        return res;
    }

    static string Header(string head, string name)
    {
        var m = Regex.Match(head, "^" + name + @":[ \t]*(.*?)\r?$", RegexOptions.IgnoreCase | RegexOptions.Multiline);
        return m.Success ? m.Groups[1].Value.Trim() : "";
    }

    static string Printable(string s, int max)
    {
        var sb = new StringBuilder();
        foreach (char c in s)
        {
            if (sb.Length >= max) break;
            sb.Append(c >= ' ' && c < 127 ? c : ' ');
        }
        return Regex.Replace(sb.ToString(), @"\s+", " ").Trim();
    }

    static void Take(FingerprintInfo f, int port, Http r, string kind)
    {
        lock (f)
        {
            var server = Header(r.Head, "Server");
            if (server.Length > 0 && !f.Servers.Contains(server)) f.Servers.Add(server);
            var auth = Regex.Match(Header(r.Head, "WWW-Authenticate"), "realm=\"([^\"]*)\"", RegexOptions.IgnoreCase);
            if (auth.Success && !f.Realms.Contains(auth.Groups[1].Value)) f.Realms.Add(auth.Groups[1].Value);
            var t = Regex.Match(r.Body, "<title[^>]*>(.*?)</title>", RegexOptions.IgnoreCase | RegexOptions.Singleline);
            if (t.Success) { var title = WebUtility.HtmlDecode(Regex.Replace(t.Groups[1].Value, @"\s+", " ").Trim()); if (title.Length > 0 && !f.Titles.Contains(title)) f.Titles.Add(title); }
            if (r.Cert.Length > 0 && !f.Certs.Contains(r.Cert)) f.Certs.Add(r.Cert);
            f.Open[port] = kind + " " + Printable(r.Head.Split('\n')[0], 80) + (server.Length > 0 ? " | " + server : "");
        }
    }

    static async Task Describe(FingerprintInfo f, int port, CancellationToken ct)
    {
        // 1. passive banner (SSH, FTP, Telnet ...)
        var tmp = new Http();
        var st = await Connect(f.IPv4, port, false, 1500, tmp, ct);
        if (st != null)
        {
            await using (st)
            {
                var buf = new byte[2048];
                int n = await Read(st, buf, 0, 1000, ct);
                if (n > 0)
                {
                    var b = Printable(Encoding.UTF8.GetString(buf, 0, n), 200);
                    lock (f) { f.Open[port] = "banner " + b; if (b.Length > 0) f.Banners.Add(b); }
                    return;
                }
            }
        }
        // 2. HTTP, 3. HTTPS
        var r = await Get(f.IPv4, port, "/", false, 2500, ct);
        if (r.Head.StartsWith("HTTP/", StringComparison.Ordinal) || r.Head.StartsWith("RTSP/", StringComparison.Ordinal)) { Take(f, port, r, "http"); return; }
        var s = await Get(f.IPv4, port, "/", true, 2500, ct);
        if (s.Head.StartsWith("HTTP/", StringComparison.Ordinal) || s.Cert.Length > 0) Take(f, port, s, "https");
    }

    static void MotionEyeStreams(FingerprintInfo f, int timeoutMs, CancellationToken ct)
    {
        var ports = Enumerable.Range(8081, 19).Concat(Enumerable.Range(9081, 19)).ToList();
        var addr = IPAddress.Parse(f.IPv4);
        var found = new ConcurrentBag<int>();
        Task.WaitAll(ports.Select(p => Task.Run(async () =>
        {
            if (!await Probe(addr, p, timeoutMs)) return;
            var r = await Get(f.IPv4, p, "/", false, 2000, ct, 4096);
            if (Header(r.Head, "Content-Type").StartsWith("multipart/x-mixed-replace", StringComparison.OrdinalIgnoreCase)) found.Add(p);
        })).ToArray());
        lock (f) foreach (var p in found.OrderBy(p => p)) f.Streams.Add($"http://{f.IPv4}:{p}/");
    }

    // ---------------------------------------------------------------- UDP

    static Socket UdpSocket(IPAddress bind, int port, bool reuse, IPAddress local)
    {
        var s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        if (reuse) s.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        s.EnableBroadcast = true;
        s.Bind(new IPEndPoint(bind, port));
        try { s.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, local.GetAddressBytes()); } catch (SocketException) { }
        return s;
    }

    static void Receive(Socket s, int ms, CancellationToken ct, Action<IPEndPoint, byte[], int> h)
    {
        var buf = new byte[9000];
        var end = DateTime.UtcNow.AddMilliseconds(ms);
        while (!ct.IsCancellationRequested)
        {
            int left = (int)(end - DateTime.UtcNow).TotalMilliseconds;
            if (left <= 0) break;
            if (!s.Poll(Math.Min(left, 200) * 1000, SelectMode.SelectRead)) continue;
            EndPoint ep = new IPEndPoint(IPAddress.Any, 0);
            int n;
            try { n = s.ReceiveFrom(buf, ref ep); } catch (SocketException) { continue; }
            h((IPEndPoint)ep, buf, n);
        }
    }

    static void WsDiscovery(IPAddress local, Func<string, FingerprintInfo> get)
    {
        var probe = "<?xml version=\"1.0\" encoding=\"utf-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" " +
            "xmlns:a=\"http://schemas.xmlsoap.org/ws/2004/08/addressing\"><s:Header>" +
            "<a:Action s:mustUnderstand=\"1\">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>" +
            $"<a:MessageID>uuid:{Guid.NewGuid()}</a:MessageID><a:ReplyTo><a:Address>" +
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>" +
            "<a:To s:mustUnderstand=\"1\">urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To></s:Header>" +
            "<s:Body><Probe xmlns=\"http://schemas.xmlsoap.org/ws/2005/04/discovery\"/></s:Body></s:Envelope>";
        using var s = UdpSocket(local, 0, false, local);
        var data = Encoding.UTF8.GetBytes(probe);
        var group = new IPEndPoint(IPAddress.Parse("239.255.255.250"), 3702);
        for (int i = 0; i < 2; i++) s.SendTo(data, group);
        Receive(s, 3000, CancellationToken.None, (ep, d, n) =>
        {
            var x = Encoding.UTF8.GetString(d, 0, n);
            var scopes = Regex.Match(x, @"<(?:\w+:)?Scopes[^>]*>(.*?)</(?:\w+:)?Scopes>", RegexOptions.Singleline);
            if (!scopes.Success || !scopes.Groups[1].Value.Contains("onvif://", StringComparison.OrdinalIgnoreCase)) return;
            var found = new Dictionary<string, string>();
            foreach (var sc in scopes.Groups[1].Value.Split(new[] { ' ', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var m = Regex.Match(Uri.UnescapeDataString(sc), @"onvif://www\.onvif\.org/(manufacturer|hardware|model|name)/(.+)$", RegexOptions.IgnoreCase);
                if (m.Success) found.TryAdd(m.Groups[1].Value.ToLowerInvariant(), m.Groups[2].Value.Trim());
            }
            found.TryGetValue("manufacturer", out var maker);
            found.TryGetValue("model", out var model);
            found.TryGetValue("name", out var name);
            found.TryGetValue("hardware", out var hw);
            if (string.Equals(name, "IPCAM", StringComparison.OrdinalIgnoreCase)) name = null;
            var f = get(ep.Address.ToString());
            lock (f)
            {
                f.Onvif = true;
                f.OnvifManufacturer = maker ?? "";
                f.OnvifModel = model ?? name ?? hw ?? "";
            }
        });
    }

    static void MagicHome(IPAddress local, string broadcast, Func<string, FingerprintInfo> get)
    {
        using var s = UdpSocket(local, 0, false, local);
        var q = Encoding.ASCII.GetBytes("HF-A11ASSISTHREAD");
        for (int i = 0; i < 2; i++)
        {
            s.SendTo(q, new IPEndPoint(IPAddress.Broadcast, 48899));
            if (IPAddress.TryParse(broadcast, out var b)) s.SendTo(q, new IPEndPoint(b, 48899));
        }
        Receive(s, 2500, CancellationToken.None, (ep, d, n) =>
        {
            // answer: "ip,mac,model"
            var parts = Encoding.ASCII.GetString(d, 0, n).Split(',');
            if (parts.Length < 3 || parts[0] != ep.Address.ToString()) return;
            var f = get(ep.Address.ToString());
            lock (f) f.MagicHomeModel = parts[2].Trim();
        });
    }

    static void MagicHomeUnicast(IPAddress local, List<string> ips, Func<string, FingerprintInfo> get)
    {
        using var s = UdpSocket(local, 0, false, local);
        var q = Encoding.ASCII.GetBytes("HF-A11ASSISTHREAD");
        var pending = new HashSet<string>(ips);
        for (int attempt = 0; attempt < 3 && pending.Count > 0; attempt++)
        {
            foreach (var ip in pending) try { s.SendTo(q, new IPEndPoint(IPAddress.Parse(ip), 48899)); } catch (SocketException) { }
            Receive(s, 1200, CancellationToken.None, (ep, d, n) =>
            {
                var parts = Encoding.ASCII.GetString(d, 0, n).Split(',');
                if (parts.Length < 3 || parts[0] != ep.Address.ToString()) return;
                var f = get(ep.Address.ToString());
                lock (f) f.MagicHomeModel = parts[2].Trim();
                pending.Remove(ep.Address.ToString());
            });
        }
    }

    static void TuyaListen(int port, Func<string, FingerprintInfo> get, CancellationToken ct)
    {
        using var s = UdpSocket(IPAddress.Any, port, true, IPAddress.Any);
        Receive(s, 60000, ct, (ep, d, n) =>
        {
            var json = TuyaDecode(d, n);
            var v = Regex.Match(json, "\"version\"\\s*:\\s*\"([^\"]+)\"");
            var f = get(ep.Address.ToString());
            lock (f) f.TuyaVersion = v.Success ? v.Groups[1].Value : "?";
        });
    }

    /// <summary>Decodes a Tuya UDP announcement (3.1 plain, 3.3 AES-ECB with the well-known key); "" if not possible.</summary>
    public static string TuyaDecode(byte[] d, int n)
    {
        if (n <= 28 || d[0] != 0 || d[1] != 0 || d[2] != 0x55 || d[3] != 0xAA) return "";
        int len = (d[12] << 24) | (d[13] << 16) | (d[14] << 8) | d[15];
        int start = 20, end = Math.Min(n, 16 + len) - 8;
        if (end <= start) return "";
        try
        {
            var key = MD5.HashData(Encoding.ASCII.GetBytes("yGAdlopoPVldABfn"));
            using var aes = Aes.Create();
            aes.Key = key;
            int clen = (end - start) / 16 * 16;
            if (clen > 0)
            {
                var p = aes.DecryptEcb(d.AsSpan(start, clen), PaddingMode.PKCS7);
                if (p.Length > 0 && p[0] == (byte)'{') return Encoding.UTF8.GetString(p);
            }
        }
        catch (CryptographicException) { }
        var plain = Encoding.UTF8.GetString(d, start, end - start);
        int brace = plain.IndexOf('{');
        return brace >= 0 ? plain[brace..] : "";
    }
}
