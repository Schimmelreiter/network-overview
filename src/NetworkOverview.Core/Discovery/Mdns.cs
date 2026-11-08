using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetworkOverview.Core.Discovery;

/// <summary>A DNS-SD service instance announced via mDNS.</summary>
public sealed class MdnsService
{
    public string Type { get; set; } = "";
    public string Instance { get; set; } = "";
    public string Target { get; set; } = "";
    public int Port { get; set; }
    public Dictionary<string, string> Txt { get; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>Everything one device (identified by its IPv4 address) announced via mDNS.</summary>
public sealed class MdnsHost
{
    public string IPv4 { get; set; } = "";
    public string HostName { get; set; } = "";
    public List<MdnsService> Services { get; } = new();

    public bool HasType(string type) => Services.Any(s => s.Type.StartsWith(type, StringComparison.OrdinalIgnoreCase));

    public string? TxtValue(string key)
    {
        foreach (var s in Services)
            if (s.Txt.TryGetValue(key, out var v) && v.Length > 0) return v;
        return null;
    }

    /// <summary>Human-friendly name taken from service instances (e.g. Cast "fn", instance label).</summary>
    public string? FriendlyName()
    {
        var fn = TxtValue("fn");
        if (!string.IsNullOrWhiteSpace(fn)) return fn;
        foreach (var s in Services)
        {
            if (s.Type.StartsWith("_googlecast", StringComparison.OrdinalIgnoreCase)) continue;
            var label = Mdns.FirstLabel(s.Instance);
            if (!string.IsNullOrWhiteSpace(label)) return label;
        }
        if (!string.IsNullOrWhiteSpace(HostName)) return Mdns.FirstLabel(HostName);
        return null;
    }

    /// <summary>Model description from TXT records (Cast "md", device-info "model", AirPlay "model", IPP "ty").</summary>
    public string? Model() => TxtValue("md") ?? TxtValue("ty") ?? TxtValue("model") ?? TxtValue("usb_MDL");
}

public sealed record DnsRecord(string Name, ushort Type, string Data, int Port, IReadOnlyList<string> Txt, string Source);

/// <summary>Minimal mDNS / DNS-SD browser (RFC 6762/6763) using legacy unicast queries.</summary>
public static class Mdns
{
    public const ushort TypeA = 1, TypePtr = 12, TypeTxt = 16, TypeAaaa = 28, TypeSrv = 33;
    const string ServiceEnum = "_services._dns-sd._udp.local";
    static readonly IPEndPoint Group = new(IPAddress.Parse("224.0.0.251"), 5353);

    public static readonly string[] KnownTypes =
    {
        "_googlecast._tcp.local", "_amzn-wplay._tcp.local", "_amzn-alexa._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local",
        "_printer._tcp.local", "_pdl-datastream._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
        "_spotify-connect._tcp.local", "_hap._tcp.local", "_device-info._tcp.local", "_workstation._tcp.local",
        "_smb._tcp.local", "_sonos._tcp.local", "_androidtvremote2._tcp.local", "_home-assistant._tcp.local",
        "_esphomelib._tcp.local", "_shelly._tcp.local", "_http._tcp.local", "_ssh._tcp.local", "_scanner._tcp.local",
        "_uscan._tcp.local", "_companion-link._tcp.local", "_mqtt._tcp.local", "_matter._tcp.local"
    };

    public static string FirstLabel(string name)
    {
        if (string.IsNullOrEmpty(name)) return "";
        int i = name.IndexOf('.');
        return i > 0 ? name[..i] : name;
    }

    public static List<MdnsHost> Browse(IPAddress localIp, int durationMs, Action<string>? log = null, CancellationToken ct = default)
    {
        var records = new List<DnsRecord>();
        var types = new HashSet<string>(KnownTypes, StringComparer.OrdinalIgnoreCase);
        using var udp = new UdpClient(new IPEndPoint(localIp, 0));
        try
        {
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localIp.GetAddressBytes());
            udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastTimeToLive, 255);
        }
        catch (SocketException ex) { log?.Invoke("mDNS socket option: " + ex.Message); }
        udp.Client.ReceiveTimeout = 100;

        var sw = Stopwatch.StartNew();
        long nextSend = 0;
        int round = 0;
        var asked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        while (sw.ElapsedMilliseconds < durationMs && !ct.IsCancellationRequested)
        {
            if (sw.ElapsedMilliseconds >= nextSend && round < 4)
            {
                var questions = new List<(string, ushort)> { (ServiceEnum, TypePtr) };
                foreach (var t in types) { questions.Add((t, TypePtr)); asked.Add(t); }
                if (round > 0) foreach (var q in MissingQuestions(records)) questions.Add(q);
                foreach (var pkt in BuildQueries(questions))
                {
                    try { udp.Send(pkt, pkt.Length, Group); }
                    catch (SocketException ex) { log?.Invoke("mDNS send: " + ex.Message); }
                }
                round++;
                nextSend = sw.ElapsedMilliseconds + Math.Max(400, durationMs / 4);
            }
            try
            {
                var ep = new IPEndPoint(IPAddress.Any, 0);
                var data = udp.Receive(ref ep);
                foreach (var r in Parse(data, ep.Address.ToString()))
                {
                    records.Add(r);
                    if (r.Type == TypePtr && r.Name.Equals(ServiceEnum, StringComparison.OrdinalIgnoreCase)
                        && r.Data.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
                        types.Add(r.Data);
                }
            }
            catch (SocketException) { }
            catch (ObjectDisposedException) { break; }
        }
        var hosts = Assemble(records);
        log?.Invoke($"mDNS: {records.Count} records, {hosts.Count} hosts, {types.Count} service types");
        return hosts;
    }

    // Ask for SRV/TXT of instances and A records of targets that were not answered yet.
    static IEnumerable<(string, ushort)> MissingQuestions(List<DnsRecord> records)
    {
        var have = new HashSet<string>(records.Select(r => r.Name + "/" + r.Type), StringComparer.OrdinalIgnoreCase);
        var res = new List<(string, ushort)>();
        foreach (var r in records)
        {
            if (r.Type == TypePtr && !r.Name.StartsWith("_services", StringComparison.OrdinalIgnoreCase))
            {
                if (!have.Contains(r.Data + "/" + TypeSrv)) res.Add((r.Data, TypeSrv));
                if (!have.Contains(r.Data + "/" + TypeTxt)) res.Add((r.Data, TypeTxt));
            }
            if (r.Type == TypeSrv && r.Data.Length > 0 && !have.Contains(r.Data + "/" + TypeA)) res.Add((r.Data, TypeA));
        }
        return res.Distinct().Take(60);
    }

    public static List<byte[]> BuildQueries(IList<(string Name, ushort Type)> questions)
    {
        var packets = new List<byte[]>();
        for (int i = 0; i < questions.Count; i += 15)
        {
            var chunk = questions.Skip(i).Take(15).ToList();
            var b = new List<byte>
            {
                0x00, 0x00, // ID
                0x00, 0x00, // flags: standard query
                (byte)(chunk.Count >> 8), (byte)chunk.Count,
                0, 0, 0, 0, 0, 0
            };
            foreach (var (name, type) in chunk)
            {
                foreach (var label in name.TrimEnd('.').Split('.'))
                {
                    var lb = Encoding.UTF8.GetBytes(label);
                    b.Add((byte)Math.Min(lb.Length, 63));
                    b.AddRange(lb.Take(63));
                }
                b.Add(0);
                b.Add((byte)(type >> 8)); b.Add((byte)type);
                b.Add(0x80); b.Add(0x01); // class IN with unicast-response bit
            }
            packets.Add(b.ToArray());
        }
        return packets;
    }

    public static List<DnsRecord> Parse(byte[] d, string source)
    {
        var list = new List<DnsRecord>();
        try
        {
            if (d.Length < 12) return list;
            int qd = (d[4] << 8) | d[5];
            int rr = ((d[6] << 8) | d[7]) + ((d[8] << 8) | d[9]) + ((d[10] << 8) | d[11]);
            int p = 12;
            for (int i = 0; i < qd; i++) { ReadName(d, ref p); p += 4; }
            for (int i = 0; i < rr && p + 10 <= d.Length; i++)
            {
                string name = ReadName(d, ref p);
                ushort type = (ushort)((d[p] << 8) | d[p + 1]);
                int len = (d[p + 8] << 8) | d[p + 9];
                p += 10;
                if (p + len > d.Length) break;
                int rd = p;
                switch (type)
                {
                    case TypeA:
                        if (len == 4) list.Add(new DnsRecord(name, type, new IPAddress(d.AsSpan(rd, 4)).ToString(), 0, Array.Empty<string>(), source));
                        break;
                    case TypePtr:
                        { int q = rd; list.Add(new DnsRecord(name, type, ReadName(d, ref q), 0, Array.Empty<string>(), source)); }
                        break;
                    case TypeSrv:
                        if (len >= 7)
                        {
                            int port = (d[rd + 4] << 8) | d[rd + 5];
                            int q = rd + 6;
                            list.Add(new DnsRecord(name, type, ReadName(d, ref q), port, Array.Empty<string>(), source));
                        }
                        break;
                    case TypeTxt:
                        {
                            var txt = new List<string>();
                            int q = rd;
                            while (q < rd + len)
                            {
                                int l = d[q++];
                                if (q + l > rd + len) break;
                                if (l > 0) txt.Add(Encoding.UTF8.GetString(d, q, l));
                                q += l;
                            }
                            list.Add(new DnsRecord(name, type, "", 0, txt, source));
                        }
                        break;
                }
                p += len;
            }
        }
        catch (IndexOutOfRangeException) { }
        catch (ArgumentException) { }
        return list;
    }

    public static string ReadName(byte[] d, ref int p)
    {
        var labels = new List<string>();
        int pos = p;
        bool jumped = false;
        int guard = 0;
        while (pos < d.Length && guard++ < 128)
        {
            int len = d[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (pos + 1 >= d.Length) break;
                int target = ((len & 0x3F) << 8) | d[pos + 1];
                if (!jumped) p = pos + 2;
                jumped = true;
                pos = target;
                continue;
            }
            pos++;
            if (pos + len > d.Length) break;
            labels.Add(Encoding.UTF8.GetString(d, pos, len));
            pos += len;
        }
        if (!jumped) p = pos;
        return string.Join(".", labels);
    }

    /// <summary>Groups records by responding device. Responders answer for their own records,
    /// so the packet source address identifies the device even without an A record.</summary>
    public static List<MdnsHost> Assemble(List<DnsRecord> records)
    {
        var hosts = new Dictionary<string, MdnsHost>();
        var addrByName = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in records.Where(r => r.Type == TypeA)) addrByName[r.Name] = r.Data;

        foreach (var group in records.GroupBy(r => r.Source))
        {
            string ip = group.Key;
            if (!IPAddress.TryParse(ip, out var addr) || addr.AddressFamily != AddressFamily.InterNetwork) continue;
            if (!hosts.TryGetValue(ip, out var h)) hosts[ip] = h = new MdnsHost { IPv4 = ip };
            var own = group.ToList();
            var aName = own.FirstOrDefault(r => r.Type == TypeA && r.Data == ip);
            if (aName != null && string.IsNullOrEmpty(h.HostName)) h.HostName = aName.Name;
            foreach (var ptr in own.Where(r => r.Type == TypePtr && !r.Name.StartsWith("_services", StringComparison.OrdinalIgnoreCase)))
            {
                if (h.Services.Any(s => s.Instance.Equals(ptr.Data, StringComparison.OrdinalIgnoreCase))) continue;
                var svc = new MdnsService { Type = ptr.Name, Instance = ptr.Data };
                var srv = records.FirstOrDefault(r => r.Type == TypeSrv && r.Name.Equals(ptr.Data, StringComparison.OrdinalIgnoreCase));
                if (srv != null)
                {
                    svc.Target = srv.Data; svc.Port = srv.Port;
                    if (string.IsNullOrEmpty(h.HostName) && addrByName.TryGetValue(srv.Data, out var a) && a == ip) h.HostName = srv.Data;
                }
                var txt = records.FirstOrDefault(r => r.Type == TypeTxt && r.Name.Equals(ptr.Data, StringComparison.OrdinalIgnoreCase));
                if (txt != null)
                    foreach (var kv in txt.Txt)
                    {
                        int eq = kv.IndexOf('=');
                        if (eq > 0) svc.Txt[kv[..eq]] = kv[(eq + 1)..];
                        else svc.Txt[kv] = "";
                    }
                h.Services.Add(svc);
            }
            // device-info carries the model of the responding host
            foreach (var txt in own.Where(r => r.Type == TypeTxt && r.Name.Contains("_device-info", StringComparison.OrdinalIgnoreCase)))
            {
                var svc = new MdnsService { Type = "_device-info._tcp.local", Instance = txt.Name };
                foreach (var kv in txt.Txt) { int eq = kv.IndexOf('='); if (eq > 0) svc.Txt[kv[..eq]] = kv[(eq + 1)..]; }
                h.Services.Add(svc);
            }
        }
        // A records announced for other addresses (e.g. by a sleep proxy) still give names
        foreach (var kv in addrByName)
            if (hosts.TryGetValue(kv.Value, out var h) && string.IsNullOrEmpty(h.HostName)) h.HostName = kv.Key;
        return hosts.Values.Where(h => h.Services.Count > 0 || h.HostName.Length > 0).ToList();
    }
}
