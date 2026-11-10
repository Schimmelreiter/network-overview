using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;

namespace NetworkOverview.Core.Discovery;

/// <summary>A device found via SSDP/UPnP, with data from its device description.</summary>
public sealed class SsdpDevice
{
    public string IPv4 { get; set; } = "";
    public string Location { get; set; } = "";
    public string Server { get; set; } = "";
    public string FriendlyName { get; set; } = "";
    public string Manufacturer { get; set; } = "";
    public string ModelName { get; set; } = "";
    public string ModelNumber { get; set; } = "";
    public string DeviceType { get; set; } = "";
    public List<string> Usns { get; } = new();

    /// <summary>Model text for display, e.g. "GS308E" or "WebOS TV 55UK6300".</summary>
    public string Model
    {
        get
        {
            if (ModelName.Length == 0) return ModelNumber;
            if (ModelNumber.Length == 0 || ModelName.Contains(ModelNumber, StringComparison.OrdinalIgnoreCase)) return ModelName;
            return ModelName + " " + ModelNumber;
        }
    }
}

/// <summary>SSDP M-SEARCH (UPnP discovery) followed by fetching the device descriptions.</summary>
public static class Ssdp
{
    static readonly IPEndPoint Group = new(IPAddress.Parse("239.255.255.250"), 1900);

    public static List<SsdpDevice> Discover(IPAddress localIp, int durationMs, Action<string>? log = null, CancellationToken ct = default)
    {
        var byIp = new Dictionary<string, SsdpDevice>();
        using (var udp = new UdpClient(new IPEndPoint(localIp, 0)))
        {
            try { udp.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastInterface, localIp.GetAddressBytes()); }
            catch (SocketException ex) { log?.Invoke("SSDP socket option: " + ex.Message); }
            udp.Client.ReceiveTimeout = 100;
            var req = Encoding.ASCII.GetBytes("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n");
            var sw = Stopwatch.StartNew();
            int sent = 0;
            while (sw.ElapsedMilliseconds < durationMs && !ct.IsCancellationRequested)
            {
                if (sent < 2 && sw.ElapsedMilliseconds >= sent * 800)
                {
                    try { udp.Send(req, req.Length, Group); } catch (SocketException ex) { log?.Invoke("SSDP send: " + ex.Message); }
                    sent++;
                }
                try
                {
                    var ep = new IPEndPoint(IPAddress.Any, 0);
                    var data = udp.Receive(ref ep);
                    var headers = ParseHeaders(Encoding.UTF8.GetString(data));
                    string ip = ep.Address.ToString();
                    if (!headers.TryGetValue("LOCATION", out var loc)) continue;
                    if (!byIp.TryGetValue(ip, out var d)) byIp[ip] = d = new SsdpDevice { IPv4 = ip };
                    // prefer the root device description
                    if (d.Location.Length == 0 || (headers.TryGetValue("ST", out var st) && st.Contains("rootdevice", StringComparison.OrdinalIgnoreCase)))
                        d.Location = loc;
                    if (headers.TryGetValue("SERVER", out var server)) d.Server = server;
                    if (headers.TryGetValue("USN", out var usn) && !d.Usns.Contains(usn)) d.Usns.Add(usn);
                }
                catch (SocketException) { }
            }
        }

        // fetch device descriptions (only from the responding host itself)
        using var http = new HttpClient(new HttpClientHandler { UseProxy = false }) { Timeout = TimeSpan.FromSeconds(3) };
        var tasks = byIp.Values.Select(async d =>
        {
            try
            {
                if (!Uri.TryCreate(d.Location, UriKind.Absolute, out var uri) || uri.Host != d.IPv4 || uri.Scheme != Uri.UriSchemeHttp) return;
                var xml = await http.GetStringAsync(uri, ct);
                ParseDescription(xml, d);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or System.Xml.XmlException) { }
        }).ToArray();
        try { Task.WaitAll(tasks, 5000); } catch (AggregateException) { }
        var list = byIp.Values.ToList();
        log?.Invoke($"SSDP: {list.Count} devices");
        return list;
    }

    public static Dictionary<string, string> ParseHeaders(string response)
    {
        var h = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in response.Split('\n').Skip(1))
        {
            int i = line.IndexOf(':');
            if (i > 0) h[line[..i].Trim()] = line[(i + 1)..].Trim();
        }
        return h;
    }

    public static void ParseDescription(string xml, SsdpDevice d)
    {
        var doc = XDocument.Parse(xml);
        var dev = doc.Descendants().FirstOrDefault(e => e.Name.LocalName == "device");
        if (dev == null) return;
        string V(string name) => dev.Elements().FirstOrDefault(e => e.Name.LocalName == name)?.Value.Trim() ?? "";
        d.FriendlyName = V("friendlyName");
        d.Manufacturer = V("manufacturer");
        d.ModelName = V("modelName");
        d.ModelNumber = V("modelNumber");
        d.DeviceType = V("deviceType");
    }
}
