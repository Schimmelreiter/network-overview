using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;

namespace NetworkOverview.Core.Discovery;

public sealed class OpenWrtStation
{
    public string Interface { get; set; } = "";
    public string Signal { get; set; } = "";
}

public sealed class OpenWrtLease
{
    public string IPv4 { get; set; } = "";
    public string Name { get; set; } = "";
}

/// <summary>Data collected from one OpenWrt device via SSH.</summary>
public sealed class OpenWrtInfo
{
    public string Target { get; set; } = "";
    public string Host => Target.Contains('@') ? Target[(Target.LastIndexOf('@') + 1)..] : Target;
    public string Name { get; set; } = "";
    public string Error { get; set; } = "";
    public string MainMac { get; set; } = "";
    public Dictionary<string, string> Interfaces { get; } = new();          // ifname -> MAC
    public Dictionary<string, string> BridgePorts { get; } = new();         // "br/portno" -> ifname
    public Dictionary<string, string> Fdb { get; } = new();                 // MAC -> port name
    public Dictionary<string, string> WifiSsid { get; } = new();            // ifname -> SSID
    public Dictionary<string, OpenWrtStation> Stations { get; } = new();    // MAC -> station
    public Dictionary<string, OpenWrtLease> Leases { get; } = new();        // MAC -> lease
    public Dictionary<string, string> Arp { get; } = new();                 // MAC -> IPv4
    public bool Ok => Error.Length == 0 && MainMac.Length > 0;
}

/// <summary>Queries OpenWrt devices with the Windows OpenSSH client (key login, BatchMode).</summary>
public static class OpenWrtClient
{
    // POSIX sh script executed on the device; uses only busybox tools.
    public const string Script = """
echo "##HOST $(cat /proc/sys/kernel/hostname)"
for d in /sys/class/net/*; do n=${d##*/}; [ -r "$d/address" ] && echo "##IF $n $(cat $d/address)"; done
for b in /sys/class/net/*/bridge; do
  [ -d "$b" ] || continue
  br=${b%/bridge}; br=${br##*/}
  for p in /sys/class/net/$br/brif/*; do [ -e "$p" ] && echo "##PORT $br ${p##*/} $(cat $p/port_no)"; done
  f=/sys/class/net/$br/brforward
  if [ -r "$f" ]; then (hexdump -v -e '16/1 "%02x " "\n"' "$f" 2>/dev/null || od -An -v -tx1 -w16 "$f") | sed "s/^ */##FDB $br /"; fi
done
if command -v iw >/dev/null 2>&1; then
  for i in $(iw dev 2>/dev/null | awk '$1=="Interface"{print $2}'); do
    echo "##WIF $i $(iw dev $i info 2>/dev/null | awk '$1=="ssid"{$1="";sub(/^ /,"");print}')"
    iw dev $i station dump 2>/dev/null | awk -v i=$i '$1=="Station"{m=$2} $1=="signal:"{print "##STA",i,m,$2}'
  done
fi
[ -r /tmp/dhcp.leases ] && sed 's/^/##LEASE /' /tmp/dhcp.leases
awk 'NR>1{print "##ARP",$1,$4,$6}' /proc/net/arp
""";

    static readonly Regex TargetRx = new(@"^[\w.\-]+@?[\w.\-:\[\]]*$", RegexOptions.Compiled);

    public static string FindSsh()
    {
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        foreach (var p in new[] { Path.Combine(win, "Sysnative", "OpenSSH", "ssh.exe"), Path.Combine(win, "System32", "OpenSSH", "ssh.exe") })
            if (File.Exists(p)) return p;
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator))
        {
            try
            {
                foreach (var n in new[] { "ssh.exe", "ssh" })
                {
                    var p = Path.Combine(dir.Trim(), n);
                    if (File.Exists(p)) return p;
                }
            }
            catch (ArgumentException) { }
        }
        return "";
    }

    public static OpenWrtInfo Query(string target, int timeoutMs = 15000, CancellationToken ct = default)
    {
        var info = new OpenWrtInfo { Target = target };
        if (!TargetRx.IsMatch(target)) { info.Error = "invalid target"; return info; }
        string ssh = FindSsh();
        if (ssh.Length == 0) { info.Error = "ssh.exe not found (Windows feature \"OpenSSH Client\")"; return info; }
        try
        {
            var psi = new ProcessStartInfo(ssh)
            {
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
            };
            foreach (var a in new[] { "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-o", "StrictHostKeyChecking=accept-new", target, "sh", "-s" })
                psi.ArgumentList.Add(a);
            using var p = Process.Start(psi)!;
            p.StandardInput.Write(Script.Replace("\r", ""));
            p.StandardInput.Close();
            var outTask = p.StandardOutput.ReadToEndAsync(ct);
            var errTask = p.StandardError.ReadToEndAsync(ct);
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                info.Error = "timeout";
                return info;
            }
            string output = outTask.Result;
            if (!output.Contains("##HOST"))
            {
                info.Error = errTask.Result.Split('\n').Select(l => l.Trim()).LastOrDefault(l => l.Length > 0) ?? $"exit {p.ExitCode}";
                return info;
            }
            Parse(output, info);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            info.Error = ex.Message;
        }
        return info;
    }

    public static void Parse(string output, OpenWrtInfo o)
    {
        foreach (var raw in output.Split('\n'))
        {
            var line = raw.TrimEnd('\r', ' ');
            Match m;
            if ((m = Regex.Match(line, @"^##HOST (.*)$")).Success) o.Name = m.Groups[1].Value.Trim();
            else if ((m = Regex.Match(line, @"^##IF (\S+) (\S+)$")).Success)
            {
                var mac = MacUtil.Normalize(m.Groups[2].Value);
                if (MacUtil.IsUsable(mac)) o.Interfaces[m.Groups[1].Value] = mac;
            }
            else if ((m = Regex.Match(line, @"^##PORT (\S+) (\S+) (\S+)$")).Success)
            {
                try { o.BridgePorts[m.Groups[1].Value + "/" + Convert.ToInt32(m.Groups[3].Value, 16)] = m.Groups[2].Value; }
                catch (FormatException) { }
            }
            else if ((m = Regex.Match(line, @"^##FDB (\S+) (.+)$")).Success)
            {
                var bytes = m.Groups[2].Value.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (bytes.Length < 13) continue;
                try
                {
                    var mac = string.Join(":", bytes.Take(6)).ToLowerInvariant();
                    bool isLocal = bytes[7] != "00";
                    int portNo = Convert.ToInt32(bytes[12], 16) * 256 + Convert.ToInt32(bytes[6], 16);
                    if (!o.BridgePorts.TryGetValue(m.Groups[1].Value + "/" + portNo, out var port)) port = "port " + portNo;
                    if (!isLocal && MacUtil.IsUsable(mac)) o.Fdb[mac] = port;
                }
                catch (FormatException) { }
            }
            else if ((m = Regex.Match(line, @"^##WIF (\S+) ?(.*)$")).Success) o.WifiSsid[m.Groups[1].Value] = m.Groups[2].Value;
            else if ((m = Regex.Match(line, @"^##STA (\S+) (\S+) (\S+)")).Success)
            {
                var mac = MacUtil.Normalize(m.Groups[2].Value);
                if (mac.Length > 0) o.Stations[mac] = new OpenWrtStation { Interface = m.Groups[1].Value, Signal = m.Groups[3].Value };
            }
            else if ((m = Regex.Match(line, @"^##LEASE \S+ (\S+) (\S+) (\S+)")).Success)
            {
                var mac = MacUtil.Normalize(m.Groups[1].Value);
                if (mac.Length > 0) o.Leases[mac] = new OpenWrtLease { IPv4 = m.Groups[2].Value, Name = m.Groups[3].Value == "*" ? "" : m.Groups[3].Value };
            }
            else if ((m = Regex.Match(line, @"^##ARP (\S+) (\S+) (\S+)")).Success)
            {
                var mac = MacUtil.Normalize(m.Groups[2].Value);
                if (MacUtil.IsUsable(mac)) o.Arp[mac] = m.Groups[1].Value;
            }
        }
        if (o.Interfaces.TryGetValue("br-lan", out var br)) o.MainMac = br;
        else if (o.Interfaces.TryGetValue("eth0", out var eth)) o.MainMac = eth;
        else o.MainMac = o.Interfaces.Values.FirstOrDefault() ?? "";
    }
}
