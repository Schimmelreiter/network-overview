using System.Net;
using NetworkOverview.Core.Discovery;
using NetworkOverview.Core.Layout;
using NetworkOverview.Core.Lltd;
using NetworkOverview.Core.Localization;
using NetworkOverview.Core.Model;
using NetworkOverview.Core.Platform;

namespace NetworkOverview.Core;

public sealed class ScanResult
{
    public NetworkModel Model { get; init; } = new();
    public LayoutResult Layout { get; init; } = new();
    public List<string> Log { get; init; } = new();
    public string Status { get; init; } = "";
    public List<string> Warnings { get; init; } = new();
    public AdapterInfo Adapter { get; init; } = new();
}

/// <summary>Runs a complete scan on a background thread. Progress texts are already localized.</summary>
public sealed class ScanController
{
    readonly List<string> log = new();
    MapperJob? job;
    volatile bool cancel;

    public void Cancel()
    {
        cancel = true;
        if (job != null) job.Cancel = true;
    }

    void Log(string s) { lock (log) log.Add(DateTime.Now.ToString("HH:mm:ss") + " " + s); }

    public Task<ScanResult> RunAsync(AdapterInfo ad, AppConfig cfg, bool npcapAvailable, IProgress<(string Text, int Done, int Total)> progress)
        => Task.Run(() => Run(ad, cfg, npcapAvailable, progress));

    ScanResult Run(AdapterInfo initial, AppConfig cfg, bool npcap, IProgress<(string Text, int Done, int Total)> progress)
    {
        void P(string text) => progress.Report((text, 0, 0));
        var warnings = new List<string>();

        // addresses can change at any time (DHCP): read the adapter again, wait briefly for a valid IPv4 address
        var ad = Refresh(initial);
        for (int i = 0; i < 10 && ad.IPv4.Length == 0 && !cancel; i++)
        {
            P(L.T("StatusWaitIp", ad.Name));
            Thread.Sleep(1000);
            ad = Refresh(initial);
        }
        Log($"Adapter {ad.Name} {ad.Mac} {(ad.IPv4.Length > 0 ? ad.IPv4 : "no IPv4")}/{ad.Prefix} GW {ad.Gateway} wireless={ad.Wireless} npcap={npcap}");
        if (ad.IPv4.Length == 0) warnings.Add(L.T("WarnNoIPv4", ad.Name));

        if (cfg.PingSweep && ad.IPv4.Length > 0)
        {
            P(L.T("StatusPing"));
            WindowsNet.PingAll(WindowsNet.SubnetHosts(ad.IPv4, ad.Prefix).Where(i => i != ad.IPv4), 6000);
        }

        var owrt = new List<OpenWrtInfo>();
        foreach (var t in ad.IPv4.Length > 0 ? cfg.Targets() : Enumerable.Empty<string>())
        {
            if (cancel) break;
            P(L.T("StatusOpenWrt", t));
            var o = OpenWrtClient.Query(t);
            Log(o.Ok ? $"OpenWrt {t}: {o.Name}, {o.Interfaces.Count} interfaces, {o.Fdb.Count} FDB, {o.Stations.Count} Wi-Fi clients, {o.Leases.Count} leases"
                     : $"OpenWrt {t}: {o.Error}");
            owrt.Add(o);
        }

        var nsdp = new List<NsdpDevice>();
        if (cfg.Nsdp && ad.IPv4.Length > 0 && !cancel)
        {
            P(L.T("StatusNsdp"));
            try { nsdp = Nsdp.Discover(ad.IPv4, ad.Mac, 1500, Log); } catch (Exception ex) { Log("NSDP: " + ex.Message); }
            if (nsdp.Count == 0) Log("NSDP: no answer");
            foreach (var d in nsdp) Log($"NSDP: {d.Model} '{d.Name}' {d.Mac} {d.IPv4} ports: {string.Join(" ", d.Ports)}");
        }

        var mdns = new List<MdnsHost>();
        if (cfg.Mdns && ad.IPv4.Length > 0 && !cancel)
        {
            P(L.T("StatusMdns"));
            try { mdns = Mdns.Browse(IPAddress.Parse(ad.IPv4), 3000, Log); } catch (Exception ex) { Log("mDNS: " + ex.Message); }
            foreach (var h in mdns)
                Log($"mDNS: {h.IPv4} {h.HostName} [{string.Join(", ", h.Services.Select(s => s.Type.Replace(".local", "")).Distinct())}] {h.Model()}");
        }

        var ssdp = new List<SsdpDevice>();
        if (cfg.Ssdp && ad.IPv4.Length > 0 && !cancel)
        {
            P(L.T("StatusSsdp"));
            try { ssdp = Ssdp.Discover(IPAddress.Parse(ad.IPv4), 2500, Log); } catch (Exception ex) { Log("SSDP: " + ex.Message); }
            foreach (var x in ssdp.Where(x => x.FriendlyName.Length > 0 || x.Model.Length > 0))
                Log($"SSDP: {x.IPv4} '{x.FriendlyName}' {x.Manufacturer} {x.Model}");
        }

        P(L.T("StatusArp"));
        var neighbors = WindowsNet.GetNeighbors(ad.Index);
        var wlan = ad.Wireless ? WindowsNet.GetWlanInfo(ad.Name) : null;

        // Wi-Fi clients (cannot send foreign source addresses) and devices to place additionally
        var wireless = new HashSet<string>(owrt.Where(o => o.Ok).SelectMany(o => o.Stations.Keys));
        var extra = new HashSet<string>();
        var pingIps = new HashSet<string>();
        foreach (var nb in neighbors)
        {
            // infrastructure is always placed: gateway and Netgear devices (possible switches without NSDP)
            bool infra = nb.IPv4 == ad.Gateway || Devices.VendorDb.Lookup(nb.Mac).StartsWith("Netgear", StringComparison.OrdinalIgnoreCase);
            if (infra || cfg.PlaceOthers) { extra.Add(nb.Mac); pingIps.Add(nb.IPv4); }
        }
        foreach (var o in owrt.Where(o => o.Ok))
        {
            extra.Add(o.MainMac);
            if (IPAddress.TryParse(o.Host, out _)) pingIps.Add(o.Host);
        }
        foreach (var d in nsdp)
        {
            extra.Add(MacUtil.Normalize(d.Mac));
            if (d.IPv4.Length > 0 && d.IPv4 != "0.0.0.0") pingIps.Add(d.IPv4);
        }
        extra.ExceptWith(wireless);
        extra.Remove(ad.Mac);
        extra.Remove("");

        var lltdHosts = new List<LltdHost>();
        var tree = new List<TNode>();
        string status = "";
        if (npcap && !cancel)
        {
            // talk to every device once so that all switches know its address
            WindowsNet.PingAll(pingIps, 1500);
            job = new MapperJob
            {
                Device = ad.NpcapDevice, MyMac = ad.Mac, MyWired = !ad.Wireless, DoTopology = cfg.Topology,
                MaxSeconds = Math.Max(1, cfg.MaxMinutes) * 60,
            };
            job.ExtraMacs.AddRange(extra);
            job.WirelessMacs.AddRange(wireless);
            job.SwitchMacs.AddRange(nsdp.Select(x => MacUtil.Normalize(x.Mac)));
            job.SwitchMacs.AddRange(extra.Where(x => Devices.VendorDb.Lookup(x).StartsWith("Netgear", StringComparison.OrdinalIgnoreCase)));
            Log($"LLTD: {job.ExtraMacs.Count} extra devices, {job.WirelessMacs.Count} known Wi-Fi clients");
            if (cancel) job.Cancel = true;
            job.Start();
            while (!job.Done)
            {
                Thread.Sleep(300);
                if (job.RoundsTotal > 0) progress.Report((L.T("StatusRound", job.RoundsDone, job.RoundsTotal), job.RoundsDone, job.RoundsTotal));
                else P(L.T("StatusDiscover"));
            }
            lock (job.Log) foreach (var l in job.Log) Log("LLTD " + l);
            lltdHosts = job.Hosts;
            tree = job.Tree;
            if (job.Error.Length > 0)
            {
                status = L.T("LltdError", job.Error);
                if (job.Error.Contains("denied", StringComparison.OrdinalIgnoreCase) || job.Error.Contains("verweigert", StringComparison.OrdinalIgnoreCase))
                    status += " " + L.T("RunAsAdmin");
            }
            else if (job.Partial) status = L.T("Partial");
            if (job.NonObservers.Count > 0)
            {
                var names = job.NonObservers.Select(mac => lltdHosts.FirstOrDefault(h => h.Mac == mac) is { Name.Length: > 0 } h ? h.Name : mac);
                warnings.Add(L.T("WarnNonObservers", string.Join(", ", names)));
            }
            if (job.Partial) warnings.Add(L.T("Partial"));
        }
        else if (!npcap) { status = L.T("NpcapMissingShort"); warnings.Add(L.T("NpcapMissingShort")); }

        P(L.T("StatusEvaluate"));
        var ips = neighbors.Select(n => n.IPv4).Concat(lltdHosts.Select(h => h.IPv4)).Where(i => i.Length > 0);
        var reverse = WindowsNet.ReverseLookup(ips, 3000);
        var data = new ScanData
        {
            Adapter = ad, Neighbors = neighbors, OpenWrt = owrt, Nsdp = nsdp, Mdns = mdns, Ssdp = ssdp, Wlan = wlan,
            LltdHosts = lltdHosts, Tree = tree, ReverseNames = reverse,
        };
        var model = ModelBuilder.Build(data);
        var layout = TreeLayout.Run(model);

        int cntL = model.All.Count(n => n.Lltd);
        int cntS = model.All.Count(n => n.Kind == NodeKind.Switch);
        int cntO = model.All.Count(n => n.Parent == null && n.Kind is NodeKind.Device or NodeKind.ManagedSwitch && !n.IsSelf);
        var summary = L.T("Summary", cntL, cntS, cntO);
        var bad = owrt.Where(o => !o.Ok).ToList();
        if (bad.Count > 0)
        {
            summary += " " + L.T("OpenWrtUnreachable", bad.Count);
            warnings.Add(L.T("WarnOpenWrt", string.Join(", ", bad.Select(o => o.Target))));
        }
        status = (status.Length > 0 ? status + " – " : "") + summary;
        Log(status);
        List<string> logCopy;
        lock (log) logCopy = new List<string>(log);
        return new ScanResult { Model = model, Layout = layout, Log = logCopy, Status = status, Warnings = warnings, Adapter = ad };
    }

    static AdapterInfo Refresh(AdapterInfo ad)
    {
        try
        {
            var all = WindowsNet.GetAdapters();
            return all.FirstOrDefault(a => a.Id == ad.Id) ?? all.FirstOrDefault(a => a.Mac == ad.Mac) ?? ad;
        }
        catch (Exception) { return ad; }
    }
}
