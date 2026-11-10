using System.Text.Json;

namespace NetworkOverview.Core.Devices;

/// <summary>A device type that was once determined from strong evidence (mDNS, SSDP, fingerprint).</summary>
public sealed class KnownDevice
{
    public DeviceType Type { get; set; }
    public string Source { get; set; } = "";
    public string Detail { get; set; } = "";
    public string Model { get; set; } = "";
    public DateTime Seen { get; set; }
}

/// <summary>
/// Remembers per MAC address what a device was identified as, so that devices in standby or switched off
/// (which then answer nothing) keep their type in later scans.
/// </summary>
public sealed class KnownDevices
{
    public Dictionary<string, KnownDevice> Devices { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static string DefaultPath =>
        Path.Combine(Path.GetDirectoryName(AppConfig.DefaultPath)!, "devices.json");

    public static KnownDevices Load(string? path = null)
    {
        try
        {
            var p = path ?? DefaultPath;
            if (File.Exists(p))
            {
                var k = JsonSerializer.Deserialize<KnownDevices>(File.ReadAllText(p));
                if (k != null)
                {
                    k.Devices = new Dictionary<string, KnownDevice>(k.Devices, StringComparer.OrdinalIgnoreCase);
                    return k;
                }
            }
        }
        catch (Exception) { }
        return new KnownDevices();
    }

    public void Save(string? path = null)
    {
        try
        {
            var p = path ?? DefaultPath;
            Directory.CreateDirectory(Path.GetDirectoryName(p)!);
            File.WriteAllText(p, JsonSerializer.Serialize(this, Options));
        }
        catch (Exception) { }
    }

    /// <summary>Applies remembered knowledge to a weak result and records strong results.</summary>
    public Classification Apply(string mac, Classification c, string model, out string knownModel)
    {
        knownModel = "";
        if (mac.Length == 0) return c;
        if (c.Strong)
        {
            Devices[mac] = new KnownDevice { Type = c.Type, Source = c.Source, Detail = c.Detail, Model = model, Seen = DateTime.Now };
            return c;
        }
        // only generic results are replaced: a type refined by name (e.g. Echo Show) stays
        bool generic = c.Type is DeviceType.Computer or DeviceType.Iot or DeviceType.AmazonDevice or DeviceType.GoogleDevice;
        if (generic && Devices.TryGetValue(mac, out var k))
        {
            knownModel = k.Model;
            return new Classification(k.Type, "Src_Previous", k.Seen.ToString("g"));
        }
        return c;
    }
}
