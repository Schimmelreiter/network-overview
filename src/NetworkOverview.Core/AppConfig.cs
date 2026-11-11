using System.Text.Json;

namespace NetworkOverview.Core;

public sealed class AppConfig
{
    public string OpenWrtTargets { get; set; } = "";
    public bool Topology { get; set; } = true;
    public bool PlaceOthers { get; set; } = true;
    public bool Nsdp { get; set; } = true;
    public bool EasySmart { get; set; } = true;
    public bool Mdns { get; set; } = true;
    public bool Ssdp { get; set; } = true;
    public bool PingSweep { get; set; }
    public bool Fingerprint { get; set; } = true;
    public bool UseNames { get; set; } = true;
    public bool ShowLastMap { get; set; } = true;
    public int MaxMinutes { get; set; } = 10;
    public string Adapter { get; set; } = "";
    public string Language { get; set; } = "system";

    static readonly JsonSerializerOptions Options = new() { WriteIndented = true };

    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "NetworkOverview", "config.json");

    public IEnumerable<string> Targets() =>
        OpenWrtTargets.Split(new[] { ' ', ',', ';', '\t', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

    public static AppConfig Load(string? path = null)
    {
        try
        {
            var p = path ?? DefaultPath;
            if (File.Exists(p)) return JsonSerializer.Deserialize<AppConfig>(File.ReadAllText(p)) ?? new AppConfig();
        }
        catch (Exception) { }
        return new AppConfig();
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
}
