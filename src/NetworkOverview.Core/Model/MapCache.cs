using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using NetworkOverview.Core.Layout;

namespace NetworkOverview.Core.Model;

/// <summary>
/// Stores the last map so that it can be shown immediately at start-up while a new scan runs
/// (Windows 7 kept its network map in a cache for 10 minutes in the same spirit).
/// </summary>
public static class MapCache
{
    sealed class Snapshot
    {
        public DateTime Time { get; set; }
        public string Status { get; set; } = "";
        public List<Dictionary<string, JsonElement>> Nodes { get; set; } = new();
    }

    public static string DefaultPath => Path.Combine(Path.GetDirectoryName(AppConfig.DefaultPath)!, "lastmap.json");

    static readonly string[] Skip = { nameof(Node.X), nameof(Node.Y), nameof(Node.Col) };

    static IEnumerable<PropertyInfo> Props() => typeof(Node).GetProperties(BindingFlags.Public | BindingFlags.Instance)
        .Where(p => !Skip.Contains(p.Name) && p.GetCustomAttribute<JsonIgnoreAttribute>() == null && p.GetIndexParameters().Length == 0);

    public static void Save(ScanResult r, string? path = null)
    {
        try
        {
            var snap = new Snapshot { Time = DateTime.Now, Status = r.Status };
            foreach (var n in r.Model.All)
            {
                var d = new Dictionary<string, JsonElement>();
                foreach (var p in Props())
                {
                    bool list = p.PropertyType == typeof(List<string>);
                    if (!p.CanWrite && !list) continue;
                    d[p.Name] = JsonSerializer.SerializeToElement(p.GetValue(n), p.PropertyType);
                }
                snap.Nodes.Add(d);
            }
            var file = path ?? DefaultPath;
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            File.WriteAllText(file, JsonSerializer.Serialize(snap));
        }
        catch (Exception) { }
    }

    /// <summary>Loads the last map; null if there is none or it cannot be read.</summary>
    public static ScanResult? Load(out DateTime time, string? path = null)
    {
        time = default;
        try
        {
            var file = path ?? DefaultPath;
            if (!File.Exists(file)) return null;
            var snap = JsonSerializer.Deserialize<Snapshot>(File.ReadAllText(file));
            if (snap == null || snap.Nodes.Count == 0) return null;
            var m = new NetworkModel();
            var props = Props().ToDictionary(p => p.Name);
            foreach (var d in snap.Nodes)
            {
                if (!d.TryGetValue(nameof(Node.Key), out var key)) continue;
                var n = new Node { Key = key.GetString() ?? "" };
                foreach (var (name, value) in d)
                {
                    if (name == nameof(Node.Key) || !props.TryGetValue(name, out var p)) continue;
                    if (p.PropertyType == typeof(List<string>)) ((List<string>)p.GetValue(n)!).AddRange(value.Deserialize<List<string>>() ?? new());
                    else if (p.CanWrite) p.SetValue(n, value.Deserialize(p.PropertyType));
                }
                m.Add(n);
            }
            time = snap.Time;
            return new ScanResult { Model = m, Layout = TreeLayout.Run(m), Status = snap.Status };
        }
        catch (Exception) { return null; }
    }
}
