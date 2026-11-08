using System.Drawing;
using NetworkOverview.Core.Model;

namespace NetworkOverview.Core.Layout;

public sealed record Segment(PointF A, PointF B, bool Dashed);

public sealed class LayoutResult
{
    public List<Segment> Segments { get; } = new();
    public float Width { get; set; }
    public float Height { get; set; }
    public float OthersY { get; set; }
}

/// <summary>Tree layout in the style of the Windows 7 network map: Internet on the right,
/// infrastructure in columns, end devices on the left. Children of a node are connected through a
/// vertical bus; wired children come first and wireless children last, each group with its own bus,
/// so the dashed wireless bus never crosses wired connections and is drawn exactly once.</summary>
public static class TreeLayout
{
    public const float RowH = 92, ColW = 160, Left = 80, Top = 60, OthersColW = 140;

    public static float HalfWidth(Node n, bool rightSide)
    {
        if (n.Kind == NodeKind.Internet) return 25;
        if (n.Kind != NodeKind.Device) return 28;
        return rightSide && n.Wireless ? 46 : 26;
    }

    public static LayoutResult Run(NetworkModel m)
    {
        var r = new LayoutResult();
        var kids = new Dictionary<string, List<Node>>();
        foreach (var n in m.All)
        {
            n.X = 0; n.Y = 0; n.Col = 0;
            if (n.Parent != null && m.Contains(n.Parent))
            {
                if (!kids.TryGetValue(n.Parent, out var l)) kids[n.Parent] = l = new List<Node>();
                l.Add(n);
            }
        }
        foreach (var k in kids.Keys.ToList())
            kids[k] = kids[k]
                .OrderBy(c => c.IsSelf ? 0 : 1)
                .ThenBy(c => c.Dashed ? 1 : 0)                  // wired first, wireless last
                .ThenBy(c => kids.ContainsKey(c.Key) ? 1 : 0)   // leaves before subtrees
                .ThenBy(c => MacUtil.IpKey(c.IPv4))
                .ThenBy(c => c.Title, StringComparer.CurrentCultureIgnoreCase)
                .ToList();

        // roots: nodes without parent, except stand-alone end devices (those go to "other devices")
        var roots = m.All.Where(n => (n.Parent == null || !m.Contains(n.Parent))
                                     && (kids.ContainsKey(n.Key) || n.IsSelf
                                         || n.Kind is not (NodeKind.Device or NodeKind.ManagedSwitch))).ToList();

        int maxCol = 0;
        int Col(Node n)
        {
            if (!kids.TryGetValue(n.Key, out var cs)) return n.Col = 0;
            n.Col = cs.Max(Col) + 1;
            maxCol = Math.Max(maxCol, n.Col);
            return n.Col;
        }
        float row = Top;
        void Place(Node n)
        {
            if (!kids.TryGetValue(n.Key, out var cs)) { n.Y = row; row += RowH; return; }
            foreach (var c in cs) Place(c);
            n.Y = cs[0].Y;
        }
        foreach (var root in roots) Col(root);
        foreach (var root in roots) Place(root);
        foreach (var n in m.All.Where(n => n.Y > 0)) n.X = Left + n.Col * ColW;

        // connections
        foreach (var (pk, cs) in kids)
        {
            var p = m[pk];
            if (p.Y <= 0) continue;
            var solid = cs.Where(c => !c.Dashed && c.Y > 0).ToList();
            var dashed = cs.Where(c => c.Dashed && c.Y > 0).ToList();
            float hp = HalfWidth(p, false);
            AddGroup(r, p, solid, false, p.X - 58, p.Y, hp);
            // with wired children present, the wireless bus joins slightly below to stay separate
            AddGroup(r, p, dashed, true, p.X - 42, solid.Count > 0 ? p.Y + 6 : p.Y, hp);
        }

        // devices without a determined position
        float y = row;
        r.OthersY = 0;
        var others = m.All.Where(n => n.Y <= 0).OrderBy(n => MacUtil.IpKey(n.IPv4)).ToList();
        int perRow = Math.Max(5, maxCol + 1);
        if (others.Count > 0)
        {
            r.OthersY = y - 25;
            y += 40;
            for (int i = 0; i < others.Count; i++)
            {
                others[i].X = Left + i % perRow * OthersColW;
                others[i].Y = y + i / perRow * RowH;
            }
            y += (float)Math.Ceiling(others.Count / (double)perRow) * RowH;
        }
        r.Width = Math.Max(Left + maxCol * ColW, Left + (perRow - 1) * OthersColW) + 100;
        r.Height = y + 10;
        return r;
    }

    static void AddGroup(LayoutResult r, Node p, List<Node> group, bool dashed, float busX, float joinY, float hp)
    {
        if (group.Count == 0) return;
        float minY = joinY, maxY = joinY;
        foreach (var c in group)
        {
            float hc = HalfWidth(c, true);
            if (Math.Abs(c.Y - joinY) < 0.5f && group.Count == 1)
            {
                // single child on the parent's row: one straight line
                r.Segments.Add(new Segment(new PointF(c.X + hc, c.Y), new PointF(p.X - hp, joinY), dashed));
                return;
            }
            r.Segments.Add(new Segment(new PointF(c.X + hc, c.Y), new PointF(busX, c.Y), dashed));
            minY = Math.Min(minY, c.Y);
            maxY = Math.Max(maxY, c.Y);
        }
        if (maxY > minY) r.Segments.Add(new Segment(new PointF(busX, minY), new PointF(busX, maxY), dashed));
        r.Segments.Add(new Segment(new PointF(busX, joinY), new PointF(p.X - hp, joinY), dashed));
    }
}
