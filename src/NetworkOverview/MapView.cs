using System.ComponentModel;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using NetworkOverview.Core;
using NetworkOverview.Core.Layout;
using NetworkOverview.Core.Localization;
using NetworkOverview.Core.Model;

namespace NetworkOverview;

/// <summary>Draws the network map. Coordinates of the layout are in logical units (96 dpi, zoom 1).</summary>
public sealed class MapView : Control
{
    ScanResult? result;
    Node? hover;
    float zoom = 1f;
    readonly ToolTip tip = new() { AutoPopDelay = 20000, InitialDelay = 400, ReshowDelay = 100 };

    [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public Theme Theme { get; set; } = Theme.Current();
    public Node? Selected { get; private set; }
    public event EventHandler<Node?>? SelectionChanged;
    public event EventHandler<(Node Node, Point Location)>? NodeContextMenu;
    public event EventHandler<Node>? NodeActivated;

    public MapView()
    {
        SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        TabStop = true;
    }

    float Scale1 => DeviceDpi / 96f * zoom;

    [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public float Zoom
    {
        get => zoom;
        set { zoom = Math.Clamp(value, 0.4f, 3f); UpdateSize(); Invalidate(); }
    }

    [Browsable(false), DesignerSerializationVisibility(DesignerSerializationVisibility.Hidden)]
    public ScanResult? Result
    {
        get => result;
        set { result = value; hover = null; Selected = null; UpdateSize(); Invalidate(); }
    }

    public void Select(Node? n) { Selected = n; Invalidate(); }

    void UpdateSize()
    {
        if (result == null) { Size = new Size(10, 10); return; }
        Size = new Size((int)(result.Layout.Width * Scale1) + 1, (int)(result.Layout.Height * Scale1) + 1);
    }

    protected override void OnDpiChangedAfterParent(EventArgs e) { base.OnDpiChangedAfterParent(e); UpdateSize(); }

    protected override void OnPaint(PaintEventArgs e)
    {
        e.Graphics.Clear(Theme.Background);
        if (result == null) return;
        e.Graphics.ScaleTransform(Scale1, Scale1);
        Render(e.Graphics, result, Theme, Selected);
    }

    public static void Render(Graphics g, ScanResult r, Theme t, Node? selected)
    {
        g.SmoothingMode = SmoothingMode.AntiAlias;
        g.TextRenderingHint = TextRenderingHint.ClearTypeGridFit;
        using var solid = new Pen(t.Line, 3);
        using var dashed = new Pen(t.Line, 3) { DashPattern = new[] { 2.5f, 1.5f } };
        foreach (var s in r.Layout.Segments) g.DrawLine(s.Dashed ? dashed : solid, s.A, s.B);

        using var font = new Font("Segoe UI", 12f, GraphicsUnit.Pixel);
        using var bold = new Font("Segoe UI", 12f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var small = new Font("Segoe UI", 10.5f, GraphicsUnit.Pixel);
        using var head = new Font("Segoe UI", 12.5f, FontStyle.Bold, GraphicsUnit.Pixel);
        using var text = new SolidBrush(t.Text);
        using var sub = new SolidBrush(t.SubText);
        using var selFill = new SolidBrush(t.SelectionFill);
        using var selPen = new Pen(t.SelectionBorder, 1);
        using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisCharacter, FormatFlags = StringFormatFlags.NoWrap };

        if (r.Layout.OthersY > 0)
        {
            g.DrawLine(selPen, 20, r.Layout.OthersY, r.Layout.Width - 20, r.Layout.OthersY);
            g.DrawString(L.T("OtherDevices"), head, sub, 20, r.Layout.OthersY + 6);
        }

        foreach (var n in r.Model.All)
        {
            if (!n.Placed) continue;
            float x = n.X, y = n.Y;
            if (n.IsSelf || n == selected)
            {
                var rc = new RectangleF(x - 66, y - 31, 132, 88);
                g.FillRectangle(selFill, rc);
                g.DrawRectangle(selPen, rc.X, rc.Y, rc.Width, rc.Height);
            }
            DeviceIcons.Draw(g, n, x, y, t);
            g.DrawString(n.Title, n.IsSelf ? bold : font, text, new RectangleF(x - 70, y + 25, 140, 17), sf);
            var st = NodeText.Subtitle(n);
            if (st.Length > 0) g.DrawString(st, small, sub, new RectangleF(x - 70, y + 41, 140, 15), sf);
        }
    }

    Node? HitTest(Point p)
    {
        if (result == null) return null;
        float x = p.X / Scale1, y = p.Y / Scale1;
        return result.Model.All.FirstOrDefault(n => n.Placed && Math.Abs(x - n.X) <= 50 && y >= n.Y - 30 && y <= n.Y + 56);
    }

    protected override void OnMouseMove(MouseEventArgs e)
    {
        base.OnMouseMove(e);
        var n = HitTest(e.Location);
        if (n == hover) return;
        hover = n;
        Cursor = n != null ? Cursors.Hand : Cursors.Default;
        if (n != null && result != null) tip.Show(NodeText.Details(n, result.Model), this, e.X + 16, e.Y + 16, 20000);
        else tip.Hide(this);
    }

    protected override void OnMouseLeave(EventArgs e) { base.OnMouseLeave(e); hover = null; tip.Hide(this); }

    protected override void OnMouseDown(MouseEventArgs e)
    {
        base.OnMouseDown(e);
        Focus();
        var n = HitTest(e.Location);
        Selected = n;
        Invalidate();
        SelectionChanged?.Invoke(this, n);
        if (e.Button == MouseButtons.Right && n != null && n.Kind != NodeKind.Internet) NodeContextMenu?.Invoke(this, (n, e.Location));
    }

    protected override void OnMouseDoubleClick(MouseEventArgs e)
    {
        base.OnMouseDoubleClick(e);
        var n = HitTest(e.Location);
        if (n != null) NodeActivated?.Invoke(this, n);
    }

    protected override void OnMouseWheel(MouseEventArgs e)
    {
        if ((ModifierKeys & Keys.Control) != 0)
        {
            Zoom *= e.Delta > 0 ? 1.1f : 1 / 1.1f;
            if (e is HandledMouseEventArgs h) h.Handled = true;
            return;
        }
        base.OnMouseWheel(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing) tip.Dispose();
        base.Dispose(disposing);
    }
}
