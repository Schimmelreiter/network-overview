using System.Drawing.Drawing2D;
using NetworkOverview.Core.Devices;
using NetworkOverview.Core.Model;

namespace NetworkOverview;

/// <summary>Self-drawn, generic device symbols (no vendor logos or product artwork).
/// Every symbol is centered at (x, y) and fits roughly into 50 x 46 units.</summary>
public static class DeviceIcons
{
    public static void Draw(Graphics g, Node n, float x, float y, Theme t)
    {
        bool grey = !(n.Lltd || n.IsSelf);
        switch (n.Kind)
        {
            case NodeKind.Internet: Globe(g, x, y, t); return;
            case NodeKind.Gateway: Router(g, x, y, n.HasWifiClients || n.OpenWrt?.WifiSsid.Count > 0, n.Virtual, t); return;
            case NodeKind.AccessPoint: Router(g, x, y, true, n.Virtual, t); return;
            case NodeKind.Router: Router(g, x, y, false, false, t); return;
            case NodeKind.Switch: Switch(g, x, y, n.Managed, n.Inferred, t); return;
            case NodeKind.ManagedSwitch: Switch(g, x, y, true, false, t); return;
        }
        switch (n.DeviceType)
        {
            case DeviceType.Phone: Phone(g, x, y, grey, t); break;
            case DeviceType.Tablet: Tablet(g, x, y, grey, t); break;
            case DeviceType.Printer: Printer(g, x, y, t); break;
            case DeviceType.Tv: Tv(g, x, y, grey, t); break;
            case DeviceType.MediaPlayer: MediaBox(g, x, y, t); break;
            case DeviceType.Iot: Chip(g, x, y, t); break;
            case DeviceType.Nas: Nas(g, x, y, t); break;
            case DeviceType.EchoDot: Puck(g, x, y, t, t.Accent, false); break;
            case DeviceType.AmazonDevice: Puck(g, x, y, t, t.SubText, false); break;
            case DeviceType.EchoSpot: RoundDisplay(g, x, y, t); break;
            case DeviceType.EchoShow: WedgeDisplay(g, x, y, t); break;
            case DeviceType.FireTv: Stick(g, x, y, t); break;
            case DeviceType.GoogleSpeaker:
            case DeviceType.GoogleDevice: Pebble(g, x, y, t); break;
            case DeviceType.GoogleDisplay: StandDisplay(g, x, y, t); break;
            case DeviceType.Chromecast: Disc(g, x, y, t); break;
            case DeviceType.HeatingController: Thermostat(g, x, y, t); break;
            case DeviceType.Receiver: Receiver(g, x, y, t); break;
            case DeviceType.AirConditioner: AirConditioner(g, x, y, t); break;
            default: Monitor(g, x, y, grey, !n.Lltd && !n.IsSelf && n.Name.Length == 0, t); break;
        }
        if (n.Wireless) Bars(g, x, y, t);
    }

    // ---------------- helpers ----------------
    static RectangleF R(float x, float y, float w, float h) => new(x, y, w, h);

    static GraphicsPath Round(RectangleF r, float rad)
    {
        var p = new GraphicsPath();
        float d = Math.Min(rad * 2, Math.Min(r.Width, r.Height));
        p.AddArc(r.X, r.Y, d, d, 180, 90);
        p.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        p.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        p.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        p.CloseFigure();
        return p;
    }

    static void Fill(Graphics g, GraphicsPath p, Color c1, Color c2, LinearGradientMode mode, Theme t, float outline = 1f)
    {
        var b = p.GetBounds();
        if (b.Width < 1 || b.Height < 1) return;
        using var br = new LinearGradientBrush(b, c1, c2, mode);
        g.FillPath(br, p);
        using var pen = new Pen(t.Outline, outline);
        g.DrawPath(pen, p);
    }

    static void Box(Graphics g, RectangleF r, float rad, Color c1, Color c2, Theme t, LinearGradientMode mode = LinearGradientMode.Vertical)
    {
        using var p = Round(r, rad);
        Fill(g, p, c1, c2, mode, t);
    }

    static void Bars(Graphics g, float x, float y, Theme t)
    {
        using var b = new SolidBrush(t.Signal);
        for (int i = 0; i < 4; i++)
        {
            float h = 5 + 4 * i;
            g.FillRectangle(b, R(x + 26 + i * 5, y + 6 - h, 3, h));
        }
    }

    // ---------------- infrastructure ----------------
    public static void Globe(Graphics g, float x, float y, Theme t)
    {
        var r = R(x - 22, y - 22, 44, 44);
        using (var br = new LinearGradientBrush(r, Color.FromArgb(130, 195, 255), Color.FromArgb(20, 75, 165), LinearGradientMode.ForwardDiagonal))
            g.FillEllipse(br, r);
        using (var land = new SolidBrush(Color.FromArgb(170, 70, 170, 70)))
        {
            g.FillEllipse(land, R(x - 15, y - 14, 15, 11));
            g.FillEllipse(land, R(x + 2, y - 3, 12, 15));
            g.FillEllipse(land, R(x - 12, y + 4, 9, 7));
        }
        using (var w = new Pen(Color.FromArgb(160, 255, 255, 255), 1))
        {
            g.DrawEllipse(w, R(x - 10, y - 22, 20, 44));
            g.DrawLine(w, x, y - 22, x, y + 22);
            g.DrawLine(w, x - 22, y, x + 22, y);
            g.DrawLine(w, x - 19, y - 11, x + 19, y - 11);
            g.DrawLine(w, x - 19, y + 11, x + 19, y + 11);
        }
        using var o = new Pen(t.Outline, 1);
        g.DrawEllipse(o, r);
    }

    public static void Router(Graphics g, float x, float y, bool antennas, bool grey, Theme t)
    {
        if (antennas)
        {
            using var ap = new Pen(t.Outline, 2);
            g.DrawLine(ap, x - 16, y - 8, x - 20, y - 24);
            g.DrawLine(ap, x + 16, y - 8, x + 20, y - 24);
        }
        Box(g, R(x - 24, y - 8, 48, 16), 3, grey ? t.ScreenGrey1 : t.DeviceBody1, grey ? t.ScreenGrey2 : t.DeviceBody2, t);
        using var led = new SolidBrush(t.Led);
        for (int i = 0; i < 4; i++) g.FillEllipse(led, R(x - 18 + i * 7, y - 2, 4, 4));
    }

    public static void Switch(Graphics g, float x, float y, bool managed, bool inferred, Theme t)
    {
        Color c1, c2;
        if (managed) { c1 = Color.FromArgb(70, 110, 190); c2 = Color.FromArgb(25, 50, 110); }
        else if (inferred) { c1 = t.Dark ? Color.FromArgb(175, 188, 210) : Color.FromArgb(235, 242, 250); c2 = t.Dark ? Color.FromArgb(105, 120, 150) : Color.FromArgb(140, 165, 200); }
        else { c1 = t.Dark ? Color.FromArgb(165, 185, 220) : Color.FromArgb(225, 238, 252); c2 = t.Dark ? Color.FromArgb(90, 115, 160) : Color.FromArgb(110, 150, 205); }
        Box(g, R(x - 24, y - 8, 48, 16), 2, c1, c2, t);
        using var port = new SolidBrush(managed ? Color.Gainsboro : Color.FromArgb(90, 90, 90));
        for (int i = 0; i < 6; i++) g.FillRectangle(port, R(x - 19 + i * 7, y - 2, 5, 4));
    }

    // ---------------- end devices ----------------
    public static void Monitor(Graphics g, float x, float y, bool grey, bool question, Theme t)
    {
        Box(g, R(x - 22, y - 22, 44, 32), 2, t.DeviceBody1, t.DeviceBody2, t);
        var scr = R(x - 19, y - 19, 38, 26);
        using (var br = new LinearGradientBrush(scr, grey ? t.ScreenGrey1 : t.Screen1, grey ? t.ScreenGrey2 : t.Screen2, LinearGradientMode.ForwardDiagonal))
            g.FillRectangle(br, scr);
        if (question)
        {
            using var f = new Font("Segoe UI", 13, FontStyle.Bold, GraphicsUnit.Pixel);
            using var sf = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("?", f, Brushes.White, scr, sf);
        }
        using var stand = new SolidBrush(t.DeviceBody2);
        g.FillRectangle(stand, R(x - 4, y + 10, 8, 6));
        Box(g, R(x - 13, y + 16, 26, 4), 1, t.DeviceBody1, t.DeviceBody2, t);
    }

    public static void Phone(Graphics g, float x, float y, bool grey, Theme t)
    {
        Box(g, R(x - 11, y - 22, 22, 42), 4, Color.FromArgb(70, 70, 75), Color.FromArgb(30, 30, 34), t);
        var scr = R(x - 9, y - 18, 18, 33);
        using var br = new LinearGradientBrush(scr, grey ? t.ScreenGrey1 : t.Screen1, grey ? t.ScreenGrey2 : t.Screen2, LinearGradientMode.ForwardDiagonal);
        g.FillRectangle(br, scr);
        using var dot = new SolidBrush(Color.FromArgb(110, 110, 115));
        g.FillEllipse(dot, R(x - 1.5f, y - 21, 3, 2.5f));
    }

    public static void Tablet(Graphics g, float x, float y, bool grey, Theme t)
    {
        Box(g, R(x - 22, y - 18, 44, 34), 4, Color.FromArgb(70, 70, 75), Color.FromArgb(30, 30, 34), t);
        var scr = R(x - 19, y - 15, 38, 28);
        using var br = new LinearGradientBrush(scr, grey ? t.ScreenGrey1 : t.Screen1, grey ? t.ScreenGrey2 : t.Screen2, LinearGradientMode.ForwardDiagonal);
        g.FillRectangle(br, scr);
    }

    public static void Printer(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 12, y - 22, 24, 12), 1, Color.White, Color.FromArgb(225, 225, 225), t);
        Box(g, R(x - 22, y - 12, 44, 22), 3, t.DeviceBody1, t.DeviceBody2, t);
        Box(g, R(x - 14, y + 6, 28, 12), 1, Color.White, Color.FromArgb(230, 230, 230), t);
        using var led = new SolidBrush(t.Led);
        g.FillEllipse(led, R(x + 14, y - 8, 4, 4));
    }

    public static void Tv(Graphics g, float x, float y, bool grey, Theme t)
    {
        Box(g, R(x - 25, y - 20, 50, 30), 2, Color.FromArgb(60, 60, 65), Color.FromArgb(25, 25, 28), t);
        var scr = R(x - 23, y - 18, 46, 26);
        using (var br = new LinearGradientBrush(scr, grey ? t.ScreenGrey1 : t.Screen1, grey ? t.ScreenGrey2 : t.Screen2, LinearGradientMode.ForwardDiagonal))
            g.FillRectangle(br, scr);
        using var pen = new Pen(t.Outline, 2);
        g.DrawLine(pen, x - 16, y + 10, x - 19, y + 17);
        g.DrawLine(pen, x + 16, y + 10, x + 19, y + 17);
    }

    public static void MediaBox(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 20, y - 12, 40, 24), 5, t.DeviceBody1, t.DeviceBody2, t);
        using var b = new SolidBrush(t.Accent);
        g.FillPolygon(b, new[] { new PointF(x - 5, y - 7), new PointF(x + 8, y), new PointF(x - 5, y + 7) });
    }

    public static void Chip(Graphics g, float x, float y, Theme t)
    {
        using var pin = new Pen(t.Outline, 2);
        for (int i = -1; i <= 1; i++)
        {
            g.DrawLine(pin, x - 18, y + i * 7, x + 18, y + i * 7);
            g.DrawLine(pin, x + i * 7, y - 18, x + i * 7, y + 18);
        }
        Box(g, R(x - 13, y - 13, 26, 26), 3, Color.FromArgb(70, 75, 80), Color.FromArgb(35, 38, 42), t);
        using var dot = new SolidBrush(t.Accent);
        g.FillEllipse(dot, R(x - 9, y - 9, 4, 4));
    }

    public static void Nas(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 15, y - 22, 30, 42), 3, Color.FromArgb(70, 70, 75), Color.FromArgb(30, 30, 34), t);
        using var slot = new SolidBrush(Color.FromArgb(120, 120, 125));
        using var led = new SolidBrush(t.Led);
        for (int i = 0; i < 3; i++)
        {
            g.FillRectangle(slot, R(x - 11, y - 17 + i * 11, 18, 7));
            g.FillEllipse(led, R(x + 9, y - 15 + i * 11, 3, 3));
        }
    }

    /// <summary>Round, short cylinder speaker with a light ring (Echo Dot style).</summary>
    public static void Puck(Graphics g, float x, float y, Theme t, Color ring, bool screen)
    {
        var body = R(x - 22, y - 10, 44, 24);
        using (var p = new GraphicsPath())
        {
            p.AddArc(body.X, body.Y, body.Width, 12, 180, -180);
            p.AddLine(body.Right, body.Y + 6, body.Right, body.Bottom - 6);
            p.AddArc(body.X, body.Bottom - 12, body.Width, 12, 0, 180);
            p.CloseFigure();
            Fill(g, p, t.Fabric, t.Dark ? Color.FromArgb(80, 80, 78) : Color.FromArgb(150, 150, 146), LinearGradientMode.Vertical, t);
        }
        var top = R(x - 22, y - 16, 44, 12);
        using (var p = new GraphicsPath())
        {
            p.AddEllipse(top);
            Fill(g, p, t.Dark ? Color.FromArgb(70, 70, 72) : Color.FromArgb(235, 235, 232), t.Dark ? Color.FromArgb(50, 50, 52) : Color.FromArgb(205, 205, 200), LinearGradientMode.Vertical, t);
        }
        using var rp = new Pen(ring, 2.5f);
        g.DrawEllipse(rp, R(x - 20, y - 15, 40, 10));
    }

    /// <summary>Round speaker with a round screen (Echo Spot style).</summary>
    public static void RoundDisplay(Graphics g, float x, float y, Theme t)
    {
        using (var p = new GraphicsPath())
        {
            p.AddArc(x - 22, y - 22, 44, 44, 150, 240);
            p.CloseFigure();
            Fill(g, p, t.Fabric, t.Dark ? Color.FromArgb(60, 60, 60) : Color.FromArgb(120, 120, 118), LinearGradientMode.Vertical, t);
        }
        var scr = R(x - 14, y - 16, 28, 28);
        using (var br = new LinearGradientBrush(scr, Color.FromArgb(40, 40, 45), Color.FromArgb(10, 10, 12), LinearGradientMode.Vertical))
            g.FillEllipse(br, scr);
        using var acc = new Pen(t.Accent, 2);
        g.DrawArc(acc, R(x - 9, y - 11, 18, 18), 200, 140);
    }

    /// <summary>Wedge-shaped smart display (Echo Show style).</summary>
    public static void WedgeDisplay(Graphics g, float x, float y, Theme t)
    {
        using (var p = new GraphicsPath())
        {
            p.AddPolygon(new[] { new PointF(x - 25, y + 16), new PointF(x - 21, y - 18), new PointF(x + 21, y - 18), new PointF(x + 25, y + 16) });
            Fill(g, p, t.Dark ? Color.FromArgb(70, 70, 72) : Color.FromArgb(60, 60, 64), Color.FromArgb(25, 25, 28), LinearGradientMode.Vertical, t);
        }
        var scr = R(x - 18, y - 15, 36, 22);
        using (var br = new LinearGradientBrush(scr, t.Screen1, t.Screen2, LinearGradientMode.ForwardDiagonal))
            g.FillRectangle(br, scr);
        using var fab = new SolidBrush(t.Fabric);
        g.FillRectangle(fab, R(x - 22, y + 10, 44, 5));
    }

    /// <summary>HDMI streaming stick (Fire TV style).</summary>
    public static void Stick(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 20, y - 7, 34, 14), 5, Color.FromArgb(55, 55, 60), Color.FromArgb(20, 20, 24), t);
        Box(g, R(x + 14, y - 4, 9, 8), 1, Color.Silver, Color.Gray, t);
        using var acc = new SolidBrush(t.Accent);
        g.FillEllipse(acc, R(x - 14, y - 2, 4, 4));
        // small remote
        Box(g, R(x - 8, y + 10, 10, 13), 3, Color.FromArgb(55, 55, 60), Color.FromArgb(20, 20, 24), t);
        using var btn = new SolidBrush(Color.FromArgb(150, 150, 150));
        g.FillEllipse(btn, R(x - 5.5f, y + 12, 5, 5));
    }

    /// <summary>Flat fabric pebble speaker with four dots (Google Home/Nest Mini style).</summary>
    public static void Pebble(Graphics g, float x, float y, Theme t)
    {
        var side = R(x - 22, y - 6, 44, 20);
        using (var p = new GraphicsPath())
        {
            p.AddEllipse(side);
            Fill(g, p, t.Fabric, t.Dark ? Color.FromArgb(85, 85, 83) : Color.FromArgb(165, 165, 160), LinearGradientMode.Vertical, t);
        }
        var top = R(x - 22, y - 12, 44, 18);
        using (var p = new GraphicsPath())
        {
            p.AddEllipse(top);
            Fill(g, p, t.Dark ? Color.FromArgb(175, 175, 170) : Color.FromArgb(238, 238, 234), t.Fabric, LinearGradientMode.Vertical, t);
        }
        Color[] c = { Color.FromArgb(66, 133, 244), Color.FromArgb(234, 67, 53), Color.FromArgb(251, 188, 5), Color.FromArgb(52, 168, 83) };
        for (int i = 0; i < 4; i++)
        {
            using var b = new SolidBrush(c[i]);
            g.FillEllipse(b, R(x - 11 + i * 6, y - 4.5f, 4, 4));
        }
    }

    /// <summary>Screen standing on a fabric speaker base (Nest Hub style).</summary>
    public static void StandDisplay(Graphics g, float x, float y, Theme t)
    {
        // round fabric speaker base, clearly visible below the floating screen
        using (var p = new GraphicsPath())
        {
            p.AddEllipse(R(x - 17, y + 6, 34, 16));
            Fill(g, p, t.Fabric, t.Dark ? Color.FromArgb(80, 80, 78) : Color.FromArgb(150, 150, 146), LinearGradientMode.Vertical, t);
        }
        // slightly tilted screen with a white frame
        using (var p = new GraphicsPath())
        {
            p.AddPolygon(new[] { new PointF(x - 22, y - 20), new PointF(x + 22, y - 20), new PointF(x + 24, y + 9), new PointF(x - 24, y + 9) });
            Fill(g, p, Color.White, Color.FromArgb(215, 215, 215), LinearGradientMode.Vertical, t);
        }
        using var br = new LinearGradientBrush(R(x - 20, y - 17, 40, 23), t.Screen1, t.Screen2, LinearGradientMode.ForwardDiagonal);
        g.FillPolygon(br, new[] { new PointF(x - 19, y - 17), new PointF(x + 19, y - 17), new PointF(x + 20.5f, y + 6), new PointF(x - 20.5f, y + 6) });
    }

    /// <summary>Wall-mounted room controller with a round display and a flame (generic heating controller).</summary>
    public static void Thermostat(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 19, y - 21, 38, 40), 6, Color.White, Color.FromArgb(222, 222, 222), t);
        var ring = R(x - 13, y - 15, 26, 26);
        using (var dark = new SolidBrush(Color.FromArgb(45, 45, 50))) g.FillEllipse(dark, ring);
        using (var arc = new Pen(Color.FromArgb(240, 130, 30), 3)) g.DrawArc(arc, R(x - 11, y - 13, 22, 22), 135, 200);
        // small flame in the centre
        using var flame = new GraphicsPath();
        flame.AddBezier(x, y - 8, x + 6, y - 2, x + 5, y + 4, x, y + 5);
        flame.AddBezier(x, y + 5, x - 5, y + 4, x - 6, y - 2, x, y - 8);
        using (var fb = new SolidBrush(Color.FromArgb(255, 160, 40))) g.FillPath(fb, flame);
        using var dot = new SolidBrush(Color.FromArgb(150, 150, 150));
        g.FillEllipse(dot, R(x - 2, y + 13, 4, 4));
    }

    /// <summary>Wall-mounted split air conditioner with louvre and cold air flow.</summary>
    public static void AirConditioner(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 26, y - 16, 52, 20), 6, Color.White, Color.FromArgb(214, 214, 218), t);
        using (var slot = new SolidBrush(Color.FromArgb(70, 72, 78))) g.FillRectangle(slot, R(x - 21, y - 1, 42, 3));
        using (var led = new SolidBrush(Color.FromArgb(60, 180, 255))) g.FillEllipse(led, R(x + 17, y - 12, 3, 3));
        using var air = new Pen(Color.FromArgb(90, 170, 240), 2f);
        for (int i = -1; i <= 1; i++)
        {
            float ax = x + i * 13;
            g.DrawBezier(air, ax, y + 6, ax - 4, y + 10, ax + 4, y + 14, ax, y + 19);
        }
    }

    /// <summary>Flat TV receiver / set-top box with a front display and a standby LED.</summary>
    public static void Receiver(Graphics g, float x, float y, Theme t)
    {
        Box(g, R(x - 25, y - 9, 50, 18), 3, Color.FromArgb(70, 70, 76), Color.FromArgb(28, 28, 32), t);
        using (var disp = new SolidBrush(Color.FromArgb(12, 30, 40))) g.FillRectangle(disp, R(x - 8, y - 4, 18, 8));
        using (var seg = new SolidBrush(Color.FromArgb(70, 200, 255)))
            for (int i = 0; i < 4; i++) g.FillRectangle(seg, R(x - 6 + i * 4.2f, y - 2, 2.8f, 4));
        using (var led = new SolidBrush(Color.FromArgb(230, 60, 50))) g.FillEllipse(led, R(x + 16, y - 1.5f, 3, 3));
        using (var slot = new Pen(Color.FromArgb(110, 110, 118), 1.2f)) g.DrawLine(slot, x - 21, y, x - 12, y);
        using var foot = new SolidBrush(Color.FromArgb(40, 40, 44));
        g.FillRectangle(foot, R(x - 21, y + 9, 6, 2));
        g.FillRectangle(foot, R(x + 15, y + 9, 6, 2));
    }

    /// <summary>Small round streaming dongle with cable (Chromecast style).</summary>
    public static void Disc(Graphics g, float x, float y, Theme t)
    {
        using (var pen = new Pen(t.Dark ? Color.FromArgb(185, 185, 190) : Color.FromArgb(40, 40, 44), 3))
            g.DrawBezier(pen, x + 8, y + 8, x + 18, y + 18, x + 22, y + 4, x + 24, y - 12);
        using (var p = new GraphicsPath())
        {
            p.AddEllipse(R(x - 15, y - 15, 30, 30));
            Fill(g, p, t.Dark ? Color.FromArgb(200, 200, 200) : Color.FromArgb(245, 245, 245), t.Dark ? Color.FromArgb(120, 120, 120) : Color.FromArgb(190, 190, 190), LinearGradientMode.ForwardDiagonal, t);
        }
        using var b = new SolidBrush(t.Accent);
        g.FillEllipse(b, R(x - 3, y - 3, 6, 6));
        using var plug = new SolidBrush(Color.Silver);
        g.FillRectangle(plug, R(x + 21, y - 19, 6, 8));
    }
}
