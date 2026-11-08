using System.Diagnostics;
using System.Drawing.Imaging;
using Microsoft.Win32;
using NetworkOverview.Core;
using NetworkOverview.Core.Lltd;
using NetworkOverview.Core.Localization;
using NetworkOverview.Core.Model;
using NetworkOverview.Core.Platform;

namespace NetworkOverview;

public sealed class MainForm : Form
{
    readonly AppConfig cfg;
    readonly ToolStrip bar = new() { GripStyle = ToolStripGripStyle.Hidden, Padding = new Padding(6, 4, 6, 4) };
    readonly ToolStripLabel lblAdapter = new();
    readonly ToolStripComboBox cbAdapter = new() { DropDownStyle = ComboBoxStyle.DropDownList, AutoSize = false, Width = 320 };
    readonly ToolStripButton btnScan = new() { DisplayStyle = ToolStripItemDisplayStyle.Text };
    readonly ToolStripButton btnSettings = new() { DisplayStyle = ToolStripItemDisplayStyle.Text };
    readonly ToolStripButton btnLog = new() { DisplayStyle = ToolStripItemDisplayStyle.Text };
    readonly ToolStripButton btnSave = new() { DisplayStyle = ToolStripItemDisplayStyle.Text };
    readonly ToolStripButton btnZoomIn = new("+") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    readonly ToolStripButton btnZoomOut = new("−") { DisplayStyle = ToolStripItemDisplayStyle.Text };
    readonly SplitContainer split = new() { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal };
    readonly Panel scroll = new() { Dock = DockStyle.Fill, AutoScroll = true };
    readonly MapView map = new() { Location = Point.Empty };
    readonly Label banner = new() { Dock = DockStyle.Top, AutoSize = false, Visible = false, Padding = new Padding(8, 6, 8, 6), TextAlign = ContentAlignment.MiddleLeft };
    readonly ListView list = new() { Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true, HideSelection = false };
    readonly StatusStrip statusStrip = new();
    readonly ToolStripStatusLabel status = new() { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
    readonly ToolStripProgressBar progress = new() { Visible = false, Width = 160 };
    readonly ContextMenuStrip ctx = new();
    readonly ToolStripMenuItem miWeb = new(), miShare = new(), miIp = new(), miMac = new(), miDetails = new();

    List<AdapterInfo> adapters = new();
    ScanController? scan;
    ScanResult? result;
    List<string> lastLog = new();
    Node? ctxNode;
    bool npcap;
    bool initializing = true;
    int sortColumn = -1;
    bool sortDescending;

    public MainForm(AppConfig cfg)
    {
        this.cfg = cfg;
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = new Size(1100, 820);
        StartPosition = FormStartPosition.CenterScreen;
        Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);

        bar.Items.AddRange(new ToolStripItem[] { lblAdapter, cbAdapter, new ToolStripSeparator(), btnScan, btnSettings, btnLog, btnSave, new ToolStripSeparator(), btnZoomOut, btnZoomIn });
        statusStrip.Items.AddRange(new ToolStripItem[] { status, progress });
        scroll.Controls.Add(map);
        split.Panel1.Controls.Add(scroll);
        split.Panel1.Controls.Add(banner);
        split.Panel2.Controls.Add(list);
        Controls.Add(split);
        Controls.Add(bar);
        Controls.Add(statusStrip);
        ctx.Items.AddRange(new ToolStripItem[] { miWeb, miShare, miIp, miMac, new ToolStripSeparator(), miDetails });

        btnScan.Click += (_, _) => { if (scan != null) { scan.Cancel(); status.Text = L.T("StatusCancelling"); } else _ = StartScan(); };
        btnSettings.Click += (_, _) => ShowSettings();
        btnLog.Click += (_, _) => { using var f = new LogForm(lastLog); f.ShowDialog(this); };
        btnSave.Click += (_, _) => SaveImage();
        btnZoomIn.Click += (_, _) => map.Zoom *= 1.2f;
        btnZoomOut.Click += (_, _) => map.Zoom /= 1.2f;
        cbAdapter.SelectedIndexChanged += (_, _) =>
        {
            if (cbAdapter.SelectedIndex < 0 || initializing || scan != null) return;
            cfg.Adapter = adapters[cbAdapter.SelectedIndex].Name;
            cfg.Save();
            _ = StartScan();
        };
        map.SelectionChanged += (_, n) => SelectInList(n);
        map.NodeContextMenu += (_, e) => ShowContextMenu(e.Node, map, e.Location);
        map.NodeActivated += (_, n) => ShowDetails(n);
        list.SelectedIndexChanged += (_, _) =>
        {
            if (list.SelectedItems.Count > 0 && list.SelectedItems[0].Tag is Node n) map.Select(n);
        };
        list.DoubleClick += (_, _) => { if (list.SelectedItems.Count > 0 && list.SelectedItems[0].Tag is Node n) ShowDetails(n); };
        list.MouseUp += (_, e) =>
        {
            if (e.Button == MouseButtons.Right && list.SelectedItems.Count > 0 && list.SelectedItems[0].Tag is Node n) ShowContextMenu(n, list, e.Location);
        };
        list.ColumnClick += (_, e) => SortList(e.Column);
        miWeb.Click += (_, _) => { if (ctxNode?.IPv4.Length > 0) Open("http://" + ctxNode.IPv4); };
        miShare.Click += (_, _) => { if (ctxNode?.IPv4.Length > 0) Open(@"\\" + ctxNode.IPv4); };
        miIp.Click += (_, _) => { if (ctxNode?.IPv4.Length > 0) Clipboard.SetText(ctxNode.IPv4); };
        miMac.Click += (_, _) => { if (ctxNode?.Mac.Length > 0) Clipboard.SetText(ctxNode.Mac); };
        miDetails.Click += (_, _) => { if (ctxNode != null) ShowDetails(ctxNode); };
        SystemEvents.UserPreferenceChanged += OnUserPreferenceChanged;

        ApplyTexts();
        ApplyTheme();
    }

    protected override void OnShown(EventArgs e)
    {
        base.OnShown(e);
        split.SplitterDistance = (int)(split.Height * 0.68);
        adapters = WindowsNet.GetAdapters();
        foreach (var a in adapters) cbAdapter.Items.Add(a.ToString());
        if (adapters.Count == 0)
        {
            MessageBox.Show(this, L.T("NoAdapter"), Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        // check Npcap before the first scan; selecting the adapter must not start a scan during start-up
        npcap = PcapIO.IsAvailable();
        int sel = Math.Max(0, adapters.FindIndex(a => a.Name == cfg.Adapter));
        cbAdapter.SelectedIndex = sel;
        initializing = false;
        if (!npcap && MessageBox.Show(this, L.T("NpcapMissingDialog"), Text, MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.Yes)
            Open("https://npcap.com/#download");
        _ = StartScan();
    }

    protected override void OnFormClosed(FormClosedEventArgs e)
    {
        SystemEvents.UserPreferenceChanged -= OnUserPreferenceChanged;
        scan?.Cancel();
        base.OnFormClosed(e);
    }

    void OnUserPreferenceChanged(object? sender, UserPreferenceChangedEventArgs e)
    {
        if (e.Category is UserPreferenceCategory.General or UserPreferenceCategory.Color or UserPreferenceCategory.VisualStyle)
            BeginInvoke(ApplyTheme);
    }

    void ApplyTheme()
    {
        var t = Theme.Current();
        map.Theme = t;
        scroll.BackColor = t.Background;
        banner.BackColor = t.Dark ? Color.FromArgb(77, 64, 20) : Color.FromArgb(255, 244, 206);
        banner.ForeColor = t.Dark ? Color.FromArgb(250, 235, 190) : Color.FromArgb(90, 60, 0);
        map.BackColor = t.Background;
        map.Invalidate();
    }

    void ApplyTexts()
    {
        Text = L.T("AppTitle");
        lblAdapter.Text = L.T("Adapter");
        btnScan.Text = scan != null ? L.T("Cancel") : L.T("Refresh");
        btnSettings.Text = L.T("Settings");
        btnLog.Text = L.T("Log");
        btnSave.Text = L.T("SaveImage");
        btnZoomIn.ToolTipText = L.T("ZoomIn");
        btnZoomOut.ToolTipText = L.T("ZoomOut");
        miWeb.Text = L.T("OpenWeb"); miShare.Text = L.T("ShowShares"); miIp.Text = L.T("CopyIp"); miMac.Text = L.T("CopyMac"); miDetails.Text = L.T("Details");
        list.Columns.Clear();
        foreach (var (key, width) in new[] { ("ColName", 170), ("ColIPv4", 105), ("ColMac", 120), ("ColVendor", 150), ("ColType", 120), ("ColMedium", 95), ("ColLink", 85), ("ColSsid", 100), ("ColLltd", 45), ("ColConnectedTo", 160) })
            list.Columns.Add(L.T(key), LogicalToDeviceUnits(width));
        FillList();
    }

    async Task StartScan()
    {
        if (cbAdapter.SelectedIndex < 0 || scan != null) return;
        var ad = adapters[cbAdapter.SelectedIndex];
        scan = new ScanController();
        SetBusy(true);
        var prog = new Progress<(string Text, int Done, int Total)>(p =>
        {
            status.Text = p.Text;
            if (p.Total > 0)
            {
                progress.Visible = true;
                progress.Maximum = p.Total;
                progress.Value = Math.Min(p.Done, p.Total);
            }
        });
        try
        {
            var r = await scan.RunAsync(ad, cfg, npcap, prog);
            result = r;
            lastLog = r.Log;
            ShowWarnings(r.Warnings);
            UpdateAdapter(r.Adapter);
            map.Result = r;
            FillList();
            status.Text = r.Status;
        }
        catch (Exception ex)
        {
            status.Text = ex.Message;
            lastLog.Add(ex.ToString());
        }
        finally
        {
            scan = null;
            SetBusy(false);
        }
    }

    void ShowWarnings(List<string> warnings)
    {
        banner.Text = string.Join(Environment.NewLine, warnings.Select(w => "⚠  " + w));
        banner.Visible = warnings.Count > 0;
        if (banner.Visible)
        {
            int lines = warnings.Sum(w => 1 + TextRenderer.MeasureText(w, banner.Font).Width / Math.Max(200, banner.Width - 40));
            banner.Height = lines * banner.Font.Height + banner.Padding.Vertical + 4;
        }
    }

    void UpdateAdapter(AdapterInfo fresh)
    {
        int i = adapters.FindIndex(a => a.Id == fresh.Id);
        if (i < 0 || fresh.Id.Length == 0) return;
        adapters[i] = fresh;
        if (i < cbAdapter.Items.Count && (string)cbAdapter.Items[i]! != fresh.ToString()) cbAdapter.Items[i] = fresh.ToString();
    }

    void SetBusy(bool busy)
    {
        btnScan.Text = busy ? L.T("Cancel") : L.T("Refresh");
        btnSettings.Enabled = !busy;
        btnSave.Enabled = !busy && result != null;
        cbAdapter.Enabled = !busy;
        progress.Visible = false;
        UseWaitCursor = false;
        Cursor = busy ? Cursors.AppStarting : Cursors.Default;
    }

    void FillList()
    {
        list.BeginUpdate();
        list.Items.Clear();
        if (result != null)
        {
            var m = result.Model;
            foreach (var n in m.All.Where(n => n.Kind != NodeKind.Internet && !(n.Virtual && n.Kind == NodeKind.Switch))
                                   .OrderBy(n => n.IsSelf ? -1 : MacUtil.IpKey(n.IPv4)))
            {
                var it = new ListViewItem(n.Title) { Tag = n };
                it.SubItems.Add(n.IPv4);
                it.SubItems.Add(n.Mac);
                it.SubItems.Add(n.Vendor);
                it.SubItems.Add(NodeText.TypeName(n));
                it.SubItems.Add(n.Medium);
                it.SubItems.Add(n.Speed);
                it.SubItems.Add(n.Ssid);
                it.SubItems.Add(n.Lltd ? L.T("Yes") : L.T("No"));
                it.SubItems.Add(m.ParentOf(n)?.Title ?? "");
                if (!n.Lltd && !n.IsSelf) it.ForeColor = SystemColors.GrayText;
                list.Items.Add(it);
            }
        }
        list.EndUpdate();
        if (sortColumn >= 0) ApplySort();
    }

    void SortList(int column)
    {
        sortDescending = column == sortColumn && !sortDescending;
        sortColumn = column;
        ApplySort();
    }

    void ApplySort()
    {
        int col = sortColumn;
        bool desc = sortDescending;
        list.ListViewItemSorter = Comparer<ListViewItem>.Create((a, b) =>
        {
            int r;
            if (col == 1) r = MacUtil.IpKey(a.SubItems[1].Text).CompareTo(MacUtil.IpKey(b.SubItems[1].Text));
            else r = string.Compare(a.SubItems[col].Text, b.SubItems[col].Text, StringComparison.CurrentCultureIgnoreCase);
            return desc ? -r : r;
        }) as System.Collections.IComparer;
        list.Sort();
    }

    void SelectInList(Node? n)
    {
        foreach (ListViewItem it in list.Items)
        {
            it.Selected = it.Tag == n;
            if (it.Selected) it.EnsureVisible();
        }
    }

    void ShowContextMenu(Node n, Control owner, Point location)
    {
        ctxNode = n;
        bool ip = n.IPv4.Length > 0;
        miWeb.Enabled = ip; miShare.Enabled = ip; miIp.Enabled = ip; miMac.Enabled = n.Mac.Length > 0;
        ctx.Show(owner, location);
    }

    void ShowDetails(Node n)
    {
        if (result != null) MessageBox.Show(this, NodeText.Details(n, result.Model), n.Title, MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    void ShowSettings()
    {
        using var f = new SettingsForm(cfg);
        if (f.ShowDialog(this) != DialogResult.OK) return;
        cfg.Save();
        L.SetLanguage(cfg.Language);
        ApplyTexts();
        map.Invalidate();
    }

    void SaveImage()
    {
        if (result == null) return;
        using var dlg = new SaveFileDialog
        {
            Filter = L.T("ImageFilter"),
            FileName = $"{L.T("ImageFileName")}_{DateTime.Now:yyyy-MM-dd}.png",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        float scale = DeviceDpi / 96f;
        using var bmp = new Bitmap((int)(result.Layout.Width * scale) + 1, (int)(result.Layout.Height * scale) + 1);
        bmp.SetResolution(DeviceDpi, DeviceDpi);
        using (var g = Graphics.FromImage(bmp))
        {
            g.Clear(map.Theme.Background);
            g.ScaleTransform(scale, scale);
            MapView.Render(g, result, map.Theme, null);
        }
        bmp.Save(dlg.FileName, ImageFormat.Png);
        status.Text = L.T("Saved", dlg.FileName);
    }

    static void Open(string target)
    {
        try { Process.Start(new ProcessStartInfo(target) { UseShellExecute = true }); }
        catch (Exception) { }
    }
}
