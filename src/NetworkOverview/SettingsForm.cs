using NetworkOverview.Core;
using NetworkOverview.Core.Localization;

namespace NetworkOverview;

public sealed class SettingsForm : Form
{
    readonly AppConfig cfg;
    readonly TextBox tbTargets = new() { Dock = DockStyle.Fill };
    readonly CheckBox cbTopology = new() { AutoSize = true }, cbOthers = new() { AutoSize = true }, cbNsdp = new() { AutoSize = true },
                      cbMdns = new() { AutoSize = true }, cbPing = new() { AutoSize = true };
    readonly NumericUpDown numMinutes = new() { Minimum = 1, Maximum = 120, Width = 70 };
    readonly ComboBox cbLanguage = new() { DropDownStyle = ComboBoxStyle.DropDownList, Width = 180 };
    static readonly string[] LanguageCodes = { "system", "de", "en", "es", "fr" };

    public SettingsForm(AppConfig cfg)
    {
        this.cfg = cfg;
        Text = L.T("SettingsTitle");
        AutoScaleMode = AutoScaleMode.Dpi;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = MinimizeBox = false;
        ShowInTaskbar = false;
        StartPosition = FormStartPosition.CenterParent;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(12);

        var t = new TableLayoutPanel { ColumnCount = 2, AutoSize = true, Dock = DockStyle.Fill };
        t.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
        t.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, LogicalToDeviceUnits(260)));
        var lblTargets = new Label { Text = L.T("OpenWrtTargets"), AutoSize = true, MaximumSize = new Size(LogicalToDeviceUnits(560), 0), Margin = new Padding(3, 3, 3, 6) };
        t.Controls.Add(lblTargets, 0, 0); t.SetColumnSpan(lblTargets, 2);
        tbTargets.Text = cfg.OpenWrtTargets;
        tbTargets.Margin = new Padding(3, 0, 3, 10);
        t.Controls.Add(tbTargets, 0, 1); t.SetColumnSpan(tbTargets, 2);
        int row = 2;
        foreach (var (cb, key, value) in new[] { (cbTopology, "OptTopology", cfg.Topology), (cbOthers, "OptPlaceOthers", cfg.PlaceOthers), (cbNsdp, "OptNsdp", cfg.Nsdp), (cbMdns, "OptMdns", cfg.Mdns), (cbPing, "OptPing", cfg.PingSweep) })
        {
            cb.Text = L.T(key); cb.Checked = value;
            t.Controls.Add(cb, 0, row); t.SetColumnSpan(cb, 2); row++;
        }
        t.Controls.Add(new Label { Text = L.T("OptMaxMinutes"), AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 10, 3, 3) }, 0, row);
        numMinutes.Value = Math.Clamp(cfg.MaxMinutes, 1, 120);
        numMinutes.Margin = new Padding(3, 8, 3, 3);
        t.Controls.Add(numMinutes, 1, row++);
        t.Controls.Add(new Label { Text = L.T("OptLanguage"), AutoSize = true, Anchor = AnchorStyles.Left, Margin = new Padding(3, 8, 3, 3) }, 0, row);
        cbLanguage.Items.AddRange(new object[] { L.T("LanguageSystem"), "Deutsch", "English", "Español", "Français" });
        cbLanguage.SelectedIndex = Math.Max(0, Array.IndexOf(LanguageCodes, cfg.Language));
        cbLanguage.Margin = new Padding(3, 6, 3, 3);
        t.Controls.Add(cbLanguage, 1, row++);

        var buttons = new FlowLayoutPanel { FlowDirection = FlowDirection.RightToLeft, AutoSize = true, Dock = DockStyle.Fill, Margin = new Padding(0, 14, 0, 0) };
        var cancel = new Button { Text = L.T("Cancel"), DialogResult = DialogResult.Cancel, AutoSize = true, MinimumSize = new Size(LogicalToDeviceUnits(85), 0) };
        var ok = new Button { Text = L.T("OK"), DialogResult = DialogResult.OK, AutoSize = true, MinimumSize = new Size(LogicalToDeviceUnits(85), 0) };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        t.Controls.Add(buttons, 0, row); t.SetColumnSpan(buttons, 2);
        Controls.Add(t);
        AcceptButton = ok;
        CancelButton = cancel;
        ok.Click += (_, _) => Apply();
    }

    void Apply()
    {
        cfg.OpenWrtTargets = tbTargets.Text.Trim();
        cfg.Topology = cbTopology.Checked;
        cfg.PlaceOthers = cbOthers.Checked;
        cfg.Nsdp = cbNsdp.Checked;
        cfg.Mdns = cbMdns.Checked;
        cfg.PingSweep = cbPing.Checked;
        cfg.MaxMinutes = (int)numMinutes.Value;
        cfg.Language = LanguageCodes[Math.Max(0, cbLanguage.SelectedIndex)];
    }
}
