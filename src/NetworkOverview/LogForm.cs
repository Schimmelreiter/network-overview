using NetworkOverview.Core.Localization;

namespace NetworkOverview;

public sealed class LogForm : Form
{
    public LogForm(IEnumerable<string> lines)
    {
        Text = L.T("LogTitle");
        AutoScaleMode = AutoScaleMode.Dpi;
        Size = new Size(950, 620);
        StartPosition = FormStartPosition.CenterParent;
        ShowInTaskbar = false;
        var tb = new TextBox
        {
            Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, WordWrap = false, Dock = DockStyle.Fill,
            Font = new Font("Consolas", 9f), Text = string.Join(Environment.NewLine, lines),
        };
        var copy = new Button { Text = L.T("CopyAll"), AutoSize = true, Dock = DockStyle.Right };
        copy.Click += (_, _) => { if (tb.Text.Length > 0) Clipboard.SetText(tb.Text); };
        var bottom = new Panel { Dock = DockStyle.Bottom, Height = LogicalToDeviceUnits(36), Padding = new Padding(6) };
        bottom.Controls.Add(copy);
        Controls.Add(tb);
        Controls.Add(bottom);
    }
}
