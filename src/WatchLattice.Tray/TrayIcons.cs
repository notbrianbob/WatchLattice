using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using WatchLattice.Common.Alerts;

namespace WatchLattice.Tray;

/// <summary>
/// The tray's shield icons, drawn at start-up at the notification area's
/// size so they stay sharp at any display scaling. Each level differs in
/// shape as well as colour (a tick, a dot, a dash, an exclamation mark), so
/// the state is readable without telling colours apart.
/// </summary>
internal sealed class TrayIcons : IDisposable
{
    private readonly Dictionary<TrayLevel, Icon> _icons = new();

    public TrayIcons()
    {
        var size = Math.Max(16, SystemInformation.SmallIconSize.Width);
        foreach (var level in Enum.GetValues<TrayLevel>()) _icons[level] = Draw(level, size);
    }

    public Icon For(TrayLevel level) => _icons[level];

    private static Icon Draw(TrayLevel level, int size)
    {
        var (fill, edge) = level switch
        {
            TrayLevel.Ok => (Color.FromArgb(0x1E, 0x8E, 0x3E), Color.FromArgb(0x0F, 0x55, 0x24)),
            TrayLevel.Attention => (Color.FromArgb(0xF2, 0xA9, 0x00), Color.FromArgb(0x8A, 0x5A, 0x00)),
            TrayLevel.Critical => (Color.FromArgb(0xD9, 0x30, 0x25), Color.FromArgb(0x7A, 0x12, 0x0C)),
            _ => (Color.FromArgb(0x8A, 0x8F, 0x98), Color.FromArgb(0x4A, 0x4E, 0x55)),
        };
        using var bitmap = new Bitmap(size, size, System.Drawing.Imaging.PixelFormat.Format32bppArgb);
        using (var g = Graphics.FromImage(bitmap))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.Clear(Color.Transparent);
            float s = size;
            using var shield = new GraphicsPath();
            // A shield: flat top, straight sides, curving to a point.
            shield.AddLine(s * 0.50f, s * 0.04f, s * 0.92f, s * 0.18f);
            shield.AddLine(s * 0.92f, s * 0.18f, s * 0.92f, s * 0.48f);
            shield.AddBezier(s * 0.92f, s * 0.48f, s * 0.92f, s * 0.74f, s * 0.72f, s * 0.88f, s * 0.50f, s * 0.97f);
            shield.AddBezier(s * 0.50f, s * 0.97f, s * 0.28f, s * 0.88f, s * 0.08f, s * 0.74f, s * 0.08f, s * 0.48f);
            shield.AddLine(s * 0.08f, s * 0.48f, s * 0.08f, s * 0.18f);
            shield.CloseFigure();
            using (var brush = new SolidBrush(fill)) g.FillPath(brush, shield);
            using (var pen = new Pen(edge, Math.Max(1f, s / 16f))) g.DrawPath(pen, shield);

            var ink = level == TrayLevel.Attention ? Color.FromArgb(0x2B, 0x1D, 0x00) : Color.White;
            using var mark = new Pen(ink, Math.Max(1.5f, s / 8f)) { StartCap = LineCap.Round, EndCap = LineCap.Round, LineJoin = LineJoin.Round };
            switch (level)
            {
                case TrayLevel.Ok:
                    g.DrawLines(mark, new[] { new PointF(s * 0.30f, s * 0.50f), new PointF(s * 0.45f, s * 0.65f), new PointF(s * 0.71f, s * 0.36f) });
                    break;
                case TrayLevel.Attention:
                    using (var dot = new SolidBrush(ink)) g.FillEllipse(dot, s * 0.36f, s * 0.36f, s * 0.28f, s * 0.28f);
                    break;
                case TrayLevel.Critical:
                    g.DrawLine(mark, s * 0.50f, s * 0.26f, s * 0.50f, s * 0.56f);
                    using (var dot = new SolidBrush(ink)) g.FillEllipse(dot, s * 0.43f, s * 0.67f, s * 0.14f, s * 0.14f);
                    break;
                default:
                    g.DrawLine(mark, s * 0.32f, s * 0.50f, s * 0.68f, s * 0.50f);
                    break;
            }
        }
        // Icon.FromHandle doesn't own the handle: clone it, then free the original.
        var handle = bitmap.GetHicon();
        try
        {
            using var borrowed = Icon.FromHandle(handle);
            return (Icon)borrowed.Clone();
        }
        finally
        {
            DestroyIcon(handle);
        }
    }

    public void Dispose()
    {
        foreach (var icon in _icons.Values) icon.Dispose();
        _icons.Clear();
    }

    [DllImport("user32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyIcon(IntPtr handle);
}
