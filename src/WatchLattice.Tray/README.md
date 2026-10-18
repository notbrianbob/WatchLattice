# WatchLattice.Tray

A Windows Forms notification-area companion for the WatchLattice hub. It reads
the local shared alert feed and provides balloons, a connected/offline
indicator, and the [dashboard](../../docs/dashboard.md): module status, alerts
with repeats grouped and per-user acknowledge/dismiss, alert details with
read-only persistence verification, the hub's recent activity,
and its settings.

Run with `--edit-settings`, it is the settings editor instead. The dashboard
starts it that way through Windows' administrator prompt; it is not meant to
be started by hand.

Run in your interactive Windows session, separately from the hub service:

```powershell
dotnet run -c Release --project src/WatchLattice.Tray
```

For a custom or service-account feed:

```powershell
dotnet run -c Release --project src/WatchLattice.Tray -- --feed 'C:\ProgramData\WatchLattice\Alerts\alerts.json'
```

See [shared alerts and tray setup](../../docs/alerts-and-tray.md) for publishing,
permissions, optional login startup, delivery limits, and Windows smoke checks.
This project targets `net8.0-windows`; `EnableWindowsTargeting` permits
cross-compilation, but running the companion requires Windows and the .NET 8
Desktop Runtime.
