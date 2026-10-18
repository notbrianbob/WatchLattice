# Shared alerts and Windows tray companion

The hub routes Canary, Defender, Firewall, and Persistence alerts into one
bounded local history. New Defender exclusions and weakened ASR rules appear as
warnings. Defender and firewall recovery, firewall policy changes back to Block,
removed Defender exclusions, and persistence removals appear as informational
events. Module failures and modules that finish without a shutdown request also
raise warnings. Decoy's cosmetic scan narration stays in its existing logs.

Every alert is also written to the Windows Application event log, for Event
Viewer, event forwarding and SIEMs. See [Event Log alerts](event-log.md) for
the settings and event IDs.

The tray is a separate, per-user Windows application. It reads the feed, shows
new warnings/critical alerts as notification balloons, and opens the
[dashboard](dashboard.md) on double-click: module status, alert history and
details, the hub's recent activity, and its settings. The dashboard groups
repeated alerts into one row and lets you acknowledge or dismiss them; that
is kept per user and never changes the feed or the Event Log. Closing the window keeps
the tray alive; **Exit tray companion** stops only the companion.

## Quick start on Windows

With the .NET 8 SDK installed, run these in separate terminals under the same account:

```powershell
dotnet run -c Release --project src/WatchLattice.Hub
dotnet run -c Release --project src/WatchLattice.Tray
```

Publish each application to its own directory:

```powershell
dotnet publish src/WatchLattice.Hub -c Release -r win-x64 --self-contained false -o C:\WatchLattice\Hub
dotnet publish src/WatchLattice.Tray -c Release -r win-x64 --self-contained false -o C:\WatchLattice\Tray
& C:\WatchLattice\Tray\ScanAlways.Tray.exe
```

The published tray requires the **.NET 8 Desktop Runtime**; the hub requires the
.NET 8 Runtime. The SDK includes these on Windows. Install the hub as documented
in the root README, using the executable's actual published path. Do not install
the tray as a service. To start it at login, optionally create a shortcut to the
tray executable in your own `shell:startup` folder. An autostart shortcut is
visible to the Persistence auditor like any other startup change.

## Feed configuration

The hub's `Alerts` settings:

| Setting | Default | Meaning |
|---|---|---|
| `Enabled` | `true` | Write the shared feed. Turning it off does not disable existing module logs. |
| `FeedPath` | `null` | `%LOCALAPPDATA%\ScanAlways\alerts.json`, under the hub's account. |
| `HistoryLimit` | `200` | Recent entries retained, clamped to 1–1000. |
| `DailySummary` | on, 8:00 | Once a day, an Info alert summarizing the last 24 hours. See [the daily summary](dashboard.md#the-daily-summary). |

The hub checks for changes every two seconds and atomically replaces the JSON
snapshot when alerts or module states change. A small `alerts.json.heartbeat.json`
sidecar is refreshed every two seconds, so idle monitoring does not repeatedly
write the whole history. Keep both files in the same directory. History is restored after restart;
module states belong to the new session. Clean shutdown marks the feed offline.
The tray considers a heartbeat older than 20 seconds stale. Its feed path can
be overridden independently:

```powershell
& C:\WatchLattice\Tray\ScanAlways.Tray.exe --feed 'C:\ProgramData\WatchLattice\Alerts\alerts.json'
```

Run only one hub writer per feed and baseline path. Multiple companions can
read the feed, but each Windows session permits one tray instance per path.
There is no network listener and no tray-to-service control channel. The tray
renders alert text only; it does not execute paths or commands found in alerts.
The things it can open are an update's release page, only when it is an
https link on github.com, the hub's own updater (see below), and its own
elevated settings editor ([the dashboard](dashboard.md#changing-settings-needs-an-administrator)).
It finds the hub next to its own folder, never through the feed.

## LocalSystem service with a user tray

The [installer](installing.md) in each release sets all of this up for you:
the feed folder, its permissions, the feed path in the hub's settings and the
tray's `--feed` argument. The steps below are for a manual setup.

The simplest setup uses the same account for the hub and tray. If the hub runs
as LocalSystem, its default LocalAppData is not the signed-in user's directory.
Use an explicit feed directory and grant that user **read**, not write, access.
For a **new dedicated directory**, an administrator can provision it as follows
(replace `COMPUTER\you` with the intended tray account):

```powershell
$feedDirectory = 'C:\ProgramData\WatchLattice\Alerts'
New-Item -ItemType Directory -Path $feedDirectory -ErrorAction Stop
icacls.exe $feedDirectory /inheritance:r
icacls.exe $feedDirectory /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 'COMPUTER\you:(OI)(CI)RX'
```

Set the service's configuration to:

```json
"Alerts": {
  "Enabled": true,
  "FeedPath": "C:\\ProgramData\\WatchLattice\\Alerts\\alerts.json",
  "HistoryLimit": 200
}
```

Restart the hub and launch the tray with `--feed` pointing to that file. Keep
the persistence baseline private to the hub's account; the tray does not need
to read it. For a different service account, grant that account modify access
to this dedicated feed directory instead. The source directories remain
read-only to the auditor; it only writes its own baseline and shared feed.

## Updates

When the hub's update checker finds a newer release, the tray shows one
notification for that version, an **Update available** entry in its menu, and a
banner at the top of the dashboard with **Install update** and **Release
notes**. Nothing is downloaded until you choose Install update. The tray then
asks for confirmation and starts `..\Hub\ScanAlways.Protection.Service.exe
--apply-update` through Windows' administrator prompt. The updater re-checks
GitHub itself, verifies the SHA-256 checksum, stops and restarts the service,
and the tray restarts on the new version. Declining the prompt changes nothing.
If the tray is not installed next to the hub, the banner still appears and
explains how to run the update from the hub's folder. See the
[updater README](../src/WatchLattice.Updater/README.md) for every step and its limits.

## Delivery behavior and limitations

- Opening the tray displays existing history without replaying old balloons.
  New warnings and critical alerts are notified once while the tray runs.
  Multiple alerts in one poll are summarized in one balloon; all retained
  events remain available in the window. Information/recovery events do not
  produce balloons. Identical events within five seconds are coalesced.
- Windows notification settings and Do Not Disturb can suppress balloons.
  The alert window remains the way to review retained events.
- The feed is bounded recent history, not a durable audit archive. A crash
  before the next write can lose the newest events, and old events roll out.
  The original module and service logs remain available.
- Feed I/O failures are logged and retried without stopping monitoring. The
  companion shows unavailable/stale status when it cannot read a current feed.
  Running module state means its execution loop is active; review its alerts
  for coverage failures or protection problems.
- Feed text may contain file paths and command arguments. Grant access only
  to the intended user. The feed is not authenticated or tamper-proof against
  someone who can write its directory. The hub never grants broad permissions
  automatically.
- The tray is Windows-only. It can be cross-compiled on Linux, while its actual
  UI, Windows notifications, and service-account permissions require Windows
  validation.

## Manual Windows smoke check

1. Start the hub and tray with matching feed paths. Confirm four module states
   appear and the feed is connected.
2. In a temporary folder configured as `Persistence:StartupFolders`, add an
   inert text file after the first inventory. With `CheckIntervalSeconds=30`,
   confirm an addition warning and tray balloon; change it and confirm the
   previous/current hashes. Remove it and confirm an information event. Use a
   temporary baseline path for this exercise; no real autostart registration
   is needed.
3. Restart the tray: history should be visible without replayed balloons.
4. Stop the hub: the tray should show offline. Start it again: history should
   remain and new changes should still notify.
5. Repeat with the service account and dedicated feed directory if deploying
   as a service. Do not disable Defender to test notifications.
