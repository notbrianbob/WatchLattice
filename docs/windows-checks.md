# What to check by hand on Windows

CI builds and tests everything on a Windows runner and installs a
release-shaped package, but the dashboard windows, real Windows settings
changes and a real update can only be checked on a Windows 11 PC. This is
one list of those checks for the features added in 0.5.0 and 0.6.0, in an
order that works on one machine. Each step links to the detailed version.

Use a PC you can undo changes on. Every step below changes something
harmless and puts it back; none of them weakens Defender or touches a real
update host.

## Before you start

1. Install 0.4.0 (or keep the copy you have), then install 0.5.0 from the
   tray's **Install update**. Without exiting the tray yourself, its icon
   disappears and comes back within about 30 seconds: the tray restarts
   itself when an update replaced its files (#25). If you install the update
   from the dashboard of a second signed-in user, or with `--apply-update`,
   the first user's tray restarts the same way.
2. Do the [0.5.0 checks](#050), then update to 0.6.0 the same way and do the
   [0.6.0 checks](#060).

## 0.5.0

1. **Update check after boot** (#24). Restart the PC with the network
   unplugged and plug it in after a few minutes. The Application event log
   shows the hub's failed update checks about 1, 2 and 4 minutes apart, and
   the next one after the network is back succeeds, rather than the hub
   waiting 12 hours. See the
   [Updater README](../src/WatchLattice.Updater/README.md).
2. **Grouped alerts, acknowledge and dismiss** (#27). Follow step 7 of
   [the dashboard checks](dashboard.md#what-needs-checking-on-windows).
3. **Install integrity check** (#28). From the hub's install folder, run
   `.\ScanAlways.Protection.Service.exe --verify-install`: it exits with `0`
   and reports every file as matching. From an elevated prompt, create an
   empty `Hub\test.dll`, run it again: it names the unexpected file and exits
   with `1`; within an hour the dashboard shows an `INSTALL_MODIFIED` alert
   and Event Viewer has event 7001. Delete `test.dll`. See
   [checking by hand](install-integrity.md#checking-by-hand).
4. **Release notes** (#29). The 0.5.0 release page on GitHub starts with the
   0.5.0 section of [CHANGELOG.md](../CHANGELOG.md), with working links.

## 0.6.0

1. **Hosts file and proxy watchdog** (#30). The first check after the
   update records a baseline (event 8007) and raises nothing else. Then
   follow [Run](../src/WatchLattice.HostsProxyWatchdog/README.md#run) in its
   README: a test hosts line for `watchlattice-test.invalid` gives a
   `HOSTS_CHANGED` warning (8004) within a minute, and turning on a proxy at
   `127.0.0.1:9` gives `PROXY_CHANGED` (8006). Undo both: the removals show
   as Info.
2. **Services in the persistence auditor** (#31). The first inventory after
   the update is an informational baseline, with no warnings for services
   that were already there. From an elevated prompt, add a service that is
   never started:

   ```powershell
   sc.exe create WatchLatticeTest binPath= "C:\Windows\System32\notepad.exe" start= auto
   ```

   Within five minutes there is an `ENTRY_ADDED` warning (5002) and a
   verification result. Then point it at a user-writable folder:

   ```powershell
   sc.exe config WatchLatticeTest binPath= "C:\ProgramData\WatchLatticeTest\none.exe"
   ```

   The next check raises a **critical** *service runs from a user-writable
   folder* alert. Remove it with `sc.exe delete WatchLatticeTest` (before
   restarting the PC) and the removal shows as Info. After the next Defender
   platform update, the moved Defender service shows as Info, *service
   updated in place*, not a warning. See
   [Coverage](../src/WatchLattice.Persistence/README.md#coverage) and
   [how alerts are graded](../src/WatchLattice.Persistence/README.md#how-alerts-are-graded).
3. **WMI event subscriptions** (#31). The baseline lists the subscriptions
   Windows ships (such as *SCM Event Log Filter*) as Info. From an elevated
   PowerShell, add an event filter with no consumer, which on its own runs
   nothing:

   ```powershell
   New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property @{
       Name = 'WatchLatticeTest'; EventNamespace = 'root/cimv2'; QueryLanguage = 'WQL'
       Query = "SELECT * FROM __InstanceCreationEvent WITHIN 3600 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'watchlattice-test.invalid'"
   }
   ```

   Within five minutes there is a **critical** *WMI event subscription* alert
   for `Filter/WatchLatticeTest`. Remove it:

   ```powershell
   Get-CimInstance -Namespace root/subscription -ClassName __EventFilter -Filter "Name='WatchLatticeTest'" | Remove-CimInstance
   ```

4. **Alert export** (#32). Follow step 8 of
   [the dashboard checks](dashboard.md#what-needs-checking-on-windows). From
   the hub folder, `.\ScanAlways.Protection.Service.exe --export-alerts
   $env:TEMP\alerts.json --format json --group` writes the same rows as the
   dashboard with **Group repeats** on. See
   [exporting alerts](dashboard.md#exporting-alerts).
5. **Daily summary** (#32). Follow step 9 of
   [the dashboard checks](dashboard.md#what-needs-checking-on-windows): the
   Overview shows the latest summary, and Event Viewer has event 1007.

## Already covered

Steps 1 to 6 of [the dashboard checks](dashboard.md#what-needs-checking-on-windows)
are from 0.4.0. Repeat them if the dashboard or settings editor changed in
the release you are checking.
