# What to check by hand on Windows

CI builds and tests everything on a Windows runner and installs a
release-shaped package, but the dashboard windows, real Windows settings
changes and a real update can only be checked on a Windows 11 PC. This is
one list of those checks for the features added in 0.5.0 to 0.8.0, in an
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
   [0.6.0 checks](#060), then update to 0.7.0 the same way and do the
   [0.7.0 checks](#070). The 0.7.0 checks end by moving the PC to the MSI.
   Then update to 0.8.0 and do the [0.8.0 checks](#080).

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

## 0.7.0

1. **Update from 0.6.0 with the new dependencies** (#34). After **Install
   update** to 0.7.0, the dashboard's Overview shows every module running and
   Activity shows the hub's startup lines. From the hub folder,
   `.\ScanAlways.Protection.Service.exe --check-update` prints
   *WatchLattice 0.7.0 is up to date.* The hub still runs on the .NET 8 runtime:
   nothing asks for .NET 10.
2. **Alert feed goes offline when the hub stops** (#36). From an elevated
   prompt, `Stop-Service 'ScanAlways Protection'`: the tray's tooltip changes
   to *WatchLattice: hub offline* within a few seconds, rather than after
   the feed goes stale. `Start-Service 'ScanAlways Protection'` brings it
   back to *hub connected*.
3. **The installers refuse each other** (#36). With the Install.cmd copy
   still installed, double-click `WatchLattice-0.7.0-win-x64.msi`: it stops
   with a message saying WatchLattice was installed with Install.cmd and to
   uninstall that first, and changes nothing.
4. **MSI install** (#36). Uninstall WatchLattice from Settings > Apps, then
   double-click the MSI: the license page, the administrator
   prompt and a progress bar appear, and with **Start the WatchLattice tray
   now** ticked the tray icon shows up after **Finish**, running as you (not
   elevated: Task Manager's *Elevated* column says No). Settings > Apps lists
   WatchLattice 0.7.0. Sign out and back in: the tray starts on its own.
   `--verify-install` from `C:\Program Files\WatchLattice\Hub` exits with
   `0`. See [the MSI](installing.md#the-msi).
5. **MSI uninstall** (#36). Uninstall WatchLattice from Settings > Apps. The
   tray closes, `C:\Program Files\WatchLattice` and
   `C:\ProgramData\WatchLattice` are gone, the canary files in your Desktop,
   Documents and Pictures are gone, and Startup apps in Task Manager no longer
   lists WatchLattice Tray. (Upgrading and reinstalling an MSI while keeping
   `appsettings.json` is covered by CI's `MSI installer` job; on a PC it is
   first possible with the next release's MSI.)
6. **Unattended MSI install** (#36). From an administrator terminal:

   ```powershell
   msiexec /i WatchLattice-0.7.0-win-x64.msi /qn /l*v $env:TEMP\wl-install.log DECOY=0 UPDATECHECK=0
   ```

   No window appears; afterwards the dashboard's Settings tab shows the decoy
   and update checks off, and the log ends with `Installation success or
   error status: 0`.
7. **winget manifests** (#37). Uninstall again, download
   `WatchLattice-0.7.0-winget.zip` from the release and follow step 2 of
   [publishing to winget](releasing.md#publishing-to-winget):
   `winget validate` passes, and `winget install --manifest` downloads the
   release's MSI, checks its hash and installs it like step 4. Leave it
   installed, or uninstall from Settings > Apps. Do not submit anything to
   winget unless you have decided to publish.

## 0.8.0

1. **Browser extension watchdog** (#39). Within five minutes of the update
   the first check records a baseline (event 10001) listing how many Edge,
   Chrome and Firefox profiles and extensions it found, and raises nothing
   else. Check the counts look right for each browser you use.
2. Install any extension you trust from Edge Add-ons (or the Chrome Web
   Store, or addons.mozilla.org). Within five minutes there is a **New
   browser extension** warning (10002) with its name, ID and version, the
   browser, profile and your account, *from the store*, and *Installed by
   policy: no*. Remove the extension: the next check shows
   `EXTENSION_REMOVED` as Info (10004).
3. Add a force-install policy for an extension that doesn't exist, as in
   [Run](../src/WatchLattice.BrowserExtensionWatchdog/README.md#run) in its
   README. The next check raises `POLICY_EXTENSION_ADDED` (10006) for *this
   computer (all users)*, and `edge://policy` lists the entry. Remove it
   (and the key, if you created it): `POLICY_EXTENSION_REMOVED` is Info
   (10008).
4. Create a new Edge or Chrome profile. The next check shows
   `PROFILE_ADDED` as Info (10010) with the extensions it came with, not one
   warning each. Delete the profile: `PROFILE_REMOVED` (10011).
5. In the dashboard's Settings tab, **Browser Extension Watchdog** lists its
   settings with their defaults. Turning `WatchFirefox` off and back on
   shows Firefox's profiles as new (Info) instead of reporting their
   extensions as added.

6. **Approve as baseline** (#40). Add a harmless Run value from an elevated
   prompt: `reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v WLApproveTest /d "C:\Windows\System32\notepad.exe"`.
   Within five minutes there is an *Autostart entry added* warning whose
   details end with `Fingerprint: sha256:…` and a *Baseline* note. Select it
   and choose **Approve as baseline…**: the administrator prompt appears, then
   the editor on the Persistence page with one new **Approved entries** line
   and a *Staged to approve* note. Save. The hub restarts and the alert shows
   *Acknowledged*, with *Approved* in its details.
7. Delete the value (`reg delete … /v WLApproveTest /f`): the next check
   raises `ENTRY_REMOVED` (Info). Add it back exactly as before: no alert, and
   the Activity tab (with *Everything* shown) has a line saying it matched an
   approved entry. Add it again with `/d "C:\Windows\System32\notepad.exe /x" /f`:
   *Autostart entry changed* as usual. Remove the value and its approval line
   in Settings when done.
8. Choose **Approve as baseline…** and decline the prompt: nothing changes and
   the alert stays *New*. Select a `VERIFY_*` alert for a task: the button
   approves the task's entry alert. Select a *New browser extension* alert
   from step 2: the editor stages its ID in **Ignored extension IDs**.

9. **Script host audit** (#__PR__). With the module still off, the dashboard's
   Settings tab lists **Script Host Audit** as off. Turn it on there (or set
   `Modules:ScriptHostAudit:Enabled` to `true`). If process creation auditing
   is off, which is the Windows default, the dashboard shows one
   *Process creation auditing is off* alert as Info (11001) and nothing
   else, and it does not repeat. Nothing in `auditpol /get /category:*`
   changed.
10. Turn auditing on as in
    [Turning on process creation auditing](../src/WatchLattice.ScriptHostAudit/README.md#turning-on-process-creation-auditing)
    in its README (both commands). Within 30 seconds the Info alert clears
    (11501). Run `powershell.exe -NoProfile -Command "Get-Date"`: no alert.
    Run `powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==`:
    within 30 seconds there is a *Suspicious script host launch* warning
    (11005) naming `powershell.exe`, its parent (`powershell.exe` or
    `WindowsTerminal.exe`), your account, the command line and *passes an
    encoded command*. Event Viewer > Windows Logs > Security has the 4688
    event at the record ID it names.
11. Select that alert and choose **Approve as baseline…**: the editor stages
    one **Approved launches** line on the Script Host Audit page. Save. Run
    the same encoded command again from the same kind of window: no alert,
    and the Activity tab says it matched an approved launch. Run it with
    `-NonInteractive` added: it alerts again. Remove the approval line when
    done.
12. Turn command lines off with
    `reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0 /f`
    and run the encoded command again: the alert says *Command line: not
    recorded*, has no *Approve as baseline* option, and a *Command lines are
    not recorded* Info alert (11002) appears. Set it back to `1`.
13. Stop the hub service, run the encoded command, start the service: the
    launch is reported once after the start. Undo auditing with the
    commands at the end of that README section if you don't want it on, and
    the module reports 11001 again.

## Already covered

Steps 1 to 6 of [the dashboard checks](dashboard.md#what-needs-checking-on-windows)
are from 0.4.0. Repeat them if the dashboard or settings editor changed in
the release you are checking.
