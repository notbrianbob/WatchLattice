# Changelog

All notable changes to WatchLattice are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the version is below 1.0,
a minor version can change behavior or settings.

The release workflow uses the section matching a tag as that GitHub release's
notes, followed by GitHub's generated list of pull requests. See
[cutting a release](docs/releasing.md).

## [Unreleased]

## [0.11.0] - 2026-11-27

### Security

- **.NET libraries updated to 10.0.15.** The `Microsoft.Extensions.*`
  packages and `System.Diagnostics.EventLog` the hub ships move from
  10.0.13 to Microsoft's current servicing release, with the lock files
  updated to match.

- **NuGet packages are pinned by content hash.** Every project now has a
  lock file with the exact version and hash of each package it uses, direct
  or transitive, and CI and the release build restore only what those files
  list. A package that differs from the reviewed one fails the build. See
  [supply chain](docs/supply-chain.md#nuget-packages). Nothing changes in
  the installed program: the package versions are the same as before.

- **Fuzz tests for everything the hub reads that someone else can write.**
  A new test project gives browser profiles, the hosts file and proxy
  settings, autostart entries, command lines, update metadata, settings,
  approvals and exports about 200,000 generated inputs on every pull
  request, and many more every night with a new random seed. Each reader
  must read its input or refuse it the way its caller expects. See
  [fuzz tests](docs/fuzzing.md), which also lists everything below. None of
  these defects was seen being used, and none let anyone run code or gain
  rights.
- **Browser profiles and extensions on another computer are no longer
  opened.** A Chromium extension's folder or a Firefox profile could be set
  to a network path, and the hub, as LocalSystem, would have contacted that
  server. Such paths are now reported and left alone.
- **A file the hub can't read no longer stops a module.** An extension named
  `__MSG__` or a browser profile with a broken escape stopped the extension
  scan for every browser and user. A service or task whose program is one
  character stopped the persistence auditor each time it restarted. Task
  definitions nested thousands of levels deep kept a CPU core busy for
  minutes and are now refused beyond 64 levels.
- **Services in user-writable folders are graded that way however the path
  is spelled**, including `x.exe. -k …` and a quoted `\SystemRoot\…`.
- **Hosts entries written with another kind of dot or an invisible
  character** now match the watched domain.
- **More secrets hidden.** The command line redactor now hides a value that
  is only partly quoted (`password=""secret`) or whose quote is never
  closed, and can no longer be slowed down by a very long URL. *Export all
  data* no longer leaves half a user name where a long line was clipped, or
  a whole one after an escape such as `\t` in a setting.
- **Stricter checks on text from outside.** Approval tokens, extension IDs
  and *Open file location* paths are refused when they end in a line break
  or contain control characters. The updater refuses a download address
  whose path contains a step up written as an escape (`..%5C`), which
  passed its "this repository's releases only" check before.

### Fixed

- An approval for an autostart entry whose name ends in a space, or contains
  half of a surrogate pair, now matches its entry instead of being asked for
  again.
- The settings editor refuses a file in which one setting is written twice
  (also when the two differ only by case), and names the setting, instead of
  failing part of the way through its checks.
- The update check reports release metadata, checksums, version text and
  `runtimeconfig.json` files it can't read as unreadable, where some shapes
  raised an unexpected error.
- Two autostart entries whose names differ only by case (possible in a
  Startup folder made case-sensitive) are compared as one entry instead of
  making the stored inventory look damaged.
- Defender and firewall status that contains text that is not valid Unicode,
  or a date outside the calendar, is reported as unavailable instead of
  raising an error.

### Added

- **Draft answers for the [OpenSSF Best Practices badge](docs/openssf-best-practices.md)**,
  with what is met, what is not met yet and why.

- **Export all data for an AI review.** The dashboard's Overview tab has
  **Export all data for AI review…**, and the hub has
  `--export-all <path or -> [--keep-names]`. Both write one Markdown file to
  upload or paste into Claude, ChatGPT or another assistant: a short brief
  telling the model what WatchLattice is and what to check, then the
  version, module health, Defender's state, the security checkup, install
  integrity, settings, alerts with their guidance, and recent hub activity.
  Your user name, computer name and e-mail addresses are hidden unless you
  untick the box, and settings that look like secrets are always hidden.
  Read-only, no administrator rights, and nothing is sent anywhere. See
  [the dashboard](docs/dashboard.md#export-all-data-for-an-ai-review).

## [0.10.0] - 2026-11-17

### Security

- **Software bill of materials.** Each release now includes
  `WatchLattice-<version>-sbom.cdx.json` (CycloneDX). It lists every NuGet
  package the hub and tray ship and the .NET runtime bundled with them,
  and the build provenance attestation covers it. See
  [supply chain](docs/supply-chain.md).
- **GitHub Actions pinned to commits.** Every action in every workflow is
  pinned to a full commit SHA, with the version in a comment, so a moved tag
  can't change what a build runs. Dependabot keeps the pins current.
- **OpenSSF Scorecard.** A weekly Scorecard run publishes the repository's
  score (shown as a README badge) and lists each finding in code scanning.

- **Canary files can no longer be redirected.** The hub runs as LocalSystem
  and plants canaries in folders the user owns. Before this change, a user
  who replaced a canary folder with a junction, or a canary with a link,
  could make the hub overwrite or delete a file anywhere, such as in System32:
  a local privilege escalation. Canaries are now written and deleted through
  a handle whose real path and link count are checked first. A folder that
  turns out to be a junction is left alone, with a warning in the log.
  If you moved Documents, Desktop or Pictures with `mklink /J`, set the
  canary folders to the real paths.
- **Likely passwords and tokens are hidden in script host alerts.** Command
  lines copied into alerts, which every user can read in the Application
  log, now show values such as `-Password x`, `token=x` or
  `https://user:pass@host` as `[hidden]`. Approvals still match the exact
  command line.
- **No startup hooks.** The hub and tray ignore `DOTNET_STARTUP_HOOKS`, so
  the environment can't load code into the service or the elevated settings
  editor.
- **[Threat model](docs/threat-model.md) of WatchLattice itself.** It
  applies STRIDE at each trust boundary and marks every threat as mitigated,
  fixed or accepted, with the reason.

### Added

- **Security checkup.** A new **Checkup** tab in the dashboard looks at
  twelve Windows settings that make attacks harder, among them Defender's
  real-time and tamper protection, the firewall, User Account Control,
  SmartScreen, Remote Desktop, SMBv1, Secure Boot, memory integrity and LSA
  protection. For each it says what it found, why it matters and where to
  change it. It only reads, with your normal rights. See
  [the security checkup](docs/dashboard.md#the-security-checkup).

- **The tray icon shows what needs attention.** A green, amber, red or grey
  shield, each with its own mark (tick, dot, exclamation mark, dash), replaces
  the fixed icon, and the tooltip says what to look at, such as *1 critical
  alert to review*. Acknowledging in the dashboard turns it green again. See
  [the tray icon](docs/alerts-and-tray.md#the-tray-icon-critical-alerts-and-the-welcome).
- **A window for critical alerts.** A critical alert opens a window over
  other windows, with its guidance, safe actions and Acknowledge, instead of
  a balloon that Focus assist can hide. It doesn't take the keyboard focus.
  It can be turned off from the tray menu.
- **First-run welcome.** The first start explains what WatchLattice watches,
  what each icon means and which modules are running. **About
  WatchLattice…** in the tray menu shows it again.

- **What an alert means and what to do.** Every alert's details in the
  dashboard now start with a plain-language *What this means* and *What to
  do*, written for each alert type, and buttons that open the Windows
  screen that helps: Windows Security, virus protection settings (for
  exclusions), firewall settings, startup apps, Task Scheduler, Services,
  proxy settings, Event Viewer, the canary file's location in Explorer, and
  a Defender quick scan (asks first). The buttons only open screens; none
  changes a setting or touches a file, and alert text never reaches a
  command line except a validated local path for Explorer to highlight. See
  [the dashboard](docs/dashboard.md#what-an-alert-means-and-what-to-do).
  Event Log entries end with the same advice; the data strings are
  unchanged.
- **MITRE ATT&CK IDs on alerts.** Alerts that are evidence of an adversary
  technique now name it (Enterprise ATT&CK v20.1), for example T1547.001
  for a new Run key value or T1685 for a Defender exclusion. The dashboard's
  alert details show it, Event Log entries carry the IDs as a new tenth data
  string and a line in their text, and exports have a new `AttackTechniques`
  column. [ATT&CK coverage](docs/attack-coverage.md) lists every mapping,
  says which are direct evidence and which only related, and lists the
  techniques WatchLattice does not watch. Event IDs and the existing data
  strings are unchanged.
- **Detection checks** ([demos/detection-checks.md](demos/detection-checks.md)):
  a harness that makes one harmless, self-reverting change of each kind the
  modules watch for (14 checks), runs the real module code and records
  whether it raised the expected alert. CI runs every check on a fresh
  Windows runner, and the results are in
  [demos/RESULTS.md](demos/RESULTS.md#detection-checks). Not part of the
  release download.

## [0.9.0] - 2026-11-16

### Changed

- **.NET 10, with the runtime included.** WatchLattice now targets .NET 10
  (LTS) instead of .NET 8, which left Microsoft support on 10 November 2026.
  The hub and the tray are published *self-contained*: the zip and the MSI
  carry the .NET 10 runtime, so nothing needs installing first, and the
  installers, the MSI and the winget manifest no longer ask for the .NET 8
  Desktop Runtime. Downloads grow from a few MB to about 85 MB. .NET
  security fixes now arrive with WatchLattice releases rather than through
  Windows Update. CI and the release workflow fail if a package is ever
  framework-dependent again, because updaters up to 0.8.0 cannot check for
  a missing runtime. (#44)
- **Upgrading from 0.8.0:** use **Install update** in the tray, or run the
  new MSI over an MSI install. Nothing to install first; settings,
  baselines and alert history are kept. You can uninstall the .NET 8
  Desktop Runtime afterwards if nothing else on the PC uses it.
- Release provenance attestations use `actions/attest-build-provenance`
  v4 (#35). `gh attestation verify` works as before.
- Dependabot no longer proposes major-version bumps for the
  Microsoft.Extensions packages, so they stay on the .NET 10 (LTS) line.

### Added

- **Signed-in users' Run keys and Startup folders.** The autostart auditor
  now reads `Run` and `RunOnce` in the hive of every signed-in user
  (`HKEY_USERS\<SID>`) and each signed-in user's Startup folder. Until now,
  under the LocalSystem service it only read the system account's HKCU and
  Startup folder, so entries added to *your* Run key or Startup folder were
  missed. Each user's existing entries become their baseline on first sight
  (Info, not a warning). Signed-out users are not reported as removed;
  anything that changed while they were away is reported when they sign in.
  Source IDs, Event IDs and settings are unchanged. (#45)
- **Runtime check in the updater**: before changing any file,
  `--apply-update` reads the new release's `runtimeconfig.json` files and
  refuses a release that needs a .NET runtime this PC doesn't have, naming
  the `winget install` command for it, instead of installing a hub that
  cannot start. Self-contained releases need nothing and pass. (#44)

## [0.8.0] - 2026-10-18

### Added

- **Browser extension watchdog** (`BrowserExtensionWatchdog` module, on by
  default): every five minutes it inventories the extensions in every Edge,
  Chrome and Firefox profile of every user on the PC (from each profile's
  `Preferences`, `Secure Preferences` and `extensions.json`), and the
  policies and registry entries that install extensions from outside the
  browser (`ExtensionInstallForcelist`, `ExtensionSettings`, Firefox
  `Extensions\Install`, and the `Software\...\Extensions` registrations
  other programs write). The first check records a baseline; after that each
  extension added is a warning naming its ID, name, version, browser, profile
  and user, how it was installed (store, policy, another program, unpacked)
  and whether by policy, and each policy added is a warning too. Removals,
  new profiles and deleted profiles are Info. Read-only; it never disables or
  removes an extension. New Event IDs 10001 to 10015. See its
  [README](src/WatchLattice.BrowserExtensionWatchdog/README.md). (#39)
- **Approve as baseline** on the dashboard's Alerts tab: select an
  *Autostart entry added* or *changed* alert (or the verification alert that
  follows it) and approve the entry exactly as it is now, so it raises no
  alert when it comes back with that value, for example after an app removed
  and re-added its Run value, or a task flipped back to a known setting. Any
  other value still alerts. For a *New browser extension* alert it adds the
  extension's ID to `IgnoredExtensionIds`. Approvals are stored in the hub's
  `appsettings.json` (new `Persistence:ApprovedEntries`, one
  `sha256:<hash> <source>/<entry>` line each), so approving goes through the
  administrator prompt and the settings editor, keeps a settings backup and
  restarts the hub; approved alerts are marked acknowledged, and an approval
  is revoked by removing its line in Settings. `ENTRY_ADDED` and
  `ENTRY_CHANGED` messages now end with a `Fingerprint: sha256:<hash>` line
  for this. Event IDs are unchanged and approving raises no new events. See
  [approving entries](src/WatchLattice.Persistence/README.md#approving-entries-as-known-good).
  (#40)
- **Script host audit** (`ScriptHostAudit` module, **off by default**): reads
  Security log event 4688 every 30 seconds and reports launches of
  PowerShell, mshta, wscript, cscript, rundll32, regsvr32, certutil,
  bitsadmin and similar programs, with the parent program, user, elevation,
  command line and why it was reported. A launch is a warning when an Office
  app, a browser, a PDF reader or another script host started it, when its
  command line uses an encoded PowerShell command, a hidden window, a
  download, `Invoke-Expression`, `javascript:` or a known abuse of the
  program (such as `certutil -urlcache` or `regsvr32 scrobj.dll`), or when a
  Windows program runs from outside the Windows folder; critical when a
  suspicious parent combines with another reason. Ordinary launches are not
  reported unless `MinimumSeverity` is `Info`. It only works when Windows
  process creation auditing is already on, and never turns it on: when it is
  off the dashboard shows one informational alert saying so, with the
  `auditpol` command in the README. Known-good launches are allowed with
  `AllowedLaunches` wildcard rules or with **Approve as baseline** (new
  `ScriptHostAudit:ApprovedLaunches`, the exact parent, program and command
  line). A cleared or overwritten Security log is reported. Read-only; it
  never blocks or stops a process. New Event IDs 11001 to 11009. See its
  [README](src/WatchLattice.ScriptHostAudit/README.md). (#41)
- [What to check by hand on Windows](docs/windows-checks.md) now has the
  0.8.0 checks: upgrading the 0.7.0 MSI, then the browser extension
  watchdog, approving entries as baseline and the script host audit.

### Changed

- **Upgrading from 0.7.0:** run the 0.8.0 MSI over an MSI install, or use
  **Install update** in the tray on either kind of install. Your
  `appsettings.json` is kept; the browser extension watchdog starts on its
  own (its first check records a baseline and raises nothing else), and the
  script host audit stays off until you turn it on. Existing baselines and
  alert history are unchanged.

## [0.7.0] - 2026-10-18

### Added

- **MSI installer**: each release also ships
  `WatchLattice-<version>-win-x64.msi`, built from the same files as the zip.
  It sets up what Install.cmd does (the `ScanAlways Protection` service, the
  alert feed folder and its permissions, the event log source, the tray at
  sign-in and the Start menu shortcut) with the first-run defaults, takes
  `TRAYUSER`, `CANARYFOLDERS`, `DECOY`, `UPDATECHECK` and `TRAYAUTOSTART`
  for unattended installs, upgrades in place keeping `appsettings.json`, and
  uninstalls from Settings > Apps as completely as `uninstall.ps1`. The zip,
  Install.cmd and the in-hub updater are unchanged, and `SHA256SUMS.txt`
  now lists both files. CI installs, upgrades and uninstalls it on every
  pull request. See [the MSI](docs/installing.md#the-msi). (#36)
- **winget manifests**: each release also carries
  `WatchLattice-<version>-winget.zip`, manifests for publishing the MSI to
  winget as `notbrianbob.WatchLattice` (templates in `packaging/winget`),
  rendered with the release's MSI URL, SHA-256 and ProductCode, depending on
  the .NET 8 Desktop Runtime, and checked with `winget validate`. CI renders
  and validates them for a test MSI on every pull request. Nothing is
  submitted to winget automatically; see
  [publishing to winget](docs/releasing.md#publishing-to-winget). (#37)
- [What to check by hand on Windows](docs/windows-checks.md) now has the
  0.7.0 checks: updating from 0.6.0, then installing, reinstalling and
  uninstalling the MSI and trying the winget manifests.

### Changed

- **Dependencies**: Microsoft.Extensions.* and System.Diagnostics.EventLog
  10.0.13 (from 8.0.x), plus System.Threading.AccessControl 10.0.13, which
  EventLog 10 needs on .NET 8 but does not pull in. Microsoft.NET.Test.Sdk 18.11.0 and
  xunit.runner.visualstudio 4.0.1. All of them ship .NET 8 builds, so
  WatchLattice still targets and runs on the .NET 8 runtime; the installer's
  requirement is unchanged. The alert feed now restores its history and
  writes its first snapshot before the modules start, which Hosting 10 no
  longer did on its own. (#34)
- **Upgrading from 0.6.0:** **Install update** in the tray updates a zip
  install as before. To move to the MSI, uninstall first; the MSI refuses to
  install over an Install.cmd install (and the other way round). Nothing
  needs reconfiguring and no new baselines are recorded.

### Fixed

- **Alert feed**: a hub stopped right after it started could leave the feed
  marked online until it went stale, because Hosting 10 may never run the
  delivery loop whose clean-up marked it offline. The feed is now marked
  offline when the service stops. (#36)
- **State files**: writing the alert feed or another state file retries a
  replace that Windows briefly refuses while a reader or a scan has the
  file open, instead of skipping that write. (#36)

## [0.6.0] - 2026-10-18

### Added

- **Hosts file and proxy watchdog** (`HostsProxyWatchdog` module, on by
  default): every minute it reads the hosts file Windows actually uses
  (following Tcpip's `DataBasePath`) and the proxy settings in WinINET (each
  signed-in user and the machine, including policies and the binary
  connection settings), WinHTTP, and `HTTP_PROXY`-style environment
  variables. The first check records a baseline; after that every change is
  reported with before and after. Hosts entries that block or redirect
  Windows Update, Defender, SmartScreen or WatchLattice's update hosts are a
  standing critical alert, and a hosts file moved to another folder is a
  warning. Read-only; it never edits the hosts file or resets a proxy. New
  Event IDs 8001 to 8009. See its
  [README](src/WatchLattice.HostsProxyWatchdog/README.md). (#30)
- **Services and WMI subscriptions in the persistence auditor**: the
  `Persistence` module now also inventories auto-start Windows services
  (program or service DLL, account, failure command; settings
  `WatchServices`) and permanent WMI event subscriptions in
  `root\subscription` (filters, consumers and bindings; setting
  `WatchWmiSubscriptions`). Both are on by default and start with an
  informational baseline. A new or changed WMI subscription, or a service
  that runs from a user-writable folder, is a critical alert. New and changed
  services are verified automatically like scheduled tasks (file location,
  signature, publisher, privilege changes), and a service whose program only
  moved to a new version folder inside Windows or Program Files (Defender
  platform updates, for example) is informational when verification follows.
  Read-only; existing Event IDs are reused. See the
  [Persistence README](src/WatchLattice.Persistence/README.md#coverage). (#31)
- **Alert export**: **Export…** on the dashboard's Alerts tab saves the list
  as shown (grouped or not, with or without dismissed rows) to CSV or JSON,
  and `--export-alerts <path> [--format csv|json] [--group]` does the same
  from the command line for scripts. CSV cells that a spreadsheet would run as
  a formula are prefixed with `'`. See
  [exporting alerts](docs/dashboard.md#exporting-alerts). (#32)
- **Daily summary**: once a day (8:00 local by default) the hub raises one
  Info alert counting the last 24 hours' alerts per module and severity, with
  the most repeated ones; the dashboard's Overview shows the latest. A
  summary missed while the PC was off is written soon after the hub starts.
  New settings section `Alerts:DailySummary` and Event ID 1007. Nothing
  leaves the PC. See [the daily summary](docs/dashboard.md#the-daily-summary).
  (#32)
- [What to check by hand on Windows](docs/windows-checks.md): one list of the
  manual checks for the 0.5.0 and 0.6.0 features.

### Changed

- **Upgrading from 0.5.0:** the first check after the update records new
  baselines for the hosts file and proxy settings, services and WMI
  subscriptions as Info alerts, without warnings for what was already there.

## [0.5.0] - 2026-10-18

### Added

- **Install integrity check** (`InstallIntegrity` module): every hour the hub
  re-hashes its own `Hub/` and `Tray/` files against
  `Hub/WatchLattice.files.sha256`, a per-file manifest that releases now
  ship, and alerts when a listed file is changed or missing or an unexpected
  `.exe` or `.dll` appears. Problems are re-checked after 30 seconds before
  alerting, and a manifest from a different release (an update waiting for a
  restart) is skipped. Read-only; it never repairs anything. New Event IDs
  7001 and 7002; `--verify-install` runs one check by hand. See
  [install integrity check](docs/install-integrity.md). (#28)
- **Grouped alerts with acknowledge and dismiss** in the dashboard: repeats of
  one alert (same module, code and resource) show as one row with a count,
  first and last seen, and the highest severity. Review state is kept per user
  in `%LOCALAPPDATA%\ScanAlways\alert-review.json`, and a new repeat makes a
  row new again. The alert feed, Event Log and event IDs are unchanged. (#27)
- `CHANGELOG.md`, used as the release notes for each tagged version.

### Changed

- After a failed update check (for example, no network yet at boot) the hub
  retries after 1, 2, 4 minutes and so on, up to the normal 12-hour interval,
  instead of waiting the full 12 hours. (#24)
- Build and test tooling updated: `actions/checkout` v7, `actions/setup-dotnet`
  v6, `actions/upload-artifact` v7, xunit 2.9.3, Microsoft.NET.Test.Sdk
  17.14.1 and xunit.runner.visualstudio 3.1.5. Shipped runtime packages are
  unchanged. (#26)

### Fixed

- The tray now restarts itself when an update replaced its files. Before,
  an update installed from anywhere other than that tray left the old tray
  running until it was exited by hand. (#25)

## [0.4.0] - 2026-10-17

### Added

- **Dashboard** in the tray with Overview, Alerts, Activity and Settings tabs,
  plus an administrator-only settings editor that validates each save, keeps
  a backup and rolls back if the hub does not keep running. (#19)
- **Persistence verification**: changed scheduled tasks behind a persistence
  alert are checked automatically (current definition, COM registration,
  target file signature and hash, trusted baseline). (#20)
- Decoy `MinSweepIntervalSeconds` setting (default 60) so an empty scan root
  cannot make the decoy spin. (#23)

### Changed

- Persistence alerts are graded by what changed: timing-only task changes are
  Info and verified automatically, while a privilege gain is flagged as
  suspicious. Event IDs are unchanged. (#22)

### Fixed

- Timing race in the persistence verification tests. (#21)

## [0.3.0] - 2026-10-17

Same commit as 0.2.0 (`a3d7ba0`). The tag was pushed from a clone that had not
pulled the newer `main`, so this release contains nothing beyond 0.2.0. The
changes meant for it shipped in 0.4.0.

## [0.2.0] - 2026-10-17

### Added

- Defender watchdog reports new Defender exclusions, weakened attack surface
  reduction rules, and cloud-delivered protection turned off or down. (#15)
- Every alert is also written to the Windows Application event log under the
  source `WatchLattice` with a stable event ID per alert type. See
  [Event Log alerts](docs/event-log.md). (#17)
- One-step installer: `Install.cmd` in the release zip installs the hub as a
  service, starts the tray at sign-in, and adds an uninstaller under
  Settings > Apps. See [installing WatchLattice](docs/installing.md). (#18)
- Reproducible demos with measured overhead in [`demos/`](demos/). (#4)
- Release workflow and updater support for Authenticode signing through
  SignPath. Releases stay unsigned until SignPath is set up; see
  [code signing](docs/code-signing.md). (#16)

### Changed

- Renamed from ScanAlways to WatchLattice. The executables, service name and
  data folders keep their old names so installed copies keep updating; see
  [names that must not change](docs/releasing.md#names-that-must-not-change). (#4)

## [0.1.0] - 2026-10-16

First release.

### Added

- The hub: one process (console or Windows service) that runs every tool as a
  module that can be switched on or off in `appsettings.json`. (#2)
- Always-Scanning Decoy. (#1)
- Canary File Watcher and Defender Health Watchdog. (#3)
- Persistence and autostart auditor, shared alert delivery, and the Windows
  tray companion. (#11)
- Firewall Health Watchdog. (#12)
- Update checker with verified, user-approved installs from GitHub Releases.
  (#13, #14)
- CI, CodeQL and repository hygiene. (#2, #10)

[Unreleased]: https://github.com/notbrianbob/WatchLattice/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/notbrianbob/WatchLattice/releases/tag/v0.3.0
[0.2.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/notbrianbob/WatchLattice/releases/tag/v0.1.0
