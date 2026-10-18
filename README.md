# WatchLattice

[![CI](https://github.com/notbrianbob/WatchLattice/actions/workflows/ci.yml/badge.svg)](https://github.com/notbrianbob/WatchLattice/actions/workflows/ci.yml)
[![CodeQL](https://github.com/notbrianbob/WatchLattice/actions/workflows/codeql.yml/badge.svg)](https://github.com/notbrianbob/WatchLattice/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![.NET 8](https://img.shields.io/badge/.NET-8.0-512BD4)
![Platform: Windows 11](https://img.shields.io/badge/platform-Windows%2011-0078D6)

**Layered defense. Independent tools. Clear signals.**

WatchLattice is an experimental, open-source Windows security toolkit that
complements Microsoft Defender with deception-based defenses, ransomware
tripwires, and continuous security-health monitoring. It is a supplement to a
real anti-malware product, not a replacement for one.

The tools are small and built for Windows 11, and they run **alongside**
Defender, never instead of it. All of them run together inside one lightweight
background service, the **WatchLattice hub**, and each one can be switched on
or off in a single config file.

## Why complement Defender?

Defender is good, and it is everywhere. That ubiquity is also its weak spot:
commodity malware is routinely tested against Defender before it is released,
and many samples check for it specifically. Far fewer are built to anticipate
small, unfamiliar tools.

WatchLattice leans on that gap. Each module adds a cheap, slightly unusual layer
of deception or early warning that a given sample was probably not built to
expect. It is defense in depth: Defender stays your primary engine for
detection and removal, and WatchLattice adds friction and tripwires around it.

## Threat model

**What WatchLattice is meant to help with**

- Commodity malware and ransomware on a single-user Windows 11 machine, running
  with the logged-in user's privileges.
- Samples that change behavior when they think they are being watched (for
  example, staying dormant while a scan appears to be running).
- Early, noisy steps of an attack that a tripwire can catch: touching decoy
  files, or trying to switch protection off.

**Assumptions**

- Microsoft Defender (or another real anti-malware product) is installed, up
  to date, and running. WatchLattice never replaces it.
- The attacker does not already have administrator or SYSTEM rights. An
  attacker with those can stop any user-mode tool, including this one.

**Out of scope**

- Targeted attacks by someone who studies the machine before acting.
- Kernel-mode threats, bootkits, and firmware implants.
- Detecting or removing malware. WatchLattice modules observe, deceive, and
  alert; they do not quarantine or delete anything.

## Tools

| Module | Status | What it does |
|--------|--------|--------------|
| **Always-Scanning Decoy** ([`src/WatchLattice.Decoy`](src/WatchLattice.Decoy/)) | Available | Makes the machine look like an anti-malware scan is permanently running, so malware that hides from scanners stays hidden. Read-only. See its [README](src/WatchLattice.Decoy/README.md). |
| **Canary File Watcher** ([`src/WatchLattice.Canary`](src/WatchLattice.Canary/)) | Available | Plants decoy files in Desktop, Documents and Pictures and alerts the moment anything modifies, renames, or deletes one: an early ransomware tripwire. See its [README](src/WatchLattice.Canary/README.md). |
| **Defender Health Watchdog** ([`src/WatchLattice.DefenderWatchdog`](src/WatchLattice.DefenderWatchdog/)) | Available | Checks every few minutes that Defender's real-time protection, tamper protection and signatures are actually on and current, and alerts when something turns them off. Also reports new Defender exclusions, weakened attack surface reduction rules, and cloud-delivered protection turned off or down. Read-only. See its [README](src/WatchLattice.DefenderWatchdog/README.md). |
| **Firewall Health Watchdog** ([`src/WatchLattice.FirewallWatchdog`](src/WatchLattice.FirewallWatchdog/)) | Available | Reports disabled Windows Firewall profiles, profiles that allow unsolicited inbound traffic by default, and every change to a profile's default inbound action. Optionally (off by default) reports newly introduced inbound allow rules. A separate layer from the Defender watchdog. Read-only. See its [README](src/WatchLattice.FirewallWatchdog/README.md). |
| **Hosts File & Proxy Watchdog** ([`src/WatchLattice.HostsProxyWatchdog`](src/WatchLattice.HostsProxyWatchdog/)) | Available | Records a baseline of the hosts file and the proxy settings Windows and most apps use (WinINET per user and per machine, WinHTTP, and `HTTP_PROXY`-style variables), then reports every change with before and after. Hosts entries that block or redirect Windows Update, Defender or WatchLattice's update hosts are critical. Read-only. See its [README](src/WatchLattice.HostsProxyWatchdog/README.md). |
| **Browser Extension Watchdog** ([`src/WatchLattice.BrowserExtensionWatchdog`](src/WatchLattice.BrowserExtensionWatchdog/)) | Available | Records which extensions are installed in every Edge, Chrome and Firefox profile on the PC, and the policies and registry entries that install extensions from outside the browser, then reports each extension or policy added or removed with its ID, name, browser, profile and how it was installed (store, policy, another program, unpacked). Read-only. See its [README](src/WatchLattice.BrowserExtensionWatchdog/README.md). |
| **Script Host Audit** ([`src/WatchLattice.ScriptHostAudit`](src/WatchLattice.ScriptHostAudit/)) | Available, off by default | Reads Windows process creation events (Security log 4688, when auditing is already on) and reports PowerShell, mshta, wscript, rundll32, regsvr32, certutil and similar launches, graded by their parent (an Office app or browser starting a script host) and command line (encoded commands, hidden windows, downloads). Never changes audit policy; says so once if auditing is off. Read-only. See its [README](src/WatchLattice.ScriptHostAudit/README.md). |
| **Persistence & Autostart Auditor** ([`src/WatchLattice.Persistence`](src/WatchLattice.Persistence/)) | Available | Records a baseline of Run/RunOnce keys, Startup files, visible scheduled tasks, auto-start services and permanent WMI event subscriptions, then reports additions, changes, removals, and gaps in coverage. Changed scheduled tasks and services are verified automatically (current definition, COM registration or service DLL, target file location, signature and hash, trusted baseline). Read-only. See its [README](src/WatchLattice.Persistence/README.md). |

The **Windows tray companion** opens the **dashboard**: hub and module status,
alerts (repeats grouped into one row, with acknowledge and dismiss, and
export to CSV or JSON), a daily summary of the last 24 hours' alerts, the
hub's recent activity, and every setting. Turning a module on or
off or changing a setting opens an elevated settings editor through Windows'
administrator prompt, so only an administrator can change anything; each save
is checked, backed up, and rolled back if the hub does not keep running. See
[the dashboard](docs/dashboard.md) and [alerts and tray setup](docs/alerts-and-tray.md).
Every alert is also written to the Windows **Application** event log under the
source `WatchLattice`, with a stable event ID per alert type, so Event Viewer,
Windows Event Forwarding and SIEM agents can pick it up. See [Event Log alerts](docs/event-log.md).

The **Update Checker** ([`src/WatchLattice.Updater`](src/WatchLattice.Updater/)) runs
in the hub too. It checks this repository's GitHub Releases, tells you in the
tray when a newer version is out, and installs it only when you choose
**Install update**, after verifying the download's SHA-256 checksum. See its
[README](src/WatchLattice.Updater/README.md) and [cutting a release](docs/releasing.md).

The **Install Integrity Check** (`InstallIntegrity`, in the same project) checks
WatchLattice's own installed files every hour against the per-file hashes its
release shipped, and alerts when one is changed, missing, or a program file
appears that the release does not contain. Read-only; it never repairs
anything. See [install integrity check](docs/install-integrity.md).

## How it fits together

```
ScanAlways.Protection.Service.exe  (the hub: one process, console or Windows service)
├── reads appsettings.json
├── discovers the modules it was built with
└── runs every enabled module side by side
    ├── Decoy             ── Modules:Decoy:Enabled
    ├── Canary            ── Modules:Canary:Enabled
    ├── DefenderWatchdog  ── Modules:DefenderWatchdog:Enabled
    ├── FirewallWatchdog  ── Modules:FirewallWatchdog:Enabled
    ├── HostsProxyWatchdog ── Modules:HostsProxyWatchdog:Enabled
    ├── BrowserExtensionWatchdog ── Modules:BrowserExtensionWatchdog:Enabled
    ├── Persistence       ── Modules:Persistence:Enabled
    ├── ScriptHostAudit   ── Modules:ScriptHostAudit:Enabled (off by default)
    ├── InstallIntegrity  ── Modules:InstallIntegrity:Enabled (checks its own files)
    └── Updater           ── Modules:Updater:Enabled (checks only)

ScanAlways.Tray.exe (runs in the signed-in user's session)
├── reads the hub's local alert feed and activity log: notifications and the dashboard
├── Change settings: opens its own settings editor, elevated, which runs --apply-settings
└── Install update: starts the hub's --apply-update, elevated, on request
```

The hub isolates modules from each other: if one fails it is logged and
restarted with back-off, and the rest keep running. Modules are compiled into
the hub; nothing is loaded from a plugins folder at runtime, so there is no
way to drop a DLL next to the service and have it executed.

## Demos and measured results

[`demos/`](demos/) holds reproducible demonstrations of what the modules
actually do, with measured overhead and the method used to measure it: the
decoy's CPU, read I/O and memory at each intensity, a canary being tripped
(with a control file that must not trip it), and the Defender watchdog's
readout for healthy and degraded states. They show signals and costs, not
protection against real malware, which these demos do not test. Latest
numbers: [demos/RESULTS.md](demos/RESULTS.md).

## Quick start

You need Windows 11 and the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
git clone https://github.com/notbrianbob/WatchLattice.git
cd WatchLattice
dotnet build -c Release
dotnet test  -c Release
```

Run the hub in a console window (Ctrl+C to stop):

```bash
dotnet run -c Release --project src/WatchLattice.Hub
```

See which modules are available and whether they are enabled:

```bash
dotnet run -c Release --project src/WatchLattice.Hub -- --list-modules
```

### Install a release

Download the latest [release](https://github.com/notbrianbob/WatchLattice/releases)
zip, extract it, and double-click **Install.cmd**. What changed in each
version is in [CHANGELOG.md](CHANGELOG.md). It installs the hub as a
service, starts the tray at sign-in, asks which folders to protect, and adds
an uninstaller under Settings > Apps. Each release also has an MSI that
installs the same thing with the defaults, for a double-click or unattended
install. See [installing WatchLattice](docs/installing.md).

### Install as a Windows service from source

From an elevated PowerShell:

```powershell
dotnet publish src/WatchLattice.Hub -c Release -r win-x64 --self-contained false -o C:\WatchLattice
sc.exe create "ScanAlways Protection" binPath= "C:\WatchLattice\ScanAlways.Protection.Service.exe" start= auto
sc.exe start "ScanAlways Protection"
```

A service runs as LocalSystem by default, so folders that default to "your"
profile (the decoy's scan roots, the canary's Desktop/Documents/Pictures)
resolve to the system profile instead. Either run the service under your own
account (`obj= ".\you" password= ...`) or list your folders explicitly in
`Decoy:ScanRoots` and `Canary:Folders`.

Persistence's HKCU inventory also follows the service account. Run the hub under
your account to monitor your current-user Run keys. The tray always runs in your
interactive session; a LocalSystem service needs an explicit shared feed path
with read permission for the tray user. See [service and tray setup](docs/alerts-and-tray.md#localsystem-service-with-a-user-tray).

To remove it:

```powershell
sc.exe stop "ScanAlways Protection"
sc.exe delete "ScanAlways Protection"
```

## Configuration

Everything lives in `appsettings.json` next to the executable
([source](src/WatchLattice.Hub/appsettings.json)). On an installed copy, the
easiest way to change it is the dashboard's settings editor
([the dashboard](docs/dashboard.md)). Any value can also be
overridden with an environment variable or a command-line switch, for example
`--Modules:Canary:Enabled=false`.

```jsonc
{
  "Hub": {
    "RestartFailedModules": true,   // restart a module that crashes
    "RestartDelaySeconds": 30,      // first back-off; doubles each time
    "MaxRestartDelaySeconds": 600
  },
  "Modules": {                      // one switch per module
    "Decoy":            { "Enabled": true },
    "Canary":           { "Enabled": true },
    "DefenderWatchdog": { "Enabled": true },
    "FirewallWatchdog": { "Enabled": true },
    "HostsProxyWatchdog": { "Enabled": true },
    "BrowserExtensionWatchdog": { "Enabled": true },
    "Persistence":      { "Enabled": true },
    "ScriptHostAudit":  { "Enabled": false },
    "Updater":          { "Enabled": true },
    "InstallIntegrity": { "Enabled": true }
  },
  // Each module's own settings live in a section named after it; see its README.
  "Decoy": { },
  "Canary": { },
  "DefenderWatchdog": { },
  "FirewallWatchdog": { },
  "HostsProxyWatchdog": { },
  "BrowserExtensionWatchdog": { },
  "Persistence": { },
  "ScriptHostAudit": { },
  "Updater": { },
  "InstallIntegrity": { },
  "Alerts": { "Enabled": true, "FeedPath": null, "HistoryLimit": 200, "EventLog": { "Enabled": true, "MinimumSeverity": "Info" },
              "DailySummary": { "Enabled": true, "Hour": 8, "TopRepeatedAlerts": 5 } }
}
```

## Honest limits

- WatchLattice **does not detect or remove malware**. The canary watcher and
  the Defender, firewall, hosts and proxy, and browser extension watchdogs raise alarms; they do not stop anything. If something is
  already running on your machine, use Defender or another real scanner.
- Deception only works on malware that checks for the signals we emulate. Many
  threats do not check, and those will not be slowed down.
- Every module runs in user mode. An attacker with administrator rights can
  stop the hub.
- A determined human attacker can tell a decoy from a real security product.
  The modules are deliberately shallow so they stay harmless and cheap.

## Repository layout

```
WatchLattice.sln
├── CHANGELOG.md                        # What changed in each release
├── src/
│   ├── WatchLattice.Common/            # Shared library: module contract, hub supervisor, decoy engine, rolling log
│   ├── WatchLattice.Hub/               # The hub executable (console app / Windows service)
│   ├── WatchLattice.Decoy/             # Module: always-scanning decoy
│   ├── WatchLattice.Canary/            # Module: canary file watcher (ransomware tripwire)
│   ├── WatchLattice.DefenderWatchdog/  # Module: Defender health watchdog
│   ├── WatchLattice.FirewallWatchdog/  # Module: Windows Firewall health watchdog
│   ├── WatchLattice.HostsProxyWatchdog/ # Module: hosts file and proxy settings watchdog
│   ├── WatchLattice.BrowserExtensionWatchdog/ # Module: browser extension watchdog
│   ├── WatchLattice.Persistence/       # Module: persistence and autostart auditor
│   ├── WatchLattice.ScriptHostAudit/   # Module: script host launch auditing (opt-in)
│   ├── WatchLattice.Updater/           # Modules + installer: update checks, verified installs, install integrity
│   └── WatchLattice.Tray/              # Windows tray companion and dashboard
├── tests/
│   ├── WatchLattice.Common.Tests/
│   ├── WatchLattice.Decoy.Tests/
│   ├── WatchLattice.Canary.Tests/
│   ├── WatchLattice.DefenderWatchdog.Tests/
│   ├── WatchLattice.FirewallWatchdog.Tests/
│   ├── WatchLattice.HostsProxyWatchdog.Tests/
│   ├── WatchLattice.BrowserExtensionWatchdog.Tests/
│   ├── WatchLattice.Persistence.Tests/
│   ├── WatchLattice.ScriptHostAudit.Tests/
│   ├── WatchLattice.Updater.Tests/
│   └── installer/                    # Install, upgrade and uninstall tests (zip and MSI) run by CI
├── installer/                        # Install.cmd, install.ps1, uninstall.ps1 (shipped in the release zip)
├── packaging/msi/                    # WiX project for the release MSI
├── demos/
│   ├── WatchLattice.Demos/           # Demo and measurement harness (not shipped)
│   ├── scripts/                      # Windows script that observes the real hub process
│   └── RESULTS.md                    # Latest measured results
└── docs/
    ├── adding-a-tool.md              # How to write a new module
    ├── alerts-and-tray.md            # Shared alerts and tray deployment
    ├── code-signing.md               # Signing releases through SignPath
    ├── dashboard.md                  # The dashboard and its settings editor
    ├── event-log.md                  # Alerts in the Windows Event Log, with event IDs
    ├── install-integrity.md          # The hub checking its own installed files
    ├── installing.md                 # Installing a release with Install.cmd or the MSI
    ├── releasing.md                  # Cutting a release the updater can install
    └── windows-checks.md             # What to check by hand on Windows for each release
```

The project was called ScanAlways until v0.1.0. The two executables
(`ScanAlways.Protection.Service.exe`, `ScanAlways.Tray.exe`), the
`ScanAlways Protection` service and the `%LOCALAPPDATA%\ScanAlways` data
folder keep that name on purpose, so installed copies keep updating and keep
their canaries and baselines. See
[names that must not change](docs/releasing.md#names-that-must-not-change).

## Design principles

- **User mode, no kernel drivers.** Nothing here installs a driver or needs
  tricks that only work as SYSTEM.
- **Harmless by construction.** Modules read and observe; they do not modify,
  quarantine, or delete your files (the canary watcher only writes the decoy
  files it creates itself), and they never touch, hook, or impersonate
  Defender's own components.
- **Honest about limits.** Every module's README says plainly what it does and
  what it cannot do.
- **One process, many small tools.** Each tool is its own project and module,
  shared code lives in `WatchLattice.Common`, and the hub runs them all.

## Roadmap

- [x] Always-scanning decoy
- [x] Hub that runs every tool as a module
- [x] Canary (honeypot) file watcher
- [x] Defender health watchdog
- [x] Firewall health watchdog (profiles and inbound default policy)
- [x] Opt-in monitoring of new inbound firewall allow rules
- [x] Persistence and autostart auditor
- [x] Shared alert delivery and Windows tray companion
- [x] Alerts in the Windows Event Log with stable event IDs
- [x] Update checks and verified, user-approved installs from GitHub Releases
- [x] Dashboard with activity, module switches and an administrator-only settings editor
- [x] Grouped repeat alerts with per-user acknowledge and dismiss
- [x] Install integrity self-check against per-file release hashes
- [x] Hosts file and proxy settings watchdog
- [x] Auto-start services and WMI event subscriptions in the persistence auditor
- [x] Alert export (CSV and JSON) and a daily alert summary
- [x] MSI installer for double-click and unattended installs
- [x] Browser extension watchdog (Edge, Chrome, Firefox)
- [x] Script host launch auditing from process creation events (opt-in)
- [ ] winget package (each release carries validated manifests; [submitting them](docs/releasing.md#publishing-to-winget) is a manual step)
- [ ] Code-signed releases (the release workflow and updater are ready; signing starts once the SignPath setup in [docs/code-signing.md](docs/code-signing.md) is done)
- [x] Reproducible demos and measured overhead

## Contributing and security

Contributions are welcome; see [CONTRIBUTING.md](CONTRIBUTING.md) and the
[Code of Conduct](CODE_OF_CONDUCT.md). To add a tool, start with
[docs/adding-a-tool.md](docs/adding-a-tool.md).

Please report vulnerabilities privately as described in
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). WatchLattice is early and experimental; use it as an extra layer
on top of a real, up-to-date anti-malware product.
