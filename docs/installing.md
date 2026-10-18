# Installing WatchLattice

Each [release](https://github.com/notbrianbob/WatchLattice/releases) comes
two ways, which install the same files the same way:

- `WatchLattice-<version>-win-x64.zip`: the hub, the tray companion, and a
  one-step installer (Install.cmd). Its first-run questions are below.
- `WatchLattice-<version>-win-x64.msi`: a Windows Installer package, for a
  double-click install with the defaults or an unattended install from a
  deployment tool. See [the MSI](#the-msi).

Use one or the other on a PC, not both: each refuses to install over the
other. The in-hub updater works the same after either.

## Before you start

WatchLattice needs the **.NET 8 Desktop Runtime (x64)**, which also includes
the .NET 8 Runtime the hub uses. The installer checks for it and stops with
instructions if it is missing. To install it:

```powershell
winget install Microsoft.DotNet.DesktopRuntime.8
```

or download it from <https://dotnet.microsoft.com/download/dotnet/8.0>.

Optionally, check the download before extracting it:

```powershell
$file = 'WatchLattice-0.8.0-win-x64.zip'   # or the .msi
$expected = (Select-String -LiteralPath .\SHA256SUMS.txt -SimpleMatch $file).Line.Split(' ')[0]
(Get-FileHash ".\$file" -Algorithm SHA256).Hash.ToLower() -eq $expected
gh attestation verify ".\$file" --repo notbrianbob/WatchLattice
```

`SHA256SUMS.txt` has one line per file (the zip and, since 0.7.0, the MSI),
so the second line picks the one you downloaded.

## Install

1. Extract the zip anywhere (your Downloads folder is fine).
2. Double-click **Install.cmd** and accept the administrator prompt.
   From a terminal, `.\install.ps1` does the same.
3. Answer the first-run questions, or press Enter for the defaults:
   - **Canary folders.** Defaults to your Desktop, Documents and Pictures
     (wherever they really are, including OneDrive). Type other folders
     separated by `;` to choose your own.
   - **Run the decoy?** Yes by default.
   - **Check GitHub for new releases?** Yes by default. Updates are only
     installed when you choose **Install update** in the tray.
   - **Start the tray when you sign in?** Yes by default.

The installer then:

- copies `Hub\` and `Tray\` to `C:\Program Files\WatchLattice` and makes the
  folder writable only by administrators,
- writes your choices to `Hub\appsettings.json`, spelling out your own folders,
  because the service runs as LocalSystem and its default folders would
  otherwise be the system profile's,
- creates the alert feed folder `C:\ProgramData\WatchLattice\Alerts`, which
  only the hub can write and only you can read,
- installs the `ScanAlways Protection` service (shown as *WatchLattice
  Protection*), set to start automatically and to restart if it crashes,
  and starts it,
- starts the tray at your sign-in (your `Run` key), adds **WatchLattice** to
  the Start menu, and lists WatchLattice under **Settings > Apps**,
- starts the tray now.

Settings for an unattended install:

| Parameter | Meaning |
|---|---|
| `-Quiet` | Accept the defaults (or the values below) without asking. |
| `-CanaryFolders 'C:\a;D:\b'` | Canary folders. |
| `-NoDecoy` | Do not run the decoy. |
| `-NoUpdateCheck` | Do not check for new releases. |
| `-NoTrayAutostart` / `-NoTrayStart` | Do not start the tray at sign-in / at the end of the install. |
| `-TrayUser 'PC\name'` | Whose tray and folders to set up. Defaults to the signed-in user. |
| `-InstallDir` | Install somewhere else. Must be in a folder only administrators can change; the installer refuses anything else. |

The installer scripts are not Authenticode-signed (release signing covers the
binaries; see [code signing](code-signing.md)). If Group Policy enforces an
`AllSigned` execution policy, `-ExecutionPolicy Bypass` in Install.cmd has no
effect and the script will not run.

## Updating

Use **Install update** in the tray (see the [updater](../src/WatchLattice.Updater/README.md)).
Running a newer release's installer over an existing install also works: it
replaces the program files, keeps your `appsettings.json` (writing the
release's copy next to it as `appsettings.json.default`) and keeps your
canaries and baselines. Add `-Reconfigure` to answer the questions again.

The installer uses the names that installed hubs and the updater depend on
(see [names that must not change](releasing.md#names-that-must-not-change)),
so an installed copy updates from the tray like any other.

## Uninstall

Open **Settings > Apps > WatchLattice > Uninstall**, or run
`C:\Program Files\WatchLattice\uninstall.ps1`. It:

- stops the tray and the service,
- deletes the canary files the hub planted that are still unchanged. A
  canary that was changed is kept as evidence and its path is printed; check
  it, then delete it yourself,
- deletes the service, the tray's sign-in entry, the Start menu shortcut and
  the Settings > Apps entry,
- removes the `WatchLattice` Application event log source, if the hub
  registered one (past entries stay in the log),
- deletes the alert feed, the hub's baselines and logs (under the system
  profile's `AppData\Local\ScanAlways` and the system `Temp\ScanAlways`),
  and the install folder.

`-KeepData` keeps the alert feed, baselines and canary manifest, so a later
install carries on from them. `-Quiet` skips the confirmation. The uninstaller
never follows a link or junction out of the folders it deletes.

## Known limits

- The service runs as LocalSystem. The Persistence auditor's current-user
  registry inventory is therefore LocalSystem's, not yours; your Startup
  folder is still watched because the installer lists it explicitly. Run the
  service under your own account (see the [README](../README.md#install-as-a-windows-service-from-source))
  if you need your own `Run` keys watched.
- One tray user per install. Other accounts on the PC can open the tray but
  cannot read the feed; rerun the installer with `-Reconfigure -TrayUser` to
  switch users.
- There is no winget package yet. Each release carries winget manifests for
  the MSI, but they have not been submitted to winget
  ([publishing to winget](releasing.md#publishing-to-winget)).

## The MSI

Double-click `WatchLattice-<version>-win-x64.msi`, accept the license and the
administrator prompt, and leave **Start the WatchLattice tray now** ticked.
It needs the same .NET 8 Desktop Runtime and stops with the same
instructions if it is missing. It sets up exactly what Install.cmd does
(above) for the user who runs it, with the first-run defaults: your Desktop,
Documents and Pictures get canaries, the decoy and update checks are on, and
the tray starts at your sign-in. Change any of them later in the dashboard's
Settings tab.

It always installs to `C:\Program Files\WatchLattice`. It is listed under
**Settings > Apps** as a Windows Installer product, so uninstalling from
there, `msiexec /x`, or `uninstall.ps1` in the install folder (which hands
over to Windows Installer) all do the same full removal described in
[Uninstall](#uninstall).

Unattended installs take the first-run choices as properties:

```powershell
msiexec /i WatchLattice-0.8.0-win-x64.msi /qn /l*v install.log CANARYFOLDERS="D:\Projects;C:\Users\me\Documents" UPDATECHECK=0
```

| Property | Meaning |
|---|---|
| `TRAYUSER="PC\name"` | Whose tray and folders to set up. Defaults to the user running msiexec. Required when it runs as SYSTEM (for example from Intune or Configuration Manager); the install fails with a message in the log otherwise. |
| `CANARYFOLDERS="C:\a;D:\b"` | Canary folders. Defaults to the tray user's Desktop, Documents and Pictures. |
| `DECOY=0` | Do not run the decoy. |
| `UPDATECHECK=0` | Do not check for new releases. |
| `TRAYAUTOSTART=0` | Do not start the tray at sign-in. |
| `KEEPDATA=1` | On uninstall (`msiexec /x … KEEPDATA=1`): keep the alert feed, baselines and canary manifest, like `uninstall.ps1 -KeepData`. |

**Upgrading.** Running a newer MSI upgrades in place: the old version is
removed and the new one installed in the same step, keeping your
`appsettings.json` (the release's copy is next to it as
`appsettings.json.default`), canaries, baselines and alert history, and your
first-run choices are not asked again. Installing an MSI of the same version
replaces it; an older one refuses and says so. **Install update** in the
tray also works on an MSI install, but it updates the files from the zip
without telling Windows Installer, so Settings > Apps keeps showing the
version the MSI installed until the next MSI upgrade. That is cosmetic: the
next MSI or uninstall still works.

**How it is built.** [`packaging/msi`](../packaging/msi) is a WiX v5 project
that packs the release's own staged files, so the MSI and the zip contain
the same bytes and the hub's [install integrity check](install-integrity.md)
passes for either. Windows Installer creates the service, the event log
source, the Start menu shortcut and the Settings > Apps entry. The parts
that depend on the tray user (the install and feed folder permissions, the
first-run settings, the sign-in entry, the service's restart-on-crash
settings) are done by the installed `install.ps1 -Msi`, and the uninstall
clean-up by `uninstall.ps1 -Msi`, so both install routes share one
implementation. Their output is in the MSI log (`/l*v`). CI's
`MSI installer` job installs, upgrades, reinstalls and uninstalls an MSI
built this way on every pull request.
