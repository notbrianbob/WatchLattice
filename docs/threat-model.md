# Threat model of WatchLattice itself

A security tool that runs as LocalSystem is also a target. This document
looks at how WatchLattice could be attacked, abused or fooled. It uses
[STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
(Spoofing, Tampering, Repudiation, Information disclosure, Denial of service,
Elevation of privilege) at each trust boundary. For what WatchLattice is meant
to protect *against*, see the [README's threat model](../README.md#threat-model).

Reviewed 2026-11-17, against the code after 0.9.0. Each row is either
**Mitigated** (and says how), **Fixed** (found in this review and changed in
the same pull request, with a test), or **Accepted** (a known limit, with the
reason). [SECURITY.md](../SECURITY.md) says how to report something missing
from this list.

## What is worth protecting

- **The PC's integrity.** WatchLattice must never become a way for a standard
  user, or malware running as one, to gain administrator or SYSTEM rights, or
  to weaken Defender.
- **The user's files.** Modules only read, except the canary watcher, which
  creates and deletes its own decoy files.
- **Alert integrity.** Alerts must be real, and a change must not be hidden
  by tampering with the record of what was there before.
- **Alert confidentiality.** Alerts contain file paths, extension names and
  command lines.

## Components and trust boundaries

| Component | Runs as | Reads from lower trust | Writes |
|---|---|---|---|
| Hub service (`ScanAlways.Protection.Service.exe`) with every module | LocalSystem | User folders (canary, decoy, startup), browser profiles, HKCU hives, the registry, Event Logs, hosts file, GitHub releases (updater) | Its own state in the SYSTEM profile; canary files in user folders; the alert feed in `%ProgramData%\WatchLattice\Alerts`; the Application log |
| Tray and dashboard (`ScanAlways.Tray.exe`) | The signed-in user | The alert feed, the Application log | The user's review file in their own profile |
| Settings editor (`ScanAlways.Tray.exe --edit-settings`) | Administrator, after a UAC prompt | Arguments from the tray | `Hub\appsettings.json`, backups, then restarts the service |
| Installer (`Install.cmd` / MSI) | Administrator | The release zip | Program Files, `%ProgramData%\WatchLattice`, the service, the tray user's Run key |
| Release pipeline | GitHub Actions | Pull requests, dependencies | Release zips, `SHA256SUMS.txt`, provenance attestations |

The boundaries that matter most are:

1. **User to hub.** A standard user controls their own folders and HKCU, and
   the hub, running as LocalSystem, reads them and writes canaries into them.
2. **Hub to user.** The hub writes alerts that the user, and other users, can
   read.
3. **Tray to settings editor.** A medium-integrity process starts an elevated one.
4. **Internet to hub.** The updater downloads code.

## Elevation of privilege

| Threat | Status | Mitigation |
|---|---|---|
| A user swaps a canary folder for a junction, or a canary for a symbolic or hard link, so the hub (as LocalSystem) overwrites or deletes a protected file such as one in System32. | **Fixed** | Found in this review. The canary watcher wrote with `File.WriteAllBytes` and deleted with `File.Delete`, which follow links. It now does every write and delete through a handle ([RedirectionSafeFile](../src/WatchLattice.Canary/RedirectionSafeFile.cs)). The folder must resolve to itself before anything is created. The handle's final path, with junctions and links resolved, must equal the requested path. The file must have one name (no hard link). Nobody else may open it while the handle is held. A file created in the wrong place is deleted through the handle before anything is written. A delete reads the content and deletes it through the same handle, so it can't be swapped in between. [RedirectionTests](../tests/WatchLattice.Canary.Tests/RedirectionTests.cs) fail on the old code. |
| A user replaces files the service runs from, or a folder above them. | Mitigated | The installer refuses an install folder that a non-administrator can change, at any level above it (`Assert-AdminOnlyLocation`). It sets the folder's owner and permissions to SYSTEM and Administrators, with read and run access for Users, and refuses links and junctions inside it. The [install integrity check](install-integrity.md) hashes every installed file hourly. |
| A user edits the hub's settings to point a path option somewhere privileged. | Mitigated | `appsettings.json` lives in the protected install folder. Changing it takes the elevated settings editor. |
| A user plants a file in a folder the hub writes state or logs to. | Mitigated | State and logs default to the SYSTEM profile (`%LOCALAPPDATA%` for LocalSystem) and `%TEMP%`, which .NET 8 and later resolve to `C:\Windows\SystemTemp` for SYSTEM. Users can't write to either. The feed folder is SYSTEM and Administrators only, with read access for the tray user. |
| Malware running as the user sets `DOTNET_STARTUP_HOOKS` and waits for the settings editor's UAC prompt, so its code runs elevated. | **Fixed** | The hub and tray are built with `StartupHookSupport=false`, so the runtime ignores startup hooks. A test checks both project files. |
| Malware running as the user sets the CLR profiler variables (`CORECLR_ENABLE_PROFILING`, `CORECLR_PROFILER_PATH`) for the same purpose. | Accepted | .NET has no switch to refuse a profiler. With an administrator account, [UAC is not a security boundary](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/): malware running as that user can wait for any elevation prompt. The hub service is not affected, because services don't take environment variables from the user. |
| Something other than the tray starts the settings editor with its own `--approve` value, to approve a malicious autostart entry. | Mitigated | It still needs the UAC prompt. The editor opens with the approval as an unsaved change, and nothing is saved until someone presses Save. Approvals are matched by SHA-256 of the exact entry. |
| The updater installs a malicious release. | Accepted, partly mitigated | Updates are started by the user, downloaded over HTTPS from GitHub Releases and checked against `SHA256SUMS.txt`. They are staged inside the protected install folder, so no new writable location is added. A release that needs a missing runtime is refused. But the checksum comes from the same release, so someone who controls the repository could publish a bad one. Authenticode pinning starts once releases are signed ([code signing](code-signing.md)). Until then, the build provenance attestation can be checked by hand ([updater limits](../src/WatchLattice.Updater/README.md#honest-limits)). |
| A module loads code that isn't part of the release. | Mitigated | Modules are compiled into the hub. There is no plug-in folder, and the install integrity check covers every file. |

## Tampering

| Threat | Status | Mitigation |
|---|---|---|
| Malware edits a module's baseline, so its change looks like it was always there. | Mitigated | Baselines live in the SYSTEM profile, which needs administrator rights. |
| Malware forges alerts in the tray. | Mitigated | Only SYSTEM and Administrators can write the feed. The tray only reads it. |
| Malware edits the user's review file to hide alerts. | Accepted | The review file only records what the user acknowledged or dismissed, in their own view. The alert itself stays in the feed and the Event Log. |
| An administrator-level attacker stops the service or edits anything. | Accepted | This is out of scope, as the [README](../README.md#threat-model) says: user-mode tools can't defend against administrator rights. The *Module failed* and Defender or firewall alerts may still be the first sign. |

## Spoofing

| Threat | Status | Mitigation |
|---|---|---|
| Another program writes events with the source `WatchLattice` to the Application log. | Accepted | Windows lets interactive users write to the Application log with any registered source, and there's no way to stop that. A SIEM should treat WatchLattice events as a lead, not proof, and can cross-check the alert ID against the tray's export. See [the Event Log page](event-log.md). |
| A fake tray icon or window imitates WatchLattice. | Accepted | Any desktop program can draw one. The dashboard's alerts come only from the SYSTEM-owned feed, so a fake window can't add alerts to the real one. |

## Information disclosure

| Threat | Status | Mitigation |
|---|---|---|
| Command lines copied from the Security log (administrators only) into alerts, which every user can read in the Application log, reveal passwords or tokens. | **Fixed** | Found in this review. Values that look like secrets (`-Password x`, `/p:x`, `token=x`, `user:pass@host`, `Bearer x`, `ConvertTo-SecureString "x"`) are now replaced with `[hidden]` before a command line goes into an alert ([CommandLineRedactor](../src/WatchLattice.ScriptHostAudit/CommandLineRedactor.cs)). Approvals still match the exact command line. A secret passed as a plain positional word can't be told apart from anything else, so `CommandLineInAlerts=false` is still the way to keep command lines out completely. The module is off by default. |
| Alerts show other users of the PC file paths, extension names and hosts file entries. | Accepted | The Application log is readable by every user, and WatchLattice is built for one person's PC. The feed itself is readable only by the tray user and administrators. On a shared PC, turn off Event Log alerts (`Alerts:EventLog:Enabled`). |
| A person shares an *Export all data* file with an AI service, and it reveals who they are or a secret from the settings. | Mitigated | The export runs as the person, never elevated, and writes only where they save it; nothing is uploaded. User name, computer name and e-mail addresses are replaced by default, and setting values whose names look like secrets are always hidden ([FullExport](../src/WatchLattice.Common/Export/FullExport.cs), [NameRedactor](../src/WatchLattice.Common/Export/NameRedactor.cs)). Program and file names stay, because the review needs them; the docs say to read the file before sharing it. |
| Text an attacker chose (a file or task name) in an *Export all data* file tells the AI assistant to say everything is fine. | Mitigated | The file's brief tells the model that text from the PC is data, never instructions. That text is flattened to one line, can't add a table column or close a code block, and is clipped. A model can still be fooled, so the export supports the person's own judgment and the dashboard, and doesn't replace them. |
| The hub, reading as SYSTEM through a junction a user made, reveals the contents of a protected file. | Mitigated | Reads that follow user-controlled paths only produce hashes (startup files, canaries), counts or names, never file contents. |

## Denial of service

| Threat | Status | Mitigation |
|---|---|---|
| Malware floods alerts (for example by touching canaries over and over) to fill the disk. | Mitigated | Canary alerts are debounced per file, the feed keeps the newest 200 alerts (`Alerts:HistoryLimit`), and the Event Log queue is bounded (256) and reports how many it dropped. |
| The same flood pushes an earlier, real alert out of the dashboard. | Accepted | Repeats group into one row, but 200 distinct alerts push older ones out of the feed. The earlier alert stays in the Event Log and in the module's own alert log. |
| A user holds an opportunistic lock on a file the decoy or persistence auditor reads, to stall it. | Accepted | That stalls one module's read until the lock breaks or the check is cancelled. Other modules keep running, and the supervisor reports a module that stops. |
| Malware stops or disables the service. | Accepted | It takes administrator rights. Standard users can't stop it, because the default service permissions only let them query it. |

## Repudiation

| Threat | Status | Mitigation |
|---|---|---|
| A settings change can't be traced. | Mitigated | Each save by the editor keeps a timestamped backup in `Hub\settings-backups`, and the hub logs the restart. |
| An alert is denied after the fact. | Mitigated | Alerts go to three places: the feed, the module's own alert log, and the Event Log. Each has a stable alert ID and time. |

## How this review was done

Each boundary above was followed through the code: every file the hub opens
under a user-controlled path, every process the tray or editor starts, every
value copied from a lower-trust source into an alert, and the installer's
permission changes. The three **Fixed** rows were the gaps found. Each has a
test that fails without the fix. Repeat the review when a module starts
writing outside its own state, or when a new process boundary is added.
