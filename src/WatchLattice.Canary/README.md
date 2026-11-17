# WatchLattice.Canary — canary file watcher

A ransomware-style tripwire. It plants a few decoy ("canary") files in the
folders ransomware goes after first, then watches them. Nothing legitimate ever
edits, renames, or deletes these files, so when something does, that is a
strong early signal that a process is mass-modifying your documents.

## What it does

1. **Plants canaries.** By default three files go into Desktop, Documents and
   Pictures: `!000_Financial_Records.docx`, `!000_Passwords_Backup.xlsx` and
   `zzz_Tax_Return_Archive.pdf`. The `!` and `zzz` prefixes put them at the start
   and end of an alphabetical walk, which is how a lot of ransomware works
   through a folder. Each file starts with the right magic bytes for its
   extension followed by random content, and is marked hidden so it doesn't
   clutter Explorer (ransomware enumerates hidden files just the same).
2. **Watches them.** A `FileSystemWatcher` per folder, filtered to the canary
   names only, reports any write, delete, rename, or replacement almost
   instantly at negligible cost.
3. **Re-checks them.** Every 60 seconds each canary is re-hashed and compared
   with the hash recorded when it was planted. This catches anything the
   watcher missed (event-buffer overflow, network folders) and canaries that
   were tampered with while the watcher wasn't running.
4. **Alerts.** A tripped canary produces a `CANARY TRIPPED` line in a rolling
   alert log (`%LOCALAPPDATA%\ScanAlways\canary-alerts.log`), a critical log
   entry (which lands in the Windows Event Log when running as a service), and
   an `AlertRaised` event that a UI host can subscribe to.

When hosted by the hub, critical canary alerts also go to the shared feed and
[Windows tray companion](../../docs/alerts-and-tray.md).

## Safety

- **It never touches your real files.** It only writes files it created, and
  it records them (with their hashes) in a manifest. If a file with a canary's
  name already exists and isn't in the manifest, that canary is skipped.
- **Detection only.** It does not kill processes, quarantine, or restore
  anything. A tripped canary is left in place as evidence.
- **Clean removal.** Set `RemoveCanariesOnStop` to delete intact canaries when
  the watcher stops. Canaries in a folder you remove from the configuration are
  cleaned up on the next start.

## Configuration (hub `appsettings.json`, section `Canary`)

| Setting | Default | Meaning |
|---|---|---|
| `Folders` | Desktop, Documents, Pictures | Folders to plant canaries in. Missing folders are skipped, never created. |
| `FileNames` | the three names above | Canary file names (no paths). |
| `MarkHidden` | `true` | Hide canaries in Explorer. |
| `CanarySizeBytes` | `24576` | Size of each canary. |
| `IntegrityCheckSeconds` | `60` | How often every canary is re-hashed (minimum 10). |
| `AlertDebounceSeconds` | `5` | Suppress duplicate alerts for the same canary and change. |
| `RemoveCanariesOnStop` | `false` | Delete intact canaries on shutdown. |
| `AlertLogPath` | `%LOCALAPPDATA%\ScanAlways\canary-alerts.log` | Rolling alert log. |
| `ManifestPath` | `%LOCALAPPDATA%\ScanAlways\canary-manifest.json` | Which files were planted, and their hashes. |

## Run

This tool runs as the `Canary` module inside the [WatchLattice hub](../WatchLattice.Hub/),
alongside the other tools. It is enabled by default; turn it off with
`Modules:Canary:Enabled = false`.

```powershell
dotnet run -c Release --project src/WatchLattice.Hub
```

To install the hub as a Windows service, see
[Install as a Windows service](../../README.md#install-as-a-windows-service)
in the top-level README.

A service runs under its own account, and the default folders (Desktop,
Documents, Pictures) resolve to *that* account's profile. When installing as a
service, either run it under your own user account (`obj= ".\you" password= ...`)
or list your folders explicitly in `Folders`.

## Honest limits

- **It detects, it doesn't stop.** By the time a canary trips, ransomware has
  started. The value is an early, high-confidence alarm, ideally before it
  reaches the bulk of your files.
- **Reads are not detected.** Windows file watchers report writes, renames and
  deletes, not reads, and NTFS last-access times are usually disabled. A
  data-stealer that only *reads* a canary won't trip it.
- **Targeted ransomware can skip it.** Malware that avoids hidden files, small
  files, or these specific names will walk past. Rename the canaries in config
  to make them your own.
- **Sync and backup tools.** OneDrive or similar may sync the canaries. That is
  harmless, but if a sync client ever rewrites a canary's content you'll get an
  alert; point `Folders` elsewhere if that happens.
- **Junctioned folders are skipped.** The hub runs as LocalSystem, so it
  refuses to write a canary through a junction or link: one a user made could
  otherwise point it at a system file (see the
  [threat model](../../docs/threat-model.md#elevation-of-privilege)). If you
  moved a folder with `mklink /J`, list the folder's real path in `Folders`.
  The log says *Did not plant canary* with the reason.
- **Runs as you.** It can only watch folders your account can read, and it
  stops if malware kills the process. Running it as a service makes that
  harder, not impossible.
