# Install integrity check

WatchLattice watches other parts of Windows for tampering, so it should notice
when its own files are tampered with too. The **Install Integrity Check**
module (`InstallIntegrity`) compares the installed `Hub\` and `Tray\` folders
with the list of file hashes their release shipped, and raises an alert when
a file was changed, is missing, or a program file appeared that the release
does not contain (a DLL planted next to the hub, for example).

It is read-only. It never repairs, replaces, quarantines or deletes anything;
it only tells you.

## How it works

1. The release workflow writes `Hub\WatchLattice.files.sha256` into every
   release zip from 0.5.0 on. It lists the SHA-256 of each file under `Hub\`
   and `Tray\`, computed after code signing, so the hashes are of the exact
   bytes that get installed. `Hub\appsettings.json` is left out because you
   edit it.
2. Two minutes after the hub starts, and then every hour, the module hashes
   the installed files and compares them with that list. It reads only local
   files and makes no network calls.
3. When it finds a problem it waits 30 seconds and checks again, and alerts
   only if the problem is still there. An update or reinstall rewrites files
   one by one, so this keeps a half-finished copy from raising a false alarm.
4. One alert describes the whole set of findings. It is raised again only
   when that set changes, and a recovery alert follows when every file
   matches again. Restarting the hub raises a still-standing finding once
   more.

Not checked:

- `Hub\appsettings.json`, `appsettings.json.default` and the
  `settings-backups` folder the settings editor keeps.
- The `.update-backup-*` and `.update-staging-*` folders the updater uses.
  A backup can outlive an update, because Windows lets a running program be
  moved aside but not deleted.
- Anything outside `Hub\` and `Tray\`, and the alert feed and logs under
  `%ProgramData%` and `%LOCALAPPDATA%`.
- Development builds (version `0.0.0-dev`). They have no release file list,
  so the module only logs that it is off.

When the file list belongs to a different release than the running hub (an
update has swapped the files and the hub has not restarted yet), the check
logs that and waits for the restart instead of alerting.

## Alerts

| Code | Severity | Event ID | When |
|---|---|---|---|
| `INSTALL_MODIFIED` | Critical when an `.exe` or `.dll` changed or appeared, otherwise Warning | 7001 | A listed file changed or is missing, or an unexpected program file is in `Hub\` or `Tray\`. The message lists up to 10 files. |
| `INSTALL_MODIFIED_CLEARED` | Info | 7501 | Every checked file matches the release again. |
| `MANIFEST_UNAVAILABLE` | Warning | 7002 | `Hub\WatchLattice.files.sha256` is missing or unreadable, so nothing can be checked. |
| `MANIFEST_UNAVAILABLE_CLEARED` | Info | 7502 | The file list is readable again. |

The alert's resource is the install folder. Event IDs are listed with all the
others in [Event Log alerts](event-log.md).

If you did not change the files yourself, treat the PC as possibly tampered
with: run a full Microsoft Defender scan, then reinstall WatchLattice from the
[release page](https://github.com/notbrianbob/WatchLattice/releases) with
`Install.cmd`.

## Checking by hand

From the hub's install folder (no administrator rights needed):

```powershell
.\ScanAlways.Protection.Service.exe --verify-install
```

It prints each changed, missing or unexpected file. Exit codes: `0` every file
matches, `1` files differ, `2` the check could not run (no readable file list,
or the files are from another release), `11` development build.

## Settings

In the hub's `appsettings.json`:

```json
"Modules": {
  "InstallIntegrity": { "Enabled": true }
},
"InstallIntegrity": {
  "CheckIntervalMinutes": 60,
  "InitialDelaySeconds": 120,
  "ReportUnexpectedBinaries": true,
  "IgnoredFiles": []
}
```

| Setting | Default | Meaning |
|---|---|---|
| `CheckIntervalMinutes` | `60` | Minutes between checks. Minimum 5. |
| `InitialDelaySeconds` | `120` | Wait after the hub starts before the first check. |
| `ReportUnexpectedBinaries` | `true` | Also report `.exe` and `.dll` files the release does not contain. |
| `IgnoredFiles` | `[]` | Paths relative to the install folder to leave out, such as `"Hub/Extra.dll"`. |

## Honest limits

- The file list sits next to the files it describes. Someone with
  administrator rights can change both, or stop the hub, so this catches
  accidental corruption, careless tampering and planted DLLs, not a
  determined administrator-level attacker. Code-signed releases (see
  [code signing](code-signing.md)) and Defender's own protections are the
  stronger layers.
- Checks run on an interval, so a file changed and then restored between two
  checks goes unnoticed.
- The updater and the installer add and replace files but never delete
  ones a newer release dropped. If a future release stops shipping a DLL, the
  old copy stays and is reported as not part of the release; add it to
  `IgnoredFiles` or delete it.
- Installs of 0.4.0 and earlier have no file list. Updating to 0.5.0 or later
  brings one.
