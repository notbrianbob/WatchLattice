# WatchLattice.Updater

Keeps an installed WatchLattice up to date from this repository's
[GitHub Releases](https://github.com/notbrianbob/WatchLattice/releases),
without visiting GitHub by hand. It has two halves:

- **Checking** runs inside the hub as the `Updater` module. Shortly after the
  hub starts, and then every 12 hours, it asks the GitHub API for the latest
  release. A newer version shows up in the tray: a one-time notification, an
  **Update available** banner in the alerts window, a tray-menu entry, and an
  informational entry in the alert history. Checking never downloads or
  installs anything.
- **Installing** happens only when you choose **Install update** in the tray
  (or run the hub with `--apply-update` yourself). Windows asks for
  administrator permission, and a console window shows each step.

## What the installer does

1. Asks the GitHub API for the latest release again. It does not trust
   anything in the alert feed.
2. Requires both `WatchLattice-<version>-win-x64.zip` and `SHA256SUMS.txt`,
   hosted under this repository's `releases/download/` path. Downloads must
   stay on GitHub's own hosts (`github.com`, `*.githubusercontent.com`) over
   HTTPS, and the package is capped at 256 MB.
3. Streams the zip into a staging folder inside the hub's install directory,
   computes its SHA-256, and compares it with `SHA256SUMS.txt`. **On a mismatch,
   or any other verification problem, it stops and changes nothing.** The same
   locked file handle is hashed and then extracted.
4. Extracts with path checks: no entry may escape the staging folder, and the
   package must contain `Hub/ScanAlways.Protection.Service.exe` and
   `Tray/ScanAlways.Tray.exe`.
5. Checks the Authenticode signature of every `.exe` and `.dll` in the package.
   Once the installed hub is signed, every file must be validly signed and
   ours by the same publisher; a broken signature is always refused. Unsigned
   installs such as v0.1.0 still accept unsigned packages. Details in
   [code signing](../../docs/code-signing.md).
6. Stops the `ScanAlways Protection` service if it is running, then swaps files.
   Every file the package replaces is first moved aside into a backup folder.
   If any step fails, all originals are moved back. Files the package does not
   contain, such as logs or anything you added, are never moved or deleted.
7. Keeps your `appsettings.json`. The release's copy is written next to it as
   `appsettings.json.default` so you can compare them.
8. Starts the service again, and the tray restarts itself on the new version.
   A tray that did not start the update (for example after `--apply-update`
   from an administrator prompt) notices within 30 seconds that its files on
   disk are a different release and restarts on them, once its dashboard is
   closed. Trays from 0.4.0 and earlier lack this check: after updating one of
   those by hand, exit the tray and start it again from the Start menu.

The tray is updated when it is installed next to the hub, as `…\Hub` and
`…\Tray` (the layout of the release zip). Other layouts update the hub only.

## Commands

From the hub's install folder:

```powershell
.\ScanAlways.Protection.Service.exe --check-update   # prints whether a newer release exists
.\ScanAlways.Protection.Service.exe --apply-update   # installs it (run as administrator)
```

`--apply-update` exits with `0` when installed, `10` when already up to date,
`2` when verification failed (nothing changed), `3` when the release cannot be
installed automatically, `4` when a failed install could not be fully rolled
back (the service is left stopped and the backup folder is named), `11` for a
development build, and `1` for anything else.

## Configuration

`Modules:Updater:Enabled` turns checking off. Settings live in the `Updater` section:

| Setting | Default | Meaning |
|---|---|---|
| `Repository` | `notbrianbob/WatchLattice` | GitHub `owner/name` whose releases are the update source. |
| `CheckIntervalHours` | `12` | Hours between checks (minimum 1). |
| `InitialDelaySeconds` | `30` | Wait after hub start before the first check. |
| `CheckDevelopmentBuilds` | `false` | Builds from source are versioned `0.0.0-dev` and do not check. |
| `MaxPackageBytes` | `268435456` | Largest package the installer will download. |

## Network use

One unauthenticated HTTPS request to `api.github.com` per check (about two a
day), sent with a `WatchLattice-Updater/<version>` user agent. No identifier,
telemetry, or machine information is sent. Failed checks, for example when
offline or when the hub starts at boot before the network is up, are logged
once and retried after 1 minute, then 2, 4, 8 and so on, up to the normal
interval; once a check succeeds the normal interval applies again. They are
not raised as protection alerts.

## Honest limits

- **The checksum proves integrity, not authorship.** `SHA256SUMS.txt` comes
  from the same release as the zip, so it catches corrupted, truncated or
  mismatched downloads. It would not catch a malicious release published by
  someone who controlled the repository. Code signatures add authorship: see
  [code signing](../../docs/code-signing.md) for how the installer compares the
  package's Authenticode signatures with the installed copy. Releases are
  unsigned until SignPath signing is set up.
  Every release carries a GitHub build provenance attestation that you can
  check by hand with
  `gh attestation verify WatchLattice-<version>-win-x64.zip --repo notbrianbob/WatchLattice`;
  the updater does not check it automatically.
- **Install somewhere only administrators can write**, such as
  `C:\Program Files\WatchLattice`. The updater stages inside the install
  directory so it adds no new writable location, but it cannot protect an
  install that ordinary users can already modify.
- Updates replace files while the old tray is still running, which Windows
  allows by renaming. Old copies that are still in use stay in a
  `.update-backup-*` folder until the next update removes them.
- Only `win-x64` packages are published.
- Builds from source (`0.0.0-dev`) never update themselves. Pull and rebuild instead.
