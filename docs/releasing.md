# Cutting a release

Releases are what the in-hub updater installs, so each one must come from
the release workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml)),
not from files uploaded by hand.

1. Make sure `main` is green.
2. Tag the commit and push the tag:

   ```bash
   git tag v0.2.0
   git push origin v0.2.0
   ```

   Use `v<major>.<minor>.<patch>`, optionally with a prerelease suffix such as
   `v0.3.0-beta.1`. Prereleases are marked as such on GitHub and are not
   offered to stable installs.
3. The workflow runs the tests, publishes the hub and tray for `win-x64`
   with that version stamped in, and creates the GitHub release with:
   - `WatchLattice-<version>-win-x64.zip`, containing `Hub/`, `Tray/`, the installer
     (`Install.cmd`, `install.ps1`, `uninstall.ps1`), `LICENSE` and `README.md`.
     `Hub/WatchLattice.files.sha256` inside it lists every installed file's
     SHA-256 for the hub's [install integrity check](install-integrity.md);
     it is written after signing by
     [`.github/scripts/Write-InstallManifest.ps1`](../.github/scripts/Write-InstallManifest.ps1)
   - `SHA256SUMS.txt`, which the updater checks before installing anything
   - a build provenance attestation for the zip

   When the SignPath secrets are set, the executables and DLLs are
   Authenticode-signed before zipping; otherwise the run logs that the
   release is unsigned. See [code signing](code-signing.md).
4. Edit the generated release notes if needed. Do not replace or re-upload
   assets: the checksum file would no longer match, and installs of that
   release would be refused (which is the point).

Installed hubs see the release at their next check (within 12 hours, or at
the next hub start), and the tray shows that an update is available.

## First install from a release

The zip includes `Install.cmd`, `install.ps1` and `uninstall.ps1` (from
[`installer/`](../installer/)). Extract it and double-click `Install.cmd`; see
[installing WatchLattice](installing.md) for what it sets up and its options.
CI's `Installer` job runs the same scripts against a release-shaped package on
every pull request: install, reinstall over it, and uninstall.

Keeping `Hub` and `Tray` side by side is what lets **Install update** in the
tray update both. The installer, its uninstaller and `install-state.json` sit
in the install folder's root, which the updater does not touch.

## Names that must not change

The project was renamed from ScanAlways to WatchLattice after v0.1.0. A few
names are part of what an installed hub depends on, so they keep the old
name. Changing any of them would break updates from installed versions:

| Name | Why it is fixed |
|---|---|
| `Hub/ScanAlways.Protection.Service.exe` | Installed updaters refuse a package without it, and existing Windows services point at this file. The update installer replaces files in place; it never repoints a service. |
| `Tray/ScanAlways.Tray.exe` | Installed updaters refuse a package without it, and use it to find the tray next to the hub. |
| `ScanAlways Protection` (service name) | The updater stops and restarts the service by this name. |
| `%LOCALAPPDATA%\ScanAlways\` and `%TEMP%\ScanAlways\` | Where the canary manifest, baselines, alert feed and logs live. A new folder would orphan planted canaries (the watcher refuses to overwrite files it has no record of) and reset every baseline. |
| `Local\ScanAlways.Tray.*` (tray mutex) | Keeps a single tray running while an old and a new copy overlap during an update. |
| `WatchLattice` event source and the [event IDs](event-log.md#event-ids) | SIEM rules and event forwarding subscriptions match on them. Add new IDs; never rename the source or change what an ID means. |

Everything else (projects, namespaces, assemblies other than the two
executables, display text, the release asset `WatchLattice-<version>-win-x64.zip`)
uses the WatchLattice name. `ReleaseLayoutCompatibilityTests` fails if the
package names change. Moving to new names needs a release whose updater
understands both, shipped and installed first.
