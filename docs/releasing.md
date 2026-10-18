# Cutting a release

Releases are what the in-hub updater installs, so each one must come from
the release workflow ([`.github/workflows/release.yml`](../.github/workflows/release.yml)),
not from files uploaded by hand.

1. Make sure `main` is green, and run the release's checks in
   [what to check by hand on Windows](windows-checks.md).
2. Move the `## [Unreleased]` entries in [`CHANGELOG.md`](../CHANGELOG.md)
   under a new `## [<version>] - <date>` heading, add its compare link at the
   bottom, and merge that to `main`. The release workflow uses this section
   as the release notes, with GitHub's generated pull request list after it;
   a version without a section gets only the generated list, and the run
   warns about it. CI's `Changelog` job checks that every version section
   can be read.
3. Update your clone to the latest `main` first, so the tag lands on the
   commit you mean to release. (v0.3.0 was tagged from a clone that had not
   pulled, so it is the same commit as v0.2.0.)

   ```bash
   git checkout main
   git pull
   git log -1 --oneline   # should be the commit you expect, for example the changelog merge
   ```

4. Tag that commit and push the tag:

   ```bash
   git tag v0.5.0
   git push origin v0.5.0
   ```

   Use `v<major>.<minor>.<patch>`, optionally with a prerelease suffix such as
   `v0.6.0-beta.1`. Prereleases are marked as such on GitHub and are not
   offered to stable installs. Do not create the release in the GitHub UI
   first; the workflow creates it and would fail if it already exists.
5. The workflow runs the tests, publishes the hub and tray for `win-x64`
   with that version stamped in, and creates the GitHub release with:
   - `WatchLattice-<version>-win-x64.zip`, containing `Hub/`, `Tray/`, the installer
     (`Install.cmd`, `install.ps1`, `uninstall.ps1`), `LICENSE` and `README.md`.
     `Hub/WatchLattice.files.sha256` inside it lists every installed file's
     SHA-256 for the hub's [install integrity check](install-integrity.md);
     it is written after signing by
     [`.github/scripts/Write-InstallManifest.ps1`](../.github/scripts/Write-InstallManifest.ps1)
   - `WatchLattice-<version>-win-x64.msi`, the same files as a Windows
     Installer package, built from the zip's staged folder by
     [`.github/scripts/Build-Msi.ps1`](../.github/scripts/Build-Msi.ps1) (see
     [the MSI](installing.md#the-msi)). A prerelease such as `0.7.0-beta.1`
     gets MSI version `0.7.0`, because Windows Installer versions are numeric;
     the final `0.7.0` MSI still replaces it.
   - `SHA256SUMS.txt`, with a line for the zip and one for the MSI. The
     updater checks the zip's line before installing anything
   - `WatchLattice-<version>-winget.zip`, the [winget manifests](#publishing-to-winget)
     for that MSI, checked with `winget validate`. Not submitted anywhere
   - a build provenance attestation for the zip and the MSI

   When the SignPath secrets are set, the executables and DLLs are
   Authenticode-signed before zipping, and the MSI is signed after it is
   built; otherwise the run logs that the release is unsigned. See
   [code signing](code-signing.md).
   - release notes from the version's `CHANGELOG.md` section
6. Edit the release notes if needed. Do not replace or re-upload
   assets: the checksum file would no longer match, and installs of that
   release would be refused (which is the point).

Installed hubs see the release at their next check (within 12 hours, or at
the next hub start), and the tray shows that an update is available.

## Publishing to winget

Each release carries `WatchLattice-<version>-winget.zip`: the three manifest
files for `notbrianbob.WatchLattice` (version, installer, en-US locale),
rendered from [`packaging/winget`](../packaging/winget) with that release's
MSI URL, SHA-256 and ProductCode, and already checked with `winget validate`.
The workflow never submits them. Publishing is your call, made once per
release you want on winget:

1. Wait for the release to finish, so the MSI is downloadable at the URL in
   the manifest.
2. On Windows, extract the zip and check it again and, if you like, try the
   install from the manifest (needs an administrator terminal and turns on
   local manifests once):

   ```powershell
   Expand-Archive WatchLattice-0.7.0-winget.zip winget-0.7.0
   winget validate --manifest winget-0.7.0
   winget settings --enable LocalManifestFiles
   winget install --manifest winget-0.7.0
   ```

3. Submit it to [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs)
   with [wingetcreate](https://github.com/microsoft/winget-create)
   (`winget install wingetcreate`). It opens the pull request from a fork
   under your GitHub account, so it asks you to sign in to GitHub:

   ```powershell
   wingetcreate submit winget-0.7.0
   ```

   The first submission adds the package; later ones add a version. Microsoft's
   pipeline installs it in a sandbox and a moderator reviews it, so expect
   it to take a few days and possibly questions on the pull request.

Things to know first:

- **Unsigned MSIs.** Until [code signing](code-signing.md) is set up, the MSI
  is unsigned. winget-pkgs accepts unsigned installers, but its antivirus and
  SmartScreen checks are more likely to flag a new unsigned security tool
  (it plants canary files and watches Defender settings), which can hold
  the submission for manual review. Users installing it outside winget also
  see SmartScreen's "Windows protected your PC" prompt. Signing first makes
  both smoother.
- **Prereleases.** The workflow renders manifests for prereleases too, but
  keep those off winget, which has no prerelease channel; a `0.7.0-beta.1`
  submitted there would be offered to everyone.
- **Silent installs.** `winget install` shows the MSI's progress bar and the
  administrator prompt. With `--silent` the MSI runs with no UI at all, so run it from an
  administrator terminal. Either way it installs for the user running winget,
  with the first-run defaults described in [the MSI](installing.md#the-msi).
- **Dependency.** The manifest depends on `Microsoft.DotNet.DesktopRuntime.8`,
  so winget installs the .NET 8 Desktop Runtime first if it is missing.
- **Updates.** `winget upgrade` runs the newer MSI, which upgrades in place
  like any MSI upgrade. The in-hub updater keeps working alongside it.

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
| MSI `UpgradeCode` `21E8E3ED-618D-4DCD-8E14-79555B2974AD` ([`Package.wxs`](../packaging/msi/Package.wxs)) | Ties every WatchLattice MSI together. A new one would install a second copy next to the old one instead of upgrading it. The winget manifest repeats it. |
| winget `PackageIdentifier` `notbrianbob.WatchLattice` | Once published, winget tracks installs and upgrades by it. |

Everything else (projects, namespaces, assemblies other than the two
executables, display text, the release asset `WatchLattice-<version>-win-x64.zip`)
uses the WatchLattice name. `ReleaseLayoutCompatibilityTests` fails if the
package names, or the MSI's service name, executables or UpgradeCode, change. Moving to new names needs a release whose updater
understands both, shipped and installed first.
