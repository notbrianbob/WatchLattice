# Changelog

All notable changes to WatchLattice are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). While the version is below 1.0,
a minor version can change behavior or settings.

The release workflow uses the section matching a tag as that GitHub release's
notes, followed by GitHub's generated list of pull requests. See
[cutting a release](docs/releasing.md).

## [Unreleased]

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

[Unreleased]: https://github.com/notbrianbob/WatchLattice/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/notbrianbob/WatchLattice/releases/tag/v0.3.0
[0.2.0]: https://github.com/notbrianbob/WatchLattice/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/notbrianbob/WatchLattice/releases/tag/v0.1.0
