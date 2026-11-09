# WatchLattice.Common

Shared, tool-agnostic library for the WatchLattice suite. Code that more than one
tool would want lives here so the individual tools stay thin.

## What's here today

### Module hosting (`WatchLattice.Common.Modules`)

- **`IWatchLatticeModule`**: the contract every tool implements so the hub can
  run it. See [docs/adding-a-tool.md](../../docs/adding-a-tool.md).
- **`ModuleCatalog`**: compile-time discovery of modules in a set of
  assemblies, id validation, and the `Modules:<Id>:Enabled` switches.
- **`ModuleSupervisor`**: runs every enabled module side by side and restarts
  a failing one with back-off, without affecting the others.
- **`HubOptions`** and **`AddWatchLatticeHub`**: hub settings and DI wiring.

### Decoy engine

The first tool (the always-scanning decoy) drove the initial contents:

- **`DecoyOptions`** — configuration for the decoy, including intensity profiles
  and scan-root resolution with sensible fallbacks.
- **`DecoyEngine`** — the read-only sweep loop: walk files, read a prefix, hash
  it, discard it, narrate, repeat. Exposes live `ScanStatistics` and a
  `StatusChanged` event so any host (service, console, or a future tray UI) can
  show status.
- **`FileWalker`** — resilient, read-only recursive file enumeration that
  swallows the access errors routine on a live system.
- **`ScanNarrator`** — turns benign file reads into believable, scanner-style
  status lines (seedable for deterministic tests).
- **`ScanLogWriter`** — size-capped, rolling cosmetic scan log.
- **`ServiceCollectionExtensions.AddWatchLatticeDecoy`** — DI wiring that binds
  options and registers the engine.

### Shared alerts and state

- **`IAlertPublisher` / `AlertHub`** — bounded structured history used by
  Canary, Defender, Firewall, Persistence, and module supervision. No disk work or UI
  callbacks run inside an alert publisher.
- **`AlertDeliveryService`** — writes the local feed and heartbeat, restores
  history, and tolerates delivery failures independently of monitoring.
- **`EventLogAlertService` / `AlertEventIds`** — copies each new alert to the
  Windows Application log (source `WatchLattice`) with a stable event ID, from
  a bounded background queue. See [Event Log alerts](../../docs/event-log.md).
- **`AlertSnapshot` / `AlertNotificationCursor`** — shared feed format,
  freshness checks, and notification deduplication for the Windows tray.
- **`UpdateNotice` / `IUpdateStatusPublisher`** — the update checker's result,
  carried in the feed so the tray can show that an update is available.
- **`AtomicJsonFile`** — bounded JSON reads and atomic replacement for the feed
  and persistence baseline.

See [alerts and tray setup](../../docs/alerts-and-tray.md).

## Conventions

- `net10.0`, nullable enabled, no Windows-only dependencies in this library so it
  builds and unit-tests cross-platform.
- Keep anything specific to a single tool in that tool's project; promote code
  here only once a second tool needs it.
