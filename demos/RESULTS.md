# Measured results

Numbers from running the demos in [README.md](README.md). They are
measurements of the machines listed, made with the method described there,
and they say nothing about how well WatchLattice protects against real
malware: no malware was run.

Rerun them on your own machine; the numbers that matter are the ones for
your hardware and your Defender configuration.

## Summary

- **Decoy CPU.** At its paced rates the decoy's CPU cost is below what the
  per-second sampling can resolve (the paced rows sit within the noise of the
  idle baseline). Measured directly with the cap lifted, one file costs about
  0.04 ms of CPU on the Linux container and 0.07 ms on the Windows runner,
  which works out to roughly 0.01 to 0.02% of one core at `Balanced`
  (3 files/s) and 0.03 to 0.06% at `FullScan` (8 files/s).
- **The shipped hub on Windows.** Observed from outside, the real
  `ScanAlways.Protection.Service.exe` running only the decoy at `Balanced`
  used 0.58% of one core (0.14% of the machine), about 90 KiB/s of reads and a
  46 MiB working set, .NET runtime included.
- **Decoy reads.** About 90 to 100 KiB/s of logical reads at `Balanced` and
  240 to 255 KiB/s at `FullScan`, as the hub defaults intend (up to 64 KiB from
  each file, 3 or 8 files a second).
- **Canary watcher.** No measurable CPU while armed and idle. Overwrite,
  rename and delete each raised an alert within 1 to 7 ms; the control file in
  the same folder raised none.
- **Detection checks.** All 14 harmless, self-reverting changes (Run keys,
  Startup folder, scheduled task, service, WMI filter, hosts, proxy,
  firewall rule, Defender exclusion, Edge extension policy, an encoded
  PowerShell launch and a canary) raised their expected alert on a fresh
  Windows runner, and each undo was reported where the module reports one.
- **Defender watchdog.** Readouts match the documented rules for each recorded
  state, and alerts fire once on change, not on every check. One live check
  (starting Windows PowerShell and running `Get-MpComputerStatus`) took about
  0.9 s, once every five minutes by default.

## Detection checks

Environment: `windows-latest` GitHub-hosted runner (Windows 10.0.26100, an
elevated throwaway VM), run from the "Detection checks" job of
[the Demos workflow](../.github/workflows/demos.yml) on 2026-11-17 for the
pull request that added the checks, with `--include-defender` and
`--include-audit-policy`. What each check changes, and why it is harmless,
is in [detection-checks.md](detection-checks.md).

**14 of 14 checks raised the expected alert, and every change was undone.**

| Check | ATT&CK | Expected alert (Event ID) | Result | Found by one check in | Hub checks every | Undo reported |
|---|---|---|---|---|---|---|
| Run key value (current user) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `ENTRY_ADDED` (5002) | ✅ detected | 1.9 s | 5 min | yes (`ENTRY_REMOVED`) |
| Run key value (all users) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `ENTRY_ADDED` (5002) | ✅ detected | 2.0 s | 5 min | yes (`ENTRY_REMOVED`) |
| Startup folder file (current user) | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | `ENTRY_ADDED` (5002) | ✅ detected | 1.7 s | 5 min | yes (`ENTRY_REMOVED`) |
| Scheduled task (disabled, never runs) | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | `ENTRY_ADDED` (5002) | ✅ detected | 1.6 s | 5 min | yes (`ENTRY_REMOVED`) |
| Auto-start service (program does not exist) | [T1543.003](https://attack.mitre.org/techniques/T1543/003/) | `ENTRY_ADDED` (5002) | ✅ detected | 1.6 s | 5 min | yes (`ENTRY_REMOVED`) |
| WMI event filter (no consumer, never runs anything) | [T1546.003](https://attack.mitre.org/techniques/T1546/003/) | `ENTRY_ADDED` (5002) | ✅ detected | 1.6 s | 5 min | yes (`ENTRY_REMOVED`) |
| Hosts file line for a test domain | [T1557](https://attack.mitre.org/techniques/T1557/) (related) | `HOSTS_CHANGED` (8004) | ✅ detected | 0.0 s | 1 min | yes (`HOSTS_CHANGED`) |
| Hosts file override of a protected domain | [T1685](https://attack.mitre.org/techniques/T1685/)<br>[T1557](https://attack.mitre.org/techniques/T1557/) (related) | `PROTECTED_HOST_OVERRIDDEN` (8002) | ✅ detected | 0.0 s | 1 min | yes (`PROTECTED_HOST_OVERRIDDEN_CLEARED`) |
| Proxy server set (current user, proxy left off) | [T1557](https://attack.mitre.org/techniques/T1557/) (related) | `PROXY_CHANGED` (8006) | ✅ detected | 0.0 s | 1 min | yes (`PROXY_CHANGED`) |
| Inbound allow firewall rule for a program that does not exist | [T1686.003](https://attack.mitre.org/techniques/T1686/003/) | `INBOUND_ALLOW_RULE_ADDED` (4012) | ✅ detected | 1.5 s | 5 min | not reported by design |
| Microsoft Defender exclusion for a folder that does not exist | [T1685](https://attack.mitre.org/techniques/T1685/) | `EXCLUSION_ADDED` (3030) | ✅ detected | 0.9 s | 5 min | yes (`EXCLUSION_REMOVED`) |
| Edge force-install policy for an extension that does not exist | [T1176.001](https://attack.mitre.org/techniques/T1176/001/) | `POLICY_EXTENSION_ADDED` (10006) | ✅ detected | 0.0 s | 5 min | yes (`POLICY_EXTENSION_REMOVED`) |
| PowerShell started with an encoded command | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | `SCRIPT_HOST_LAUNCHED` (11005) | ✅ detected | 1.2 s | 30 s | not reported by design |
| Canary file overwritten | [T1486](https://attack.mitre.org/techniques/T1486/) (related) | `CANARY_MODIFIED` (2001) | ✅ detected | 0.3 s | immediate (file events) | not reported by design |

*Found by one check in* is how long the module's own check took once the
change was made; in the hub the change is found at the module's next check,
so up to *Hub checks every* later. A pass shows that the module's real code
reports that kind of change on this machine. It is not a detection rate
against real malware, which these checks do not run, and an attacker with
administrator rights can stop the hub before making such a change.

## Run 2: Windows (GitHub Actions)

Environment: `windows-latest` GitHub-hosted runner, .NET 8, run from
[the Demos workflow](../.github/workflows/demos.yml) on 2026-10-17. The
runner image ships with Defender's real-time protection switched off, so
the live readout below is a genuinely degraded machine, not a typical PC.

### Decoy (harness)

| Window | CPU (% of one core) | CPU (% of machine) | Logical reads | Read calls/s | Files opened | Peak working set |
|---|---:|---:|---:|---:|---:|---:|
| Baseline (harness idle) | 0.42 | 0.104 | 0 B/s | 0.0 | 0 | 51.18 MiB |
| Decoy Balanced | 0.65 | 0.163 | 92.8 KiB/s | 3.0 | 180 (3.0/s) | 57.09 MiB |
| Decoy FullScan | 0.68 | 0.169 | 238.8 KiB/s | 8.0 | 478 (8.0/s) | 59.96 MiB |

Baseline noise was ±0.71% of one core per second (±0.18% on a window mean).
With the cap lifted the engine opened 206,318 files in 15 s using 14,953 ms
of CPU: **0.072 ms per file**, predicting 0.007% / 0.022% / 0.058% of one core
at `Idle` / `Balanced` / `FullScan`.

### Decoy (the real hub, seen from outside)

`demos/scripts/Show-DecoySignals.ps1`, hub started with only the decoy at
`Balanced`, 60 s window:

```text
Id ProcessName                   Path
-- -----------                   ----
1804 ScanAlways.Protection.Service <publish>\ScanAlways.Protection.Service.exe
```

| Wall | CPU (% of one core) | CPU (% of machine) | Logical reads | Read calls/s | Peak working set |
|---:|---:|---:|---:|---:|---:|
| 60 s | 0.58 | 0.144 | 90.5 KiB/s | 3.0 | 46.3 MiB |

### Canary watcher

| Window | CPU (% of one core) | Logical reads |
|---|---:|---:|
| Baseline (nothing armed) | 0.104 | 0 B/s |
| Armed, nothing happening | 0.104 | 0 B/s |

| Action | Expected | Result | Time to alert |
|---|---|---|---:|
| Create and edit an ordinary file next to the canaries (control) | no alert | no alert | n/a |
| Overwrite the first 4 KiB of a canary with random bytes | alert | alert: Modified | 3.8 ms |
| Rename a canary to `.locked` | alert | alert: Renamed | 1.0 ms |
| Delete a canary | alert | alert: Deleted | 0.7 ms |

### Defender watchdog, live readout of the runner

```text
Health: Critical. Real-time protection is OFF; Behavior monitoring is off;
Scanning of downloaded files and attachments is off; On-access protection is
off; Tamper protection is OFF.

AMServiceEnabled          True
AntivirusEnabled          True
RealTimeProtectionEnabled False
BehaviorMonitorEnabled    False
IoavProtectionEnabled     False
OnAccessProtectionEnabled False
IsTamperProtected         False
AMRunningMode             Normal
```

One check took 907 ms (median of 3; the first, cold, took 4.6 s). The recorded
healthy and degraded states gave the same readouts as on Linux (Run 1).

## Run 1: Linux container


Environment:

- Date (UTC): 2026-10-16 08:49
- OS: Ubuntu 24.04.5 LTS (X64)
- CPU: Intel(R) Xeon(R) Processor @ 2.10GHz, 4 logical cores
- Runtime: .NET 8.0.31
- Host: Linux cloud container (no Defender; the live watchdog readout and the Windows hub script do not apply)

### Always-scanning decoy

#### Setup

- Corpus: 2,000 files, 274.60 MiB, seed 1337, in 38 folders
- Window: 60 s per intensity, sampled every 1000 ms, after a 15 s baseline
- I/O counter: /proc/self/io (rchar, syscr)
- Engine settings: the hub defaults (`MaxFilesPerSecond` 8, `BytesReadPerFile` 64 KiB, `MaxFileSizeBytes` 256 MiB)

#### Measured overhead

| Window | CPU (% of one core) | CPU (% of machine) | Logical reads | Read calls/s | Files opened | Peak working set | Peak managed heap |
|---|---:|---:|---:|---:|---:|---:|---:|
| Baseline (harness idle) | 1.07 | 0.267 | 7.0 KiB/s | 39.1 | 0 | 63.29 MiB | 14.20 MiB |
| Decoy Balanced | 0.75 | 0.187 | 101.2 KiB/s | 41.1 | 179 (3.0/s) | 74.39 MiB | 16.44 MiB |
| Decoy FullScan | 0.90 | 0.225 | 254.8 KiB/s | 46.6 | 480 (8.0/s) | 80.85 MiB | 19.20 MiB |

Noise: CPU use per 1000 ms interval varies by ±1.33% of one core on the idle baseline (one standard deviation), from the .NET runtime and the sampler itself, so each window's mean is only known to about ±0.34% (standard error). A decoy row within that of the baseline means the decoy's CPU cost is too small for this method to resolve; the cost-per-file run below measures it directly.

Working set is the whole harness process (the .NET runtime included), so read it as an upper bound for the module.

#### Cost per file

With the pacing cap lifted for 15 s, the engine opened 361,085 files (24073/s) and read 10573.80 MiB, using 14830 ms of CPU.
After subtracting the baseline rate, that is **0.041 ms of CPU per file**. At the paced rates this predicts:

| Intensity | Files/s | Predicted CPU (% of one core) |
|---|---:|---:|
| Idle | 1 | 0.004 |
| Balanced | 3 | 0.012 |
| FullScan | 8 | 0.033 |

The corpus was written just before the run, so its files are in the OS file cache: these are CPU costs with warm-cache reads. On a cold cache each file read also waits on the disk, which adds latency but little CPU.

#### What it emits

First lines of the scanner-style log (`scan-activity.log`), copied verbatim:

```text
[2026-10-16 08:46:15] Starting Balanced protection sweep of <corpus>
[2026-10-16 08:46:21] Scanning (signature): <corpus>/folder06/file00349.docx
[2026-10-16 08:46:21] Scan in progress — 19 items checked, 0 threats found, 551.3 KB read, 3.1 items/s
[2026-10-16 08:46:27] Indexing (signature): <corpus>/folder06/file01287.docx
[2026-10-16 08:46:27] Scan in progress — 37 items checked, 0 threats found, 1.1 MB read, 3.0 items/s
[2026-10-16 08:46:33] Indexing (emulation): <corpus>/folder06/file01789.exe
[2026-10-16 08:46:33] Scan in progress — 55 items checked, 0 threats found, 1.8 MB read, 3.0 items/s
[2026-10-16 08:46:39] Inspecting (emulation): <corpus>/folder06/folder03/folder04/file01036.exe
```


### Canary file watcher

#### Setup

- Planted 3 canaries in a throwaway `Documents` folder:
  - `!000_Financial_Records.docx` (24.0 KiB)
  - `!000_Passwords_Backup.xlsx` (24.0 KiB)
  - `zzz_Tax_Return_Archive.pdf` (24.0 KiB)
- Windows: 30 s before arming (baseline) and 30 s armed with nothing happening, sampled every 1000 ms
- I/O counter: /proc/self/io (rchar, syscr)

#### Idle overhead

| Window | CPU (% of one core) | Logical reads | Peak working set |
|---|---:|---:|---:|
| Baseline (harness idle, nothing armed) | 0.133 | 6.7 KiB/s | 206.58 MiB |
| Watcher armed, nothing happening | 0.200 | 7.2 KiB/s | 210.96 MiB |

The difference between the two rows is the armed watcher's cost. Its integrity re-hash runs every 60 s by default, so a window shorter than that may not include one.

#### Tripping the canaries

| Action | Expected | Result | Time to alert |
|---|---|---|---:|
| Create and edit an ordinary file next to the canaries (control) | no alert | no alert | n/a |
| Overwrite the first 4 KiB of a canary with random bytes (in-place encryption) | alert | alert: Modified (content written) | 6.9 ms |
| Rename a canary to `.locked` (encrypt-and-rename) | alert | alert: Renamed (renamed to !000_Passwords_Backup.xlsx.locked) | 1.1 ms |
| Delete a canary | alert | alert: Deleted (file deleted) | 4.4 ms |

Every step behaved as expected.

#### What it emits

The canary alert log (`canary-alerts.log`), copied verbatim:

```text
[2026-10-16 08:49:01] Canary watcher armed: 3 canaries in 1 folders
[2026-10-16 08:49:34] CANARY TRIPPED: Modified <Documents>/!000_Financial_Records.docx (content written)
[2026-10-16 08:49:35] CANARY TRIPPED: Renamed <Documents>/!000_Passwords_Backup.xlsx (renamed to !000_Passwords_Backup.xlsx.locked)
[2026-10-16 08:49:35] CANARY TRIPPED: Deleted <Documents>/zzz_Tax_Return_Archive.pdf (file deleted)
```


### Defender health watchdog

#### Readouts for recorded states

Each state is a `Get-MpComputerStatus` result run through the real evaluator with the default thresholds.

| State | Health | Findings |
|---|---|---|
| Healthy | **Healthy** | none |
| Real-time protection switched off | **Critical** | [Critical] Real-time protection is OFF.<br>[Warning] On-access protection is off. |
| Tamper protection off, signatures 3 days old | **Degraded** | [Warning] Tamper protection is OFF, so other programs can change Defender's settings.<br>[Warning] Antivirus signatures are 3 days old (last updated 2026-10-13 12:00 UTC). |
| Signatures 9 days old | **Critical** | [Critical] Antivirus signatures are 9 days old (last updated 2026-10-07 12:00 UTC). |
| Another antivirus is primary (passive mode) | **Degraded** | [Warning] Defender is in Passive Mode; another antivirus product is providing real-time protection. |
| Status cannot be read | **Unknown** | [Warning] Could not read Defender status: Get-MpComputerStatus failed (exit 1): module not found |

#### Alerting on change

Five checks in a row: healthy, real-time protection turned off, still off, back on, healthy.
The watchdog log shows one alert when the problem appears and one line when it clears:

```text
check 1: Healthy  Defender healthy: real-time protection on, tamper protection on, signatures current.
check 2: Critical Defender critical: Real-time protection is OFF.
check 3: Critical Defender critical: Real-time protection is OFF.
check 4: Healthy  Defender healthy: real-time protection on, tamper protection on, signatures current.
check 5: Healthy  Defender healthy: real-time protection on, tamper protection on, signatures current.
```

`defender-watchdog.log`, copied verbatim:

```text
[2026-10-16 08:49:36] DEFENDER ALERT [Critical] Real-time protection is OFF.
[2026-10-16 08:49:36] Defender recovered: Real-time protection is OFF. is no longer reported.
```
