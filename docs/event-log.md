# Alerts in the Windows Event Log

Every shared alert (the same ones the tray shows) is also written to the
Windows **Application** log under the event source **`WatchLattice`**. That
makes WatchLattice visible to Event Viewer, Windows Event Forwarding (WEF)
subscriptions, and SIEM agents that already collect the Application log,
without anything new listening on the network.

Each alert type has its own stable event ID, so a rule can key on
`Source = WatchLattice` and an ID instead of parsing text.

## Turning it on or off

On by default. In the hub's `appsettings.json`:

```json
"Alerts": {
  "EventLog": {
    "Enabled": true,
    "MinimumSeverity": "Info"
  }
}
```

| Setting | Default | Meaning |
|---|---|---|
| `Enabled` | `true` | Write alerts to the Application log. The tray feed is unaffected either way. |
| `MinimumSeverity` | `Info` | `Info`, `Warning` or `Critical`. Alerts below it stay out of the Event Log (they still reach the tray). |

`Alerts:Enabled` (the tray feed) and `Alerts:EventLog:Enabled` are independent.

## Registering the event source

Creating the `WatchLattice` source needs administrator rights once per machine.
The hub does it itself at startup when it runs as its Windows service
(LocalSystem) or from an elevated prompt. After that, any account can write
to it.

If the hub starts without admin rights and the source does not exist yet,
monitoring carries on normally, nothing is written to the Event Log, and the
tray shows one **Event Log alerts unavailable** warning (`EVENTLOG_UNAVAILABLE`)
saying so. To register the source by hand, from an elevated PowerShell:

```powershell
New-EventLog -LogName Application -Source WatchLattice -MessageResourceFile "$env:windir\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll"
```

The source uses the in-box .NET Framework message file, which renders each
entry's text in Event Viewer and does not move if WatchLattice is reinstalled
somewhere else. If the registered message file is missing, the hub
re-registers the source at its next elevated start.

To remove the source (for example after uninstalling), from an elevated
PowerShell: `Remove-EventLog -Source WatchLattice`.

## What an entry contains

| Field | Value |
|---|---|
| Log | `Application` |
| Source | `WatchLattice` |
| Event ID | From the tables below |
| Level | Critical alert → **Error**, Warning → **Warning**, Info → **Information** |
| Task category | None |

The entry's event data (the `<EventData>` elements in the XML view, and what
WEF forwards) holds these strings, in this order:

| # | Data |
|---|---|
| 1 | Readable text: title, message, module, alert code, severity, resource (when there is one), alert ID and time. This is what Event Viewer's General tab shows. |
| 2 | Module ID, e.g. `DefenderWatchdog` |
| 3 | Alert code, e.g. `REALTIME_OFF` |
| 4 | Severity: `Info`, `Warning` or `Critical` |
| 5 | Title |
| 6 | Message |
| 7 | Resource (a path, rule, profile or setting), or empty |
| 8 | Alert ID (a GUID, the same one the tray feed uses) |
| 9 | Time the alert was raised, UTC, ISO 8601 |

New fields are only ever appended. Alert text can include file names chosen by
whoever created the file, so treat it as data: control characters are replaced
with spaces, and nothing in an entry is ever executed.

Example query for the last day's warnings and errors:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Application'; ProviderName = 'WatchLattice'; Level = 2, 3; StartTime = (Get-Date).AddDays(-1) }
```

## Event IDs

IDs are grouped by module in blocks of 1000. Within a block:

- **1–499**: a specific alert, listed below.
- **501–899**: recovery. When a standing problem clears, its
  `<CODE>_CLEARED` alert uses the problem's ID **+ 500** (for example
  `REALTIME_OFF` is 3006, so `REALTIME_OFF_CLEARED` is 3506). Recovery events
  are always Information.
- **900 / 901 / 902**: an alert code this version does not classify yet,
  at Info / Warning / Critical. Alerts from an unknown module use 9900–9902.

An ID never changes meaning once released, and retired IDs are not reused.
[`AlertEventIds`](../src/WatchLattice.Common/Alerts/AlertEventIds.cs) is the
source of truth, and a test fails if this page and the code disagree.

### Hub (1000)

| ID | Code | Level | Meaning |
|---|---|---|---|
| 1001 | `MODULE_FAILED` | Warning | A module threw and is being restarted (or restart is disabled). Raised under the failing module's ID. |
| 1002 | `MODULE_FINISHED` | Warning | A module stopped without a shutdown request. Raised under that module's ID. |
| 1003 | `ALERT_HISTORY_UNAVAILABLE` | Warning | The previous alert history could not be restored at startup. |
| 1004 | (none) | Warning | Alerts arrived faster than the Event Log accepted them and some were skipped; data string 2 is how many. They remain in the tray history and module logs. |
| 1005 | `EVENTLOG_UNAVAILABLE` | Warning | The event source is not registered and could not be registered. Shown in the tray only, since the log can't be written. |
| 1006 | `EVENTLOG_WRITE_FAILED` | Warning | Writing to the Event Log failed. Shown in the tray; written to the log if writing recovers. |

### Canary (2000)

| ID | Code | Level | Meaning |
|---|---|---|---|
| 2001 | `CANARY_MODIFIED` | Error | A canary file was written to or replaced. |
| 2002 | `CANARY_DELETED` | Error | A canary file was deleted. |
| 2003 | `CANARY_RENAMED` | Error | A canary file was renamed (ransomware often appends an extension). |

### Defender watchdog (3000)

Standing findings have a `_CLEARED` recovery event at ID + 500.

| ID | Code | Level | Meaning |
|---|---|---|---|
| 3001 | `STATUS_UNAVAILABLE` | Warning | Defender status could not be read. |
| 3002 | `NOT_RUNNING` | Error | Defender antivirus is not running. |
| 3003 | `PASSIVE_MODE` | Warning | Defender is in passive mode. |
| 3004 | `SERVICE_DISABLED` | Error | The Defender antimalware service is disabled. |
| 3005 | `ANTIVIRUS_DISABLED` | Error | Defender antivirus is disabled. |
| 3006 | `REALTIME_OFF` | Error | Real-time protection is off. |
| 3007 | `BEHAVIOR_MONITOR_OFF` | Warning | Behavior monitoring is off. |
| 3008 | `IOAV_OFF` | Warning | Scanning of downloads and attachments is off. |
| 3009 | `ON_ACCESS_OFF` | Warning | On-access protection is off. |
| 3010 | `TAMPER_PROTECTION_OFF` | Warning or Error | Tamper protection is off (Error when `TamperProtectionOffIsCritical`). |
| 3011 | `SIGNATURES_STALE` | Warning | Signatures are older than `MaxSignatureAgeHours`. |
| 3012 | `SIGNATURES_VERY_STALE` | Error | Signatures are older than `CriticalSignatureAgeHours`. |
| 3013 | `SIGNATURE_DATE_UNKNOWN` | Information | Defender did not report when signatures were updated. |
| 3014 | `STATE_SAVE_FAILED` | Warning | The watchdog could not save its baseline. |
| 3015 | `STATE_UNREADABLE` | Warning | The watchdog's saved baseline could not be read. |
| 3020 | `SETTINGS_UNAVAILABLE` | Warning | Defender settings (exclusions, ASR, cloud) could not be read. |
| 3021 | `EXCLUSIONS_HIDDEN` | Warning | Defender hides its exclusion list from this account. |
| 3022 | `CLOUD_PROTECTION_OFF` | Warning | Cloud-delivered protection is off. |
| 3023 | `BLOCK_AT_FIRST_SEEN_OFF` | Warning | Block at first sight is off. |
| 3024 | `BROAD_EXCLUSION:*` | Warning | A broad exclusion exists (a whole drive, a common extension, a common process). The code ends with the exclusion. |
| 3030 | `EXCLUSION_ADDED` | Warning | A new Defender exclusion. |
| 3031 | `EXCLUSIONS_ADDED` | Warning | Several new exclusions, summarized. |
| 3032 | `EXCLUSION_REMOVED` | Information | A Defender exclusion was removed. |
| 3033 | `EXCLUSIONS_REMOVED` | Information | Several exclusions removed, summarized. |
| 3034 | `ASR_RULE_WEAKENED` | Warning | An attack surface reduction rule was weakened or turned off. |
| 3035 | `ASR_RULES_WEAKENED` | Warning | Several ASR rules weakened, summarized. |
| 3036 | `ASR_RULE_STRENGTHENED` | Information | An ASR rule was strengthened. |
| 3037 | `CLOUD_BLOCK_LEVEL_LOWERED` | Warning | The cloud block level was lowered. |
| 3038 | `CLOUD_BLOCK_LEVEL_RAISED` | Information | The cloud block level was raised. |
| 3039 | `SETTINGS_BASELINE_CREATED` | Information | First settings baseline recorded. |

### Firewall watchdog (4000)

Standing findings have a `_CLEARED` recovery event at ID + 500.

| ID | Code | Level | Meaning |
|---|---|---|---|
| 4001 | `STATUS_UNAVAILABLE` | Warning | Firewall status could not be read. |
| 4002 | `PROFILE_DISABLED_DOMAIN` | Error or Warning | The Domain profile is off (Error when it may be in use). |
| 4003 | `PROFILE_DISABLED_PRIVATE` | Error or Warning | The Private profile is off. |
| 4004 | `PROFILE_DISABLED_PUBLIC` | Error or Warning | The Public profile is off. |
| 4005 | `INBOUND_DEFAULT_ALLOW_DOMAIN` | Error or Warning | The Domain profile allows unsolicited inbound by default. |
| 4006 | `INBOUND_DEFAULT_ALLOW_PRIVATE` | Error or Warning | The Private profile allows unsolicited inbound by default. |
| 4007 | `INBOUND_DEFAULT_ALLOW_PUBLIC` | Error or Warning | The Public profile allows unsolicited inbound by default. |
| 4008 | `INBOUND_DEFAULT_CHANGED_DOMAIN` | Warning or Information | The Domain default inbound action changed (Warning when to Allow). |
| 4009 | `INBOUND_DEFAULT_CHANGED_PRIVATE` | Warning or Information | The Private default inbound action changed. |
| 4010 | `INBOUND_DEFAULT_CHANGED_PUBLIC` | Warning or Information | The Public default inbound action changed. |
| 4011 | `RULES_UNAVAILABLE` | Warning | Inbound rules could not be read (only with `MonitorInboundAllowRules`). |
| 4012 | `INBOUND_ALLOW_RULE_ADDED` | Warning | A new inbound allow rule. |
| 4013 | `INBOUND_ALLOW_RULES_ADDED` | Warning | Several new inbound allow rules, summarized. |
| 4014 | `RULE_BASELINE_CREATED` | Information | First inbound rule baseline recorded. |
| 4015 | `STATE_SAVE_FAILED` | Warning | The watchdog could not save its baseline. |
| 4016 | `STATE_UNREADABLE` | Warning | The watchdog's saved baseline could not be read. |

### Persistence auditor (5000)

| ID | Code | Level | Meaning |
|---|---|---|---|
| 5001 | `BASELINE_CREATED` | Information | First autostart baseline recorded. |
| 5002 | `ENTRY_ADDED` | Warning | A new Run/RunOnce value, Startup file or scheduled task. |
| 5003 | `ENTRY_CHANGED` | Warning or Information | An existing autostart entry changed. Information only when a scheduled task's trigger timing is all that changed and automatic verification follows; that 5010–5012 event carries the assessment. |
| 5004 | `ENTRY_REMOVED` | Information | An autostart entry was removed. |
| 5005 | `SOURCE_UNAVAILABLE` | Warning | An autostart location could not be read. |
| 5006 | `SOURCE_RECOVERED` | Information | That location is readable again. |
| 5010 | `VERIFY_PASSED` | Information | Automatic verification of a changed scheduled task: every check passed. Evidence, not proof the task is harmless. |
| 5011 | `VERIFY_NEEDS_REVIEW` | Warning | Automatic verification: an unknown handler, unfamiliar or missing signature, missing file, or a check that could not be completed. |
| 5012 | `VERIFY_SUSPICIOUS` | Error | Automatic verification: the program or COM class was changed, the task gained highest privileges or now runs as SYSTEM or Administrators, a per-user registration overrides the machine one, a signature is invalid, or the task differs from the trusted baseline. |
| 5013 | `VERIFICATION_STORE_FAILED` | Warning | Verification findings could not be saved, or an unreadable findings file was moved aside. |

### Updater (6000)

| ID | Code | Level | Meaning |
|---|---|---|---|
| 6001 | `UPDATE_AVAILABLE` | Information | A newer WatchLattice release is available. |

### Install integrity check (7000)

Both findings have a `_CLEARED` recovery event at ID + 500. See
[install integrity check](install-integrity.md).

| ID | Code | Level | Meaning |
|---|---|---|---|
| 7001 | `INSTALL_MODIFIED` | Error or Warning | WatchLattice's installed files differ from the release: a file changed or is missing, or an unexpected program file is present (Error when an `.exe` or `.dll` changed or appeared). |
| 7002 | `MANIFEST_UNAVAILABLE` | Warning | The release's file list next to the hub is missing or unreadable, so the install cannot be checked. |

## Relationship to the hub's own log messages

Separately from these alerts, .NET's service host writes the hub's own
warnings and errors (for example a module's stack trace) to the Application
log under the source `ScanAlways.Protection.Service`. Those are diagnostics
with no stable IDs. Use the `WatchLattice` source for detection rules.

## Limits

- The Event Log copy is written by the same hub process that raises the
  alert. Someone with administrator rights can stop the hub or clear the log;
  forwarding with WEF to another machine is what protects the record.
- Alerts are queued (up to 256) and written in the background, so a crash can
  lose the last few. A flood beyond that keeps the earliest alerts and writes
  one 1004 entry with the number skipped.
- Identical alerts within five seconds are coalesced before they reach the
  Event Log, as they are for the tray.
- Alert history restored at hub startup is not written again.
