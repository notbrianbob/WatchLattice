# WatchLattice.ScriptHostAudit — script host launch auditing

A lot of malware never drops an obvious program. A booby-trapped document or
web page starts PowerShell with an encoded command, `mshta` runs an HTML
application from a URL, `regsvr32` or `rundll32` load script from the
network, or `certutil` downloads the next stage. These are Windows' own
programs ("living off the land"), so the launch itself is often the only
trace.

Windows can record every process it starts in the Security log as event
**4688**, with the parent program and, optionally, the full command line.
This module reads those events and reports launches of script hosts and
similar programs, graded by who started them and what they were asked to do.

**Off by default.** Process creation auditing is off on most PCs, and this
module never turns it on. Turn auditing on first (below), then the module.

## Turning on process creation auditing

From an elevated prompt:

```powershell
# Record process creation (event 4688). The GUID form works in every Windows language.
auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable

# Include the command line in those events (recommended; without it the module
# can only grade launches by parent and folder).
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f

# Check it: "Process Creation   Success"
auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"
```

The same two settings in Group Policy (`gpedit.msc`):

- Computer Configuration > Windows Settings > Security Settings > Advanced
  Audit Policy Configuration > System Audit Policies > Detailed Tracking >
  **Audit Process Creation**: Success.
- Computer Configuration > Administrative Templates > System > Audit Process
  Creation > **Include command line in process creation events**: Enabled.

On a domain-joined PC, a domain policy can override local settings; ask
whoever manages it. To undo: `auditpol /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:disable`
and delete the `ProcessCreationIncludeCmdLine_Enabled` value.

Every process start then adds one event to the Security log, whose default
maximum size (20 MB) holds days to weeks of events on a typical PC. A larger
log keeps more history: `wevtutil sl Security /ms:209715200` (200 MB).

Then turn the module on in the dashboard's Settings tab, or in the hub's
`appsettings.json`: `"Modules": { "ScriptHostAudit": { "Enabled": true } }`.

## What it reads

| Source | What |
|---|---|
| Security log, event 4688 | Every 30 seconds, the process creation events newer than the last one it read, newest first, stopping at its bookmark. Only events whose new program is a watched script host are rendered and parsed. |
| Audit policy (`AuditQuerySystemPolicy`) | Whether the *Process Creation* subcategory records successes. |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit` | Whether `ProcessCreationIncludeCmdLine_Enabled` is on. |

The hub runs as its service under LocalSystem, which can read all three. Run
from an ordinary prompt, it can read none of them and says so.

The first check after the module is turned on starts from the newest event,
so earlier launches are not reported. After that, the position it has read to
is saved (`%LOCALAPPDATA%\ScanAlways\script-host-audit-state.json`), so
launches while the hub was stopped are reported when it starts, and none is
reported twice.

### Watched programs

`powershell.exe`, `pwsh.exe`, `powershell_ise.exe`, `mshta.exe`, `wscript.exe`,
`cscript.exe`, `rundll32.exe`, `regsvr32.exe`, `certutil.exe`, `bitsadmin.exe`,
`msbuild.exe`, `installutil.exe`, `regasm.exe`, `regsvcs.exe`, `cmstp.exe`,
`wmic.exe`, `msxsl.exe`, `hh.exe`, `forfiles.exe` and `scriptrunner.exe`.
`ScriptHosts` adds more (for example `python.exe`); `IncludeBuiltInScriptHosts: false`
uses only yours. Programs are matched by file name.

## How launches are graded

Each launch of a watched program gets reasons, in plain words:

| Reason | Examples |
|---|---|
| **Suspicious parent** | Started by an Office app (`winword.exe`, `excel.exe`, `outlook.exe`, ...), a browser (`msedge.exe`, `chrome.exe`, `firefox.exe`, ...), a PDF reader, a mail app, or another script host (`mshta.exe`, `wscript.exe`, `cscript.exe`). `SuspiciousParents` adds more; `IncludeBuiltInSuspiciousParents: false` uses only yours. |
| **Command line** | PowerShell `-EncodedCommand` in any abbreviation (`-e`, `-ec`, `-enc`, ...) or `-WindowStyle Hidden`; `FromBase64String`; downloading (`DownloadString`, `Net.WebClient`, `Invoke-WebRequest`, `Start-BitsTransfer`, ...); `Invoke-Expression`/`iex`; `javascript:` or `vbscript:`; `mshta` with a URL; `regsvr32` with `scrobj.dll` or `/i:` a URL; `rundll32` with `url.dll` and similar URL-opening exports; `certutil -urlcache`/`-decode`; `bitsadmin /transfer`; `cmstp` with an `.inf`; `wmic process call create` or a stylesheet. |
| **Unusual folder** | A Windows program (such as `powershell.exe` or `mshta.exe`) running from outside `C:\Windows\System32`, `SysWOW64`, `WinSxS` or the .NET Framework folder, for example a renamed-back copy in `%TEMP%`. |

The severity follows from them:

| Severity | When |
|---|---|
| Info | No reason. An ordinary launch. |
| Warning | One or more reasons of one kind, for example an encoded command, or Word starting PowerShell. |
| Critical | A suspicious parent **and** another reason, for example Word starting PowerShell with an encoded command. |

`MinimumSeverity` (default `Warning`) decides what is reported. Info launches
are counted in the module's debug log only, because PowerShell and rundll32
run all day on most PCs. Set it to `Info` to see every launch.

These are heuristics for "worth a look", not verdicts. Plenty of legitimate
software uses encoded commands or hidden windows, and plenty of malware
avoids every pattern above.

## What it reports

Event IDs are in [docs/event-log.md](../../docs/event-log.md#script-host-audit-11000).

| Code | Severity | When |
|---|---|---|
| `SCRIPT_HOST_LAUNCHED` | Warning or Critical (Info with `MinimumSeverity: Info`) | One launch: the program and its full path, the parent and its full path, the user, whether it was elevated and its integrity level, the time, the command line, the reasons, and the record ID and process IDs to find it in Event Viewer. Resource is `<parent path>\|<program path>`. When a command line was recorded, the message ends with a `Fingerprint: sha256:` line used to approve it. |
| `SCRIPT_HOST_LAUNCHES` | The highest of them | More than `MaxIndividualAlerts` launches in one check, summarized. Each one is still written to the module's log. |
| `PROCESS_AUDITING_OFF` | Info, standing | Windows is not recording process creation. Reported once, not every check, and cleared when auditing is turned on. |
| `COMMAND_LINE_NOT_RECORDED` | Info, standing | Events arrive without command lines. |
| `AUDIT_POLICY_UNAVAILABLE` | Info, standing | The audit policy could not be read. Launches are still read from the log. |
| `SECURITY_LOG_UNAVAILABLE` | Warning, standing | The Security log could not be read (for example the hub is not running as its service). |
| `EVENTS_MISSED` | Warning | The Security log was cleared (look for event 1102), records were overwritten before they were read, or more than `MaxEventsPerCheck` processes started between two checks. |
| `STATE_SAVE_FAILED` | Warning, standing | The bookmark could not be saved. |
| `STATE_UNREADABLE` | Warning | The saved bookmark could not be read; reading starts again from the newest event. |

## Allowing known launches

Two settings stop known-good launches from alerting. Both are read at hub
start, so changing them restarts the hub.

**`ApprovedLaunches`** is written by **Approve as baseline…** on the
dashboard's Alerts tab: select a single launch alert that shows a command line
and choose it. It adds one line,
`sha256:<SHA-256 of the exact command line> <parent path>|<program path>`, so
the same parent program starting the same script host with exactly that
command line raises no alert again. A different parent, program or command
line (even one extra space) still alerts. Remove the line in Settings to
revoke it.

**`AllowedLaunches`** is for launches whose command line changes each time,
such as an editor running scripts from temporary files. One rule per line,
`<parent>|<script host>|<command line>`, where `*` and `?` are wildcards, an
empty part matches anything, and each program part matches either the full
path or the file name:

```json
"AllowedLaunches": [
  "C:\\Users\\*\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe|powershell.exe|*",
  "C:\\Program Files\\Vendor\\agent.exe|powershell.exe|powershell.exe -NoProfile -File \"C:\\Program Files\\Vendor\\scripts\\*.ps1\""
]
```

Prefer full paths for the parent: a rule for just `Code.exe` also allows a
program someone else named `Code.exe`. An allowed or approved launch that
would otherwise have alerted is written to the Activity tab as one line, so
you can see what the rules hid.

## Read-only by design

It never changes the audit policy, the Security log or its size, and never
blocks, suspends or stops a process. Everything it reports has already run by
the time it reads the event; it tells you so you can look, it does not
prevent anything. Microsoft Defender's attack surface reduction rules (*Block
Office applications from creating child processes*, *Block JavaScript or
VBScript from launching downloaded executable content*, *Block execution of
potentially obfuscated scripts*) are what prevents these; the
[Defender watchdog](../WatchLattice.DefenderWatchdog/README.md) reports when
those rules are weakened.

## Configuration (hub `appsettings.json`, section `ScriptHostAudit`)

| Setting | Default | Meaning |
|---|---|---|
| `CheckIntervalSeconds` | `30` | Seconds between reads (minimum 10). |
| `IncludeBuiltInScriptHosts` | `true` | Watch the programs listed above. |
| `ScriptHosts` | `[]` | More program file names to watch. |
| `IncludeBuiltInSuspiciousParents` | `true` | Treat the built-in Office, browser, reader and script host parents as suspicious. |
| `SuspiciousParents` | `[]` | More parent file names to treat as suspicious. |
| `AllowedLaunches` | `[]` | `parent\|host\|command line` wildcard rules that never alert. |
| `ApprovedLaunches` | `[]` | Exact launches approved from the dashboard. |
| `MinimumSeverity` | `Warning` | `Info`, `Warning` or `Critical`: the lowest graded launch that is reported. |
| `CommandLineInAlerts` | `true` | Copy command lines into alerts. See below. |
| `MaxIndividualAlerts` | `5` | More launches than this in one check are summarized in one alert. |
| `MaxChangesPerAlert` | `20` | At most this many launches are listed in a summary. |
| `MaxEventsPerCheck` | `5000` | At most this many process creation events are read per check; the oldest of a larger burst are skipped and reported as `EVENTS_MISSED`. |
| `StatePath` | `null` | Bookmark file. Null picks `%LOCALAPPDATA%\ScanAlways\script-host-audit-state.json`. |
| `AlertLogPath` | `null` | Rolling log of everything it reported. Null picks `%LOCALAPPDATA%\ScanAlways\script-host-audit.log`. |

**Command lines in alerts.** Only administrators can read the Security log,
but alerts also go to the tray feed and the Windows Application log, which
every user on the PC can read. Command lines sometimes carry passwords or
tokens. On a PC shared with people who should not see each other's command
lines, set `CommandLineInAlerts` to `false`: alerts then give the command
line's length and the record ID to look it up, and approving still works.

## Run

With auditing and the module on, from any prompt:

```powershell
# A plain launch: Info, so not reported with the default MinimumSeverity.
powershell.exe -NoProfile -Command "Get-Date"

# A harmless encoded command (it runs Get-Date): a Warning within 30 seconds.
powershell.exe -NoProfile -EncodedCommand RwBlAHQALQBEAGEAdABlAA==
```

The dashboard shows *Suspicious script host launch* with the command line and
*passes an encoded command*. The event is in Event Viewer under Windows Logs >
Security, event 4688, at the record ID the alert names.

## Honest limits

- **Nothing is reported unless Windows records it.** With process creation
  auditing off, the module only says so. With command lines off, it can't see
  encoded commands or URLs.
- **After the fact.** It reads the log every 30 seconds; the process has run
  (and may have finished) by then. It is a detector, not a blocker.
- **File names, not identities.** A copy of PowerShell renamed to
  `notepad.exe` is not watched (the folder check only catches Windows'
  programs under their own names). Parent names can be spoofed the same way,
  which is why full-path allow rules are safer.
- **In-process script engines are invisible.** Malware that hosts PowerShell
  or a script engine inside its own process (no `powershell.exe` launch)
  creates no 4688 event for it. PowerShell's own Script Block Logging
  (Microsoft-Windows-PowerShell/Operational, event 4104) sees more; this
  module does not read it.
- **Command lines can be disguised.** Quoting tricks, caret escapes,
  environment variables and variable concatenation can hide every pattern
  above from a text match. The grading catches the common, lazy cases.
- **Someone with administrator rights can turn auditing off or clear the
  log.** Turning auditing off is reported (as Info, once); clearing the log is
  reported as `EVENTS_MISSED`. Forwarding the Security log to another machine
  is what protects the record.
- **A busy PC can outrun it.** More than `MaxEventsPerCheck` process starts
  in 30 seconds skips the oldest of them, and a small Security log can
  overwrite events while the hub is stopped; both are reported.
- **Overhead is not measured yet.** Each check renders only new events whose
  program is watched; on an idle PC that is a handful per check.
