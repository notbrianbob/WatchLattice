# The dashboard

The tray companion's window is the WatchLattice dashboard. Open it by
double-clicking the tray icon or choosing **Open dashboard** from its menu.
It has four tabs:

| Tab | What it shows |
|---|---|
| **Overview** | Hub connection, and every module with its running state, whether it is turned on in the settings, and what it does. **Turn on…/Turn off…** and **Change settings…** open the settings editor. Below the list, the hub's latest [daily summary](#the-daily-summary). |
| **Alerts** | Recent alerts from every module, newest first, with full details for the selected one. Repeats of the same alert share one row with a count, and you can acknowledge or dismiss rows (see [grouping, acknowledging and dismissing alerts](#grouping-acknowledging-and-dismissing-alerts)). **Export…** saves the list as CSV or JSON (see [exporting alerts](#exporting-alerts)). For persistence alerts, the **Verification** column, **Verify entry** and **View verification details…** (see [verifying changed scheduled tasks](../src/WatchLattice.Persistence/README.md#verifying-changed-scheduled-tasks)). |
| **Activity** | The hub's own recent log: modules starting, stopping, failing and recovering, checks that could not run, feed and Event Log problems. Filter by level or text. |
| **Settings** | Every setting the hub reads, its current value, and whether it comes from appsettings.json or is the built-in default. |

The dashboard runs as you, with your normal rights, and cannot change
anything by itself. **Verify entry** only reads: it checks a scheduled task,
its COM registration and its files with your rights and saves the result in
your own profile.

## Grouping, acknowledging and dismissing alerts

A busy autostart entry can raise the same alert many times. On the Alerts tab,
**Group repeats** (on by default) shows every alert with the same module, code
and resource (the entry, file or setting it is about) as one row:

- **Last seen** and the details are from the newest alert. **Severity** is the
  highest of all of them, so a repeat that was once a warning never reads as
  Info.
- **Count** is how many times it was seen. The details pane lists the earlier
  ones under *Repeats*. Turn **Group repeats** off to see every alert on its
  own row again.
- **Status** is *New* until you review it. A grouped row that you reviewed
  before it repeated shows how many are new, for example *2 new*.

Select one or more rows (Ctrl+A selects all) and choose:

| Action | What it does |
|---|---|
| **Acknowledge** | Marks the row as seen. It stays in the list, greyed out. |
| **Dismiss** (or the Delete key) | Hides the row. **Show dismissed** brings hidden rows back into the list, where **Show again** un-hides them. |
| **Acknowledge all** | Acknowledges every new row in the list. |

Neither is permanent: when the same alert happens again, its row is *New*
again and shows up even if you dismissed it. The tab's title shows how many
rows are new.

This only changes what the dashboard shows you. The hub, the alert feed and
the [Windows Event Log](event-log.md) still keep every alert, with the same
event IDs, and new warnings still raise a notification. What you acknowledged
or dismissed is kept for your account only, in
`%LOCALAPPDATA%\ScanAlways\alert-review.json` (the newest 2,000 rows), so it
needs no administrator permission and survives restarts and updates. Deleting
that file makes every row new again.

## Approving entries as known-good

**Approve as baseline…** on the Alerts tab is for an autostart entry or
browser extension you have checked and expect to see again. Select an
*Autostart entry added* or *changed* alert (or the verification alert after
it), or a *New browser extension* alert, and choose it. Windows asks for
administrator permission, and the [settings editor](#changing-settings-needs-an-administrator)
opens with the approval staged as one new line:

- for an autostart entry, in the Persistence page's **Approved entries**: that
  entry with exactly its current value no longer alerts; any other value does;
- for an extension, in the Browser Extension Watchdog page's **Ignored
  extension IDs**: that extension no longer alerts in any profile.

**Save and restart hub** saves it, and the dashboard marks those alerts
acknowledged. The alert's details show *Approved* under *Baseline* from then
on. To revoke an approval, remove its line in the editor and save. Approvals
are part of the hub's settings, not your review file, so they apply to every
account and only an administrator can change them. See
[approving entries](../src/WatchLattice.Persistence/README.md#approving-entries-as-known-good)
for exactly what is matched.

## Exporting alerts

**Export…** on the Alerts tab saves the rows the list shows, as it shows them,
to a file you choose: grouped or one row per alert as **Group repeats** is
set, and dismissed rows only when **Show dismissed** is on. Pick *CSV* for a
spreadsheet or *JSON* for scripts and tickets.

| Column (CSV) / field (JSON) | Meaning |
|---|---|
| `LastSeenUtc`, `FirstSeenUtc` | Newest and oldest occurrence in the row, UTC, ISO 8601. The same for an ungrouped row. |
| `Count` | How many alerts the row stands for. |
| `Severity`, `Module`, `Code`, `Title`, `Message`, `Resource` | From the newest occurrence; severity is the highest of the row. |
| `Status`, `NewCount` | Your review state, as the Status column shows it (*New*, *2 new*, *Acknowledged*, *Dismissed*). |
| `AlertId` | The newest occurrence's ID, the same one the Event Log entry carries. |
| `EventId` | Its [Event Log ID](event-log.md#event-ids). |

The JSON file also has `version` (1), `exportedAt`, `grouped`, the row and
alert counts, and for each row an `occurrences` list with every alert's ID,
time, severity and title. CSV files are UTF-8 with a byte order mark, so
Excel shows non-English file names correctly.

Alert text can contain file and task names that whoever created them chose.
So that a spreadsheet never runs one as a formula, a CSV cell that would
start with `=`, `+`, `-`, `@`, a tab or a line break gets a leading `'`
(for example `'=cmd|…`). The JSON file is unchanged text.

The export only reads. It runs as you, holds only what the dashboard already
shows, and is written where you save it; nothing is sent anywhere. Keep it
somewhere private: it can list paths and program names from your PC.

### From the command line

```powershell
cd 'C:\Program Files\WatchLattice\Hub'
.\ScanAlways.Protection.Service.exe --export-alerts $env:USERPROFILE\alerts.csv
.\ScanAlways.Protection.Service.exe --export-alerts alerts.json --group
.\ScanAlways.Protection.Service.exe --export-alerts - --format json   # to standard output
```

It exports the whole alert history in the feed, including dismissed rows,
one row per alert unless you add `--group`. The format comes from
`--format csv|json`, or else from the file name (`.json` is JSON, anything
else CSV). Status is the review state of the account running it. Only the
account the installer gave the feed to (and SYSTEM) can read the feed, so run
it as that user; it needs no administrator rights. Exit codes: `0` written,
`1` the feed could not be read, `2` bad arguments or the file could not be
written.

## The daily summary

Once a day the hub raises one **Daily summary** alert (Info, code
`DAILY_SUMMARY`, [Event ID 1007](event-log.md#hub-1000)) about the 24 hours
before it: how many alerts each module raised, by severity, and which alerts
repeated most. The Overview tab shows the newest one, and every summary is
also in the Alerts list (they group into one row) and the Event Log. Being
Info, it never raises a notification. Earlier summaries are not counted.

```text
5 alerts in the 24 hours since 2026-10-17 08:00 +02:00: 2 critical, 3 warning.

By module:
  Persistence: 3 (1 critical, 2 warning)
  Canary: 1 (1 critical)
  DefenderWatchdog: 1 (1 warning)

Most repeated:
  3 × Persistence: Autostart entry changed (Run\Updater)
```

The counts come from the hub's alert history, which keeps the newest
`Alerts:HistoryLimit` alerts (200 by default). On a very busy day older alerts
roll out of it, and the summary says so and from when it counts; the Windows
Event Log still has all of them.

If the PC was off or asleep at the usual time, the missed summary is written
about a minute after the hub next starts. A new install waits for the first
scheduled time. Nothing is emailed or sent anywhere.

| Setting (`Alerts:DailySummary`) | Default | Meaning |
|---|---|---|
| `Enabled` | `true` | Write the daily summary. |
| `Hour` | `8` | Hour of the day, `0` to `23` in the PC's local time. Larger values mean `23`. If daylight saving skips that hour, the summary is an hour later that day. |
| `TopRepeatedAlerts` | `5` | How many of the most repeated alerts to name, at most 20. `0` leaves the list out. |

## Changing settings needs an administrator

The hub's settings live in `Hub\appsettings.json` in the install folder
(`C:\Program Files\WatchLattice` by default), which only administrators can
change. That is on purpose: the hub runs as LocalSystem, so whoever can edit
its settings decides what it does.

So the first time you choose **Change settings…**, **Turn on…/Turn off…**, or
double-click a setting, Windows asks for administrator permission. If you
approve, the **settings editor** opens as its own elevated window, and you can
make as many changes as you like there without being asked again. If you
decline, nothing changes and the dashboard stays as it was. On a standard
account, Windows asks for an administrator's password instead, so only an
administrator can change settings.

In the editor:

- Each module and hub area has its own page. Pages with unsaved changes are
  marked with a dot.
- Values are checked as you type: numbers must be whole numbers (or numbers)
  that are 0 or more, choices come from a list, and lists take one entry per
  line. A value that is not set shows the hub's built-in default.
- **Save and restart hub** lists your changes and asks you to confirm. The hub
  then:
  1. checks the new settings again, the same way, and refuses anything that
     does not fit,
  2. saves a copy of the current file in `Hub\settings-backups\` (the newest
     10 are kept),
  3. replaces `appsettings.json` in one step, so it is never half-written,
  4. restarts the `ScanAlways Protection` service, and
  5. if the hub does not keep running with the new settings, puts the backup
     back and starts it again.
- **Undo all changes** goes back to what is saved. Closing with unsaved
  changes asks first.

The editor keeps the rest of the file as it is, including settings it does not
know about. It warns about keys in a WatchLattice section that this version
does not use, such as a misspelt name.

### Settings the dashboard does not change

Two settings are shown but locked, and saving refuses any change to them:

| Setting | Why |
|---|---|
| `Updater:Repository` | Where updates come from. A settings change must never be able to point the updater at another repository. |
| `Alerts:FeedPath` | The installer gave only your account read access to the feed folder. Moving the feed would disconnect the tray. |

An administrator can still change them by editing `appsettings.json` and
restarting the service.

### From the command line

The editor uses two hub commands, which also work by hand:

```powershell
cd 'C:\Program Files\WatchLattice\Hub'
.\ScanAlways.Protection.Service.exe --describe-settings   # the schema and current file, as JSON; no rights needed
.\ScanAlways.Protection.Service.exe --apply-settings      # from an administrator prompt
```

`--apply-settings` reads the new settings from `appsettings.json.pending` in
the hub folder, never from a path you pass it, because only administrators
can write that folder. Its exit codes are `0` saved, `20` nothing changed,
`21` refused (the reasons are printed), `22` the hub did not keep running so
the previous settings were restored, and `1` any other failure.

## How the Activity tab works

The hub copies its own log lines (Information and above, following the usual
`Logging:LogLevel` settings) into `alerts.json.activity.json`, next to the
alert feed, keeping the newest 500 across restarts. Like the feed, it is
display-only: only the hub can write it and only the tray user can read it,
and the dashboard never runs anything it contains. Lines can contain file
paths. It is a convenience, not an audit log; the Windows Event Log keeps
every alert (see [Event Log alerts](event-log.md)).

## Without the installer

The dashboard finds the hub through the release layout: `..\Hub\` next to the
tray's own folder, as the installer and the release zip set it up. A tray
started from somewhere else still shows status, alerts and activity, and its
Settings tab explains that it cannot reach the hub's settings. Edit
`appsettings.json` next to the hub by hand in that case.

## What needs checking on Windows

CI installs a release-shaped package on a Windows runner and runs
`--describe-settings` and `--apply-settings` against the real service,
including a refused change to a locked setting. The windows themselves
(the administrator prompt, the editor, and the dashboard tabs) can only be
checked by hand (for the other modules' hand checks, see
[what to check by hand on Windows](windows-checks.md)):

1. Open the dashboard. Overview lists every module; Activity shows the hub's
   startup lines; Settings lists every section.
2. Choose **Turn off…** on the decoy. Approve the prompt. The editor opens on
   the Modules page with the decoy switched off and one unsaved change. Save.
   The hub restarts, Overview shows the decoy as Disabled and Off, and
   `Hub\settings-backups` has one file.
3. Choose **Change settings…** again and decline the prompt: nothing opens and
   nothing changes.
4. In the editor, type `abc` into a number: the field explains the problem and
   Save stays disabled.
5. On a standard (non-administrator) account, the prompt asks for an
   administrator's password.
6. Alerts: after Windows reschedules `SvcRestartTask` (or after
   `ENTRY_CHANGED` for any task), the alert's Verification column shows the
   automatic outcome and a `VERIFY_*` alert follows. A reschedule alone shows
   as Info, titled *schedule timing only*, with no balloon. **Verify entry** shows
   *Verifying…*, then *(manual)*, with no administrator prompt. **View
   verification details…** lists both runs; the report shows the logged change
   under *At alert time* and the DLL, hash and signer under *Current state*.
7. Alerts: repeated *Autostart entry changed* alerts for one task show as one
   row with a count. **Acknowledge** greys it out; **Dismiss** hides it and the
   count line says one row is hidden. After the next change to that task the
   row is back as *1 new*. Close and reopen the dashboard: the review is kept.
   Turn off **Group repeats**: each alert has its own row again.
8. Alerts: **Export…**, save as CSV, and open it in Excel: the columns match
   [exporting alerts](#exporting-alerts), non-English names look right, and a
   message starting with `=` shows as text, not a formula. Save again as JSON
   with **Group repeats** off: there is one row per alert. With **Show
   dismissed** off, dismissed rows are not in the file.
9. Overview: set `Alerts:DailySummary:Hour` to the next hour and wait for
   it. *Latest daily summary* shows the counts, and Event Viewer has event
   1007 from `WatchLattice`. Restart the PC the next day after that hour has
   passed: a missed summary is written about a minute after the hub starts.
