# WatchLattice.BrowserExtensionWatchdog — browser extension watchdog

A browser extension can read and change every page you open, so a malicious
one can steal session cookies and passwords, inject ads, swap search results,
or watch what you type. They rarely arrive by the user clicking "Add":
adware and info-stealers install them by writing a policy that force-installs
an extension, by registering one in the registry so the browser picks it up,
by dropping one into the profile, or by loading one unpacked.

This module inventories the extensions in every Edge, Chrome and Firefox
profile on the PC, and the policies and registrations that install them from
outside the browser. It records a baseline on its first check, then reports
each extension or policy added or removed, with the extension's ID, name,
version, browser, profile, user, how it was installed, and whether it was
installed by policy.

## What it reads

| Browser | Where | What |
|---|---|---|
| Microsoft Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data` of every user | Each profile (`Default`, `Profile 1`, ...) named from `Local State`; installs from `extensions.settings` in the profile's `Preferences` and `Secure Preferences`; names and versions from the installed `Extensions\<id>\<version>\manifest.json` (and its default locale) when the preferences don't carry them. |
| Google Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data` of every user | The same as Edge. |
| Mozilla Firefox | `%APPDATA%\Mozilla\Firefox\profiles.ini` of every user | Each listed profile's `extensions.json`, Firefox's own add-on database. Only extensions: themes, dictionaries and language packs are left out. |
| Policies and registrations | `HKLM` and each signed-in user's `HKEY_USERS\<SID>` | `Software\Policies\Microsoft\Edge` and `Software\Policies\Google\Chrome`: `ExtensionInstallForcelist` and the `force_installed` and `normal_installed` entries of `ExtensionSettings`. `Software\Policies\Mozilla\Firefox`: `Extensions\Install` and `ExtensionSettings`. External install registrations other programs write: `Software\Google\Chrome\Extensions`, `Software\Microsoft\Edge\Extensions` and `Software\Mozilla\Firefox\Extensions`, and their `Wow6432Node` copies. |

Users come from the ProfileList (local, domain and Entra ID accounts). The
hub runs as its service under LocalSystem, so it can read every user's
folders without the browsers running; it never starts a browser.

Extensions that are part of the browser itself are left out: Chromium's
component extensions (such as the PDF viewer) and Firefox's built-in and
system add-ons. Extensions the browser installs by default (such as Google
Docs Offline) are included, and labelled as such.

### How an extension was installed

Each alert says how the browser recorded the install:

| Source | Chromium | Firefox |
|---|---|---|
| From the store | Installed from the Chrome Web Store or Edge Add-ons | Installed from addons.mozilla.org or about:addons |
| By policy | A force-install or install policy | `installTelemetryInfo.source` is `enterprise-policy` |
| By another program | Registered in the registry or by an external preferences file | In a shared folder or registry location, or dropped into the profile (`sideload`) |
| Unpacked | Loaded unpacked in developer mode, or from the command line | Loaded temporarily from about:debugging |
| By default | Registered with `was_installed_by_default` or `was_installed_by_oem` | (none) |
| Other | Installed from a file or website outside the store, or a location this version doesn't know | Any other source |

Every extension alert also states `Installed by policy: yes` or `no`.

## What it reports

| Alert | When | Severity |
|---|---|---|
| `BASELINE_CREATED` | First check: how many profiles and extensions each browser has, and the install policies and registrations. An inventory, not a safety verdict. | Info |
| `EXTENSION_ADDED` | An extension appeared in a profile seen before. One alert each, up to `MaxIndividualAlerts` per check. | Warning (Info for an extension the browser installs by default) |
| `EXTENSIONS_ADDED` | More than `MaxIndividualAlerts` appeared in one check: one summary listing up to `MaxChangesPerAlert`. | Warning |
| `EXTENSION_REMOVED`, `EXTENSIONS_REMOVED` | An extension was removed (when `ReportRemovals` is on). | Info |
| `POLICY_EXTENSION_ADDED`, `POLICY_EXTENSIONS_ADDED` | A policy or registration that installs an extension was added, for the machine or a user. Expected on a managed PC; on a personal one this is how adware keeps an extension installed. | Warning |
| `POLICY_EXTENSION_REMOVED`, `POLICY_EXTENSIONS_REMOVED` | One was removed. | Info |
| `PROFILE_ADDED` | A browser profile seen for the first time (a new profile, a new user, or a browser installed later), with the extensions it already has. They are recorded without an alert each. | Info |
| `PROFILE_REMOVED` | A profile seen before is gone, with the extensions it had. | Info |
| `PROFILE_UNREADABLE` | A profile, or a browser's list of profiles, could not be read. Its last inventory is kept, so a read error is never reported as a removal. Standing. | Warning |
| `POLICY_UNAVAILABLE` | Policies could not be read. Standing. | Warning |
| `STATE_SAVE_FAILED`, `STATE_UNREADABLE` | The inventory could not be saved, or the saved one could not be read and was started over. | Warning |

Standing alerts are reported when they appear and again (as Info, with
`_CLEARED`) when they clear. Event IDs are 10001 to 10015; see
[Event Log alerts](../../docs/event-log.md#browser-extension-watchdog-10000).
Alerts also go to the tray and the dashboard, a `BROWSER EXTENSION` line in
`%LOCALAPPDATA%\ScanAlways\browser-extension-watchdog.log`, and the hub's log.

A user whose folders can't be read (signed out of a roaming profile, or the
hub running without administrator rights) is not a change: their last
inventory is kept and compared when they can be read again. A signed-out
user's registry hive is not loaded, so their per-user policies are kept the
same way.

## Read-only by design

The watchdog opens every file and registry key for reading only, with
sharing that lets a running browser keep writing. It never disables, removes
or changes an extension, a profile, a preference or a policy, and never
launches anything. To remove an extension, use the browser's own extensions
page (`edge://extensions`, `chrome://extensions`, `about:addons`), and check
`edge://policy` or `chrome://policy` for one a policy keeps installing.

## Configuration (hub `appsettings.json`, section `BrowserExtensionWatchdog`)

| Setting | Default | Meaning |
|---|---|---|
| `CheckIntervalSeconds` | `300` | Seconds between checks (minimum 60). Each check reads a few small files per browser profile and a few registry keys. |
| `WatchEdge`, `WatchChrome`, `WatchFirefox` | `true` | Which browsers to watch. Turning one off forgets its inventory, so turning it back on starts fresh. |
| `WatchPolicies` | `true` | Watch install policies and external install registrations. |
| `ReportRemovals` | `true` | Report removed extensions and policies (as Info). Additions are always reported. |
| `IgnoredExtensionIds` | `[]` | Extension IDs (wildcards `*` and `?`) that never alert, for extensions you approved. They are still recorded. |
| `MaxIndividualAlerts` | `5` | Up to this many additions (or removals) in one check get an alert each; more are summarized in one. |
| `MaxChangesPerAlert` | `20` | Items listed in one alert; the rest are counted. |
| `MaxFileBytes` | `33554432` | A `Preferences`, `Local State` or `extensions.json` larger than this is reported as unreadable instead of read. |
| `UserProfileFolders` | `[]` | User profile folders (such as `C:\Users\alex`) to read instead of every user in the ProfileList. For testing; per-user policies are not read then. |
| `StatePath` | `%LOCALAPPDATA%\ScanAlways\browser-extensions-state.json` | The inventory. |
| `AlertLogPath` | `%LOCALAPPDATA%\ScanAlways\browser-extension-watchdog.log` | Rolling alert log. |

## Run

This tool runs as the `BrowserExtensionWatchdog` module inside the
[WatchLattice hub](../WatchLattice.Hub/). It is enabled by default; turn it
off with `Modules:BrowserExtensionWatchdog:Enabled = false`.

To see it work, let one check run, then install any extension you trust from
the browser's store, wait five minutes, and remove it again. For a policy
alert without installing anything, from an elevated PowerShell add a
force-install entry for an ID that doesn't exist, pointing at a host that
doesn't exist, then remove it:

```powershell
$key = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
New-Item $key -Force | Out-Null
New-ItemProperty $key -Name 1 -Value 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://watchlattice-test.invalid/update.xml' -Force | Out-Null
# wait for the next check, then:
Remove-ItemProperty $key -Name 1
```

If the `ExtensionInstallForcelist` key didn't exist before, remove it too
(`Remove-Item $key`), or Edge keeps showing "Your browser is managed by your
organization".

## Honest limits

- **It reports, it doesn't judge or remove.** It can't tell a good extension
  from a bad one; it tells you one appeared, where, and how it got there.
- **Polling, not real-time.** An extension is noticed within one check
  interval. One that is installed, used and removed between checks can slip
  past, and so can one loaded only for a single browser session from the
  command line (`--load-extension`) without being recorded in the profile.
- **Only Edge, Chrome and Firefox, in their default folders.** Other
  Chromium browsers (Brave, Opera, Vivaldi), portable installs, profiles
  started with `--user-data-dir`, Firefox's `distribution\policies.json`, and
  per-site permissions inside an extension are not covered. Other users'
  `AppData` is assumed to be in their profile folder (folder redirection is
  only followed for the account the hub runs as).
- **An update that adds permissions is not reported.** Extensions update
  themselves; only additions and removals are compared, not versions or
  permissions.
- **It trusts the browser's own records.** Something that edits a profile's
  preferences to hide an extension, or an attacker with administrator rights
  who stops the hub or edits its inventory, is not caught.
