# WatchLattice.HostsProxyWatchdog — hosts file and proxy settings watchdog

Two small settings decide where a Windows machine's traffic actually goes, and
malware changes both:

- The **hosts file** overrides DNS. One line can send `yourbank.example` to a
  phishing server, or point Windows Update and Defender's definition servers
  at `0.0.0.0` so the machine quietly stops getting fixes and signatures.
- The **proxy settings** route web traffic through a server of the attacker's
  choosing, or through an auto-config (PAC) script they host, where it can be
  watched or altered. Banking trojans and adware have done this for years.

This module reads both every minute, records a baseline on its first check,
and reports every later change with what it was before and after.

## What it reads

| Source | Where | Why |
|---|---|---|
| Hosts file | The file Windows uses: `hosts` in Tcpip's `DataBasePath` folder (`HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`, default `%SystemRoot%\System32\drivers\etc`) | Following `DataBasePath` catches malware that leaves the usual file alone and points Windows at a different one. |
| WinINET, per user | `HKEY_USERS\<SID>\Software\Microsoft\Windows\CurrentVersion\Internet Settings` (`ProxyEnable`, `ProxyServer`, `ProxyOverride`, `AutoConfigURL`), its `Connections\DefaultConnectionSettings` binary, the matching `Software\Policies\...` key, and the user's `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY` environment variables | What browsers using the system proxy, Office and most apps follow. Read for every signed-in user (and LocalSystem), because the hub runs as a service under LocalSystem, whose own HKCU is not yours. |
| WinINET, machine | The same values under `HKLM`, the machine policy key (including `ProxySettingsPerUser`), and machine-wide environment variables | Machine-wide proxy policy and variables apply to every account. |
| WinHTTP | `HKLM\...\Internet Settings\Connections\WinHttpSettings` (what `netsh winhttp show proxy` shows) | Used by Windows services, including parts of Windows Update and Defender. |

The binary connection settings are decoded into named fields
(`Connection.ProxyServer`, `Connection.AutoConfigURL`, `WinHTTP.ProxyServer`
and so on). Their change counter is skipped, so Windows rewriting the same
settings is not a change. A blob in an unknown layout is still compared, by
hash.

## What it reports

| Alert | When | Severity |
|---|---|---|
| `BASELINE_CREATED` | First check: how many hosts entries exist and which proxy settings are set. An inventory, not a safety verdict. | Info |
| `PROTECTED_HOST_OVERRIDDEN` | The hosts file has an entry for a protected domain (below), whether it blocks it (`0.0.0.0`, loopback) or redirects it. Standing: raised once, cleared when the entries are gone. | Critical |
| `HOSTS_CHANGED` | Entries were added, pinned to different addresses, or removed. One alert per check, listing up to `MaxChangesPerAlert` changes and counting the rest. | Critical if a protected host was added or changed, Warning for other additions and changes, Info for removals only |
| `HOSTS_PATH_MOVED` | `DataBasePath` is not the Windows default. Standing. | Warning |
| `PROXY_CHANGED` | A user's, the machine's or WinHTTP's proxy settings differ from the baseline. One alert per place per check, every changed value with before and after. | Warning when a proxy server, PAC script, environment proxy or proxy policy was turned on or pointed somewhere new; Info when settings were only cleared or turned off, or only bypass lists or "automatically detect settings" changed |
| `HOSTS_UNAVAILABLE`, `PROXY_UNAVAILABLE` | Something could not be read. Standing. | Warning |
| `STATE_SAVE_FAILED`, `STATE_UNREADABLE` | The baseline could not be saved, or the saved one could not be read and was started over. | Warning |

Standing alerts are reported when they appear and again (as Info, with
`_CLEARED`) when they clear; a check that can't read the hosts file never
counts as a clear. Event IDs are 8001 to 8009; see
[Event Log alerts](../../docs/event-log.md#hosts-file-and-proxy-watchdog-8000).
Alerts also go to the tray and the dashboard, a `HOSTS/PROXY` line in
`%LOCALAPPDATA%\ScanAlways\hosts-proxy-watchdog.log`, and the hub's log.

A user who signs out is not a change: their last settings are kept and
compared again when they sign back in. A user seen for the first time is
recorded quietly (logged, not alerted).

### Protected domains

Each covers its subdomains: `windowsupdate.com`, `update.microsoft.com`,
`delivery.mp.microsoft.com`, `wdcp.microsoft.com`, `wdcpalt.microsoft.com`,
`wd.microsoft.com`, `definitionupdates.microsoft.com`,
`smartscreen.microsoft.com`, `smartscreen-prod.microsoft.com`,
`security.microsoft.com`, `go.microsoft.com` (Defender's definition download
links), `github.com` and `githubusercontent.com` (WatchLattice's own updates),
and `virustotal.com`. Microsoft telemetry hosts are deliberately not on the
list, so privacy tools that block telemetry in the hosts file only produce the
ordinary `HOSTS_CHANGED` warning when they make their change.

Add your own with `ProtectedDomains`. If you block one of these on purpose,
list it in `IgnoredHosts` rather than turning the built-in list off.

## Read-only by design

The watchdog opens the hosts file and every registry key for reading only. It
never edits the hosts file, never resets a proxy, never runs `netsh`, and
never launches anything. Reading the machine's settings needs no
administrator rights; reading other signed-in users' settings does, which the
hub has when it runs as its service. Without it, only the current account is
read.

Microsoft Defender also flags some hosts file hijacks on its own
(`SettingsModifier:Win32/HostsFileHijack`). This module is a second, simpler
signal that also covers proxies and changes Defender considers harmless.

## Configuration (hub `appsettings.json`, section `HostsProxyWatchdog`)

| Setting | Default | Meaning |
|---|---|---|
| `CheckIntervalSeconds` | `60` | Seconds between checks (minimum 15). Each check is one file read and a few registry reads. |
| `WatchHostsFile` | `true` | Watch the hosts file and `DataBasePath`. Turning it off forgets the hosts baseline. |
| `WatchProxySettings` | `true` | Watch proxy settings. Turning it off forgets the proxy baseline. |
| `IncludeBuiltInProtectedDomains` | `true` | Use the protected domain list above. |
| `ProtectedDomains` | `[]` | More domains (each covering its subdomains) whose hosts entries are critical. |
| `IgnoredHosts` | `[]` | Host names (wildcards `*` and `?`) whose hosts entries never alert, for entries you added on purpose. |
| `MaxChangesPerAlert` | `20` | Changes listed in one alert; the rest are counted. Keeps a 100,000-line ad-block list from producing a giant alert. |
| `MaxHostsFileBytes` | `16777216` | A larger hosts file is reported as unreadable instead of read. |
| `HostsFilePath` | `null` | Watch this file instead of the one Windows uses (for testing). |
| `StatePath` | `%LOCALAPPDATA%\ScanAlways\hosts-proxy-state.json` | The baseline. |
| `AlertLogPath` | `%LOCALAPPDATA%\ScanAlways\hosts-proxy-watchdog.log` | Rolling alert log. |

## Run

This tool runs as the `HostsProxyWatchdog` module inside the
[WatchLattice hub](../WatchLattice.Hub/). It is enabled by default; turn it off
with `Modules:HostsProxyWatchdog:Enabled = false`.

To see it work without weakening anything, let one check run, then add a line
for a name nobody uses to the hosts file from an elevated editor, for example
`203.0.113.10 watchlattice-test.invalid`, wait a minute, and remove it again.
For a proxy alert, turn on **Use a proxy server** in Settings > Network &
internet > Proxy with address `127.0.0.1` and port `9`, wait a minute, and
turn it off. Don't add entries for real update hosts to test the critical
alert on a machine you rely on.

## Honest limits

- **It reports, it doesn't repair.** Removing an entry or a proxy is your
  call; the watchdog only tells you something changed.
- **Polling, not real-time.** A change is noticed within one check interval.
  Something that changes a setting, uses it, and restores it between checks
  can slip past.
- **Not every way to redirect traffic.** It does not watch DNS server
  settings, per-adapter or VPN connection proxies, browser-specific proxy
  settings (for example Firefox's own), `netsh interface portproxy`, root
  certificates, or the 32-bit registry view of WinHTTP.
- **Signed-out users are not read.** Their registry hive is not loaded, so a
  change made to it offline is only seen once they sign in.
- **Legitimate tools change these too.** Corporate proxies, VPN clients,
  debugging proxies like Fiddler, and ad-blocking hosts lists all trigger
  alerts the first time. The alert shows exactly what changed so you can judge.
- **It trusts what Windows reports.** An attacker with administrator rights
  can stop the hub or edit its baseline.
