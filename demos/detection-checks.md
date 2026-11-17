# Detection checks

The detection checks answer one question for each kind of change a module
watches for: **when this happens on a real Windows machine, does the module's
real code report it?** For each one the harness makes a single harmless,
clearly named change, runs the module once, records the alert, undoes the
change, and runs the module again to see the undo reported.

They are not a malware test. Nothing runs malware or attack tools, and a
pass says nothing about a detection *rate* against real attacks. It shows
the plumbing works end to end on that machine: the module reads the real
Windows source, compares it with its baseline, and raises the alert (with
its Event ID and [ATT&CK technique](../docs/attack-coverage.md)) that the hub
would show.

The latest results are in [RESULTS.md](RESULTS.md#detection-checks).

## What each check changes

Every change is chosen to do nothing even if it were left behind, and every
name starts with `WatchLatticeDetectionTest`:

| Check | Change | Why it is harmless |
|---|---|---|
| Run key value (current user, and all users) | A Run value pointing at `C:\Windows\System32\WatchLatticeDetectionTest-does-not-exist.exe` | The program does not exist, and only administrators can create files in that folder. |
| Startup folder file | An empty `WatchLatticeDetectionTest.txt` in your Startup folder | At worst Notepad opens an empty file at sign-in. |
| Scheduled task | `\WatchLatticeDetectionTest\WatchLatticeDetectionTest`, disabled, one trigger on 1 January 2000, action `cmd.exe /c exit` | Disabled, and the trigger is in the past. |
| Auto-start service | Service `WatchLatticeDetectionTest` for the missing program above | Never started; at boot it would fail to start. |
| WMI event filter | `__EventFilter` `WatchLatticeDetectionTest` for the year 1999 | A filter without a consumer and binding can't run anything. |
| Hosts file lines | `127.0.0.1 watchlattice-detection-test.invalid`, and the same for `watchlattice-protected-test.invalid`, which the check adds to the module's protected list for the run | `.invalid` is reserved and never resolves on the internet. The file is written back byte for byte. |
| Proxy server | `ProxyServer = 127.0.0.1:9` for your account, with the proxy left **off** | Browsing is not affected. Skipped if a proxy is on. |
| Firewall rule | Inbound allow rule for TCP 49999 for the missing program | Nothing can listen behind it. |
| Edge extension policy | Force-install entry for extension ID `pppppppppppppppppppppppppppppppp` with an `.invalid` update URL | Neither the extension nor its update host exists. While it is there, Edge shows *Managed by your organization*. |
| Script host launch | `powershell.exe -NoProfile -EncodedCommand` running `Get-Date` | Prints the date. |
| Canary | Overwrites one canary planted in a throwaway temp folder | Only touches the throwaway folder. |
| Defender exclusion (opt-in, `--include-defender`) | Adds the path exclusion `C:\WatchLatticeDetectionTest-does-not-exist`, then removes it | The folder does not exist, so nothing is excluded from scanning, but it *is* a change to Defender's settings for a few seconds, which is why it is opt-in. |
| Process creation auditing (opt-in, `--include-audit-policy`) | Turns on *Audit Process Creation* and command lines in it, only if they are off, for the script host check | Puts both back afterwards. |

Each module runs with its state files in a throwaway folder, so the PC's real
WatchLattice baselines and alert history are not touched. If you run the
checks on a PC where the hub is running, the hub sees the changes too and
alerts on them: that is expected.

Not checked, because the change would weaken the PC even briefly: turning
off real-time protection, a firewall profile or tamper protection, lowering
Defender's cloud block level, and editing the hosts entries of real update
or security domains. Those alerts are covered by unit tests against recorded
readouts and by the [Windows hand checks](../docs/windows-checks.md).

## Run them

On Windows 11 with the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0),
from an **elevated** prompt (without one, the checks that need
administrator rights are skipped):

```powershell
# See every change first; this changes nothing
dotnet run -c Release --project demos/WatchLattice.DetectionChecks -- list

# Run the default checks
dotnet run -c Release --project demos/WatchLattice.DetectionChecks -- run

# Include the opt-in checks (best on a VM you can throw away)
dotnet run -c Release --project demos/WatchLattice.DetectionChecks -- run --include-defender --include-audit-policy

# If a run was interrupted, remove anything named WatchLatticeDetectionTest it left behind
dotnet run -c Release --project demos/WatchLattice.DetectionChecks -- cleanup
```

Results go to `detection-results/` (override with `--out`): `summary.md`
and `results.json` with every alert's text. The command exits with `1` if a
check that ran missed its alert or could not undo its change.

The [Demos workflow](../.github/workflows/demos.yml) runs every check,
including the opt-in ones, on a fresh GitHub-hosted Windows runner for each
pull request that touches `src/` or `demos/`, and attaches the results to the
run.

## Reading the results

- **Found by one check in** is how long the module's own check took after
  the change. In the hub, the change is found at the module's next check, so
  up to its interval later (for example 5 minutes for autostart entries).
- **Undo reported** is whether undoing the change raised the expected
  removal alert, such as `ENTRY_REMOVED`. A firewall rule's removal and a
  script host launch have no undo alert by design.
- A check that misses fails the run. It is not retried until it passes.
