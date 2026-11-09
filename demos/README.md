# Demos and measured results

These demos show what each WatchLattice module actually does on a machine and
what it costs to run. Each one is scripted, seeded, and writes its raw data
next to its summary, so anyone can rerun it and check the numbers.

What they are **not**: evidence that WatchLattice stops real malware. Nothing
here runs malware, and none of the results should be read as a detection or
protection rate. They measure signals and overhead, nothing more.

The latest numbers are in [RESULTS.md](RESULTS.md).

## Run them

You need the [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0).
Everything runs in user mode, in throwaway folders under your temp directory.

```bash
# All three demos (about 4 minutes with the defaults)
dotnet run -c Release --project demos/WatchLattice.Demos -- all

# One at a time
dotnet run -c Release --project demos/WatchLattice.Demos -- decoy --seconds 60 --intensity Idle,Balanced,FullScan
dotnet run -c Release --project demos/WatchLattice.Demos -- canary
dotnet run -c Release --project demos/WatchLattice.Demos -- watchdog --live   # --live reads this machine's Defender status (Windows)
```

On Windows, with PowerShell 7, this one also looks at the real hub process
from outside, the way another program on the machine would:

```powershell
pwsh demos/scripts/Show-DecoySignals.ps1 -Seconds 60 -Intensity Balanced
```

Results go to `demo-results/` (override with `--out` / `-OutDir`): a
`summary.md` per demo, the raw per-second samples as CSV, and copies of the
logs each module wrote. The [Demos workflow](../.github/workflows/demos.yml)
runs the same commands on fresh GitHub-hosted Windows and Linux runners and
attaches the results to the run.

## What each demo does

### Always-scanning decoy

1. Builds a synthetic corpus: 2,000 files of mixed types and sizes (mostly
   small, a few up to 4 MiB), generated from a fixed seed so every run sweeps
   identical bytes. `--corpus DIR` sweeps a folder of your choice instead.
2. Measures the harness with nothing running, as the baseline.
3. Runs the real `DecoyEngine` at each intensity (default `Balanced` and
   `FullScan`, 60 s each) with the hub's default settings, sampling once per
   second.
4. Runs the engine once more with its pacing cap lifted, to get a CPU cost
   per file that is large enough to measure (see below).
5. Copies the first lines of the scanner-style log it wrote.

`Show-DecoySignals.ps1` complements this on Windows: it publishes and starts
the actual hub (`ScanAlways.Protection.Service.exe`) with only the decoy
enabled, shows the resident process, reports whether the
`ScanAlways Protection` service is installed, and measures that process from
outside with `Get-Process` and `Win32_Process`.

### Canary file watcher

1. Measures a baseline with nothing armed.
2. Plants the default three canaries in a throwaway `Documents` folder and
   measures the armed watcher with nothing happening.
3. Does what ransomware does, one step at a time, and times each alert:
   overwrites the start of a canary with random bytes, renames one to
   `.locked`, deletes one.
4. Before those, creates and edits an ordinary file in the same folder as a
   control. It must **not** raise an alert; if it does, or if any canary step
   fails to alert, the demo exits non-zero.

### Defender health watchdog

1. Feeds six recorded `Get-MpComputerStatus` states (healthy, real-time
   protection off, tamper protection off with 3-day-old signatures, 9-day-old
   signatures, passive mode, status unreadable) through the real evaluator and
   prints each readout.
2. Runs five checks in a row through the real watchdog (healthy, off, off,
   on, on) to show it alerts once when a problem appears and once when it
   clears, rather than on every check.
3. With `--live` on Windows, reads this machine's real status (read-only,
   the same query the module runs) and times how long one check takes.

The demo never changes a Defender setting. Showing a degraded readout from a
recorded state, instead of switching protection off to get one, is deliberate.

## How it is measured

| Quantity | Source |
|---|---|
| CPU | The process's total processor time (`Process.TotalProcessorTime`), sampled each second. Reported as % of one logical core and % of the whole machine. |
| Read I/O | The OS's per-process counters: `GetProcessIoCounters` ReadTransferCount / ReadOperationCount on Windows, `/proc/self/io` rchar / syscr on Linux. These count every read the process issued, whether it was served from disk or the file cache, which is what a file-activity monitor sees. |
| Memory | Peak working set of the process, and peak managed heap (`GC.GetTotalMemory`). |
| Alert latency | Stopwatch from just before the file operation to the module's `AlertRaised` event. |
| Watchdog check time | Wall time of one `Get-MpComputerStatus` call through the module's provider, median of three. |

Things to keep in mind when reading the numbers:

- **The harness is a .NET process too.** Its runtime, timers and the sampler
  itself cost something, and that cost varies from second to second. Each
  decoy summary reports that noise. When a module's cost is smaller than the
  noise, the paced rows can't separate it from the baseline, and the
  report says so instead of quoting a difference.
- **Cost per file covers that gap.** With the cap lifted, the engine opens
  thousands of files a second, so its CPU time is well above the noise. The
  baseline rate is subtracted and the remainder divided by files opened. The
  paced cost is that figure times files per second. It assumes the cost per
  file is the same at both speeds, which is reasonable for a fixed 64 KiB read
  and hash but is an assumption.
- **Warm cache.** The corpus is written just before it is read, so reads come
  from the file cache. On a real profile some reads go to disk; that adds
  latency, not much CPU.
- **Working set is a ceiling.** It is the whole process, runtime included.
- **CI runners are not your PC.** They are shared virtual machines, and
  their Defender configuration is the image's, not a typical home setup.
  Run the demos on your own machine for numbers that mean something for it.
