<#
.SYNOPSIS
    Shows, from the outside, the signals the always-scanning decoy puts on a
    Windows machine, and measures the real hub process's CPU, read I/O and
    memory over a sample window.

.DESCRIPTION
    Publishes the hub, starts it as a console process with only the Decoy
    module enabled, sweeping a seeded synthetic corpus, and then:

      1. shows the resident process as any process list sees it,
      2. reports whether the "ScanAlways Protection" service is installed,
      3. samples the process once per interval with Get-Process (CPU time,
         working set) and Win32_Process (ReadTransferCount, ReadOperationCount),
      4. prints the tail of the scanner-style log.

    It reads and observes only. It does not install a service, change any
    Defender setting, or touch files outside the corpus and the output folder.
    Everything it writes goes under -OutDir and -WorkDir.

.EXAMPLE
    pwsh demos/scripts/Show-DecoySignals.ps1 -Seconds 60 -Intensity Balanced
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [int]$Seconds = 60,
    [ValidateSet('Idle', 'Balanced', 'FullScan')]
    [string]$Intensity = 'Balanced',
    [int]$SampleSeconds = 1,
    [int]$Files = 2000,
    [int]$Seed = 1337,
    [string]$OutDir = 'demo-results/decoy-hub',
    [string]$WorkDir = (Join-Path ([System.IO.Path]::GetTempPath()) 'watchlattice-demos')
)

$ErrorActionPreference = 'Stop'
$repo = Resolve-Path (Join-Path $PSScriptRoot '..' '..')
New-Item -ItemType Directory -Force -Path $OutDir, $WorkDir | Out-Null
$OutDir = Resolve-Path $OutDir
$publishDir = Join-Path $WorkDir 'hub'
$corpus = Join-Path $WorkDir 'decoy-corpus'
$scanLog = Join-Path $OutDir 'scan-activity.log'
$hubLog = Join-Path $OutDir 'hub-console.log'
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $corpus, $scanLog, $hubLog

Write-Host "Publishing the hub to $publishDir"
dotnet publish (Join-Path $repo 'src/WatchLattice.Hub') -c Release -o $publishDir --nologo -v quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'dotnet publish failed' }

Write-Host "Creating the synthetic corpus ($Files files, seed $Seed)"
dotnet run -c Release --project (Join-Path $repo 'demos/WatchLattice.Demos') -- corpus --corpus $corpus --files $Files --seed $Seed --out $OutDir --work $WorkDir
if ($LASTEXITCODE -ne 0) { throw 'corpus creation failed' }

$exe = Join-Path $publishDir 'ScanAlways.Protection.Service.exe'
$hubArgs = @(
    '--Modules:Canary:Enabled=false',
    '--Modules:DefenderWatchdog:Enabled=false',
    '--Modules:FirewallWatchdog:Enabled=false',
    '--Modules:HostsProxyWatchdog:Enabled=false',
    '--Modules:BrowserExtensionWatchdog:Enabled=false',
    '--Modules:Persistence:Enabled=false',
    '--Modules:ScriptHostAudit:Enabled=false',
    '--Modules:Updater:Enabled=false',
    "--Decoy:Intensity=$Intensity",
    "--Decoy:ScanRoots:0=$corpus",
    "--Decoy:ScanLogPath=$scanLog"
)
$proc = Start-Process -FilePath $exe -ArgumentList $hubArgs -PassThru -NoNewWindow -RedirectStandardOutput $hubLog
try {
    Start-Sleep -Seconds 3

    $md = [System.Collections.Generic.List[string]]::new()
    $md.Add('## Decoy signals, seen from outside the process')
    $md.Add('')
    $md.Add("Hub started with only the Decoy module enabled, intensity $Intensity, sweeping $Files seeded files. Window: $Seconds s, sampled every $SampleSeconds s.")
    $md.Add('')

    $md.Add('### 1. Resident process')
    $md.Add('')
    $md.Add('```text')
    $seen = Get-Process -Id $proc.Id | Select-Object Id, ProcessName, @{ n = 'Path'; e = { $_.Path -replace [regex]::Escape($publishDir), '<publish>' } }
    $md.Add(($seen | Format-Table -AutoSize | Out-String).Trim())
    $md.Add('```')
    $md.Add('')

    $md.Add('### 2. Windows service')
    $md.Add('')
    $svc = Get-Service -Name 'ScanAlways Protection' -ErrorAction SilentlyContinue
    if ($svc) {
        $md.Add("``ScanAlways Protection`` is installed: status $($svc.Status), start type $($svc.StartType).")
    } else {
        $md.Add('``ScanAlways Protection`` is not installed on this machine; this run used console mode. Installing it (see the top-level README) adds the service entry to the same process.')
    }
    $md.Add('')

    $samples = [System.Collections.Generic.List[object]]::new()
    $end = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $end -and -not $proc.HasExited) {
        $p = Get-Process -Id $proc.Id
        $w = Get-CimInstance Win32_Process -Filter "ProcessId = $($proc.Id)"
        $samples.Add([pscustomobject]@{
            Time       = Get-Date
            CpuMs      = $p.TotalProcessorTime.TotalMilliseconds
            ReadBytes  = [long]$w.ReadTransferCount
            ReadOps    = [long]$w.ReadOperationCount
            WorkingSet = $p.WorkingSet64
        })
        Start-Sleep -Seconds $SampleSeconds
    }
    $samples | Export-Csv -NoTypeInformation -Path (Join-Path $OutDir 'samples-hub.csv')
    if ($samples.Count -lt 2) { throw 'The hub exited before it could be measured; see hub-console.log.' }

    $first = $samples[0]; $last = $samples[$samples.Count - 1]
    $wall = ($last.Time - $first.Time).TotalSeconds
    $cpu = ($last.CpuMs - $first.CpuMs) / 1000
    $cpuCore = 100 * $cpu / $wall
    $md.Add('### 3. Measured overhead of the hub process')
    $md.Add('')
    $md.Add('| Wall | CPU (% of one core) | CPU (% of machine) | Logical reads | Read calls/s | Peak working set |')
    $md.Add('|---:|---:|---:|---:|---:|---:|')
    $md.Add(('| {0:F0} s | {1:F2} | {2:F3} | {3:F1} KiB/s | {4:F1} | {5:F1} MiB |' -f
        $wall, $cpuCore, ($cpuCore / [Environment]::ProcessorCount),
        (($last.ReadBytes - $first.ReadBytes) / 1KB / $wall),
        (($last.ReadOps - $first.ReadOps) / $wall),
        (($samples | Measure-Object WorkingSet -Maximum).Maximum / 1MB)))
    $md.Add('')
    $md.Add('Counters: `Get-Process` TotalProcessorTime and WorkingSet64; `Win32_Process` ReadTransferCount and ReadOperationCount (all reads the process issued, cached or not). The hub process includes the .NET runtime and hosting, so this is the cost of running the decoy as it actually ships.')
    $md.Add('')

    $md.Add('### 4. Scanner-style log')
    $md.Add('')
    $md.Add('Last lines of `scan-activity.log`, verbatim:')
    $md.Add('')
    $md.Add('```text')
    if (Test-Path $scanLog) {
        $fs = [System.IO.File]::Open($scanLog, 'Open', 'Read', 'ReadWrite, Delete')
        try { $lines = ([System.IO.StreamReader]::new($fs)).ReadToEnd() -split "`r?`n" | Where-Object { $_ } }
        finally { $fs.Dispose() }
        $lines | Select-Object -Last 10 | ForEach-Object { $md.Add(($_ -replace [regex]::Escape($corpus), '<corpus>')) }
    } else {
        $md.Add('(no log written)')
    }
    $md.Add('```')
    $md.Add('')

    $text = $md -join "`n"
    Set-Content -Path (Join-Path $OutDir 'summary.md') -Value $text -Encoding utf8
    Write-Host $text
}
finally {
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force }
}
