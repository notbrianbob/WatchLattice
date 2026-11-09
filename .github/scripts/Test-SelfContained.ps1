<#
.SYNOPSIS
    Checks that a staged release folder carries its own .NET runtime.

.DESCRIPTION
    Updaters up to 0.8.0 install whatever the latest release is without
    checking which .NET runtime it needs, and leave the hub stopped if it
    cannot start. So every release must stay self-contained: this fails
    when Hub/ or Tray/ is framework-dependent.

    It also lists runtime .exe and .dll files without a valid Authenticode
    signature, as a warning. Once releases are signed, the updater refuses
    an update with any unsigned binary, so those would need attention
    before signing is turned on (see docs/code-signing.md).
#>
param([Parameter(Mandatory)] [string]$Stage)

$ErrorActionPreference = 'Stop'
foreach ($app in @('Hub/ScanAlways.Protection.Service', 'Tray/ScanAlways.Tray')) {
    $config = Join-Path $Stage "$app.runtimeconfig.json"
    if (-not (Test-Path -LiteralPath $config)) { throw "$app.runtimeconfig.json is missing from the package." }
    $options = (Get-Content -Raw -LiteralPath $config | ConvertFrom-Json).runtimeOptions
    if (-not ($options.PSObject.Properties.Name -contains 'includedFrameworks')) {
        throw "$app is framework-dependent. Publish it with --self-contained true; updaters up to 0.8.0 cannot check for a missing runtime."
    }
    Write-Host "$app carries .NET $(@($options.includedFrameworks)[0].version)."
}

if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $unsigned = @()
    foreach ($file in Get-ChildItem (Join-Path $Stage 'Hub'), (Join-Path $Stage 'Tray') -Recurse -Include *.exe, *.dll) {
        if ($file.Name -like 'WatchLattice.*' -or $file.Name -like 'ScanAlways.*') { continue }
        $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
        if ($signature.Status -ne 'Valid') { $unsigned += "$($file.Directory.Name)/$($file.Name) ($($signature.Status))" }
    }
    if ($unsigned) {
        Write-Host "::warning title=Unsigned runtime files::$($unsigned.Count) runtime file(s) have no valid signature: $($unsigned -join ', ')"
    } else {
        Write-Host 'Every runtime .exe and .dll has a valid signature.'
    }
}
