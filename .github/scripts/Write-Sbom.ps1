<#
.SYNOPSIS
    Writes a CycloneDX software bill of materials (SBOM) for the release.

.DESCRIPTION
    Lists every NuGet package the hub and tray ship (from
    packaging/sbom/release.slnf, for win-x64) with versions, hashes and
    package URLs. It then adds the .NET runtime that the self-contained
    release bundles, read from the published runtimeconfig files, because
    that runtime is not a package reference and the tool would leave it out.

    The release workflow publishes the result next to the zip as
    WatchLattice-<version>-sbom.cdx.json and covers it with the build
    provenance attestation. CI writes one on every pull request so this
    script can't break silently.

.PARAMETER Stage
    The published package folder with Hub\ and Tray\. Optional: without it
    the runtime is not added (CI's quick check).
#>
param(
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$OutFile,
    [string]$Stage,
    [string]$CycloneDxVersion = '6.3.1'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$root = Resolve-Path (Join-Path $PSScriptRoot '../..')
$tools = Join-Path ([IO.Path]::GetTempPath()) "cyclonedx-$CycloneDxVersion"
if (-not (Test-Path $tools)) {
    dotnet tool install CycloneDX --version $CycloneDxVersion --tool-path $tools | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "Could not install CycloneDX $CycloneDxVersion." }
}
$exe = Get-ChildItem $tools -Filter 'dotnet-CycloneDX*' | Where-Object { $_.Extension -in '', '.exe' } | Select-Object -First 1
if (-not $exe) { throw "dotnet-CycloneDX was not found in $tools." }

$outDir = Split-Path -Parent ([IO.Path]::GetFullPath($OutFile))
New-Item -ItemType Directory -Force $outDir | Out-Null
$name = Split-Path -Leaf $OutFile
& $exe.FullName (Join-Path $root 'packaging/sbom/release.slnf') -rt win-x64 -o $outDir -fn $name -F Json `
    -sn WatchLattice -sv $Version | Out-Host
if ($LASTEXITCODE -ne 0) { throw "CycloneDX failed with exit code $LASTEXITCODE." }

$bom = Get-Content -Raw (Join-Path $outDir $name) | ConvertFrom-Json
if (-not $bom.components -or @($bom.components).Count -lt 5) { throw "The SBOM lists $(@($bom.components).Count) components; expected the hub's and tray's packages." }
foreach ($required in 'Microsoft.Extensions.Hosting', 'System.Diagnostics.EventLog') {
    if (-not ($bom.components | Where-Object name -eq $required)) { throw "The SBOM is missing $required." }
}

if ($Stage) {
    # The self-contained release bundles these frameworks; their versions are
    # in each published runtimeconfig.json.
    $frameworks = @{}
    foreach ($config in Get-ChildItem $Stage -Recurse -Filter '*.runtimeconfig.json') {
        $json = Get-Content -Raw $config.FullName | ConvertFrom-Json
        foreach ($framework in @($json.runtimeOptions.includedFrameworks)) {
            if ($framework) { $frameworks["$($framework.name)@$($framework.version)"] = $framework }
        }
    }
    if ($frameworks.Count -eq 0) { throw "No includedFrameworks in $Stage; is the release still self-contained?" }
    $components = [Collections.Generic.List[object]]::new()
    $components.AddRange([object[]]@($bom.components))
    foreach ($framework in $frameworks.Values | Sort-Object name) {
        $package = "$($framework.name).Runtime.win-x64"
        $components.Add([pscustomobject][ordered]@{
            type        = 'framework'
            'bom-ref'   = "pkg:nuget/$package@$($framework.version)"
            name        = $package
            version     = $framework.version
            description = "$($framework.name) $($framework.version), bundled with the self-contained release"
            purl        = "pkg:nuget/$package@$($framework.version)"
        })
        Write-Host "Added bundled runtime $package $($framework.version)"
    }
    $bom.components = $components.ToArray()
    $bom | ConvertTo-Json -Depth 64 | Set-Content -Encoding utf8NoBOM (Join-Path $outDir $name)
}

Write-Host "SBOM: $OutFile, $(@($bom.components).Count) components"
