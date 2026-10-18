<#
.SYNOPSIS
    Builds WatchLattice-<version>-win-x64.msi from a staged release folder.

.DESCRIPTION
    The stage is the folder the release zip is made from: Hub/ and Tray/
    (already signed, with Hub/WatchLattice.files.sha256 written) plus the
    installer scripts, LICENSE and README.md. The MSI installs exactly those
    bytes, so the hub's install integrity check passes for either kind of
    install. Windows only (WiX needs Windows Installer to build an MSI).

.EXAMPLE
    .github/scripts/Build-Msi.ps1 -Stage $env:STAGE -Version 0.7.0 -OutFile dist/WatchLattice-0.7.0-win-x64.msi
#>
param(
    [Parameter(Mandatory)] [string]$Stage,
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$OutFile
)

$ErrorActionPreference = 'Stop'
$Stage = (Resolve-Path -LiteralPath $Stage).Path

# Windows Installer versions are major.minor.build, so a prerelease such as
# 0.7.0-beta.1 builds as 0.7.0 (the MSI allows same-version upgrades).
if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)') { throw "'$Version' does not start with major.minor.patch." }
$productVersion = $Matches[0]
if ([int]$Matches[1] -gt 255 -or [int]$Matches[2] -gt 255 -or [int]$Matches[3] -gt 65535) {
    throw "'$productVersion' is outside what Windows Installer accepts (255.255.65535)."
}

$project = Join-Path $PSScriptRoot '../../packaging/msi/WatchLattice.Installer.wixproj'
$out = Join-Path ([IO.Path]::GetTempPath()) "watchlattice-msi-$([guid]::NewGuid().ToString('N'))"
# --no-incremental: MSBuild does not see a new version or stage as a change, so
# a second build would otherwise hand back the previous MSI.
dotnet build $project -c Release --no-incremental "-p:StageDir=$Stage" "-p:ProductVersion=$productVersion" -o $out
if ($LASTEXITCODE -ne 0) { throw "The MSI build failed (exit $LASTEXITCODE)." }

$msi = @(Get-ChildItem -LiteralPath $out -Recurse -Filter 'WatchLattice.msi')
if ($msi.Count -ne 1) { throw "Expected one WatchLattice.msi under $out, found $($msi.Count)." }
$msi = $msi[0].FullName
$parent = Split-Path -Parent $OutFile
if ($parent) { New-Item -ItemType Directory -Force -Path $parent | Out-Null }
Copy-Item -LiteralPath $msi -Destination $OutFile -Force
Remove-Item -LiteralPath $out -Recurse -Force
Write-Host "Built $OutFile (ProductVersion $productVersion)"
