<#
.SYNOPSIS
    Writes Hub/WatchLattice.files.sha256 for a staged release folder.

.DESCRIPTION
    Lists the SHA-256 of every file under Hub/ and Tray/ (except the
    user-edited Hub/appsettings.json and the manifest itself) in the format
    src/WatchLattice.Updater/InstallManifest.cs reads. The hub's install
    integrity check compares the installed files against it. Run it after
    signing, so the hashes are of the bytes that get installed.
#>
param(
    [Parameter(Mandatory)] [string]$Stage,
    [Parameter(Mandatory)] [string]$Version
)

$ErrorActionPreference = 'Stop'
$Stage = (Resolve-Path -LiteralPath $Stage).Path
$manifest = Join-Path $Stage 'Hub/WatchLattice.files.sha256'
$skip = @('Hub/appsettings.json', 'Hub/WatchLattice.files.sha256')
$lines = @("# WatchLattice $Version")
$folders = @('Hub', 'Tray') | ForEach-Object { Join-Path $Stage $_ } | Where-Object { Test-Path -LiteralPath $_ }
foreach ($file in Get-ChildItem -LiteralPath $folders -Recurse -File | Sort-Object FullName) {
    $relative = [IO.Path]::GetRelativePath($Stage, $file.FullName).Replace('\', '/')
    if ($skip -contains $relative) { continue }
    $lines += "$((Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant())  $relative"
}
Set-Content -Encoding ascii -LiteralPath $manifest -Value $lines
Write-Host "Wrote $manifest ($($lines.Count - 1) files)"
