<#
.SYNOPSIS
    Renders the winget manifests for a release's MSI, and optionally checks
    them with `winget validate`.

.DESCRIPTION
    Fills in the templates in packaging/winget (version, installer URL,
    SHA-256, the MSI's ProductCode, release date) and writes the three files
    winget-pkgs expects into -OutDir. Nothing is submitted anywhere; see
    docs/releasing.md#publishing-to-winget for how to submit them.

    The ProductCode is read from the MSI, which needs Windows. Pass
    -ProductCode to render elsewhere.

.EXAMPLE
    .github/scripts/Write-WingetManifest.ps1 -Version 0.7.0 -Msi dist/WatchLattice-0.7.0-win-x64.msi -OutDir dist/winget -Validate
#>
param(
    [Parameter(Mandatory)] [string]$Version,
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$OutDir,
    # Defaults to the MSI asset of the v<Version> release on GitHub.
    [string]$InstallerUrl,
    [string]$Repository = 'notbrianbob/WatchLattice',
    [string]$ProductCode,
    [string]$ReleaseDate = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd'),
    # Run `winget validate` on the result, installing winget first if missing.
    [switch]$Validate
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ($Version -notmatch '^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') { throw "'$Version' is not a release version like 1.2.3 or 1.2.3-beta.1." }
# The MSI's own version: Build-Msi.ps1 drops any prerelease suffix.
$msiVersion = "$($Matches[1]).$($Matches[2]).$($Matches[3])"
$Msi = (Resolve-Path -LiteralPath $Msi).Path
if (-not $InstallerUrl) { $InstallerUrl = "https://github.com/$Repository/releases/download/v$Version/WatchLattice-$Version-win-x64.msi" }
if ($InstallerUrl -notmatch '^https://') { throw "The installer URL must be https: $InstallerUrl" }

function Get-MsiProperty([string]$Path, [string]$Name) {
    # WindowsInstaller's COM objects have no type library, so every call goes through InvokeMember.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
    $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$Name'"))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $record = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
    $value = if ($record) { $record.GetType().InvokeMember('StringData', 'GetProperty', $null, $record, @(1)) }
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($database) | Out-Null
    [Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer) | Out-Null
    $value
}

if (-not $ProductCode) { $ProductCode = Get-MsiProperty $Msi 'ProductCode' }
if ($ProductCode -notmatch '^\{[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\}$') { throw "'$ProductCode' is not an MSI ProductCode like {01234567-89AB-CDEF-0123-456789ABCDEF}." }

$values = [ordered]@{
    VERSION          = $Version
    MSI_VERSION      = $msiVersion
    INSTALLER_URL    = $InstallerUrl
    INSTALLER_SHA256 = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToUpperInvariant()
    PRODUCT_CODE     = $ProductCode.ToUpperInvariant()
    RELEASE_DATE     = $ReleaseDate
}

$templates = @(Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../packaging/winget') -Filter '*.yaml')
if ($templates.Count -ne 3) { throw "Expected 3 manifest templates in packaging/winget, found $($templates.Count)." }
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
foreach ($template in $templates) {
    $text = [IO.File]::ReadAllText($template.FullName)
    # '## ' lines are notes about the template itself.
    $text = [regex]::Replace($text, '(?m)^## .*\r?\n', '')
    foreach ($key in $values.Keys) { $text = $text.Replace("{{$key}}", $values[$key]) }
    $left = [regex]::Matches($text, '\{\{[A-Z0-9_]+\}\}') | ForEach-Object Value | Select-Object -Unique
    if ($left) { throw "$($template.Name) still has placeholders: $($left -join ', ')" }
    # winget-pkgs wants UTF-8 without a byte order mark.
    [IO.File]::WriteAllText((Join-Path $OutDir $template.Name), $text, [Text.UTF8Encoding]::new($false))
}
Write-Host "Wrote the winget manifests for $Version to $OutDir (ProductCode $($values.PRODUCT_CODE), SHA-256 $($values.INSTALLER_SHA256))"

if ($Validate) {
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host 'winget is not installed; installing it with Microsoft.WinGet.Client.'
        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
        Install-Module Microsoft.WinGet.Client -Force -Scope CurrentUser -Repository PSGallery
        Repair-WinGetPackageManager -AllUsers -Latest -Force
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) { throw 'winget is still not available after installing it.' }
    }
    winget --version
    $output = winget validate --manifest $OutDir --disable-interactivity 2>&1 | Out-String
    $exit = $LASTEXITCODE
    Write-Host $output
    if ($exit -ne 0) {
        # Warnings (for example about an installer URL that does not exist yet)
        # leave a non-zero exit code but a valid manifest.
        if ($output -match 'succeeded with warnings') {
            Write-Host "::warning title=winget validate::The winget manifest for $Version validated with warnings; see the log."
        } else {
            throw "winget validate rejected the manifest (exit $exit)."
        }
    }
    $global:LASTEXITCODE = 0
}
