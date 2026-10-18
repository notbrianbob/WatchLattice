<#
.SYNOPSIS
    Removes WatchLattice: the service, the tray, its canary files, settings
    and data.

.DESCRIPTION
    install.ps1 copies this script into the install folder, and Settings >
    Apps > WatchLattice runs it from there. It asks for administrator rights
    when it needs them, then:

      1. stops the tray companion and the "ScanAlways Protection" service,
      2. deletes the canary files the hub planted that are still unchanged
         (changed ones are left in place as evidence and listed),
      3. deletes the service, the tray's sign-in entry, the Start menu
         shortcut and the Settings > Apps entry,
      4. deletes the alert feed, the hub's baselines and logs, and the
         install folder.

    Nothing outside what WatchLattice created is touched.

.PARAMETER InstallDir
    The install folder. Defaults to the folder this script is in when it is
    an install, otherwise %ProgramFiles%\WatchLattice.

.PARAMETER KeepData
    Keep the alert feed, baselines, logs and canary manifest, so a later
    install picks up where this one left off. Intact canaries are still
    removed.

.PARAMETER Quiet
    Do not ask for confirmation.

.PARAMETER Msi
    Used by the WatchLattice MSI while Windows Installer removes the product.
    Does only what Windows Installer cannot: removes the canary files, the
    tray's sign-in entries and the data folders. Windows Installer removes
    the service, files, shortcut, event log source and Settings > Apps entry.

    Run without -Msi on an MSI install, this script hands the uninstall to
    Windows Installer (msiexec /x), so nothing is left registered.

.EXAMPLE
    & 'C:\Program Files\WatchLattice\uninstall.ps1'
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir,
    [switch]$KeepData,
    [switch]$Quiet,
    [switch]$Msi,
    # Set when this script relaunches itself elevated, so its window stays open.
    [switch]$PauseAtEnd
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

# The same fixed names install.ps1 and the updater use.
$ServiceName = 'ScanAlways Protection'
$HubExeName = 'ScanAlways.Protection.Service.exe'
$TrayExeName = 'ScanAlways.Tray.exe'
$DataFolderName = 'ScanAlways'

$DataRoot = Join-Path $env:ProgramData 'WatchLattice'
$RunValueName = 'WatchLattice Tray'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WatchLattice'
$StateFileName = 'install-state.json'
$EventSource = 'WatchLattice'

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Note([string]$Message) { Write-Host "    $Message" }
function Write-Caution([string]$Message) { Write-Host "    $Message" -ForegroundColor Yellow }

function Test-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Deletes a folder without ever following a junction or symbolic link in it:
# a link is removed itself, never what it points to, so a link planted in a
# data folder cannot lead the delete anywhere else.
function Remove-Tree([IO.FileSystemInfo]$Item) {
    if (-not ($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and $Item -is [IO.DirectoryInfo]) {
        foreach ($child in $Item.EnumerateFileSystemInfos()) { Remove-Tree $child }
    }
    $Item.Attributes = if ($Item -is [IO.DirectoryInfo]) { [IO.FileAttributes]::Directory } else { [IO.FileAttributes]::Normal }
    $Item.Delete()
}

function Remove-Folder([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    try {
        Remove-Tree (Get-Item -LiteralPath $Path -Force)
        Write-Note "Deleted $Path"
    }
    catch {
        Write-Caution "Could not delete all of $Path ($($_.Exception.Message)). Delete the rest by hand."
        $script:problems++
    }
}

function Remove-TrayRunValue([string]$RunKey, [string]$Who) {
    $value = Get-ItemProperty -LiteralPath $RunKey -Name $RunValueName -ErrorAction SilentlyContinue
    if ($value -and "$($value.$RunValueName)" -like "*$TrayExeName*") {
        Remove-ItemProperty -LiteralPath $RunKey -Name $RunValueName
        Write-Note "Removed the tray from $Who's sign-in."
    }
}

$problems = 0
try {
    # Native tools (the hub, reg.exe, sc.exe) report through exit codes; with
    # 'Stop', Windows PowerShell would turn their redirected stderr into errors.
    function Invoke-Quietly([scriptblock]$Command) { $ErrorActionPreference = 'Continue'; & $Command }

    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run this from 64-bit PowerShell (the default "Windows PowerShell"), not the x86 one.'
    }

    if (-not $InstallDir) {
        $InstallDir = if (Test-Path -LiteralPath (Join-Path $PSScriptRoot "Hub\$HubExeName")) { $PSScriptRoot } else { Join-Path $env:ProgramFiles 'WatchLattice' }
    }
    $InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')

    $state = $null
    $statePath = Join-Path $InstallDir $StateFileName
    if (Test-Path -LiteralPath $statePath) { $state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json }

    if ($Msi) {
        # Windows Installer runs this as LocalSystem, with no one to ask.
        $Quiet = [switch]$true
    }
    elseif ($state -and $state.PSObject.Properties.Name -contains 'ProductCode' -and $state.ProductCode) {
        # Installed from the MSI: let Windows Installer remove it, which runs
        # this script with -Msi and keeps its own records straight.
        Write-Step 'WatchLattice was installed from the MSI; removing it with Windows Installer'
        $arguments = @('/x', $state.ProductCode)
        if ($Quiet) { $arguments += '/qn' }
        if ($KeepData) { $arguments += 'KEEPDATA=1' }
        $msiexec = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') -ArgumentList $arguments -Wait -PassThru
        # 3010: removed, and Windows wants a restart to finish.
        if ($msiexec.ExitCode -notin 0, 3010) { throw "Windows Installer could not remove WatchLattice (exit code $($msiexec.ExitCode))." }
        Write-Host 'WatchLattice was removed.' -ForegroundColor Green
        $exitCode = 0
        if ($PauseAtEnd) { Read-Host 'Press Enter to close this window' | Out-Null }
        exit $exitCode
    }

    if (-not (Test-Administrator)) {
        Write-Step 'Asking for administrator rights to remove the service'
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"", '-InstallDir', "`"$InstallDir`"", '-PauseAtEnd')
        if ($KeepData) { $arguments += '-KeepData' }
        if ($Quiet) { $arguments += '-Quiet' }
        try {
            $elevated = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        }
        catch {
            throw 'The administrator prompt was declined. Nothing was removed.'
        }
        exit $elevated.ExitCode
    }

    $hubExe = Join-Path $InstallDir "Hub\$HubExeName"
    $trayExe = Join-Path $InstallDir "Tray\$TrayExeName"
    $installed = Test-Path -LiteralPath $hubExe
    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if (-not $installed -and -not $service) {
        throw "WatchLattice is not installed in $InstallDir. Pass the install folder with -InstallDir."
    }
    if ($service -and $installed -and $service.PathName.Trim().Trim('"') -ne $hubExe) {
        throw "The '$ServiceName' service runs $($service.PathName), not the copy in $InstallDir. Run the uninstall.ps1 next to that copy instead."
    }

    if (-not $Quiet) {
        Write-Host "This removes WatchLattice from $InstallDir, its service, and the canary files it planted."
        if (-not $KeepData) { Write-Host 'Its alert history, baselines and logs are deleted too (use -KeepData to keep them).' }
        if ((Read-Host 'Remove WatchLattice? [y/N]').Trim() -notmatch '^(y|yes)$') {
            Write-Host 'Nothing was removed.'
            throw [OperationCanceledException]::new()
        }
    }

    Write-Step 'Stopping WatchLattice'
    Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($TrayExeName)) -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path -eq $trayExe } | Stop-Process -Force
    if ($service -and $service.State -ne 'Stopped') {
        Stop-Service -Name $ServiceName -Force
        Write-Note 'Stopped the hub service.'
    }

    # The hub ran as LocalSystem, so its manifest is in the system profile
    # unless appsettings.json names another place.
    $systemLocalAppData = Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local'
    $dataDirs = @((Join-Path $systemLocalAppData $DataFolderName))
    $tempDirs = @((Join-Path $env:SystemRoot "SystemTemp\$DataFolderName"), (Join-Path $env:SystemRoot "Temp\$DataFolderName"))
    if ($installed) {
        Write-Step 'Removing canary files'
        $manifest = Join-Path $dataDirs[0] 'canary-manifest.json'
        $configPath = Join-Path $InstallDir 'Hub\appsettings.json'
        $configured = $null
        try { $configured = (Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json).Canary.ManifestPath } catch { }
        $removeArgs = @('--remove-canaries')
        if (-not $configured) { $removeArgs += "--Canary:ManifestPath=$manifest" }
        $output = Invoke-Quietly { & $hubExe @removeArgs 2>&1 }
        $code = $LASTEXITCODE
        $output | Where-Object { "$_" -notmatch '^info: ' } | ForEach-Object { Write-Note "$_" }
        if ($code -eq 1) {
            Write-Caution 'The canaries listed above were changed after they were planted, so they were kept. Check them, then delete them by hand.'
        }
        elseif ($code -ne 0) {
            Write-Caution "Could not remove the canary files (exit code $code). Their paths are in $manifest."
            $problems++
            $KeepData = $true
        }
    }

    Write-Step 'Removing the service, sign-in entry and shortcuts'
    if ($service -and -not $Msi) {
        Invoke-Quietly { & sc.exe delete $ServiceName 2>&1 | Out-Null }
        for ($i = 0; $i -lt 60 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
        if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
            Write-Caution "The '$ServiceName' service is marked for deletion and goes away after a restart."
        }
        else {
            Write-Note "Deleted the '$ServiceName' service."
        }
    }

    # Every signed-in user's Run key, in case the tray user changed between installs.
    $hives = @(Get-ChildItem -LiteralPath 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -notmatch '_Classes$' })
    foreach ($hive in $hives) {
        Remove-TrayRunValue (Join-Path $hive.PSPath 'Software\Microsoft\Windows\CurrentVersion\Run') $hive.PSChildName
    }
    # A tray user who is signed out: open their registry hive just long enough.
    if ($state -and -not (Test-Path -LiteralPath "Registry::HKEY_USERS\$($state.TrayUserSid)")) {
        $userProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$($state.TrayUserSid)'"
        $mount = 'WatchLatticeUninstall'
        if ($userProfile -and (Test-Path -LiteralPath (Join-Path $userProfile.LocalPath 'NTUSER.DAT'))) {
            Invoke-Quietly { & reg.exe load "HKU\$mount" (Join-Path $userProfile.LocalPath 'NTUSER.DAT') 2>&1 | Out-Null }
            if ($LASTEXITCODE -eq 0) {
                try { Remove-TrayRunValue "Registry::HKEY_USERS\$mount\Software\Microsoft\Windows\CurrentVersion\Run" $state.TrayUser }
                finally {
                    [GC]::Collect()
                    [GC]::WaitForPendingFinalizers()
                    Invoke-Quietly { & reg.exe unload "HKU\$mount" 2>&1 | Out-Null }
                }
            }
            else {
                Write-Caution "Could not open $($state.TrayUser)'s registry. Remove '$RunValueName' from their Startup apps in Task Manager."
            }
        }
    }

    # The hub registers this Application log source on its first start. Past
    # entries stay in the log; without the source they show without their text.
    if (-not $KeepData -and -not $Msi) {
        try {
            if ([Diagnostics.EventLog]::SourceExists($EventSource) -and
                [Diagnostics.EventLog]::LogNameFromSourceName($EventSource, '.') -eq 'Application') {
                [Diagnostics.EventLog]::DeleteEventSource($EventSource)
                Write-Note "Removed the '$EventSource' Application event log source."
            }
        }
        catch { Write-Caution "Could not remove the '$EventSource' event log source: $($_.Exception.Message)" }
    }

    if (-not $Msi) {
        $shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'WatchLattice.lnk'
        if (Test-Path -LiteralPath $shortcut) { Remove-Item -LiteralPath $shortcut -Force }
        if (Test-Path -LiteralPath $UninstallKey) { Remove-Item -LiteralPath $UninstallKey -Recurse -Force }
    }

    Write-Step 'Removing files'
    Set-Location -LiteralPath $env:SystemRoot
    if (-not $KeepData) {
        Remove-Folder $DataRoot
        foreach ($dir in $dataDirs + $tempDirs) { Remove-Folder $dir }
    }
    else {
        Write-Note "Kept $DataRoot and $($dataDirs[0])."
    }
    # Under Windows Installer the install folder goes after its files do.
    if ($installed -and -not $Msi) { Remove-Folder $InstallDir }

    Write-Host ''
    if ($problems) {
        Write-Host 'WatchLattice was removed, with the warnings above.' -ForegroundColor Yellow
    }
    else {
        Write-Host 'WatchLattice was removed.' -ForegroundColor Green
    }
    $exitCode = 0
}
catch [OperationCanceledException] {
    $exitCode = 1
}
catch {
    Write-Host ''
    Write-Host "Uninstall failed: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}

if ($PauseAtEnd) {
    Write-Host ''
    Read-Host 'Press Enter to close this window' | Out-Null
}
exit $exitCode
