<#
.SYNOPSIS
    Installs a packaged build with installer\install.ps1, checks what it set
    up, reinstalls over it, then uninstalls and checks nothing is left.

.DESCRIPTION
    CI runs this on a Windows runner (as an administrator) against a folder
    laid out like the release zip. It changes the machine it runs on: it
    installs the "ScanAlways Protection" service and plants canary files in a
    scratch folder. Do not run it on a PC that already has WatchLattice.

.EXAMPLE
    powershell -File tests\installer\Test-Installer.ps1 -Package $env:RUNNER_TEMP\package
#>
#Requires -Version 5.1
param(
    [Parameter(Mandatory)] [string]$Package,
    [string]$Scratch = (Join-Path $env:SystemDrive 'WatchLatticeInstallerTest')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$ServiceName = 'ScanAlways Protection'
$InstallDir = Join-Path $env:ProgramFiles 'WatchLattice'
$FeedDir = Join-Path $env:ProgramData 'WatchLattice\Alerts'
$SystemData = Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\ScanAlways'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WatchLattice'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'WatchLattice.lnk'
$TrayUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name

$failures = 0
function Check([string]$Name, [bool]$Condition) {
    if ($Condition) { Write-Host "  ok    $Name" -ForegroundColor Green }
    else { Write-Host "  FAIL  $Name" -ForegroundColor Red; $script:failures++ }
}

function Wait-Until([scriptblock]$Condition, [int]$Seconds = 60) {
    for ($i = 0; $i -lt $Seconds * 2; $i++) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 500
    }
    $false
}

function Invoke-Script([string]$Path, [string[]]$Arguments) {
    Write-Host "> $Path $($Arguments -join ' ')"
    # Out-Host keeps the script's output in the log instead of in this function's return value.
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Path @Arguments | Out-Host
    $LASTEXITCODE
}

function Get-Canaries([string]$Folder) {
    @(Get-ChildItem -LiteralPath $Folder -Force -File | Where-Object { $_.Name -notlike 'keep-*' })
}

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "'$ServiceName' is already installed here." }
$canaryFolder = Join-Path $Scratch 'Protected'
New-Item -ItemType Directory -Force -Path $canaryFolder | Out-Null
Set-Content -LiteralPath (Join-Path $canaryFolder 'keep-real-document.txt') -Value 'a file the user owns'

Write-Host '== Install'
$code = Invoke-Script (Join-Path $Package 'install.ps1') @('-Quiet', '-TrayUser', $TrayUser, '-CanaryFolders', $canaryFolder, '-NoUpdateCheck', '-NoTrayStart')
Check 'install.ps1 exits 0' ($code -eq 0)
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
Check 'service exists' ($null -ne $service)
Check 'service starts automatically as LocalSystem' ($service -and $service.StartMode -eq 'Auto' -and $service.StartName -eq 'LocalSystem')
Check 'service points at the installed hub' ($service -and $service.PathName -eq "`"$InstallDir\Hub\ScanAlways.Protection.Service.exe`"")
Check 'service is running' (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' })

$config = Get-Content -Raw -LiteralPath "$InstallDir\Hub\appsettings.json" | ConvertFrom-Json
Check 'feed path is the shared folder' ($config.Alerts.FeedPath -eq "$FeedDir\alerts.json")
Check 'canary folders are the chosen ones' ((@($config.Canary.Folders) -join '|') -eq $canaryFolder)
Check 'update checks are off as asked' ($config.Modules.Updater.Enabled -eq $false)
Check 'decoy is on by default' ($config.Modules.Decoy.Enabled -eq $true)
Check 'decoy scans the tray user''s profile' (@($config.Decoy.ScanRoots) -contains $env:USERPROFILE)

Check 'hub writes the feed heartbeat' (Wait-Until { Test-Path -LiteralPath "$FeedDir\alerts.json.heartbeat.json" })
Check 'tray user can read the feed' ($null -ne (Get-Content -Raw -LiteralPath "$FeedDir\alerts.json.heartbeat.json"))
$feedAcl = (Get-Acl -LiteralPath $FeedDir).Access | Where-Object { $_.IdentityReference.Value -eq $TrayUser }
Check 'tray user has read, not write, access to the feed' ($feedAcl -and -not ($feedAcl | Where-Object { $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData }))
$usersAcl = (Get-Acl -LiteralPath $InstallDir).Access | Where-Object { $_.IdentityReference.Value -eq 'BUILTIN\Users' }
Check 'Users can only read the install folder' ($usersAcl -and -not ($usersAcl | Where-Object { $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData }))

Check 'hub registers its Application event log source' (Wait-Until { [Diagnostics.EventLog]::SourceExists('WatchLattice') })
if (-not [Diagnostics.EventLog]::SourceExists('WatchLattice')) {
    # Show why: the hub reports a failed registration as an alert and in its activity log.
    foreach ($file in "$FeedDir\alerts.json", "$FeedDir\alerts.json.activity.json") {
        Write-Host "--- $file"
        if (Test-Path -LiteralPath $file) { Get-Content -Raw -LiteralPath $file | Out-Host }
    }
}
Check 'canaries are planted' (Wait-Until { (Get-Canaries $canaryFolder).Count -ge 3 })
Check 'tray starts at sign-in' ("$((Get-ItemProperty -LiteralPath $RunKey -Name 'WatchLattice Tray' -ErrorAction SilentlyContinue).'WatchLattice Tray')" -like '*ScanAlways.Tray.exe*--feed*')
Check 'Start menu shortcut exists' (Test-Path -LiteralPath $Shortcut)
Check 'listed in Settings > Apps' (Test-Path -LiteralPath $UninstallKey)
Check 'uninstall.ps1 is installed' (Test-Path -LiteralPath "$InstallDir\uninstall.ps1")

Write-Host '== Reinstall over it'
$config.Alerts.HistoryLimit = 123
ConvertTo-Json -InputObject $config -Depth 32 | Set-Content -LiteralPath "$InstallDir\Hub\appsettings.json"
$code = Invoke-Script (Join-Path $Package 'install.ps1') @('-Quiet', '-TrayUser', $TrayUser, '-NoTrayStart')
Check 'reinstall exits 0' ($code -eq 0)
Check 'reinstall keeps the user''s settings' ((Get-Content -Raw -LiteralPath "$InstallDir\Hub\appsettings.json" | ConvertFrom-Json).Alerts.HistoryLimit -eq 123)
Check 'reinstall writes the release defaults alongside' (Test-Path -LiteralPath "$InstallDir\Hub\appsettings.json.default")
Check 'service is running again' (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' })

Write-Host '== Dashboard settings and activity'
$hubExe = "$InstallDir\Hub\ScanAlways.Protection.Service.exe"
$settingsPath = "$InstallDir\Hub\appsettings.json"
Check 'hub writes its activity next to the feed' (Wait-Until { Test-Path -LiteralPath "$FeedDir\alerts.json.activity.json" })
$described = & $hubExe --describe-settings | Out-String
Check 'describe-settings exits 0' ($LASTEXITCODE -eq 0)
$description = $described | ConvertFrom-Json
Check 'describe-settings lists the module switches' (@($description.sections | Where-Object { $_.path -eq 'Modules' }).Count -eq 1)
Check 'describe-settings lists the daily summary settings' (@($description.sections | Where-Object { $_.path -eq 'Alerts:DailySummary' }).Count -eq 1)

& $hubExe --export-alerts "$Scratch\alerts.csv" | Out-Host
Check 'export-alerts writes a CSV for the tray user' ($LASTEXITCODE -eq 0 -and (Get-Content -LiteralPath "$Scratch\alerts.csv" -TotalCount 1) -like 'LastSeenUtc,FirstSeenUtc,Count,*')
& $hubExe --export-alerts "$Scratch\alerts.txt" --format json --group | Out-Host
$exported = if (Test-Path -LiteralPath "$Scratch\alerts.txt") { Get-Content -Raw -LiteralPath "$Scratch\alerts.txt" | ConvertFrom-Json } else { $null }
Check 'export-alerts writes grouped JSON when asked' ($LASTEXITCODE -eq 0 -and $exported -and $exported.version -eq 1 -and $exported.grouped -eq $true)

$config = Get-Content -Raw -LiteralPath $settingsPath | ConvertFrom-Json
$config.Canary.IntegrityCheckSeconds = 90
# Windows PowerShell writes UTF-8 with a byte order mark, as Notepad can; the hub must accept it.
ConvertTo-Json -InputObject $config -Depth 32 | Set-Content -Encoding UTF8 -LiteralPath "$settingsPath.pending"
& $hubExe --apply-settings | Out-Host
Check 'apply-settings saves a valid change' ($LASTEXITCODE -eq 0)
Check 'the change is in appsettings.json' ((Get-Content -Raw -LiteralPath $settingsPath | ConvertFrom-Json).Canary.IntegrityCheckSeconds -eq 90)
Check 'the previous settings are backed up' (@(Get-ChildItem -LiteralPath "$InstallDir\Hub\settings-backups" -Filter 'appsettings-*.json').Count -eq 1)
Check 'the staged file is removed' (-not (Test-Path -LiteralPath "$settingsPath.pending"))
Check 'service is running with the new settings' (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' })

$before = Get-Content -Raw -LiteralPath $settingsPath
$config = $before | ConvertFrom-Json
$config.Updater.Repository = 'someone-else/WatchLattice'
ConvertTo-Json -InputObject $config -Depth 32 | Set-Content -Encoding UTF8 -LiteralPath "$settingsPath.pending"
& $hubExe --apply-settings | Out-Host
Check 'apply-settings refuses to change the update source' ($LASTEXITCODE -eq 21)
Check 'a refused change leaves appsettings.json alone' ((Get-Content -Raw -LiteralPath $settingsPath) -eq $before)

Write-Host '== Uninstall'
# Change one canary while the hub is stopped, so the watcher does not react
# to it first: uninstall must keep it and remove the rest.
Stop-Service -Name $ServiceName
$tampered = (Get-Canaries $canaryFolder)[0].FullName
Set-ItemProperty -LiteralPath $tampered -Name Attributes -Value Normal
[IO.File]::WriteAllText($tampered, 'tampered')
$code = Invoke-Script (Join-Path $InstallDir 'uninstall.ps1') @('-Quiet')
Check 'uninstall.ps1 exits 0' ($code -eq 0)
Check 'service is gone' (Wait-Until { -not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) })
Check 'intact canaries are removed' (@(Get-Canaries $canaryFolder | Where-Object { $_.FullName -ne $tampered }).Count -eq 0)
Check 'the changed canary is kept as evidence' (Test-Path -LiteralPath $tampered)
Check 'the user''s own file is untouched' ((Get-Content -LiteralPath (Join-Path $canaryFolder 'keep-real-document.txt')) -eq 'a file the user owns')
Check 'install folder is gone' (-not (Test-Path -LiteralPath $InstallDir))
Check 'feed folder is gone' (-not (Test-Path -LiteralPath (Split-Path $FeedDir)))
Check 'hub data is gone' (-not (Test-Path -LiteralPath $SystemData))
Check 'sign-in entry is gone' ($null -eq (Get-ItemProperty -LiteralPath $RunKey -Name 'WatchLattice Tray' -ErrorAction SilentlyContinue))
Check 'Start menu shortcut is gone' (-not (Test-Path -LiteralPath $Shortcut))
Check 'event log source is gone' (-not [Diagnostics.EventLog]::SourceExists('WatchLattice'))
Check 'Settings > Apps entry is gone' (-not (Test-Path -LiteralPath $UninstallKey))

Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
if ($failures) { throw "$failures installer check(s) failed." }
Write-Host 'All installer checks passed.' -ForegroundColor Green
