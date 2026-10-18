<#
.SYNOPSIS
    Installs the WatchLattice MSI, checks what it set up, upgrades it, installs
    a rebuild of the same version over it, then uninstalls and checks nothing
    is left.

.DESCRIPTION
    CI runs this on a Windows runner (as an administrator) with three MSIs
    built from one release-shaped folder by .github/scripts/Build-Msi.ps1:
    -Msi (an older version), -UpgradeMsi (a newer one) and -RebuiltMsi (the
    newer version built again, so a different product code). It changes the
    machine it runs on: it installs the "ScanAlways Protection" service and
    plants canary files in a scratch folder. Do not run it on a PC that
    already has WatchLattice.

.EXAMPLE
    powershell -File tests\installer\Test-Msi.ps1 -Package $env:RUNNER_TEMP\package -Msi a.msi -UpgradeMsi b.msi -RebuiltMsi c.msi
#>
#Requires -Version 5.1
param(
    [Parameter(Mandatory)] [string]$Package,
    [Parameter(Mandatory)] [string]$Msi,
    [Parameter(Mandatory)] [string]$UpgradeMsi,
    [Parameter(Mandatory)] [string]$RebuiltMsi,
    [Parameter(Mandatory)] [string]$LogDir,
    [string]$Scratch = (Join-Path $env:SystemDrive 'WatchLatticeMsiTest')
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

$ServiceName = 'ScanAlways Protection'
$InstallDir = Join-Path $env:ProgramFiles 'WatchLattice'
$FeedDir = Join-Path $env:ProgramData 'WatchLattice\Alerts'
$SystemData = Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\ScanAlways'
$ScriptUninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WatchLattice'
$EventSourceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\WatchLattice'
$RunKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
$Shortcut = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'WatchLattice.lnk'
$TrayUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$Settings = Join-Path $InstallDir 'Hub\appsettings.json'
$StatePath = Join-Path $InstallDir 'install-state.json'

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

function Invoke-Msiexec([string]$Name, [string[]]$Arguments) {
    $log = Join-Path $LogDir "$Name.log"
    Write-Host "> msiexec $($Arguments -join ' ')"
    $process = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\msiexec.exe') `
        -ArgumentList ($Arguments + @('/qn', '/norestart', '/l*v', "`"$log`"")) -Wait -PassThru
    if ($process.ExitCode -ne 0 -and (Test-Path -LiteralPath $log)) {
        # The first failing action and what it printed are just above "Return value 3".
        $lines = Get-Content -LiteralPath $log
        $failed = @($lines | Select-String -SimpleMatch 'Return value 3.' | Select-Object -First 1)
        $end = if ($failed) { $failed[0].LineNumber } else { $lines.Count }
        Write-Host "--- $log (up to the failure)"
        $lines[[Math]::Max(0, $end - 60)..($end - 1)] | Out-Host
    }
    $process.ExitCode
}

function Invoke-Script([string]$Path, [string[]]$Arguments) {
    Write-Host "> $Path $($Arguments -join ' ')"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $Path @Arguments | Out-Host
    $LASTEXITCODE
}

function Get-Canaries([string]$Folder) {
    @(Get-ChildItem -LiteralPath $Folder -Force -File | Where-Object { $_.Name -notlike 'keep-*' })
}

# Settings > Apps entries Windows Installer made for WatchLattice.
function Get-MsiEntries {
    @(Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' |
        ForEach-Object { Get-ItemProperty -LiteralPath $_.PSPath } |
        Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and $_.DisplayName -eq 'WatchLattice' -and
            $_.PSObject.Properties.Name -contains 'WindowsInstaller' -and $_.WindowsInstaller -eq 1 })
}

function Get-State { Get-Content -Raw -LiteralPath $StatePath | ConvertFrom-Json }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "'$ServiceName' is already installed here." }
$canaryFolder = Join-Path $Scratch 'Protected'
New-Item -ItemType Directory -Force -Path $canaryFolder | Out-Null
Set-Content -LiteralPath (Join-Path $canaryFolder 'keep-real-document.txt') -Value 'a file the user owns'

Write-Host '== Install'
$code = Invoke-Msiexec 'install' @('/i', "`"$Msi`"", "CANARYFOLDERS=`"$canaryFolder`"", 'UPDATECHECK=0')
Check 'msiexec install exits 0' ($code -eq 0)
$service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
Check 'service exists' ($null -ne $service)
Check 'service starts automatically as LocalSystem' ($service -and $service.StartMode -eq 'Auto' -and $service.StartName -eq 'LocalSystem')
Check 'service points at the installed hub' ($service -and $service.PathName -eq "`"$InstallDir\Hub\ScanAlways.Protection.Service.exe`"")
Check 'service is running' (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' })
Check 'service restarts after a crash' ((& sc.exe qfailure $ServiceName | Out-String) -match 'RESTART')

$config = Get-Content -Raw -LiteralPath $Settings | ConvertFrom-Json
Check 'feed path is the shared folder' ($config.Alerts.FeedPath -eq "$FeedDir\alerts.json")
Check 'canary folders are the chosen ones' ((@($config.Canary.Folders) -join '|') -eq $canaryFolder)
Check 'update checks are off as asked' ($config.Modules.Updater.Enabled -eq $false)
Check 'decoy is on by default' ($config.Modules.Decoy.Enabled -eq $true)
Check 'decoy scans the installing user''s profile' (@($config.Decoy.ScanRoots) -contains $env:USERPROFILE)
Check 'release defaults are installed alongside' (Test-Path -LiteralPath "$Settings.default")

Check 'hub writes the feed heartbeat' (Wait-Until { Test-Path -LiteralPath "$FeedDir\alerts.json.heartbeat.json" })
Check 'tray user can read the feed' ($null -ne (Get-Content -Raw -LiteralPath "$FeedDir\alerts.json.heartbeat.json" -ErrorAction SilentlyContinue))
$feedAcl = (Get-Acl -LiteralPath $FeedDir).Access | Where-Object { $_.IdentityReference.Value -eq $TrayUser }
Check 'tray user has read, not write, access to the feed' ($feedAcl -and -not ($feedAcl | Where-Object { $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData }))
$usersAcl = (Get-Acl -LiteralPath $InstallDir).Access | Where-Object { $_.IdentityReference.Value -eq 'BUILTIN\Users' }
Check 'Users can only read the install folder' ($usersAcl -and -not ($usersAcl | Where-Object { $_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::WriteData }))

Check 'Application event log source is registered' ([Diagnostics.EventLog]::SourceExists('WatchLattice') -and [Diagnostics.EventLog]::LogNameFromSourceName('WatchLattice', '.') -eq 'Application')
$messageFile = (Get-ItemProperty -LiteralPath $EventSourceKey -Name EventMessageFile -ErrorAction SilentlyContinue).EventMessageFile
Check 'event source has a message file that exists' ($messageFile -and (Test-Path -LiteralPath ([Environment]::ExpandEnvironmentVariables($messageFile))))
Check 'canaries are planted' (Wait-Until { (Get-Canaries $canaryFolder).Count -ge 3 })
Check 'tray starts at sign-in' ("$((Get-ItemProperty -LiteralPath $RunKey -Name 'WatchLattice Tray' -ErrorAction SilentlyContinue).'WatchLattice Tray')" -like '*ScanAlways.Tray.exe*--feed*')
Check 'Start menu shortcut exists' (Test-Path -LiteralPath $Shortcut)
$entries = Get-MsiEntries
Check 'listed once in Settings > Apps' ($entries.Count -eq 1)
Check 'no Install.cmd entry next to it' (-not (Test-Path -LiteralPath $ScriptUninstallKey))
$state = Get-State
Check 'install-state.json records the MSI install' ($state.InstalledBy -eq 'msi' -and $entries.Count -eq 1 -and $state.ProductCode -eq $entries[0].PSChildName)
Check 'install-state.json records the tray user' ($state.TrayUser -eq $TrayUser)

$code = Invoke-Script (Join-Path $Package 'install.ps1') @('-Quiet', '-NoTrayStart')
Check 'install.ps1 refuses to install over the MSI' ($code -eq 1)
Check 'service is still running' ((Get-Service -Name $ServiceName).Status -eq 'Running')

Write-Host '== Upgrade'
$config.Alerts.HistoryLimit = 123
ConvertTo-Json -InputObject $config -Depth 32 | Set-Content -LiteralPath $Settings
$canariesBefore = (Get-Canaries $canaryFolder).Count
$code = Invoke-Msiexec 'upgrade' @('/i', "`"$UpgradeMsi`"")
Check 'msiexec upgrade exits 0' ($code -eq 0)
Check 'upgrade keeps the user''s settings' ((Get-Content -Raw -LiteralPath $Settings | ConvertFrom-Json).Alerts.HistoryLimit -eq 123)
Check 'upgrade keeps the first-run choices' ((@((Get-Content -Raw -LiteralPath $Settings | ConvertFrom-Json).Canary.Folders) -join '|') -eq $canaryFolder)
$entries = Get-MsiEntries
Check 'still listed once, as the new version' ($entries.Count -eq 1 -and $entries[0].DisplayVersion -eq '0.0.2')
Check 'install-state.json has the new product code' ($entries.Count -eq 1 -and (Get-State).ProductCode -eq $entries[0].PSChildName)
Check 'service is running again' (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' })
Check 'canaries are kept' ((Get-Canaries $canaryFolder).Count -eq $canariesBefore)
Check 'feed folder is kept' (Test-Path -LiteralPath "$FeedDir\alerts.json.heartbeat.json")

Write-Host '== Install a rebuild of the same version over it'
$code = Invoke-Msiexec 'reinstall' @('/i', "`"$RebuiltMsi`"")
Check 'msiexec reinstall exits 0' ($code -eq 0)
$entries = Get-MsiEntries
Check 'still listed once' ($entries.Count -eq 1)
Check 'reinstall keeps the user''s settings' ((Get-Content -Raw -LiteralPath $Settings | ConvertFrom-Json).Alerts.HistoryLimit -eq 123)
Check 'service is running after the reinstall' (Wait-Until { (Get-Service -Name $ServiceName).Status -eq 'Running' })

Write-Host '== Uninstall (uninstall.ps1 hands over to Windows Installer)'
# Change one canary while the hub is stopped, so the watcher does not react
# to it first: uninstall must keep it and remove the rest.
Stop-Service -Name $ServiceName
$tampered = (Get-Canaries $canaryFolder)[0].FullName
Set-ItemProperty -LiteralPath $tampered -Name Attributes -Value Normal
[IO.File]::WriteAllText($tampered, 'tampered')
Copy-Item -LiteralPath (Join-Path $InstallDir 'uninstall.ps1') -Destination (Join-Path $Scratch 'uninstall.ps1')
$code = Invoke-Script (Join-Path $Scratch 'uninstall.ps1') @('-Quiet', '-InstallDir', $InstallDir)
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
Check 'Settings > Apps entry is gone' ((Get-MsiEntries).Count -eq 0)

Remove-Item -LiteralPath $Scratch -Recurse -Force -ErrorAction SilentlyContinue
if ($failures) { throw "$failures MSI check(s) failed." }
Write-Host 'All MSI checks passed.' -ForegroundColor Green
