<#
.SYNOPSIS
    Installs WatchLattice from an extracted release: the hub as a Windows
    service, the tray companion at sign-in, and your first-run choices.

.DESCRIPTION
    Run it from the folder you extracted the release zip into (the one with
    Hub\ and Tray\ next to this script), or double-click Install.cmd. It asks
    for administrator rights when it needs them, then:

      1. checks that the .NET 8 Runtime and Desktop Runtime are installed,
      2. copies Hub\ and Tray\ to the install folder (Program Files by default),
      3. asks which folders get canary files, and whether to run the decoy
         and the update checker, and writes those into Hub\appsettings.json,
      4. creates a shared alert feed in %ProgramData%\WatchLattice\Alerts that
         only the hub can write and only you (the tray user) can read,
      5. installs and starts the "ScanAlways Protection" service as
         LocalSystem, restarting it if it ever crashes,
      6. starts the tray at your sign-in, adds a Start menu shortcut, and
         registers WatchLattice under Settings > Apps for a clean uninstall.

    Running it again over an existing install updates the files and keeps
    your appsettings.json (the release's copy is written next to it as
    appsettings.json.default). Use -Reconfigure to answer the questions again.

    The in-hub updater keeps working after this install: the service name,
    executable names and data folders are the ones it expects.

.PARAMETER InstallDir
    Where to install. Defaults to %ProgramFiles%\WatchLattice. It must be in a
    folder that only administrators can change, because the service runs
    from it as LocalSystem.

.PARAMETER TrayUser
    The account whose tray reads the alert feed and whose folders are
    protected. Defaults to the signed-in user.

.PARAMETER CanaryFolders
    Folders to plant canary files in, instead of asking. Separate several
    with ';'. Defaults to the tray user's Desktop, Documents and Pictures.

.PARAMETER NoDecoy
    Do not run the always-scanning decoy.

.PARAMETER NoUpdateCheck
    Do not check GitHub for new releases.

.PARAMETER NoTrayAutostart
    Do not start the tray at sign-in.

.PARAMETER NoTrayStart
    Do not start the tray at the end of the install.

.PARAMETER Reconfigure
    Ask the first-run questions again on an existing install and rewrite
    those settings in appsettings.json.

.PARAMETER Quiet
    Accept the defaults (or the values given as parameters) without asking.

.PARAMETER Msi
    Used by the WatchLattice MSI, which runs this script from the install
    folder after it has installed the files and the service. Does only the
    parts that depend on the tray user: the install folder and alert feed
    permissions, the first-run settings (without asking), the service's
    restart-on-crash settings, the tray's sign-in entry and
    install-state.json. Windows Installer does the rest.

.PARAMETER ProductCode
    With -Msi: the MSI's product code, recorded so uninstall.ps1 can hand an
    uninstall over to Windows Installer.

.EXAMPLE
    .\install.ps1

.EXAMPLE
    .\install.ps1 -Quiet -CanaryFolders 'D:\Projects;C:\Users\me\Documents' -NoDecoy
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles 'WatchLattice'),
    [string]$TrayUser,
    [string[]]$CanaryFolders,
    [switch]$NoDecoy,
    [switch]$NoUpdateCheck,
    [switch]$NoTrayAutostart,
    [switch]$NoTrayStart,
    [switch]$Reconfigure,
    [switch]$Quiet,
    [switch]$Msi,
    [string]$ProductCode,
    # Set when this script relaunches itself elevated, so its window stays open.
    [switch]$PauseAtEnd
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3

# These names are what installed hubs and the updater depend on; see
# docs/releasing.md#names-that-must-not-change.
$ServiceName = 'ScanAlways Protection'
$HubExeName = 'ScanAlways.Protection.Service.exe'
$TrayExeName = 'ScanAlways.Tray.exe'

$ServiceDisplayName = 'WatchLattice Protection'
$DataRoot = Join-Path $env:ProgramData 'WatchLattice'
$FeedDir = Join-Path $DataRoot 'Alerts'
$FeedPath = Join-Path $FeedDir 'alerts.json'
$RunValueName = 'WatchLattice Tray'
$UninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WatchLattice'
$StateFileName = 'install-state.json'
$TrustedSids = @(
    'S-1-5-18',      # LocalSystem
    'S-1-5-32-544',  # Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'  # TrustedInstaller
)

function Write-Step([string]$Message) { Write-Host "==> $Message" -ForegroundColor Cyan }
function Write-Note([string]$Message) { Write-Host "    $Message" }
function Write-Caution([string]$Message) { Write-Host "    $Message" -ForegroundColor Yellow }

function Test-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Windows PowerShell's -File passes each argument as one string, so lists go
# across as 'a;b' and are split again here.
function ConvertTo-ArgumentList([hashtable]$Parameters) {
    $list = @()
    foreach ($entry in $Parameters.GetEnumerator()) {
        $value = $entry.Value
        if ($value -is [System.Management.Automation.SwitchParameter]) {
            if ($value.IsPresent) { $list += "-$($entry.Key)" }
        }
        else {
            $text = (@($value) | ForEach-Object { "$_".TrimEnd('\') }) -join ';'
            $list += "-$($entry.Key)", "`"$text`""
        }
    }
    $list
}

function Invoke-Native([string]$FilePath, [string[]]$Arguments) {
    # Windows PowerShell turns redirected stderr into errors; report the exit code instead.
    $ErrorActionPreference = 'Continue'
    $output = & $FilePath @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath $($Arguments -join ' ') failed ($LASTEXITCODE): $($output -join ' ')"
    }
}

function Read-YesNo([string]$Question, [bool]$Default) {
    if ($Quiet) { return $Default }
    $suffix = if ($Default) { '[Y/n]' } else { '[y/N]' }
    while ($true) {
        $answer = (Read-Host "$Question $suffix").Trim()
        if (-not $answer) { return $Default }
        if ($answer -match '^(y|yes)$') { return $true }
        if ($answer -match '^(n|no)$') { return $false }
    }
}

function Split-PathList([string[]]$Values) {
    @($Values | ForEach-Object { "$_".Split(';') } | ForEach-Object { $_.Trim().Trim('"') } | Where-Object { $_ })
}

function Get-OwnerSid([string]$Path) {
    (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
}

function Assert-NoReparsePoints([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    $links = @($item) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue) |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }
    if ($links) {
        throw "$Path contains links or junctions ($(@($links)[0].FullName)). Remove them, then run the install again."
    }
}

# The service runs as LocalSystem from the install folder, so nobody but an
# administrator may be able to replace it: not in the folder, and not by
# renaming or re-permissioning any folder above it.
function Assert-AdminOnlyLocation([string]$Path) {
    $dangerous = [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
    $genericAllOrWrite = 0x10000000 -bor 0x40000000

    $current = [IO.Path]::GetDirectoryName($Path.TrimEnd('\'))
    while ($current) {
        if (Test-Path -LiteralPath $current) {
            $acl = Get-Acl -LiteralPath $current
            $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
            if ($TrustedSids -notcontains $owner) {
                throw "$current is owned by $owner, not an administrator. Pick an -InstallDir inside a folder only administrators can change, such as Program Files."
            }
            foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
                if ($rule.AccessControlType -ne 'Allow') { continue }
                if ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
                if ($TrustedSids -contains $rule.IdentityReference.Value) { continue }
                $rights = [int64]$rule.FileSystemRights
                if (($rights -band [int64]$dangerous) -or ($rights -band $genericAllOrWrite)) {
                    throw "$($rule.IdentityReference.Value) can change $current. Pick an -InstallDir inside a folder only administrators can change, such as Program Files."
                }
            }
        }
        $current = [IO.Path]::GetDirectoryName($current)
    }
}

# Replaces a folder's permissions with: SYSTEM and Administrators full
# control, plus the given extra grants, inherited by everything inside.
function Set-ProtectedAcl([string]$Path, [string[]]$ExtraGrants) {
    Invoke-Native icacls.exe @($Path, '/setowner', '*S-1-5-32-544', '/T', '/C', '/Q')
    $grants = @('*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F') + @($ExtraGrants)
    Invoke-Native icacls.exe (@($Path, '/inheritance:r', '/grant:r') + $grants + @('/Q'))
    if (Get-ChildItem -LiteralPath $Path -Force) {
        Invoke-Native icacls.exe @((Join-Path $Path '*'), '/reset', '/T', '/C', '/Q')
    }
}

function New-OwnedDirectory([string]$Path, [string]$Purpose) {
    if (Test-Path -LiteralPath $Path) {
        $owner = Get-OwnerSid $Path
        if ($TrustedSids -notcontains $owner) {
            throw "$Path already exists and belongs to $owner, not an administrator. Check what it is and remove it, then run the install again. ($Purpose)"
        }
        Assert-NoReparsePoints $Path
    }
    else {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Resolve-TrayAccount([string]$Name) {
    if (-not $Name) {
        $console = $null
        try { $console = (Get-CimInstance Win32_ComputerSystem).UserName } catch { }
        $Name = if ($console) { $console } else { [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    }
    try {
        # The MSI passes the installing user as a SID.
        if ($Name -match '^S-1-\d+(-\d+)+$') {
            $sid = $Name
            $Name = (New-Object Security.Principal.SecurityIdentifier($sid)).Translate([Security.Principal.NTAccount]).Value
        }
        else {
            $sid = (New-Object Security.Principal.NTAccount($Name)).Translate([Security.Principal.SecurityIdentifier]).Value
        }
    }
    catch {
        throw "Could not find the account '$Name'. Pass the tray user as -TrayUser 'COMPUTER\name'."
    }
    if ($sid -eq 'S-1-5-18') {
        throw 'The tray user cannot be LocalSystem. Pass the account that uses the tray as -TrayUser (TRAYUSER for the MSI).'
    }
    $userProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
    if (-not $userProfile) {
        throw "'$Name' has no profile on this PC yet. Sign in as that user once, or pass a different -TrayUser."
    }
    [pscustomobject]@{
        Name        = $Name
        Sid         = $sid
        ProfilePath = $userProfile.LocalPath
        Hive        = "Registry::HKEY_USERS\$sid"
    }
}

# Reads one of the user's known folders (Desktop, Documents, ...) from their
# own registry hive, so OneDrive-redirected folders resolve correctly.
function Get-UserFolder($Account, [string]$ValueName, [string]$Fallback) {
    $key = "$($Account.Hive)\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    if (Test-Path -LiteralPath $key) {
        $raw = (Get-Item -LiteralPath $key).GetValue($ValueName, $null, 'DoNotExpandEnvironmentNames')
        if ($raw) {
            $withProfile = $raw -replace '%USERPROFILE%', $Account.ProfilePath.Replace('$', '$$')
            return [Environment]::ExpandEnvironmentVariables($withProfile)
        }
    }
    Join-Path $Account.ProfilePath $Fallback
}

function Test-Framework([string]$Name, [version]$Minimum) {
    $roots = @(Join-Path $env:ProgramFiles 'dotnet')
    $registered = Get-ItemProperty -Path 'HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64' -Name InstallLocation -ErrorAction SilentlyContinue
    if ($registered) { $roots = @($registered.InstallLocation) + $roots }
    foreach ($root in $roots) {
        $dir = Join-Path $root "shared\$Name"
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($candidate in Get-ChildItem -LiteralPath $dir -Directory) {
            $parsed = $null
            if ([version]::TryParse(($candidate.Name -split '-')[0], [ref]$parsed) -and
                $parsed.Major -eq $Minimum.Major -and $parsed -ge $Minimum) { return $true }
        }
    }
    $false
}

function Assert-Runtimes([string]$PackageRoot) {
    $missing = @()
    foreach ($config in @(
        (Join-Path $PackageRoot 'Hub\ScanAlways.Protection.Service.runtimeconfig.json'),
        (Join-Path $PackageRoot 'Tray\ScanAlways.Tray.runtimeconfig.json'))) {
        $options = (Get-Content -Raw -LiteralPath $config | ConvertFrom-Json).runtimeOptions
        $frameworks = if ($options.PSObject.Properties.Name -contains 'frameworks') { @($options.frameworks) } else { @($options.framework) }
        foreach ($framework in $frameworks) {
            if (-not (Test-Framework $framework.name ([version]$framework.version)) -and $missing -notcontains $framework.name) {
                $missing += $framework.name
            }
        }
    }
    if ($missing) {
        throw ("WatchLattice needs the .NET 8 Desktop Runtime (x64), which also includes the .NET Runtime. Missing: $($missing -join ', ').`n" +
            "    Install it with:  winget install Microsoft.DotNet.DesktopRuntime.8`n" +
            "    or download it from https://dotnet.microsoft.com/download/dotnet/8.0, then run the install again.")
    }
}

function Set-ConfigValue($Object, [string]$Path, $Value) {
    $parts = $Path.Split(':')
    $node = $Object
    for ($i = 0; $i -lt $parts.Length - 1; $i++) {
        $name = $parts[$i]
        if ($node.PSObject.Properties.Name -notcontains $name -or $null -eq $node.$name) {
            $node | Add-Member -NotePropertyName $name -NotePropertyValue ([pscustomobject]@{}) -Force
        }
        $node = $node.$name
    }
    $node | Add-Member -NotePropertyName $parts[-1] -NotePropertyValue $Value -Force
}

function Wait-ServiceGone([string]$Name) {
    for ($i = 0; $i -lt 60 -and (Get-Service -Name $Name -ErrorAction SilentlyContinue); $i++) { Start-Sleep -Milliseconds 500 }
}

try {
    if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
        throw 'Run this from 64-bit PowerShell (the default "Windows PowerShell"), not the x86 one.'
    }

    if ($Msi) {
        # Windows Installer has put this script in the install folder, and
        # runs it as LocalSystem without a console to ask questions on.
        $InstallDir = $PSScriptRoot
        $Quiet = [switch]$true
    }

    if (-not (Test-Administrator)) {
        Write-Step 'Asking for administrator rights to install the service'
        $forward = @{}
        foreach ($key in $PSBoundParameters.Keys) { $forward[$key] = $PSBoundParameters[$key] }
        if (-not $forward.ContainsKey('TrayUser')) { $forward['TrayUser'] = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"") +
            (ConvertTo-ArgumentList $forward) + @('-PauseAtEnd')
        try {
            $elevated = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $arguments -Verb RunAs -Wait -PassThru
        }
        catch {
            throw 'The administrator prompt was declined. Nothing was installed.'
        }
        exit $elevated.ExitCode
    }

    # Windows PowerShell wraps some arrays as {"value": [...], "Count": n} in
    # ConvertTo-Json unless this type data is removed for the session.
    Remove-TypeData -TypeName System.Array -ErrorAction SilentlyContinue

    $packageRoot = $PSScriptRoot
    $InstallDir = [IO.Path]::GetFullPath($InstallDir).TrimEnd('\')
    foreach ($required in @("Hub\$HubExeName", "Tray\$TrayExeName")) {
        if (-not (Test-Path -LiteralPath (Join-Path $packageRoot $required))) {
            throw "This folder has no $required. Run install.ps1 from the folder you extracted the WatchLattice release zip into."
        }
    }
    if (-not $Msi -and $packageRoot.TrimEnd('\') -eq $InstallDir) {
        throw "Run install.ps1 from the extracted release, not from $InstallDir."
    }

    $version = (Get-Item -LiteralPath (Join-Path $packageRoot "Hub\$HubExeName")).VersionInfo.ProductVersion
    Write-Host "WatchLattice $version installer" -ForegroundColor Green
    Write-Host 'WatchLattice complements Microsoft Defender; it does not replace it.'
    Write-Host ''

    Write-Step 'Checking prerequisites'
    Assert-Runtimes $packageRoot
    Assert-AdminOnlyLocation $InstallDir
    $account = Resolve-TrayAccount $TrayUser
    Write-Note "Tray user: $($account.Name)"

    $hubDir = Join-Path $InstallDir 'Hub'
    $trayDir = Join-Path $InstallDir 'Tray'
    $hubExe = Join-Path $hubDir $HubExeName
    $trayExe = Join-Path $trayDir $TrayExeName
    $configPath = Join-Path $hubDir 'appsettings.json'
    $statePath = Join-Path $InstallDir $StateFileName

    $previousState = $null
    if (Test-Path -LiteralPath $statePath) {
        try { $previousState = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json } catch { }
    }
    $msiInstalled = $previousState -and $previousState.PSObject.Properties.Name -contains 'InstalledBy' -and $previousState.InstalledBy -eq 'msi'
    if ($msiInstalled -and -not $Msi) {
        throw "WatchLattice in $InstallDir was installed from the MSI. Install a new version with its MSI, or uninstall it from Settings > Apps first."
    }

    $service = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
    if ($service) {
        $existingPath = $service.PathName.Trim().Trim('"')
        if ($existingPath -ne $hubExe) {
            throw ("A '$ServiceName' service already exists for $($service.PathName).`n" +
                "    Remove it first (from an administrator prompt: sc.exe stop `"$ServiceName`" then sc.exe delete `"$ServiceName`"),`n" +
                "    or install over it with -InstallDir '$([IO.Path]::GetDirectoryName([IO.Path]::GetDirectoryName($existingPath)))'.")
        }
    }
    # The MSI has always just installed appsettings.json; whether this is a
    # first install is whether an earlier one left install-state.json.
    $upgrade = if ($Msi) { $null -ne $previousState } else { Test-Path -LiteralPath $configPath }
    $askQuestions = -not $upgrade -or $Reconfigure

    # First-run choices, asked before anything is changed.
    $canaryList = $null; $decoy = $null; $updates = $null
    if ($askQuestions) {
        Write-Step 'First-run choices'
        if ($CanaryFolders) {
            $canaryList = Split-PathList $CanaryFolders
        }
        else {
            $canaryList = @(
                (Get-UserFolder $account 'Desktop' 'Desktop'),
                (Get-UserFolder $account 'Personal' 'Documents'),
                (Get-UserFolder $account 'My Pictures' 'Pictures')) | Where-Object { Test-Path -LiteralPath $_ -PathType Container }
            if (-not $Quiet) {
                Write-Host ''
                Write-Host 'The canary watcher plants a few small, hidden decoy files in these folders and'
                Write-Host 'alerts you when anything modifies, renames or deletes one (an early ransomware sign):'
                $canaryList | ForEach-Object { Write-Host "      $_" }
                $typed = (Read-Host "Press Enter to use them, or type other folders separated by ';'").Trim()
                if ($typed) { $canaryList = Split-PathList @($typed) }
            }
        }
        $canaryList = @($canaryList | ForEach-Object {
            if (-not [IO.Path]::IsPathRooted($_)) { Write-Caution "Skipping '$_': use a full path."; return }
            $full = [IO.Path]::GetFullPath($_)
            if (Test-Path -LiteralPath $full -PathType Container) { $full } else { Write-Caution "Skipping '$full': the folder does not exist." }
        } | Select-Object -Unique)
        if (-not $canaryList) { Write-Caution 'No canary folders: the canary watcher will be turned off.' }

        if (-not $Quiet) {
            Write-Host ''
            Write-Host 'The always-scanning decoy makes the PC look like a scan is always running, which'
            Write-Host 'some malware avoids. It reads (never writes) files slowly, in the background.'
        }
        $decoy = if ($NoDecoy) { $false } else { Read-YesNo 'Run the decoy?' $true }
        $updates = if ($NoUpdateCheck) { $false } else { Read-YesNo 'Check GitHub for new WatchLattice releases (never installs without asking)?' $true }
    }
    $autostart = if ($NoTrayAutostart) { $false } elseif ($Quiet -or -not $askQuestions) { $true } else { Read-YesNo 'Start the tray companion when you sign in?' $true }

    if ($Msi) {
        # Windows Installer has stopped the service and tray and installed the
        # files, keeping an existing appsettings.json.
        Write-Step "Securing $InstallDir"
        Set-ProtectedAcl $InstallDir @('*S-1-5-32-545:(OI)(CI)RX')
    }
    else {
        Write-Step "Installing files to $InstallDir"
        $existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($existing -and $existing.Status -ne 'Stopped') {
            Write-Note 'Stopping the running hub service'
            Stop-Service -Name $ServiceName -Force
        }
        Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($TrayExeName)) -ErrorAction SilentlyContinue |
            Where-Object { $_.Path -and $_.Path -eq $trayExe } | Stop-Process -Force

        New-OwnedDirectory $InstallDir 'install folder'
        Set-ProtectedAcl $InstallDir @('*S-1-5-32-545:(OI)(CI)RX')
        $savedConfig = if ($upgrade) { [IO.File]::ReadAllBytes($configPath) } else { $null }
        Copy-Item -LiteralPath (Join-Path $packageRoot 'Hub'), (Join-Path $packageRoot 'Tray') -Destination $InstallDir -Recurse -Force
        foreach ($file in @('uninstall.ps1', 'LICENSE', 'README.md')) {
            $source = Join-Path $packageRoot $file
            if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination $InstallDir -Force }
        }
        if ($savedConfig) {
            Copy-Item -LiteralPath $configPath -Destination "$configPath.default" -Force
            [IO.File]::WriteAllBytes($configPath, $savedConfig)
            Write-Note 'Kept your appsettings.json; the release defaults are in appsettings.json.default.'
        }
        # Installed program files, like any installer writes them: drop the
        # downloaded-from-the-internet mark the zip passed on, so the tray does
        # not show an "open file" warning at every sign-in.
        Get-ChildItem -LiteralPath $InstallDir -Recurse -File | Unblock-File
    }

    Write-Step "Creating the alert feed folder $FeedDir"
    New-OwnedDirectory $DataRoot 'alert feed folder'
    New-OwnedDirectory $FeedDir 'alert feed folder'
    Set-ProtectedAcl $DataRoot @()
    Invoke-Native icacls.exe @($FeedDir, '/grant', "*$($account.Sid):(OI)(CI)RX", '/Q')
    Write-Note "Only the hub can write it; $($account.Name) can read it."

    if ($askQuestions) {
        Write-Step 'Writing your choices to Hub\appsettings.json'
        $config = Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json
        $documents = Get-UserFolder $account 'Personal' 'Documents'
        $scanRoots = @(
            $account.ProfilePath,
            $documents,
            (Get-UserFolder $account 'My Pictures' 'Pictures'),
            (Get-UserFolder $account 'AppData' 'AppData\Roaming'),
            (Get-UserFolder $account 'Local AppData' 'AppData\Local')) | Select-Object -Unique
        # The service runs as LocalSystem, whose own profile is not yours: every
        # per-user folder is spelled out for the tray user instead.
        Set-ConfigValue $config 'Alerts:FeedPath' $FeedPath
        Set-ConfigValue $config 'Canary:Folders' ([string[]]$canaryList)
        Set-ConfigValue $config 'Modules:Canary:Enabled' ([bool]$canaryList)
        Set-ConfigValue $config 'Decoy:ScanRoots' ([string[]]$scanRoots)
        Set-ConfigValue $config 'Modules:Decoy:Enabled' $decoy
        Set-ConfigValue $config 'Modules:Updater:Enabled' $updates
        Set-ConfigValue $config 'Persistence:StartupFolders' ([string[]]@(
            (Get-UserFolder $account 'Startup' 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'),
            [Environment]::GetFolderPath('CommonStartup')))
        $json = ConvertTo-Json -InputObject $config -Depth 32
        [IO.File]::WriteAllText($configPath, $json, (New-Object Text.UTF8Encoding($false)))
        Write-Note "Canary folders: $(if ($canaryList) { $canaryList -join '; ' } else { 'none (canary watcher off)' })"
        Write-Note "Decoy: $(if ($decoy) { 'on' } else { 'off' }). Update checks: $(if ($updates) { 'on' } else { 'off' })."
    }
    else {
        Write-Note 'Kept your existing settings. Run with -Reconfigure to choose again.'
    }

    $trayCommand = "`"$trayExe`" --feed `"$FeedPath`""
    $runKey = "$($account.Hive)\Software\Microsoft\Windows\CurrentVersion\Run"
    if ($autostart) {
        Write-Step 'Starting the tray at sign-in'
        if (Test-Path -LiteralPath $account.Hive) {
            if (-not (Test-Path -LiteralPath $runKey)) { New-Item -Path $runKey -Force | Out-Null }
            Set-ItemProperty -LiteralPath $runKey -Name $RunValueName -Value $trayCommand
            Write-Note "Added '$RunValueName' to $($account.Name)'s Run key."
        }
        else {
            Write-Caution "$($account.Name) is not signed in, so the tray was not added to their sign-in. Start it from the Start menu."
        }
    }
    elseif (Test-Path -LiteralPath $runKey) {
        Remove-ItemProperty -LiteralPath $runKey -Name $RunValueName -ErrorAction SilentlyContinue
    }

    $shortcutPath = Join-Path ([Environment]::GetFolderPath('CommonPrograms')) 'WatchLattice.lnk'
    if (-not $Msi) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $trayExe
        $shortcut.Arguments = "--feed `"$FeedPath`""
        $shortcut.WorkingDirectory = $trayDir
        $shortcut.Description = 'WatchLattice alerts and status'
        $shortcut.Save()
    }

    Write-Step "Installing the '$ServiceName' service"
    if ($Msi) {
        # Windows Installer created the service; only its recovery settings are left.
    }
    elseif (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) {
        New-Service -Name $ServiceName -BinaryPathName "`"$hubExe`"" -DisplayName $ServiceDisplayName -StartupType Automatic `
            -Description 'WatchLattice hub: canary files, Defender and firewall health, persistence auditing. Complements Microsoft Defender.' | Out-Null
    }
    else {
        Set-Service -Name $ServiceName -StartupType Automatic
    }
    # Restart after a crash: 1 minute, 1 minute, then 5 minutes; reset after a day.
    Invoke-Native sc.exe @('failure', $ServiceName, 'reset=', '86400', 'actions=', 'restart/60000/restart/60000/restart/300000')

    $state = [ordered]@{
        Version       = $version
        InstalledAt   = (Get-Date).ToUniversalTime().ToString('o')
        TrayUser      = $account.Name
        TrayUserSid   = $account.Sid
        FeedDirectory = $FeedDir
        DataDirectory = $DataRoot
        InstalledBy   = $(if ($Msi) { 'msi' } else { 'script' })
    }
    if ($Msi) { $state.ProductCode = $ProductCode }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

    if ($Msi) {
        # Windows Installer lists the product in Settings > Apps and starts
        # the service once this script returns.
        Write-Host "WatchLattice $version is set up for $($account.Name)." -ForegroundColor Green
        exit 0
    }

    $uninstallCommand = "`"$(Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')`" -NoProfile -ExecutionPolicy Bypass -File `"$(Join-Path $InstallDir 'uninstall.ps1')`" -PauseAtEnd"
    New-Item -Path $UninstallKey -Force | Out-Null
    $entries = @{
        DisplayName     = 'WatchLattice'
        Publisher       = 'WatchLattice contributors'
        InstallLocation = $InstallDir
        DisplayIcon     = $trayExe
        UninstallString = $uninstallCommand
        URLInfoAbout    = 'https://github.com/notbrianbob/WatchLattice'
    }
    foreach ($entry in $entries.GetEnumerator()) { Set-ItemProperty -LiteralPath $UninstallKey -Name $entry.Key -Value $entry.Value }
    Set-ItemProperty -LiteralPath $UninstallKey -Name NoModify -Value 1 -Type DWord
    Set-ItemProperty -LiteralPath $UninstallKey -Name NoRepair -Value 1 -Type DWord

    Write-Step 'Starting the hub'
    $startedAt = (Get-Date).ToUniversalTime().AddSeconds(-1)
    Start-Service -Name $ServiceName
    $heartbeat = "$FeedPath.heartbeat.json"
    $beating = { (Test-Path -LiteralPath $heartbeat) -and (Get-Item -LiteralPath $heartbeat).LastWriteTimeUtc -gt $startedAt }
    for ($i = 0; $i -lt 60 -and -not (& $beating); $i++) { Start-Sleep -Milliseconds 500 }
    if (& $beating) {
        Write-Note 'The hub is running and writing the alert feed.'
    }
    else {
        Write-Caution "The service started but has not written $heartbeat yet. Check Event Viewer > Windows Logs > Application."
    }

    if (-not $NoTrayStart) {
        # Opening the shortcut through Explorer starts the tray in the signed-in
        # user's own, unelevated session rather than in this administrator one.
        Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') -ArgumentList "`"$shortcutPath`""
    }

    Write-Host ''
    Write-Host "WatchLattice $version is installed." -ForegroundColor Green
    Write-Host "    Settings:  $configPath (restart the '$ServiceName' service after editing)"
    Write-Host '    Alerts:    the WatchLattice tray icon, or WatchLattice in the Start menu'
    Write-Host '    Updates:   the tray offers new releases; nothing installs without your OK'
    Write-Host '    Uninstall: Settings > Apps > WatchLattice, or uninstall.ps1 in the install folder'
    $exitCode = 0
}
catch {
    Write-Host ''
    Write-Host "Install failed: $($_.Exception.Message)" -ForegroundColor Red
    $exitCode = 1
}

if ($PauseAtEnd) {
    Write-Host ''
    Read-Host 'Press Enter to close this window' | Out-Null
}
exit $exitCode
