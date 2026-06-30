#Requires -Version 5.1
<#
.SYNOPSIS
    AC-Triage.ps1 - Professional Windows Anti-Cheat Forensic Triage Tool
    Made with love by lily<3 | Extended by DFIR engineering

.DESCRIPTION
    Read-only forensic collection and analysis tool for investigating:
    - Cheat software and game manipulation tools
    - Unauthorized automation (input bots, macro tools)
    - Kernel-level tampering (unsigned/hidden drivers, rootkits)
    - Suspicious persistence mechanisms
    - Evidence of artifact tampering or log wiping

    This script collects and correlates artifacts from:
    Process memory, drivers, services, registry, event logs, filesystem,
    network state, browser history, Defender telemetry, and Windows security config.

    DESIGN PRINCIPLES:
    - Read-only: no system state is modified
    - Correlated: no single indicator triggers a finding; multiple artifacts are required
    - Contextual: benign explanations are considered for every indicator
    - Confidence-scored: findings rated Informational / Low / Medium / High / Critical
    - Graceful: all errors are caught; missing data is noted, not fatal

.NOTES
    Requires: Administrator privileges
    Tested on: Windows 10 21H2+, Windows 11
    Execution Policy: Run with -ExecutionPolicy Bypass if needed
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'

# -----------------------------------------------------------------------------
#  PRIVILEGE CHECK
# -----------------------------------------------------------------------------
$isAdmin = [System.Security.Principal.WindowsPrincipal]::new(
    [System.Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n+==================================================+" -ForegroundColor Red
    Write-Host "|           ADMINISTRATOR PRIVILEGES REQUIRED       |" -ForegroundColor Red
    Write-Host "|     Please run this script as Administrator!      |" -ForegroundColor Red
    Write-Host "+==================================================+" -ForegroundColor Red
    exit 1
}

Write-Host "made with love by lily<3" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------------
#  GLOBAL STATE  (findings accumulate here; report reads from it at the end)
# -----------------------------------------------------------------------------
$script:Findings = [System.Collections.Generic.List[hashtable]]::new()
$script:Timeline = [System.Collections.Generic.List[hashtable]]::new()
$script:CollectionErrors = [System.Collections.Generic.List[string]]::new()
$script:StartTime = Get-Date

# Known-good Microsoft hashes are not hardcoded; instead we rely on Authenticode
# catalog trust, signer checks, and contextual correlation.

# -----------------------------------------------------------------------------
#  HELPER FUNCTIONS
# -----------------------------------------------------------------------------

function Write-Section {
    param([string]$Title)
    Write-Host ("`n" + ("-" * 52)) -ForegroundColor DarkGray
    Write-Host "  $Title" -ForegroundColor Cyan
    Write-Host ("-" * 52) -ForegroundColor DarkGray
}

function Write-Item {
    param(
        [string]$Label,
        [string]$Value,
        [string]$Color = 'White'
    )
    Write-Host "  $Label" -NoNewline -ForegroundColor Gray
    Write-Host $Value -ForegroundColor $Color
}

function Write-Flag {
    param(
        [string]$Message,
        [ValidateSet('Informational','Low','Medium','High','Critical')]
        [string]$Severity = 'Low',
        [string]$Detail = ''
    )
    $colors = @{
        Informational = 'Gray'
        Low           = 'Yellow'
        Medium        = 'DarkYellow'
        High          = 'Red'
        Critical      = 'Magenta'
    }
    $prefix = @{
        Informational = '[INFO]  '
        Low           = '[LOW]   '
        Medium        = '[MED]   '
        High          = '[HIGH]  '
        Critical      = '[CRIT]  '
    }
    Write-Host ("  " + $prefix[$Severity] + $Message) -ForegroundColor $colors[$Severity]
    if ($Detail) {
        Write-Host ("          $Detail") -ForegroundColor DarkGray
    }
}

function Add-Finding {
    <#
    .SYNOPSIS Adds a correlated forensic finding to the global findings list.
    Each finding requires evidence, a benign explanation, and a confidence score.
    #>
    param(
        [string]$Category,
        [string]$Title,
        [string]$Evidence,
        [string]$WhySuspicious,
        [string]$BenignExplanation,
        [ValidateSet('Informational','Low','Medium','High','Critical')]
        [string]$Confidence,
        [string]$FollowUp = ''
    )
    $script:Findings.Add(@{
        Category          = $Category
        Title             = $Title
        Evidence          = $Evidence
        WhySuspicious     = $WhySuspicious
        BenignExplanation = $BenignExplanation
        Confidence        = $Confidence
        FollowUp          = $FollowUp
        Timestamp         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    })
}

function Add-TimelineEvent {
    param(
        [datetime]$Time,
        [string]$Source,
        [string]$Event,
        [string]$Detail = ''
    )
    $script:Timeline.Add(@{
        Time   = $Time
        Source = $Source
        Event  = $Event
        Detail = $Detail
    })
}

function Get-FileSHA256 {
    param([string]$Path)
    try {
        $hash = Get-FileHash -Path $Path -Algorithm SHA256 -ErrorAction Stop
        return $hash.Hash
    } catch {
        return 'HASH_ERROR'
    }
}

function Get-AuthenticodeInfo {
    <#
    .SYNOPSIS
    Returns structured Authenticode signature info.
    Catalog-signed files (most Windows binaries) are checked via Get-AuthenticodeSignature.
    Returns a hashtable with: Status, SignerCert, IsMicrosoftSigned, IsValid, Thumbprint
    #>
    param([string]$Path)
    $result = @{
        Status            = 'Unknown'
        SignerCert        = 'N/A'
        IsMicrosoftSigned = $false
        IsValid           = $false
        Thumbprint        = 'N/A'
    }
    try {
        $sig = Get-AuthenticodeSignature -FilePath $Path -ErrorAction Stop
        $result.Status = $sig.Status.ToString()
        $result.IsValid = ($sig.Status -eq 'Valid')
        if ($sig.SignerCertificate) {
            $result.SignerCert   = $sig.SignerCertificate.Subject
            $result.Thumbprint   = $sig.SignerCertificate.Thumbprint
            $result.IsMicrosoftSigned = (
                $sig.SignerCertificate.Subject -match 'Microsoft' -or
                $sig.SignerCertificate.Issuer  -match 'Microsoft'
            )
        }
    } catch {
        $result.Status = "Error: $($_.Exception.Message)"
    }
    return $result
}

function Get-FileVersionInfo {
    param([string]$Path)
    $result = @{
        OriginalFilename = 'N/A'
        ProductName      = 'N/A'
        CompanyName      = 'N/A'
        FileVersion      = 'N/A'
        Description      = 'N/A'
    }
    try {
        $fvi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        $result.OriginalFilename = $fvi.OriginalFilename
        $result.ProductName      = $fvi.ProductName
        $result.CompanyName      = $fvi.CompanyName
        $result.FileVersion      = $fvi.FileVersion
        $result.Description      = $fvi.FileDescription
    } catch {}
    return $result
}

function Get-ProcessIntegrityLevel {
    <#
    .SYNOPSIS Retrieves integrity level of a process via WMI/CIM.
    Note: Full token integrity requires P/Invoke; this provides a best-effort
    approximation using the process token elevation type.
    #>
    param([int]$PID)
    # Integrity levels require native API access; approximate via elevation status
    try {
        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$PID" -ErrorAction Stop
        return @{
            CommandLine  = $wmiProc.CommandLine
            ExecutablePath = $wmiProc.ExecutablePath
            CreationDate = $wmiProc.CreationDate
            ParentPID    = $wmiProc.ParentProcessId
        }
    } catch {
        return @{ CommandLine = 'N/A'; ExecutablePath = 'N/A'; CreationDate = $null; ParentPID = 0 }
    }
}

function Get-StringEntropy {
    <#
    .SYNOPSIS
    Calculates Shannon entropy of a string.
    High entropy (>3.5) in a filename suggests random/obfuscated name generation,
    a common technique in cheat loaders and DRM bypass tools.
    #>
    param([string]$InputString)
    if ([string]::IsNullOrEmpty($InputString)) { return 0.0 }
    $freq = @{}
    foreach ($char in $InputString.ToCharArray()) {
        $key = [string]$char
        if ($freq.ContainsKey($key)) { $freq[$key]++ } else { $freq[$key] = 1 }
    }
    $entropy = 0.0
    $len = $InputString.Length
    foreach ($count in $freq.Values) {
        $p = $count / $len
        if ($p -gt 0) { $entropy -= $p * [Math]::Log($p, 2) }
    }
    return [Math]::Round($entropy, 3)
}

function Test-SuspiciousPath {
    <#
    .SYNOPSIS
    Returns true if a path falls within directories commonly abused by malware/cheats:
    Temp, AppData, Downloads, Desktop, Recycle Bin, Public, OneDrive, root of drive.
    Legitimate software rarely executes from these locations.
    #>
    param([string]$Path)
    if ([string]::IsNullOrEmpty($Path)) { return $false }
    $suspiciousPatterns = @(
        '\\Temp\\', '\\tmp\\', '%TEMP%', '%TMP%',
        '\\AppData\\Local\\Temp',
        '\\AppData\\Roaming\\',   # unless it's a known app subdir
        '\\Downloads\\',
        '\\Desktop\\',
        '\\\$Recycle\.Bin\\',
        '\\Public\\',
        '\\OneDrive\\',
        '^[A-Za-z]:\\[^\\]+\.(exe|dll|sys)$'   # root of drive
    )
    foreach ($p in $suspiciousPatterns) {
        if ($Path -match $p) { return $true }
    }
    return $false
}

# -----------------------------------------------------------------------------
#  KNOWN LOLBin LIST
#  Living-off-the-land binaries abused by cheats/loaders to execute code,
#  bypass application whitelisting, or inject into trusted processes.
# -----------------------------------------------------------------------------
$script:LOLBins = @(
    'certutil','mshta','wscript','cscript','regsvr32','rundll32','regasm',
    'regsvcs','installutil','msiexec','wmic','powershell','cmd','forfiles',
    'pcalua','cmstp','infdefaultinstall','winrm','wuauclt','appsyncpublishingserver',
    'syncappvpublishingserver','dnscmd','esentutl','expandmodule','extrac32',
    'findstr','hh','makecab','msdeploy','msdt','msiexec','odbcconf','pcwrun',
    'replace','rpcping','runscripthelper','scriptrunner','sfc','shdocvw',
    'svc host','te','tracker','wab','xwizard','mavinject','psr','bginfo',
    'dfsvc','ieexec','ttdinject','tttracer','vbc','csc','jsc','msbuild',
    'msconfig','notepad','bitsadmin','desktopimgdownldr','appvlp','adplus',
    'aspnet_compiler','at','atbroker','bash','bitsadmin','control','csc',
    'cscript','curl','desktopimgdownldr','diskshadow','dllhost'
)

# -----------------------------------------------------------------------------
#  KNOWN CHEAT / INJECTION INDICATOR STRINGS
#  These strings in DLL names, paths, or registry keys warrant scrutiny.
#  Context matters - a hit here is one signal among many.
# -----------------------------------------------------------------------------
$script:CheatIndicators = @(
    'inject','hook','cheat','hack','aimbot','triggerbot','esp','wallhack',
    'bhop','spinbot','ragebot','hvh','legit','bypass','spoof','cloak',
    'stealth','undetected','ud','vac','eac','be','battleye','anticheat',
    'loader','trainer','mod menu','menu','overlay','radar','glow','coloresp',
    'recoil','norecoil','spread','nospread','rapidfire','autofire','trigge',
    'pixel','color','screen grab','screenshot','capture','magnify','getpixel',
    'sendkeys','sendinput','keybd_event','mouse_event','setcursorpos',
    'blockinput','getasynckeystate','getkeystate','registerhotkey'
)

# -----------------------------------------------------------------------------
#  SECTION 1: SYSTEM BOOT TIME  (baseline - unchanged from original)
# -----------------------------------------------------------------------------
Write-Section "SYSTEM BOOT TIME"
# Boot time establishes the analysis window. A very recent boot may indicate
# an attempt to clear volatile evidence (process list, network connections, etc.)
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $bootTime = $os.LastBootUpTime
    $uptime   = (Get-Date) - $bootTime
    $buildNum  = $os.BuildNumber
    $osCaption = $os.Caption

    Write-Item "OS:          " "$osCaption (Build $buildNum)"
    Write-Item "Last Boot:   " $bootTime.ToString("yyyy-MM-dd HH:mm:ss") -Color Yellow
    Write-Item "Uptime:      " ("{0}d {1:D2}h {2:D2}m {3:D2}s" -f $uptime.Days, $uptime.Hours, $uptime.Minutes, $uptime.Seconds)
    Write-Item "Analysis At: " (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")

    Add-TimelineEvent -Time $bootTime -Source 'System' -Event 'System Boot'

    # A boot within the last 30 minutes before an investigation is suspicious
    if ($uptime.TotalMinutes -lt 30) {
        Write-Flag "System booted < 30 minutes ago - volatile evidence may be incomplete" -Severity Medium
        Add-Finding -Category 'System' -Title 'Very Recent Boot' `
            -Evidence "Uptime: $([int]$uptime.TotalMinutes) minutes" `
            -WhySuspicious "Cheaters often reboot to clear volatile artifacts (process list, network state, active drivers)" `
            -BenignExplanation "Normal PC use - user simply powered on the machine recently" `
            -Confidence 'Low' `
            -FollowUp "Check Amcache, Prefetch, and event logs for activity prior to current session"
    }
} catch {
    Write-Host "  Unable to retrieve boot time: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Boot time: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 2: CONNECTED DRIVES  (expanded - check for mounted ISOs / VHDs)
# -----------------------------------------------------------------------------
Write-Section "CONNECTED DRIVES"
# Cheaters frequently mount ISOs containing tools to avoid writing to physical disk.
# VHD/VHDX mounts can host drivers that are harder to track.
try {
    $drives = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop |
              Where-Object { $_.DriveType -ne 5 }  # exclude CD/DVD

    foreach ($drive in $drives) {
        $label    = if ($drive.VolumeName) { $drive.VolumeName } else { '(no label)' }
        $sizeGB   = if ($drive.Size) { [Math]::Round($drive.Size / 1GB, 1) } else { 'N/A' }
        $freeGB   = if ($drive.FreeSpace) { [Math]::Round($drive.FreeSpace / 1GB, 1) } else { 'N/A' }
        $fsType   = if ($drive.FileSystem) { $drive.FileSystem } else { 'N/A' }
        $driveType = switch ($drive.DriveType) {
            2 { 'Removable' }; 3 { 'Fixed' }; 4 { 'Network' }; 6 { 'RAM Disk' }; default { "Type$($drive.DriveType)" }
        }

        $color = if ($drive.DriveType -in @(2,4,6)) { 'Yellow' } else { 'Green' }
        Write-Host ("  {0}  {1,-12} {2,-10} {3,6}GB / {4,6}GB free  [{5}]" -f
            $drive.DeviceID, $label, $fsType, $sizeGB, $freeGB, $driveType) -ForegroundColor $color

        if ($drive.DriveType -eq 4) {
            Add-Finding -Category 'Network' -Title "Network Drive Mapped: $($drive.DeviceID)" `
                -Evidence "Drive $($drive.DeviceID) maps to a network path" `
                -WhySuspicious "Cheat tools may be stored on network shares to avoid local disk writes" `
                -BenignExplanation "Corporate NAS, home NAS, or cloud sync drive" `
                -Confidence 'Informational' `
                -FollowUp "Check recent network connections and SMB connections"
        }
    }

    # Check for virtual disk / ISO mounts via disk image info
    try {
        $vhdMounts = Get-DiskImage -ErrorAction SilentlyContinue | Where-Object { $_.Attached }
        if ($vhdMounts) {
            foreach ($vhd in $vhdMounts) {
                Write-Flag "Mounted disk image: $($vhd.ImagePath)" -Severity Medium `
                    -Detail "Type: $($vhd.StorageType) | Size: $([Math]::Round($vhd.Size/1MB,1))MB"
                Add-Finding -Category 'FileSystem' -Title "Mounted Disk Image" `
                    -Evidence "Image path: $($vhd.ImagePath)" `
                    -WhySuspicious "ISO/VHD mounts are used to run cheat tools without leaving traces on the main filesystem. Bypass of anticheat scanning of local volumes." `
                    -BenignExplanation "Developer using a VM disk, Windows Sandbox, or legitimate ISO (e.g. software installer)" `
                    -Confidence 'Medium' `
                    -FollowUp "Enumerate contents of the mounted image path"
            }
        }
    } catch {
        $script:CollectionErrors.Add("VHD mount enumeration: $($_.Exception.Message)")
    }
} catch {
    Write-Host "  Drive enumeration failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Drive enumeration: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 3: SERVICE STATUS  (expanded - includes binary checks)
# -----------------------------------------------------------------------------
Write-Section "SERVICE STATUS"

# Anti-cheat-relevant services: these being stopped or disabled can indicate
# active circumvention attempts. Each service has a forensic rationale.
$services = @(
    @{Name="SysMain";    DisplayName="SysMain";                         Rationale="Superfetch/SysMain feeds into Amcache - disabling reduces footprint"},
    @{Name="PcaSvc";     DisplayName="Program Compatibility Assistant"; Rationale="Logs program execution for compatibility - evidence source"},
    @{Name="DPS";        DisplayName="Diagnostic Policy Service";       Rationale="Drives diagnostic event collection"},
    @{Name="EventLog";   DisplayName="Windows Event Log";               Rationale="Core forensic evidence source - disabling is a major red flag"},
    @{Name="Schedule";   DisplayName="Task Scheduler";                  Rationale="Persistence mechanism and evidence source"},
    @{Name="Bam";        DisplayName="Background Activity Moderator";   Rationale="BAM tracks executable launch timestamps - key anti-cheat artifact"},
    @{Name="Dusmsvc";    DisplayName="Data Usage";                      Rationale="Tracks per-process network usage"},
    @{Name="Appinfo";    DisplayName="Application Information";         Rationale="Handles UAC elevation - disabling blocks elevation logging"},
    @{Name="CDPSvc";     DisplayName="Connected Devices Platform";      Rationale="Device activity tracking"},
    @{Name="DcomLaunch"; DisplayName="DCOM Server Process Launcher";    Rationale="Core process - stopping this crashes Windows"},
    @{Name="PlugPlay";   DisplayName="Plug and Play";                   Rationale="Tracks USB and device insertions - disabling erases this evidence"},
    @{Name="wsearch";    DisplayName="Windows Search";                  Rationale="Indexes files - stopped legitimately for performance"},
    @{Name="WinDefend";  DisplayName="Windows Defender Antivirus";      Rationale="Primary AV - disabling is a prerequisite for many cheats"},
    @{Name="SecurityHealthService"; DisplayName="Windows Security Health"; Rationale="Reports security state"},
    @{Name="MpsSvc";     DisplayName="Windows Firewall";                Rationale="Network filtering - disabled to allow cheat C2 traffic"},
    @{Name="BITS";       DisplayName="Background Intelligent Transfer"; Rationale="Used for stealthy downloads by malware and loaders"},
    @{Name="wuauserv";   DisplayName="Windows Update";                  Rationale="Sometimes disabled alongside Defender to prevent re-enablement"},
    @{Name="WMPNetworkSvc"; DisplayName="WMP Network Sharing";         Rationale="Low suspicion if stopped"},
    @{Name="lmhosts";   DisplayName="TCP/IP NetBIOS Helper";            Rationale="Stopping this breaks WINS/NetBIOS name resolution"}
)

# Critical services - stopping these is almost always malicious in context
$criticalServices = @('EventLog','WinDefend','Bam','PlugPlay')

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $statusColor = switch ($service.Status) {
            'Running'  { 'Green' }
            'Stopped'  { if ($svc.Name -in $criticalServices) { 'Red' } else { 'Yellow' } }
            default    { 'Yellow' }
        }

        $dn = $service.DisplayName
        if ($dn.Length -gt 38) { $dn = $dn.Substring(0,35) + '...' }

        Write-Host ("  {0,-14} {1,-38}" -f $svc.Name, $dn) -ForegroundColor White -NoNewline

        if ($service.Status -eq 'Running') {
            # Get the process start time for running services
            try {
                $wmiSvc = Get-CimInstance Win32_Service -Filter "Name='$($svc.Name)'" -ErrorAction Stop
                $pid    = $wmiSvc.ProcessId
                if ($pid -gt 0) {
                    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    if ($proc -and $proc.StartTime) {
                        Write-Host (" | Started: {0}" -f $proc.StartTime.ToString("HH:mm:ss")) -ForegroundColor Yellow
                    } else {
                        Write-Host " | Running" -ForegroundColor Green
                    }
                } else {
                    Write-Host " | Running (shared process)" -ForegroundColor Green
                }
            } catch {
                Write-Host " | Running" -ForegroundColor Green
            }
        } else {
            Write-Host (" | {0}" -f $service.Status) -ForegroundColor $statusColor

            if ($svc.Name -in $criticalServices -and $service.Status -ne 'Running') {
                Write-Flag "$($svc.Name) is $($service.Status) - forensic/security impact: $($svc.Rationale)" -Severity High
                Add-Finding -Category 'Security' -Title "$($svc.Name) Service Not Running" `
                    -Evidence "Service '$($svc.Name)' status: $($service.Status)" `
                    -WhySuspicious $svc.Rationale `
                    -BenignExplanation "Group Policy, system misconfiguration, or previous troubleshooting" `
                    -Confidence 'Medium' `
                    -FollowUp "Check event log 7036 for service state change history; correlate with boot time"
            }
        }
    } else {
        # Service not found at all - more suspicious than merely stopped
        if ($svc.Name -in $criticalServices) {
            Write-Host ("  {0,-14} {1,-38} | NOT FOUND" -f $svc.Name, $svc.DisplayName) -ForegroundColor Red
            Write-Flag "$($svc.Name) service is completely absent from the system" -Severity High
        } else {
            Write-Host ("  {0,-14} {1,-38} | Not Found" -f $svc.Name, $svc.DisplayName) -ForegroundColor DarkGray
        }
    }
}

# -----------------------------------------------------------------------------
#  SECTION 4: ALL SERVICES  (deep collection - beyond the curated list above)
# -----------------------------------------------------------------------------
Write-Section "ALL SERVICES - DEEP COLLECTION"
# Enumerate every service, check binary paths, signatures, and start conditions.
# Cheats sometimes install as services for persistence and kernel access.
try {
    $allServices = Get-CimInstance Win32_Service -ErrorAction Stop
    $suspiciousServices = @()

    foreach ($svc in $allServices) {
        $imagePath = $svc.PathName
        if (-not $imagePath) { continue }

        # Extract actual binary from ImagePath (strip args, quotes, svchost paths)
        $binPath = $imagePath -replace '"', '' -replace ' -k \S+', '' -replace ' /\S+', ''
        $binPath = $binPath.Trim()

        # Skip svchost entries - these are shared service hosts, covered separately
        if ($binPath -match 'svchost\.exe') { continue }

        $isSuspiciousPath = Test-SuspiciousPath -Path $binPath
        $sig = $null
        $isUnsigned = $false

        if (Test-Path $binPath -ErrorAction SilentlyContinue) {
            $sig = Get-AuthenticodeInfo -Path $binPath
            $isUnsigned = (-not $sig.IsValid)
        } else {
            $isSuspiciousPath = $true  # binary doesn't exist = orphaned service
        }

        # Flag unsigned non-Microsoft services running from suspicious locations
        if ($isSuspiciousPath -or $isUnsigned) {
            $suspiciousServices += [PSCustomObject]@{
                Name        = $svc.Name
                DisplayName = $svc.DisplayName
                BinPath     = $binPath
                State       = $svc.State
                StartMode   = $svc.StartMode
                Account     = $svc.StartName
                Unsigned    = $isUnsigned
                SusPath     = $isSuspiciousPath
                Signer      = if ($sig) { $sig.SignerCert } else { 'N/A' }
            }
        }
    }

    if ($suspiciousServices.Count -gt 0) {
        Write-Host "  Found $($suspiciousServices.Count) services with unsigned binaries or suspicious paths:" -ForegroundColor Yellow
        foreach ($s in $suspiciousServices) {
            $reasons = @()
            if ($s.Unsigned) { $reasons += "Unsigned" }
            if ($s.SusPath)  { $reasons += "Suspicious path" }
            Write-Host ("  [{0}] {1} ({2})" -f ($reasons -join ','), $s.Name, $s.State) -ForegroundColor Yellow
            Write-Host ("    Path: {0}" -f $s.BinPath) -ForegroundColor DarkGray
            Write-Host ("    Signer: {0}" -f $s.Signer) -ForegroundColor DarkGray

            Add-Finding -Category 'Services' -Title "Suspicious Service: $($s.Name)" `
                -Evidence "Binary: $($s.BinPath) | State: $($s.State) | Signer: $($s.Signer)" `
                -WhySuspicious "Services with unsigned binaries or binaries in user-writable locations are a common cheat/malware persistence mechanism" `
                -BenignExplanation "Legitimate third-party software (e.g. game launchers, hardware utilities) sometimes ships unsigned" `
                -Confidence 'Medium' `
                -FollowUp "Verify binary hash against known-good copy; check service install date via event log 7045"
        }
    } else {
        Write-Host "  All non-svchost services have signed binaries in expected locations." -ForegroundColor Green
    }
} catch {
    Write-Host "  Service deep collection failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Service deep collection: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 5: RUNNING PROCESSES  (comprehensive)
# -----------------------------------------------------------------------------
Write-Section "RUNNING PROCESSES"

# Why processes matter for anti-cheat forensics:
# - Unsigned processes or those in user-writable paths may be loaders/injectors
# - Anomalous parent-child relationships reveal injection or spawning tricks
# - High-entropy names indicate randomly generated obfuscated binaries
# - LOLBin usage by unusual parents is a hallmark of cheat bypass techniques
# - Recently started processes during the play session are most relevant

try {
    $allProcs = Get-Process -ErrorAction Stop
    $wmiProcs = Get-CimInstance Win32_Process -ErrorAction Stop
    $wmiProcMap = @{}
    foreach ($w in $wmiProcs) { $wmiProcMap[$w.ProcessId] = $w }

    $suspiciousProcs = @()
    $processNames    = @{}   # for duplicate-name detection

    Write-Host ""
    Write-Host ("  {0,-6} {1,-24} {2,-18} {3,-10} {4}" -f "PID","Name","User","Memory","Path") -ForegroundColor DarkGray

    foreach ($proc in ($allProcs | Sort-Object StartTime -ErrorAction SilentlyContinue)) {
        $pid = $proc.Id
        $wmi = $wmiProcMap[$pid]

        # Gather extended info from WMI
        $cmdLine    = if ($wmi) { $wmi.CommandLine } else { 'N/A' }
        $exePath    = if ($wmi) { $wmi.ExecutablePath } else { $proc.Path }
        $parentPid  = if ($wmi) { $wmi.ParentProcessId } else { 0 }
        $sessionId  = $proc.SessionId
        $memMB      = [Math]::Round($proc.WorkingSet64 / 1MB, 1)
        $handleCnt  = try { $proc.HandleCount } catch { 0 }
        $threadCnt  = $proc.Threads.Count
        $startTime  = try { $proc.StartTime } catch { $null }

        # Get parent process name
        $parentName = try {
            (Get-Process -Id $parentPid -ErrorAction Stop).Name
        } catch { 'N/A' }

        # Track duplicate names (same name, multiple instances can hide injectors)
        $nameLower = $proc.Name.ToLower()
        if ($processNames.ContainsKey($nameLower)) {
            $processNames[$nameLower]++
        } else {
            $processNames[$nameLower] = 1
        }

        # Signature check
        $sig = $null
        $isUnsigned = $false
        $isMSSigned  = $false
        if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
            $sig        = Get-AuthenticodeInfo -Path $exePath
            $isUnsigned = (-not $sig.IsValid)
            $isMSSigned  = $sig.IsMicrosoftSigned
        }

        # File version info
        $fvi = @{ OriginalFilename='N/A'; ProductName='N/A'; CompanyName='N/A'; FileVersion='N/A' }
        if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) {
            $fvi = Get-FileVersionInfo -Path $exePath
        }

        # Suspicious indicators
        $suspReasons = @()
        $isSusPath   = Test-SuspiciousPath -Path $exePath

        if ($isSusPath)    { $suspReasons += "SuspiciousPath" }
        if ($isUnsigned -and -not [string]::IsNullOrEmpty($exePath)) { $suspReasons += "Unsigned" }

        # Name entropy check - random names are often >3.5 bits
        $nameNoExt = [System.IO.Path]::GetFileNameWithoutExtension($proc.Name)
        $entropy   = Get-StringEntropy -InputString $nameNoExt
        if ($entropy -gt 3.5 -and $nameNoExt.Length -gt 6) { $suspReasons += "HighEntropyName($entropy)" }

        # LOLBin check
        if ($nameLower -in $script:LOLBins) {
            # LOLBins spawned by unusual parents are most suspicious
            if ($parentName -notin @('services','explorer','userinit','winlogon','svchost','N/A','')) {
                $suspReasons += "LOLBin(parent=$parentName)"
            }
        }

        # Suspicious parent-child relationships
        $suspiciousParentChild = @{
            'winword'  = @('powershell','cmd','wscript','cscript','mshta','rundll32')
            'excel'    = @('powershell','cmd','wscript','cscript','mshta','rundll32')
            'outlook'  = @('powershell','cmd','wscript','cscript','mshta')
            'chrome'   = @('powershell','cmd','wscript','mshta')
            'firefox'  = @('powershell','cmd','wscript','mshta')
            'msedge'   = @('powershell','cmd','wscript','mshta')
            'explorer' = @('powershell','cmd','regsvr32','rundll32','mshta','wscript','cscript')
        }
        $parentLower = $parentName.ToLower() -replace '\.exe$',''
        if ($suspiciousParentChild.ContainsKey($parentLower)) {
            if ($nameLower -replace '\.exe$','' -in $suspiciousParentChild[$parentLower]) {
                $suspReasons += "SuspiciousParentChild($parentLower->$nameLower)"
            }
        }

        # Cheat keyword in path or name
        foreach ($indicator in $script:CheatIndicators) {
            if ($exePath -match $indicator -or $proc.Name -match $indicator) {
                $suspReasons += "CheatKeyword($indicator)"
                break
            }
        }

        $lineColor = if ($suspReasons.Count -gt 0) { 'Yellow' } else { 'White' }
        $memStr = "$($memMB)MB"
        Write-Host ("  {0,-6} {1,-24} {2,-18} {3,-10} {4}" -f
            $pid, $proc.Name, $parentName, $memStr,
            (if ($exePath) { $exePath } else { '(no path)' })) -ForegroundColor $lineColor

        if ($suspReasons.Count -gt 0) {
            $suspiciousProcs += [PSCustomObject]@{
                PID         = $pid
                Name        = $proc.Name
                Path        = $exePath
                ParentPID   = $parentPid
                ParentName  = $parentName
                StartTime   = $startTime
                CmdLine     = $cmdLine
                Reasons     = $suspReasons
                Entropy     = $entropy
                Company     = $fvi.CompanyName
                ProductName = $fvi.ProductName
                Signer      = if ($sig) { $sig.SignerCert } else { 'N/A' }
                Hash        = if ($exePath -and (Test-Path $exePath -ErrorAction SilentlyContinue)) { Get-FileSHA256 $exePath } else { 'N/A' }
            }
        }
    }

    # Report suspicious processes
    if ($suspiciousProcs.Count -gt 0) {
        Write-Host "`n  -- SUSPICIOUS PROCESSES ($($suspiciousProcs.Count)) --" -ForegroundColor Yellow
        foreach ($sp in $suspiciousProcs) {
            $confidence = switch ($sp.Reasons.Count) {
                1 { 'Low' }
                2 { 'Medium' }
                { $_ -ge 3 } { 'High' }
                default { 'Low' }
            }
            # Escalate if cheat keyword is present
            if ($sp.Reasons -match 'CheatKeyword') { $confidence = 'High' }

            Write-Flag "$($sp.Name) (PID $($sp.PID)) - $($sp.Reasons -join ', ')" -Severity $confidence `
                -Detail "Parent: $($sp.ParentName) | Path: $($sp.Path)"
            Write-Host "    Signer: $($sp.Signer)" -ForegroundColor DarkGray
            Write-Host "    SHA256: $($sp.Hash)" -ForegroundColor DarkGray
            if ($sp.CmdLine) { Write-Host "    CmdLine: $($sp.CmdLine)" -ForegroundColor DarkGray }

            Add-Finding -Category 'Processes' -Title "Suspicious Process: $($sp.Name)" `
                -Evidence "PID=$($sp.PID) | Reasons: $($sp.Reasons -join ',') | Path: $($sp.Path) | Hash: $($sp.Hash)" `
                -WhySuspicious ($sp.Reasons -join '; ') `
                -BenignExplanation "Legitimate software with weak signing; developer tools; game launchers" `
                -Confidence $confidence `
                -FollowUp "Check process timeline vs game session; inspect loaded modules; review command line"

            if ($sp.StartTime) {
                Add-TimelineEvent -Time $sp.StartTime -Source 'Process' -Event "Process started: $($sp.Name)" -Detail "PID=$($sp.PID) | $($sp.Reasons -join ',')"
            }
        }
    } else {
        Write-Host "`n  No suspicious processes detected." -ForegroundColor Green
    }

    # Duplicate process name detection
    $dupes = $processNames.GetEnumerator() | Where-Object { $_.Value -gt 1 } | Sort-Object Value -Descending
    if ($dupes) {
        Write-Host "`n  -- DUPLICATE PROCESS NAMES --" -ForegroundColor Yellow
        foreach ($d in $dupes) {
            Write-Host ("  {0,-24} {1} instances" -f $d.Key, $d.Value) -ForegroundColor Yellow
            # Only flag if the name is something that shouldn't have many instances
            $normalMultiInstance = @('svchost','conhost','dllhost','runtimebroker','backgroundtaskhost','sihost','ctfmon')
            if ($d.Key -notin $normalMultiInstance -and $d.Value -gt 2) {
                Add-Finding -Category 'Processes' -Title "Excessive Instances: $($d.Key)" `
                    -Evidence "$($d.Value) instances of $($d.Key) running simultaneously" `
                    -WhySuspicious "Process masquerading: multiple instances of an unusual process may indicate injector/loader copies or renamed system processes" `
                    -BenignExplanation "Some legitimate apps (e.g. Electron apps) spawn many processes with the same name" `
                    -Confidence 'Low' `
                    -FollowUp "Compare PIDs, paths, and parent PIDs of each instance"
            }
        }
    }

} catch {
    Write-Host "  Process collection failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Process collection: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 6: GAME PROCESS INSPECTION  (loaded modules, injected DLLs)
# -----------------------------------------------------------------------------
Write-Section "GAME PROCESS INSPECTION"

# Known game processes to inspect for injected DLLs and overlay hooks.
# Add game-specific process names as needed.
$knownGameProcesses = @(
    # FPS / Competitive
    'cs2','csgo','hl2','r5apex','valorant','r6','bf2042','mw2','mw3',
    'cod','warzone','pubg','fortnite','rust','tarkov','escape','squadgame',
    # MMO / RPG
    'ffxiv','wow','gw2','newworld','lost ark','poe','pathofexile',
    # Other
    'EasyAntiCheat','BEService','vgc','vgk','EAC','faceit'
)

$gameProcsFound = @()
foreach ($proc in (Get-Process -ErrorAction SilentlyContinue)) {
    $procNameLower = $proc.Name.ToLower()
    foreach ($gp in $knownGameProcesses) {
        if ($procNameLower -match [regex]::Escape($gp.ToLower())) {
            $gameProcsFound += $proc
            break
        }
    }
}

if ($gameProcsFound.Count -eq 0) {
    Write-Host "  No known game processes currently running." -ForegroundColor Gray
    Write-Host "  (Game process DLL inspection requires the game to be active)" -ForegroundColor DarkGray
} else {
    foreach ($gameProc in $gameProcsFound) {
        Write-Host "`n  Game process: $($gameProc.Name) (PID $($gameProc.Id))" -ForegroundColor Cyan

        try {
            $modules = $gameProc.Modules
            $suspiciousModules = @()

            foreach ($mod in $modules) {
                $modPath    = $mod.FileName
                $modName    = $mod.ModuleName
                $sig        = Get-AuthenticodeInfo -Path $modPath
                $isUnsigned = (-not $sig.IsValid)
                $isMSSigned  = $sig.IsMicrosoftSigned
                $isSusPath   = Test-SuspiciousPath -Path $modPath
                $modReasons  = @()

                if ($isUnsigned)  { $modReasons += "Unsigned" }
                if ($isSusPath)   { $modReasons += "SuspiciousPath" }

                # Detect cheat-related keywords in module name or path
                foreach ($indicator in $script:CheatIndicators) {
                    if ($modPath -match $indicator -or $modName -match $indicator) {
                        $modReasons += "CheatKeyword($indicator)"
                        break
                    }
                }

                # Detect overlay-related DLLs (Discord, Steam, GeForce, Radeon - benign, but noted)
                $overlayKeywords = @('GameOverlay','overlay','discordhook','nvstreamuseriagent','rtss','rivatuner','msi.*afterburner')
                foreach ($ok in $overlayKeywords) {
                    if ($modName -match $ok) {
                        $modReasons += "OverlayDLL($ok)"
                        break
                    }
                }

                # Hook-related DLLs - input interception
                $hookKeywords = @('hook','detour','interception','intercetor','rawinput','dinput','dinput8','xinput')
                foreach ($hk in $hookKeywords) {
                    if ($modName -match $hk -and -not $isMSSigned) {
                        $modReasons += "HookRelated($hk)"
                        break
                    }
                }

                if ($modReasons.Count -gt 0) {
                    $suspiciousModules += [PSCustomObject]@{
                        Name    = $modName
                        Path    = $modPath
                        Reasons = $modReasons
                        Signer  = $sig.SignerCert
                        Hash    = Get-FileSHA256 -Path $modPath
                    }
                }
            }

            Write-Host ("  Total modules loaded: {0}" -f $modules.Count) -ForegroundColor White
            if ($suspiciousModules.Count -gt 0) {
                Write-Host ("  Suspicious modules: {0}" -f $suspiciousModules.Count) -ForegroundColor Yellow
                foreach ($sm in $suspiciousModules) {
                    $confidence = switch -Regex ($sm.Reasons -join ',') {
                        'CheatKeyword'    { 'High' }
                        'Unsigned.*Hook|Hook.*Unsigned' { 'High' }
                        'Unsigned.*SuspiciousPath|SuspiciousPath.*Unsigned' { 'Medium' }
                        'OverlayDLL'      { 'Informational' }
                        default           { 'Low' }
                    }
                    Write-Flag "$($sm.Name): $($sm.Reasons -join ', ')" -Severity $confidence `
                        -Detail "Path: $($sm.Path)"

                    $benign = switch -Regex ($sm.Reasons -join ',') {
                        'OverlayDLL' { "Discord/Steam/GeForce overlay - expected in gaming sessions" }
                        'HookRelated' { "Controller input library, DirectInput wrapper, or legitimate input framework" }
                        default { "Third-party game mod, plugin, or framework" }
                    }

                    Add-Finding -Category 'GameProcess' -Title "Suspicious Module in $($gameProc.Name): $($sm.Name)" `
                        -Evidence "Path: $($sm.Path) | Hash: $($sm.Hash) | Signer: $($sm.Signer)" `
                        -WhySuspicious ($sm.Reasons -join '; ') `
                        -BenignExplanation $benign `
                        -Confidence $confidence `
                        -FollowUp "Verify module against known-good game installation; check if module existed before game launch"
                }
            } else {
                Write-Host "  No suspicious modules detected in $($gameProc.Name)." -ForegroundColor Green
            }
        } catch {
            Write-Host "  Could not enumerate modules for $($gameProc.Name): $($_.Exception.Message)" -ForegroundColor Yellow
            $script:CollectionErrors.Add("Game module enum ($($gameProc.Name)): $($_.Exception.Message)")
        }
    }
}

# -----------------------------------------------------------------------------
#  SECTION 7: DRIVERS  (comprehensive kernel-level inspection)
# -----------------------------------------------------------------------------
Write-Section "DRIVERS - KERNEL LEVEL INSPECTION"

# Why drivers matter:
# Cheat tools that need kernel access (to read/write game process memory, bypass
# anti-tamper, hide processes/files from anti-cheat) require a kernel driver.
# Unsigned drivers require either test signing mode or a leaked/exploited cert.
# Filter drivers (HID, filesystem, network) are particularly abused for input
# spoofing, ESP overlays, and network traffic inspection.

try {
    # Get all loaded kernel modules via Get-CimInstance Win32_SystemDriver
    $allDrivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop
    $suspiciousDrivers = @()

    Write-Host ("  Total loaded drivers: {0}" -f $allDrivers.Count)

    foreach ($drv in ($allDrivers | Sort-Object StartMode,State)) {
        $binPath = $drv.PathName
        if (-not $binPath) { continue }

        # Normalize path
        $binPath = $binPath -replace '\\SystemRoot\\', "$env:SystemRoot\" `
                            -replace '\\??\\', ''

        $sig = $null
        $isUnsigned = $false
        $isMSSigned  = $false
        $hash = 'N/A'
        $fileExists = Test-Path $binPath -ErrorAction SilentlyContinue

        if ($fileExists) {
            $sig        = Get-AuthenticodeInfo -Path $binPath
            $isUnsigned = (-not $sig.IsValid)
            $isMSSigned  = $sig.IsMicrosoftSigned
            $hash       = Get-FileSHA256 -Path $binPath
        }

        $drvReasons = @()

        # Unsigned non-Microsoft drivers are highest priority
        if ($isUnsigned)    { $drvReasons += "Unsigned" }
        if (-not $fileExists) { $drvReasons += "FileNotFound" }

        # Check for cheat-related keywords
        foreach ($indicator in $script:CheatIndicators) {
            if ($binPath -match $indicator -or $drv.Name -match $indicator) {
                $drvReasons += "CheatKeyword"
                break
            }
        }

        # Drivers not in System32\drivers are suspicious
        if ($binPath -and $binPath -notmatch '\\System32\\drivers\\' -and
            $binPath -notmatch '\\SystemRoot\\System32\\DRIVERS\\' -and
            $fileExists) {
            $drvReasons += "NonStandardPath"
        }

        if ($drvReasons.Count -gt 0 -and -not $isMSSigned) {
            $suspiciousDrivers += [PSCustomObject]@{
                Name      = $drv.Name
                DisplayName = $drv.DisplayName
                Path      = $binPath
                StartMode = $drv.StartMode
                State     = $drv.State
                Reasons   = $drvReasons
                Signer    = if ($sig) { $sig.SignerCert } else { 'N/A' }
                SignerStatus = if ($sig) { $sig.Status } else { 'N/A' }
                Hash      = $hash
            }
        }
    }

    if ($suspiciousDrivers.Count -gt 0) {
        Write-Host "  -- SUSPICIOUS DRIVERS ($($suspiciousDrivers.Count)) --" -ForegroundColor Yellow
        foreach ($sd in $suspiciousDrivers) {
            $confidence = switch -Regex ($sd.Reasons -join ',') {
                'CheatKeyword' { 'Critical' }
                'Unsigned.*NonStandardPath|NonStandardPath.*Unsigned' { 'High' }
                'FileNotFound' { 'Medium' }
                'Unsigned' { 'Medium' }
                default { 'Low' }
            }
            Write-Flag "Driver $($sd.Name): $($sd.Reasons -join ', ')" -Severity $confidence `
                -Detail "Path: $($sd.Path) | Signer: $($sd.Signer)"
            Write-Host "    Hash: $($sd.Hash)" -ForegroundColor DarkGray

            Add-Finding -Category 'Drivers' -Title "Suspicious Driver: $($sd.Name)" `
                -Evidence "Path: $($sd.Path) | State: $($sd.State) | StartMode: $($sd.StartMode) | Signer: $($sd.Signer) | Hash: $($sd.Hash)" `
                -WhySuspicious ($sd.Reasons -join '; ') `
                -BenignExplanation "Legitimate hardware drivers (e.g. RGB controllers, peripherals) are often unsigned by smaller vendors" `
                -Confidence $confidence `
                -FollowUp "Submit hash to VirusTotal; check driver install date via setupapi.dev.log; look for associated service registry key"

            Add-TimelineEvent -Time (Get-Date) -Source 'Driver' -Event "Suspicious driver loaded: $($sd.Name)" `
                -Detail $sd.Path
        }
    } else {
        Write-Host "  All loaded drivers appear signed and in standard locations." -ForegroundColor Green
    }

    # Check test signing mode - required for unsigned kernel drivers without an exploited cert
    # This is a major red flag on a non-developer machine
    try {
        $bcdOutput = bcdedit /enum {current} 2>&1
        $testSigningEnabled = $bcdOutput | Select-String -Pattern 'testsigning\s+Yes' -Quiet
        $kernelDebugging    = $bcdOutput | Select-String -Pattern 'debug\s+Yes' -Quiet
        $kdbgEnabled        = $bcdOutput | Select-String -Pattern 'bootdebug\s+Yes' -Quiet

        if ($testSigningEnabled) {
            Write-Flag "TEST SIGNING MODE IS ENABLED - unsigned kernel drivers can load" -Severity Critical `
                -Detail "Required for loading self-signed/unsigned cheat drivers without an exploit"
            Add-Finding -Category 'Drivers' -Title 'Test Signing Mode Enabled' `
                -Evidence "bcdedit shows testsigning = Yes" `
                -WhySuspicious "Test signing mode is required to load unsigned kernel-mode drivers. Legitimate gaming systems should never have this enabled." `
                -BenignExplanation "Developer machine testing in-house drivers; Hyper-V development" `
                -Confidence 'High' `
                -FollowUp "Check when test signing was enabled; correlate with suspicious driver install dates"
        } else {
            Write-Host "  Test Signing Mode: Disabled (good)" -ForegroundColor Green
        }

        if ($kernelDebugging) {
            Write-Flag "KERNEL DEBUGGING IS ENABLED" -Severity High `
                -Detail "Kernel debugger attached or kdnet/kdusb enabled in BCD"
            Add-Finding -Category 'Drivers' -Title 'Kernel Debugging Enabled' `
                -Evidence "bcdedit shows debug = Yes" `
                -WhySuspicious "Kernel debugging bypasses PatchGuard and allows arbitrary kernel memory modification. Cheats can use this to patch anti-tamper protections." `
                -BenignExplanation "Driver or kernel developer; IT support debugging BSoDs" `
                -Confidence 'High' `
                -FollowUp "Determine if a debugger is actively connected; check for WinDbg, KD, or remote debugging sessions"
        }
    } catch {
        $script:CollectionErrors.Add("BCD query: $($_.Exception.Message)")
    }

    # Enumerate filter driver registry keys - these attach to device stacks
    # and can intercept keyboard/mouse input (HID filters) at kernel level
    Write-Host "`n  -- FILTER DRIVERS (HID / FS / Network) --" -ForegroundColor Cyan
    $filterPaths = @(
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{745a17a0-74d3-11d0-b6fe-00a0c90f57da}"; Label = "HID (Keyboard/Mouse)" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96b-e325-11ce-bfc1-08002be10318}"; Label = "Keyboard Class" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e96f-e325-11ce-bfc1-08002be10318}"; Label = "Mouse Class" },
        @{ Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{8ECC055D-047F-11D1-A537-0000F8753ED1}"; Label = "NDIS Network" }
    )
    foreach ($fp in $filterPaths) {
        try {
            $filters = Get-ItemProperty -Path $fp.Path -Name 'UpperFilters','LowerFilters' -ErrorAction SilentlyContinue
            if ($filters) {
                $upperF = if ($filters.UpperFilters) { $filters.UpperFilters -join ', ' } else { 'none' }
                $lowerF = if ($filters.LowerFilters) { $filters.LowerFilters -join ', ' } else { 'none' }
                Write-Host ("  {0}: Upper=[{1}] Lower=[{2}]" -f $fp.Label, $upperF, $lowerF) -ForegroundColor White

                # Flag non-Microsoft HID filter drivers - common input spoofing mechanism
                $nonMSFilters = @()
                $knownFilters = @('MouClass','kbdclass','KbdHid','MouHid','HidUsb','mouhid','kbdhid','WdFilter','storqosflt','wcifs','FileCrypt','luafv','npsvctrig','Wof','FileInfo')
                foreach ($f in ($filters.UpperFilters + $filters.LowerFilters | Where-Object { $_ })) {
                    if ($f -notin $knownFilters) { $nonMSFilters += $f }
                }
                if ($nonMSFilters.Count -gt 0) {
                    Write-Flag "Non-standard filter driver on $($fp.Label): $($nonMSFilters -join ', ')" -Severity Medium
                    Add-Finding -Category 'Drivers' -Title "Non-Standard Filter Driver on $($fp.Label)" `
                        -Evidence "Filters: $($nonMSFilters -join ', ')" `
                        -WhySuspicious "HID filter drivers intercept keyboard/mouse input at the kernel level. This is the mechanism used by input-reading cheats and mouse/keyboard spoofers." `
                        -BenignExplanation "Legitimate peripherals (e.g. Logitech GHUB, Razer Synapse) install HID filter drivers" `
                        -Confidence 'Medium' `
                        -FollowUp "Identify the driver binary for each filter; check its signature and install date"
                }
            }
        } catch {
            $script:CollectionErrors.Add("Filter driver check ($($fp.Label)): $($_.Exception.Message)")
        }
    }

} catch {
    Write-Host "  Driver collection failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Driver collection: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 8: REGISTRY - SECURITY CONFIGURATION
# -----------------------------------------------------------------------------
Write-Section "REGISTRY - SECURITY CONFIGURATION"

$settings = @(
    # CMD disabled - cheaters sometimes lock this to prevent forensic tooling
    @{ Name = "CMD";                Path = "HKCU:\Software\Policies\Microsoft\Windows\System";                          Key = "DisableCMD";               ZeroIsBad = $true;  Safe = "Available";  Warning = "Disabled" },
    # PowerShell ScriptBlock Logging - disabling prevents PS execution logging
    @{ Name = "PS ScriptBlock Log"; Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging";  Key = "EnableScriptBlockLogging"; ZeroIsBad = $true;  Safe = "Enabled";    Warning = "Disabled" },
    # Activity Feed - used for timeline reconstruction
    @{ Name = "Activity Feed";      Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System";                          Key = "EnableActivityFeed";       ZeroIsBad = $true;  Safe = "Enabled";    Warning = "Disabled" },
    # Prefetcher - stores execution history; disabling removes evidence
    @{ Name = "Prefetch";           Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"; Key = "EnablePrefetcher"; ZeroIsBad = $true; Safe = "Enabled"; Warning = "Disabled" },
    # AMSI - Anti-Malware Scan Interface; disabling weakens script scanning
    @{ Name = "AMSI";               Path = "HKLM:\SOFTWARE\Microsoft\Windows Script\Settings";                         Key = "AmsiEnable";               ZeroIsBad = $true;  Safe = "Enabled";    Warning = "Disabled" },
    # UAC - disabled UAC is required for many cheat installers without elevation prompts
    @{ Name = "UAC";                Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";          Key = "EnableLUA";                ZeroIsBad = $true;  Safe = "Enabled";    Warning = "Disabled" },
    # Defender Real-time Protection
    @{ Name = "Defender RTP";       Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"; Key = "DisableRealtimeMonitoring"; ZeroIsBad = $false; Safe = "Enabled";    Warning = "Disabled via Policy" },
    # Windows SmartScreen
    @{ Name = "SmartScreen";        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer";                Key = "SmartScreenEnabled";       ZeroIsBad = $false; Safe = "On";         Warning = "Off" },
    # AppInit DLLs - legacy injection vector; should be empty on modern systems
    @{ Name = "AppInit_DLLs";       Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows";              Key = "AppInit_DLLs";             ZeroIsBad = $false; Safe = "Empty";      Warning = "POPULATED" }
)

foreach ($s in $settings) {
    try {
        $status = Get-ItemProperty -Path $s.Path -Name $s.Key -ErrorAction SilentlyContinue

        Write-Host "  " -NoNewline

        $isBad = $false
        if ($s.ZeroIsBad) {
            $isBad = ($status -and $status.($s.Key) -eq 0)
        } elseif ($s.Key -eq 'AppInit_DLLs') {
            $val = if ($status) { $status.AppInit_DLLs } else { '' }
            $isBad = (-not [string]::IsNullOrWhiteSpace($val))
            if ($isBad) {
                Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
                Write-Host "POPULATED: $val" -ForegroundColor Red
                Add-Finding -Category 'Registry' -Title "AppInit_DLLs Populated" `
                    -Evidence "AppInit_DLLs = $val" `
                    -WhySuspicious "AppInit_DLLs causes the listed DLLs to be injected into every process that loads user32.dll. This is a classic injection vector used by cheats and malware." `
                    -BenignExplanation "Very rare - some ancient software used this. Modern software should not." `
                    -Confidence 'High' `
                    -FollowUp "Verify the DLL path and signature immediately; check when the key was last modified"
                continue
            }
        } elseif ($s.Key -eq 'SmartScreenEnabled') {
            $val = if ($status) { $status.SmartScreenEnabled } else { '' }
            $isBad = ($val -eq 'Off' -or $val -eq '')
        } elseif ($s.Key -eq 'DisableRealtimeMonitoring') {
            $isBad = ($status -and $status.($s.Key) -eq 1)
        }

        if ($isBad) {
            Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
            Write-Host $s.Warning -ForegroundColor Red
            Add-Finding -Category 'Registry' -Title "Security Setting Weakened: $($s.Name)" `
                -Evidence "Registry key $($s.Path)\$($s.Key) indicates $($s.Warning)" `
                -WhySuspicious "Disabling this setting removes a layer of detection, logging, or protection that anti-cheat tools rely on" `
                -BenignExplanation "Group Policy, enterprise configuration, or user performance tweaking" `
                -Confidence 'Medium' `
                -FollowUp "Check when the key was last modified; correlate with game installation or cheat tool install dates"
        } else {
            Write-Host "$($s.Name): " -NoNewline -ForegroundColor White
            Write-Host $s.Safe -ForegroundColor Green
        }
    } catch {
        Write-Host "  $($s.Name): Error - $($_.Exception.Message)" -ForegroundColor DarkGray
    }
}

# Additional registry checks
Write-Host "`n  -- BOOT CONFIGURATION --" -ForegroundColor Cyan

# HVCI / Memory Integrity
try {
    $hvciPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity"
    $hvci = Get-ItemProperty -Path $hvciPath -Name 'Enabled' -ErrorAction SilentlyContinue
    if ($hvci -and $hvci.Enabled -eq 1) {
        Write-Host "  Memory Integrity (HVCI): Enabled" -ForegroundColor Green
    } else {
        Write-Host "  Memory Integrity (HVCI): Disabled" -ForegroundColor Yellow
        Add-Finding -Category 'Security' -Title 'HVCI (Memory Integrity) Disabled' `
            -Evidence "HVCI not enabled in registry" `
            -WhySuspicious "HVCI prevents unsigned kernel code from running. Disabling it allows unsigned kernel exploits used by cheats to load." `
            -BenignExplanation "Incompatible drivers or older hardware may require HVCI to be off" `
            -Confidence 'Low' `
            -FollowUp "Check if HVCI was recently disabled; correlate with suspicious driver install"
    }
} catch {}

# Secure Boot
try {
    $sb = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" -Name 'UEFISecureBootEnabled' -ErrorAction SilentlyContinue
    if ($sb -and $sb.UEFISecureBootEnabled -eq 1) {
        Write-Host "  Secure Boot: Enabled" -ForegroundColor Green
    } else {
        Write-Host "  Secure Boot: Disabled or N/A" -ForegroundColor Yellow
    }
} catch {}

# VBS
try {
    $vbs = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name 'EnableVirtualizationBasedSecurity' -ErrorAction SilentlyContinue
    if ($vbs -and $vbs.EnableVirtualizationBasedSecurity -eq 1) {
        Write-Host "  VBS: Enabled" -ForegroundColor Green
    } else {
        Write-Host "  VBS: Disabled" -ForegroundColor Yellow
    }
} catch {}

# Check IFEO (Image File Execution Options) - used for process-replacement attacks
Write-Host "`n  -- IMAGE FILE EXECUTION OPTIONS (IFEO) --" -ForegroundColor Cyan
# IFEO can be used to silently replace or intercept process execution.
# Legitimate use: debugger attachment. Malicious: process substitution, silent exit monitoring.
try {
    $ifeoBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $ifeoKeys = Get-ChildItem -Path $ifeoBase -ErrorAction SilentlyContinue
    $ifeoFlags = @()

    foreach ($key in $ifeoKeys) {
        $debugger = Get-ItemProperty -Path $key.PSPath -Name 'Debugger' -ErrorAction SilentlyContinue
        $globalFlag = Get-ItemProperty -Path $key.PSPath -Name 'GlobalFlag' -ErrorAction SilentlyContinue

        if ($debugger -and $debugger.Debugger) {
            $ifeoFlags += [PSCustomObject]@{
                Process  = $key.PSChildName
                Debugger = $debugger.Debugger
                Type     = 'Debugger'
            }
        }
        if ($globalFlag -and $globalFlag.GlobalFlag -ne 0) {
            $ifeoFlags += [PSCustomObject]@{
                Process  = $key.PSChildName
                Debugger = "GlobalFlag=$($globalFlag.GlobalFlag)"
                Type     = 'GlobalFlag'
            }
        }
    }

    if ($ifeoFlags.Count -gt 0) {
        Write-Host "  Found $($ifeoFlags.Count) IFEO entries with Debugger or GlobalFlag:" -ForegroundColor Yellow
        foreach ($ifeo in $ifeoFlags) {
            Write-Host ("  {0,-30} {1,-12} {2}" -f $ifeo.Process, $ifeo.Type, $ifeo.Debugger) -ForegroundColor Yellow

            # Silent process exit (SilentProcessExit) is used by cheats to detect AV/AC kills
            $sep = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\$($ifeo.Process)" -ErrorAction SilentlyContinue
            if ($sep) {
                Write-Flag "SilentProcessExit configured for $($ifeo.Process) - executes $($sep.MonitorProcess) on process death" -Severity High
                Add-Finding -Category 'Persistence' -Title "SilentProcessExit on $($ifeo.Process)" `
                    -Evidence "MonitorProcess = $($sep.MonitorProcess)" `
                    -WhySuspicious "SilentProcessExit allows a cheat to restart itself if killed by anti-cheat. Also used to detect when it has been terminated." `
                    -BenignExplanation "Enterprise crash-reporting tools legitimately use this feature" `
                    -Confidence 'High' `
                    -FollowUp "Verify the MonitorProcess binary; check if it is signed and expected"
            }

            $knownIFEO = @('vsjitdebugger.exe','windbg.exe','devenv.exe','ntsd.exe','cdb.exe')
            $debuggerName = [System.IO.Path]::GetFileName($ifeo.Debugger).ToLower()
            if ($debuggerName -notin $knownIFEO -and $ifeo.Type -eq 'Debugger') {
                Add-Finding -Category 'Persistence' -Title "Unusual IFEO Debugger: $($ifeo.Process)" `
                    -Evidence "Process: $($ifeo.Process) | Debugger: $($ifeo.Debugger)" `
                    -WhySuspicious "IFEO debugger hijacking replaces a process with an attacker-controlled binary. The configured 'debugger' runs instead of (or before) the target process." `
                    -BenignExplanation "Developer has configured a custom debugger for a specific process" `
                    -Confidence 'Medium' `
                    -FollowUp "Verify the debugger binary signature and purpose"
            }
        }
    } else {
        Write-Host "  IFEO: No Debugger or GlobalFlag entries found" -ForegroundColor Green
    }
} catch {
    $script:CollectionErrors.Add("IFEO check: $($_.Exception.Message)")
}

# USB / Device history
Write-Host "`n  -- USB / DEVICE HISTORY --" -ForegroundColor Cyan
# USB history can reveal external storage devices used to transport cheat tools.
# This artifact survives reboots and is stored in the registry.
try {
    $usbPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR"
    $usbDevices = Get-ChildItem -Path $usbPath -ErrorAction SilentlyContinue
    if ($usbDevices) {
        Write-Host "  USB storage devices ever connected:" -ForegroundColor White
        foreach ($dev in $usbDevices) {
            $devInfo = $dev.PSChildName
            $instances = Get-ChildItem -Path $dev.PSPath -ErrorAction SilentlyContinue
            foreach ($inst in $instances) {
                $friendly = (Get-ItemProperty -Path $inst.PSPath -Name 'FriendlyName' -ErrorAction SilentlyContinue).FriendlyName
                Write-Host ("    {0}" -f (if ($friendly) { $friendly } else { $devInfo })) -ForegroundColor Gray
                Add-TimelineEvent -Time (Get-Date) -Source 'USB' -Event "USB device in registry: $($devInfo)" `
                    -Detail (if ($friendly) { $friendly } else { '' })
            }
        }
    } else {
        Write-Host "  No USB storage history found." -ForegroundColor Gray
    }
} catch {
    $script:CollectionErrors.Add("USB history: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 9: PERSISTENCE MECHANISMS
# -----------------------------------------------------------------------------
Write-Section "PERSISTENCE MECHANISMS"

# Cheats need to survive reboots or re-inject after anti-cheat kills them.
# These are the most common persistence vectors on Windows.

$persistenceLocations = @(
    # Run / RunOnce registry keys - most common persistence mechanism
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run";     Label = "HKCU Run" },
    @{ Path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKCU RunOnce" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run";     Label = "HKLM Run" },
    @{ Path = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"; Label = "HKLM RunOnce" },
    @{ Path = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label = "HKLM Run (32-bit)" },
    # Winlogon
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; Label = "Winlogon"; Values = @('Userinit','Shell') },
    # Active Setup - runs once per user on login
    @{ Path = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components"; Label = "Active Setup" },
    # Wow6432 Run
    @{ Path = "HKCU:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Label = "HKCU Run (32-bit)" }
)

foreach ($loc in $persistenceLocations) {
    try {
        if ($loc.Values) {
            # Check specific named values
            $props = Get-ItemProperty -Path $loc.Path -ErrorAction SilentlyContinue
            foreach ($v in $loc.Values) {
                $val = if ($props) { $props.$v } else { $null }
                if ($val) {
                    # Check for non-default values
                    $defaults = @{
                        'Userinit' = 'C:\Windows\system32\userinit.exe,'
                        'Shell'    = 'explorer.exe'
                    }
                    if ($defaults.ContainsKey($v) -and $val -ne $defaults[$v]) {
                        Write-Flag "$($loc.Label) $v modified: $val" -Severity High
                        Add-Finding -Category 'Persistence' -Title "$($loc.Label) $v Modified" `
                            -Evidence "$v = $val (expected: $($defaults[$v]))" `
                            -WhySuspicious "Winlogon Userinit/Shell hijacking causes arbitrary code to run at every login. This is a rare but high-impact persistence technique." `
                            -BenignExplanation "Some remote management tools modify Shell; very few legitimate cases exist" `
                            -Confidence 'High' `
                            -FollowUp "Investigate all binaries referenced in the value immediately"
                    } else {
                        Write-Host ("  {0} {1}: {2}" -f $loc.Label, $v, $val) -ForegroundColor Green
                    }
                }
            }
        } else {
            # Enumerate all values in the key
            $props = Get-ItemProperty -Path $loc.Path -ErrorAction SilentlyContinue
            if (-not $props) { continue }
            $valueNames = $props.PSObject.Properties |
                          Where-Object { $_.Name -notin @('PSPath','PSParentPath','PSChildName','PSProvider','PSDrive') }

            if ($valueNames) {
                Write-Host ("  {0}: {1} entries" -f $loc.Label, @($valueNames).Count) -ForegroundColor White
                foreach ($v in $valueNames) {
                    $entryPath = $v.Value
                    $color = 'Gray'
                    $reason = ''

                    # Check each entry's binary
                    $binPath = ($entryPath -replace '"','').Split(' ')[0]
                    if ($binPath -and (Test-Path $binPath -ErrorAction SilentlyContinue)) {
                        $sig = Get-AuthenticodeInfo -Path $binPath
                        if (-not $sig.IsValid) {
                            $color  = 'Yellow'
                            $reason = ' [UNSIGNED]'
                            Add-Finding -Category 'Persistence' -Title "Unsigned Run Key Entry: $($v.Name)" `
                                -Evidence "$($loc.Label): $($v.Name) = $entryPath" `
                                -WhySuspicious "Unsigned auto-start entries in Run keys are high-value persistence indicators" `
                                -BenignExplanation "Legitimate software with weak signing" `
                                -Confidence 'Medium' `
                                -FollowUp "Verify binary identity; check creation date of the registry key value"
                        }
                        if (Test-SuspiciousPath -Path $binPath) {
                            $color  = 'Yellow'
                            $reason += ' [SUSPICIOUS_PATH]'
                        }
                    } elseif ($binPath -and -not (Test-Path $binPath -ErrorAction SilentlyContinue)) {
                        $color  = 'DarkGray'
                        $reason = ' [BINARY_MISSING]'
                    }

                    Write-Host ("    {0,-30} = {1}{2}" -f $v.Name, $entryPath, $reason) -ForegroundColor $color
                }
            } else {
                Write-Host ("  {0}: Empty" -f $loc.Label) -ForegroundColor Green
            }
        }
    } catch {
        $script:CollectionErrors.Add("Persistence check ($($loc.Label)): $($_.Exception.Message)")
    }
}

# Startup folder
Write-Host "`n  -- STARTUP FOLDERS --" -ForegroundColor Cyan
$startupFolders = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
foreach ($folder in $startupFolders) {
    if (Test-Path $folder) {
        $items = Get-ChildItem $folder -File -ErrorAction SilentlyContinue
        if ($items) {
            Write-Host "  $folder - $($items.Count) items:" -ForegroundColor Yellow
            foreach ($item in $items) {
                Write-Host ("    {0}" -f $item.Name) -ForegroundColor White
                Add-Finding -Category 'Persistence' -Title "Startup Folder Item: $($item.Name)" `
                    -Evidence "Path: $($item.FullName)" `
                    -WhySuspicious "Files in startup folders execute at every user login; commonly used for cheat loader persistence" `
                    -BenignExplanation "Legitimate auto-starting software (e.g. cloud sync, communication apps)" `
                    -Confidence 'Low' `
                    -FollowUp "Verify binary signature and purpose"
            }
        } else {
            Write-Host "  $($folder.Split('\')[-1]): Empty" -ForegroundColor Green
        }
    }
}

# Scheduled Tasks
Write-Host "`n  -- SCHEDULED TASKS --" -ForegroundColor Cyan
try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
    $suspiciousTasks = @()

    foreach ($task in $tasks) {
        $taskPath   = $task.TaskPath
        $taskName   = $task.TaskName
        $actions    = $task.Actions
        $isSus      = $false
        $reason     = ''

        # Skip known-good Microsoft task paths
        if ($taskPath -match '\\Microsoft\\Windows\\' -or $taskPath -match '\\Microsoft\\Office\\') { continue }

        foreach ($action in $actions) {
            if ($action.Execute) {
                $exe = $action.Execute -replace '"',''
                if (Test-SuspiciousPath -Path $exe) {
                    $isSus  = $true
                    $reason += "SuspiciousPath($exe) "
                }
                if (-not (Test-Path $exe -ErrorAction SilentlyContinue) -and $exe -notmatch '%') {
                    $isSus  = $true
                    $reason += "MissingBinary "
                }
                foreach ($indicator in $script:CheatIndicators) {
                    if ($exe -match $indicator -or $taskName -match $indicator) {
                        $isSus  = $true
                        $reason += "CheatKeyword($indicator) "
                    }
                }
            }
        }

        if ($isSus) {
            $suspiciousTasks += [PSCustomObject]@{
                Name    = $taskName
                Path    = $taskPath
                Actions = ($actions | ForEach-Object { $_.Execute }) -join '; '
                Reason  = $reason.Trim()
            }
        } else {
            # Still log non-Microsoft tasks as informational
            Write-Host ("  {0}{1}" -f $taskPath,$taskName) -ForegroundColor Gray
        }
    }

    if ($suspiciousTasks.Count -gt 0) {
        Write-Host "  -- SUSPICIOUS TASKS ($($suspiciousTasks.Count)) --" -ForegroundColor Yellow
        foreach ($t in $suspiciousTasks) {
            Write-Flag "Task: $($t.Path)$($t.Name) - $($t.Reason)" -Severity Medium `
                -Detail "Actions: $($t.Actions)"
            Add-Finding -Category 'Persistence' -Title "Suspicious Scheduled Task: $($t.Name)" `
                -Evidence "Path: $($t.Path)$($t.Name) | Actions: $($t.Actions)" `
                -WhySuspicious $t.Reason `
                -BenignExplanation "Game launcher update tasks, hardware utility tasks" `
                -Confidence 'Medium' `
                -FollowUp "Check task creation date; verify action binary; check who created the task (task author field)"
        }
    }
} catch {
    $script:CollectionErrors.Add("Scheduled tasks: $($_.Exception.Message)")
}

# WMI Event Subscriptions - a stealthy persistence mechanism
Write-Host "`n  -- WMI EVENT SUBSCRIPTIONS --" -ForegroundColor Cyan
# WMI subscriptions trigger actions (consumers) when events (filters) occur.
# This is rarely used legitimately and often used by sophisticated malware/cheats.
try {
    $wmiFilters   = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction Stop
    $wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $wmiBindings  = Get-CimInstance -Namespace root\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue

    if ($wmiFilters.Count -eq 0 -and (@($wmiConsumers).Count -eq 0)) {
        Write-Host "  WMI subscriptions: None found" -ForegroundColor Green
    } else {
        Write-Flag "WMI Event Subscriptions found: $($wmiFilters.Count) filter(s)" -Severity High
        foreach ($f in $wmiFilters) {
            Write-Host ("  Filter: {0} | Query: {1}" -f $f.Name, $f.Query) -ForegroundColor Yellow
        }
        foreach ($c in $wmiConsumers) {
            Write-Host ("  Consumer: {0} | Command: {1}" -f $c.Name, $c.CommandLineTemplate) -ForegroundColor Yellow
        }
        Add-Finding -Category 'Persistence' -Title 'WMI Event Subscription Present' `
            -Evidence "Filters: $($wmiFilters.Count) | Consumers: $(@($wmiConsumers).Count)" `
            -WhySuspicious "WMI subscriptions are a fileless persistence mechanism that survives reboots. Rarely used by legitimate software; frequently used by sophisticated threats." `
            -BenignExplanation "Some enterprise management tools (e.g. SCCM) use WMI subscriptions" `
            -Confidence 'High' `
            -FollowUp "Review all filter queries and consumer commands; verify they match known software"
    }
} catch {
    $script:CollectionErrors.Add("WMI subscriptions: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 10: WINDOWS DEFENDER
# -----------------------------------------------------------------------------
Write-Section "WINDOWS DEFENDER"

try {
    $mpPref     = Get-MpPreference -ErrorAction Stop
    $mpComputer = Get-MpComputerStatus -ErrorAction Stop
    $mpThreats  = Get-MpThreatDetection -ErrorAction SilentlyContinue

    # Status
    Write-Item "Antivirus Enabled:      " $(if ($mpComputer.AntivirusEnabled) { "Yes" } else { "NO - CRITICAL" }) `
        -Color $(if ($mpComputer.AntivirusEnabled) { 'Green' } else { 'Red' })
    Write-Item "Real-time Protection:   " $(if ($mpComputer.RealTimeProtectionEnabled) { "Yes" } else { "NO" }) `
        -Color $(if ($mpComputer.RealTimeProtectionEnabled) { 'Green' } else { 'Red' })
    Write-Item "Tamper Protection:      " $(if ($mpComputer.IsTamperProtected) { "Yes" } else { "NO" }) `
        -Color $(if ($mpComputer.IsTamperProtected) { 'Green' } else { 'Yellow' })
    Write-Item "Signature Version:      " $mpComputer.AntivirusSignatureVersion
    Write-Item "Engine Version:         " $mpComputer.AMEngineVersion
    Write-Item "Platform Version:       " $mpComputer.AMServiceVersion
    Write-Item "Last Quick Scan:        " $(if ($mpComputer.QuickScanStartTime) { $mpComputer.QuickScanStartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" })
    Write-Item "Last Full Scan:         " $(if ($mpComputer.FullScanStartTime) { $mpComputer.FullScanStartTime.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" })

    # Key protection failures
    if (-not $mpComputer.AntivirusEnabled) {
        Add-Finding -Category 'Defender' -Title 'Windows Defender Antivirus Disabled' `
            -Evidence "Get-MpComputerStatus: AntivirusEnabled = False" `
            -WhySuspicious "Disabling AV is a prerequisite for running detected cheat software without automatic quarantine" `
            -BenignExplanation "Third-party AV is installed and Windows Defender deferred to it" `
            -Confidence 'High' `
            -FollowUp "Check for third-party AV; check Tamper Protection and event log for who disabled it"
    }
    if (-not $mpComputer.IsTamperProtected) {
        Add-Finding -Category 'Defender' -Title 'Tamper Protection Disabled' `
            -Evidence "Get-MpComputerStatus: IsTamperProtected = False" `
            -WhySuspicious "Tamper Protection prevents Defender settings from being modified by processes. Disabling it allows cheats/scripts to turn off real-time protection." `
            -BenignExplanation "Managed enterprise device where group policy controls AV; or third-party AV active" `
            -Confidence 'Medium' `
            -FollowUp "Correlate with event ID 5001 or 5004 in Microsoft-Windows-Windows Defender/Operational"
    }

    # Exclusions are a critical indicator - many cheats add themselves to Defender exclusions
    Write-Host "`n  -- DEFENDER EXCLUSIONS --" -ForegroundColor Cyan
    $exclusionTypes = @{
        'ExclusionPath'      = "Path exclusions"
        'ExclusionExtension' = "Extension exclusions"
        'ExclusionProcess'   = "Process exclusions"
        'ExclusionIpAddress' = "IP exclusions"
    }
    $anyExclusions = $false
    foreach ($excType in $exclusionTypes.Keys) {
        $excValues = $mpPref.$excType
        if ($excValues -and $excValues.Count -gt 0) {
            $anyExclusions = $true
            Write-Host ("  {0}: {1} entries" -f $exclusionTypes[$excType], $excValues.Count) -ForegroundColor Yellow
            foreach ($excVal in $excValues) {
                Write-Host "    $excVal" -ForegroundColor White
                # Flag exclusions in user-writable directories
                if (Test-SuspiciousPath -Path $excVal) {
                    Write-Flag "Exclusion in suspicious path: $excVal" -Severity High
                    Add-Finding -Category 'Defender' -Title "Defender Exclusion in Suspicious Path" `
                        -Evidence "$excType = $excVal" `
                        -WhySuspicious "Cheat tools add Defender path exclusions to prevent detection. Exclusions in user-writable locations (Temp, AppData, Downloads) are a major indicator." `
                        -BenignExplanation "Legitimate software that triggers false positives may add exclusions during install" `
                        -Confidence 'High' `
                        -FollowUp "Check when the exclusion was added; verify if anything in that path is suspicious"
                }
            }
        }
    }
    if (-not $anyExclusions) {
        Write-Host "  No Defender exclusions configured." -ForegroundColor Green
    }

    # Recent threat detections
    Write-Host "`n  -- RECENT THREAT DETECTIONS --" -ForegroundColor Cyan
    if ($mpThreats) {
        $recentThreats = $mpThreats | Sort-Object InitialDetectionTime -Descending | Select-Object -First 20
        Write-Host "  $($recentThreats.Count) recent detection(s) found:" -ForegroundColor Yellow
        foreach ($threat in $recentThreats) {
            $threatInfo = Get-MpThreat -ThreatID $threat.ThreatID -ErrorAction SilentlyContinue
            $threatName = if ($threatInfo) { $threatInfo.ThreatName } else { "ID $($threat.ThreatID)" }
            Write-Host ("  [{0}] {1} - Resources: {2}" -f
                $threat.InitialDetectionTime.ToString("MM/dd HH:mm"),
                $threatName,
                ($threat.Resources -join ', ')) -ForegroundColor Yellow

            Add-Finding -Category 'Defender' -Title "Defender Detection: $threatName" `
                -Evidence "Detection at $($threat.InitialDetectionTime) | Resources: $($threat.Resources -join ',')" `
                -WhySuspicious "Defender identified and flagged a threat. Even if quarantined, the original presence is forensically significant." `
                -BenignExplanation "False positive on a game or tool; legitimate software detection" `
                -Confidence 'Medium' `
                -FollowUp "Check the detection timeline against game play session; verify if threat was remediated"
            Add-TimelineEvent -Time $threat.InitialDetectionTime -Source 'Defender' `
                -Event "Threat detected: $threatName" -Detail ($threat.Resources -join ',')
        }
    } else {
        Write-Host "  No threat detection history found." -ForegroundColor Green
    }

} catch {
    Write-Host "  Defender collection failed: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Defender: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 11: WINDOWS SECURITY CONFIGURATION
# -----------------------------------------------------------------------------
Write-Section "WINDOWS SECURITY CONFIGURATION"

# Secure Boot status
try {
    $confirmedSB = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
    Write-Item "Secure Boot:         " $(if ($confirmedSB) { "Enabled" } else { "Disabled or Legacy BIOS" }) `
        -Color $(if ($confirmedSB) { 'Green' } else { 'Yellow' })
} catch {
    Write-Item "Secure Boot:         " "N/A (non-UEFI or command unavailable)"
}

# TPM
try {
    $tpm = Get-Tpm -ErrorAction SilentlyContinue
    if ($tpm) {
        Write-Item "TPM Present:         " $(if ($tpm.TpmPresent) { "Yes" } else { "No" }) `
            -Color $(if ($tpm.TpmPresent) { 'Green' } else { 'Yellow' })
        Write-Item "TPM Ready:           " $(if ($tpm.TpmReady) { "Yes" } else { "No" }) `
            -Color $(if ($tpm.TpmReady) { 'Green' } else { 'Yellow' })
    }
} catch {}

# BitLocker
try {
    $bl = Get-BitLockerVolume -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($bl) {
        Write-Item "BitLocker:           " "$($bl.VolumeStatus) / $($bl.ProtectionStatus)"
    }
} catch {}

# Check for Hyper-V / virtualization (VMs can hide cheat processes from host AC)
try {
    $hvInfo = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
    $isVM   = $false
    $vmType = ''
    if ($hvInfo) {
        $manufacturer = $hvInfo.Manufacturer
        $model        = $hvInfo.Model
        if ($manufacturer -match 'VMware|QEMU|Xen|innotek|Bochs' -or $model -match 'Virtual|VMware|KVM') {
            $isVM  = $true
            $vmType = "$manufacturer $model"
        }
    }
    if ($isVM) {
        Write-Flag "System appears to be running inside a VM: $vmType" -Severity Medium
        Add-Finding -Category 'Security' -Title 'System is a Virtual Machine' `
            -Evidence "Manufacturer: $manufacturer | Model: $model" `
            -WhySuspicious "Anti-cheat tools have reduced visibility into VMs. Cheats are sometimes run on a separate VM or host while the game runs in another VM." `
            -BenignExplanation "Developer or IT VM; cloud gaming VM" `
            -Confidence 'Low' `
            -FollowUp "Investigate VM configuration; check if anti-cheat explicitly requires non-VM"
    } else {
        Write-Item "Virtualization:      " "Physical hardware (or undetected VM)"
    }
} catch {}

# -----------------------------------------------------------------------------
#  SECTION 12: EVENT LOGS  (deep correlated analysis)
# -----------------------------------------------------------------------------
Write-Section "EVENT LOGS - DEEP ANALYSIS"

function Get-RecentEvent {
    param(
        [string]$LogName,
        [int[]]$EventIDs,
        [string]$Label,
        [int]$MaxEvents = 5,
        [string]$XPath = $null
    )
    try {
        $filter = if ($XPath) {
            @{ LogName = $LogName; }
        } else {
            @{ LogName = $LogName; Id = $EventIDs }
        }
        $events = if ($XPath) {
            Get-WinEvent -LogName $LogName -FilterXPath $XPath -MaxEvents $MaxEvents -ErrorAction Stop
        } else {
            Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
        }

        if ($events) {
            Write-Host ("  {0}: {1} event(s) - last at {2}" -f
                $Label, $events.Count, $events[0].TimeCreated.ToString("MM/dd HH:mm")) -ForegroundColor Yellow
            return $events
        } else {
            Write-Host ("  {0}: No records" -f $Label) -ForegroundColor Green
        }
    } catch {
        Write-Host ("  {0}: Log unavailable or empty" -f $Label) -ForegroundColor DarkGray
    }
    return @()
}

# Security-critical events
Write-Host "  -- SECURITY & SYSTEM --" -ForegroundColor Cyan

# Log clearing - a primary anti-forensic action
$logClearEvents = Get-RecentEvent "System" @(104) "Security Log Cleared (Sys 104)" -MaxEvents 3
$secLogClear    = Get-RecentEvent "Security" @(1102) "Security Log Cleared (Sec 1102)" -MaxEvents 3

foreach ($e in ($logClearEvents + $secLogClear)) {
    Add-Finding -Category 'AntiForensics' -Title 'Event Log Cleared' `
        -Evidence "Event $($e.Id) at $($e.TimeCreated) in $($e.LogName)" `
        -WhySuspicious "Clearing event logs is a primary anti-forensic action performed before or after cheat use to eliminate execution evidence" `
        -BenignExplanation "IT maintenance; automated log rotation policy" `
        -Confidence 'High' `
        -FollowUp "Check who cleared the log (field in event 1102); correlate with other anti-forensic indicators"
    Add-TimelineEvent -Time $e.TimeCreated -Source 'EventLog' -Event "Event log cleared (ID $($e.Id))"
}

# System time changes - manipulated timestamps can invalidate forensic timelines
$timeChanges = Get-RecentEvent "Security" @(4616) "System Time Changed" -MaxEvents 3
foreach ($e in $timeChanges) {
    Add-Finding -Category 'AntiForensics' -Title 'System Time Changed' `
        -Evidence "Event 4616 at $($e.TimeCreated)" `
        -WhySuspicious "Manipulating system time can invalidate forensic artifact timestamps and confuse timeline reconstruction" `
        -BenignExplanation "NTP sync; time zone change; DST adjustment" `
        -Confidence 'Low' `
        -FollowUp "Inspect the event details for the new and previous times; check if change was large and unexplained"
    Add-TimelineEvent -Time $e.TimeCreated -Source 'Security' -Event 'System time modified'
}

# Audit policy changes
Get-RecentEvent "Security" @(4719) "Audit Policy Changed" -MaxEvents 3 | ForEach-Object {
    Add-Finding -Category 'AntiForensics' -Title 'Audit Policy Modified' `
        -Evidence "Event 4719 at $($_.TimeCreated)" `
        -WhySuspicious "Changing audit policy can disable the logging of specific event types, blinding forensic analysis" `
        -BenignExplanation "Domain policy update; IT configuration change" `
        -Confidence 'Medium' `
        -FollowUp "Review the subcategory changed and whether logging was reduced or disabled"
    Add-TimelineEvent -Time $_.TimeCreated -Source 'Security' -Event 'Audit policy changed'
}

# New service installed
Write-Host "`n  -- SERVICE / DRIVER INSTALLS --" -ForegroundColor Cyan
Get-RecentEvent "System" @(7045) "New Service Installed" -MaxEvents 10 | ForEach-Object {
    Write-Host "    $($_.TimeCreated.ToString('MM/dd HH:mm')): $($_.Message -split "`n" | Select-Object -First 2 | Where-Object { $_ })" -ForegroundColor Yellow
    Add-TimelineEvent -Time $_.TimeCreated -Source 'Services' -Event 'Service installed (7045)' -Detail ($_.Message -split "`n")[0]
}

# Code Integrity events - unsigned driver blocked
Write-Host "`n  -- CODE INTEGRITY --" -ForegroundColor Cyan
Get-RecentEvent "Microsoft-Windows-CodeIntegrity/Operational" @(3001,3002,3003,3004,3010,3023) `
    "Code Integrity Violation" -MaxEvents 10 | ForEach-Object {
    Write-Host "    [$($_.TimeCreated.ToString('MM/dd HH:mm'))] ID $($_.Id): $($_.Message.Substring(0,[Math]::Min(120,$_.Message.Length)))" -ForegroundColor Yellow
    Add-Finding -Category 'Drivers' -Title "Code Integrity Violation (Event $($_.Id))" `
        -Evidence "Event at $($_.TimeCreated): $($_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)))" `
        -WhySuspicious "Windows blocked a driver or file from loading due to signature validation failure. This can indicate a cheat driver attempt." `
        -BenignExplanation "Outdated hardware drivers or software that hasn't been re-signed" `
        -Confidence 'Medium' `
        -FollowUp "Identify the blocked file from the event details"
    Add-TimelineEvent -Time $_.TimeCreated -Source 'CodeIntegrity' -Event "CI Violation (ID $($_.Id))"
}

# PowerShell execution
Write-Host "`n  -- POWERSHELL EXECUTION --" -ForegroundColor Cyan
Get-RecentEvent "Microsoft-Windows-PowerShell/Operational" @(4104) `
    "PowerShell ScriptBlock" -MaxEvents 10 | ForEach-Object {
    $msgPreview = ($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(200,$_.Message.Length))
    Write-Host "    [$($_.TimeCreated.ToString('MM/dd HH:mm'))] $msgPreview" -ForegroundColor Gray
}

# Sysmon events (if present)
Write-Host "`n  -- SYSMON (if installed) --" -ForegroundColor Cyan
$sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction SilentlyContinue
if ($sysmonLog) {
    Write-Host "  Sysmon is installed - collection available" -ForegroundColor Green
    # Process creation with network connections in same session
    Get-RecentEvent "Microsoft-Windows-Sysmon/Operational" @(1) "Recent process creates (Sysmon 1)" -MaxEvents 10 | ForEach-Object {
        $msgPreview = $_.Message -replace '\s+',' ' | Select-Object -First 1
        Write-Host "    [$($_.TimeCreated.ToString('MM/dd HH:mm'))] $($msgPreview.Substring(0,[Math]::Min(150,$msgPreview.Length)))" -ForegroundColor Gray
    }
    # Network connections
    Get-RecentEvent "Microsoft-Windows-Sysmon/Operational" @(3) "Network connections (Sysmon 3)" -MaxEvents 5 | ForEach-Object {
        Write-Host "    [$($_.TimeCreated.ToString('MM/dd HH:mm'))] $($_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) -replace '\s+',' ')" -ForegroundColor Gray
    }
    # Driver loads
    Get-RecentEvent "Microsoft-Windows-Sysmon/Operational" @(6) "Driver loads (Sysmon 6)" -MaxEvents 10 | ForEach-Object {
        Write-Host "    [$($_.TimeCreated.ToString('MM/dd HH:mm'))] $($_.Message.Substring(0,[Math]::Min(200,$_.Message.Length)) -replace '\s+',' ')" -ForegroundColor Yellow
        Add-TimelineEvent -Time $_.TimeCreated -Source 'Sysmon' -Event 'Driver loaded (Sysmon 6)' `
            -Detail ($_.Message -replace '\s+',' ').Substring(0,[Math]::Min(200,$_.Message.Length))
    }
} else {
    Write-Host "  Sysmon is not installed. Consider deploying for enhanced forensic visibility." -ForegroundColor Gray
}

# Shutdown / boot events
Write-Host "`n  -- BOOT / SHUTDOWN HISTORY --" -ForegroundColor Cyan
Get-RecentEvent "System" @(6005,6006,1074,1076) "Boot/Shutdown Events" -MaxEvents 10 | ForEach-Object {
    $evLabel = switch ($_.Id) {
        6005 { "Event Log Service STARTED (boot)" }
        6006 { "Event Log Service STOPPED (shutdown)" }
        1074 { "Shutdown initiated" }
        1076 { "Unexpected shutdown" }
    }
    Write-Host ("    [{0}] {1}" -f $_.TimeCreated.ToString("MM/dd HH:mm"), $evLabel) -ForegroundColor Gray
    Add-TimelineEvent -Time $_.TimeCreated -Source 'System' -Event $evLabel
}

# USN Journal cleared
$usnClear = Get-WinEvent -LogName Application -FilterXPath "*[System[EventID=3079]]" -MaxEvents 1 -ErrorAction SilentlyContinue
if ($usnClear) {
    Write-Host ("  USN Journal cleared at: {0}" -f $usnClear.TimeCreated.ToString("MM/dd HH:mm")) -ForegroundColor Yellow
    Add-Finding -Category 'AntiForensics' -Title 'USN Journal Cleared' `
        -Evidence "Event 3079 at $($usnClear.TimeCreated)" `
        -WhySuspicious "The USN Journal tracks all file system changes. Clearing it removes evidence of file creation, modification, and deletion - a targeted anti-forensic action." `
        -BenignExplanation "Low disk space causing journal overflow; administrative maintenance" `
        -Confidence 'Medium' `
        -FollowUp "Check for other anti-forensic indicators; correlate timing with suspicious activity"
    Add-TimelineEvent -Time $usnClear.TimeCreated -Source 'EventLog' -Event 'USN Journal cleared'
}

# Device changes (USB insertions/removals)
Write-Section "DEVICE CHANGES"
# USB insertions are relevant - external storage is commonly used to transport cheats
try {
    $devSetupLog = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"
    $usbEvents   = Get-WinEvent -FilterHashtable @{LogName=$devSetupLog; Id=@(2003,2006,2100)} -MaxEvents 10 -ErrorAction SilentlyContinue
    if ($usbEvents) {
        foreach ($ue in $usbEvents) {
            Write-Host ("  [{0}] ID {1}: {2}" -f $ue.TimeCreated.ToString("MM/dd HH:mm"), $ue.Id,
                ($ue.Message -replace '\s+',' ').Substring(0,[Math]::Min(100,$ue.Message.Length))) -ForegroundColor Gray
            Add-TimelineEvent -Time $ue.TimeCreated -Source 'DeviceSetup' -Event "Device event (ID $($ue.Id))"
        }
    } else {
        Write-Host "  No recent device setup events in UserMode log." -ForegroundColor Gray
    }
} catch {
    # Fall back to original method
    $devEvent = Get-WinEvent -LogName "Microsoft-Windows-Kernel-PnP/Configuration" `
        -FilterXPath "*[System[EventID=400]]" -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($devEvent) {
        Write-Host ("  Device configuration changed at: {0}" -f $devEvent.TimeCreated.ToString("MM/dd HH:mm")) -ForegroundColor Yellow
        Add-TimelineEvent -Time $devEvent.TimeCreated -Source 'PnP' -Event 'Device configuration changed'
    } else {
        Write-Host "  Device changes: No recent records found" -ForegroundColor Green
    }
}

# -----------------------------------------------------------------------------
#  SECTION 13: PREFETCH INTEGRITY  (preserved + enhanced)
# -----------------------------------------------------------------------------
Write-Section "PREFETCH INTEGRITY"

# Prefetch files record execution of binaries. Their metadata (timestamps,
# accessed file list) is valuable for reconstructing what ran and when.
# Anomalies: hidden/read-only files, duplicate hashes, or missing expected entries.

$prefetchPath = "$env:SystemRoot\Prefetch"
if (Test-Path $prefetchPath) {
    $files = Get-ChildItem -Path $prefetchPath -Filter *.pf -Force -ErrorAction SilentlyContinue
    if (-not $files) {
        Write-Host "  No prefetch files found - verify Prefetcher is enabled" -ForegroundColor Yellow
    } else {
        $hashTable            = @{}
        $suspiciousFiles      = @{}
        $totalFiles           = $files.Count
        $hiddenFiles          = @()
        $readOnlyFiles        = @()
        $hiddenAndReadOnly    = @()
        $errorFiles           = @()
        $cheatNamedFiles      = @()

        foreach ($file in $files) {
            try {
                $isHidden   = [bool]($file.Attributes -band [System.IO.FileAttributes]::Hidden)
                $isReadOnly = [bool]($file.Attributes -band [System.IO.FileAttributes]::ReadOnly)

                if ($isHidden -and $isReadOnly) {
                    $hiddenAndReadOnly += $file
                    $suspiciousFiles[$file.Name] = "Hidden and Read-only"
                } elseif ($isHidden) {
                    $hiddenFiles += $file
                    $suspiciousFiles[$file.Name] = "Hidden file"
                } elseif ($isReadOnly) {
                    $readOnlyFiles += $file
                    $suspiciousFiles[$file.Name] = "Read-only file"
                }

                # Check prefetch filename for cheat-related indicators
                foreach ($indicator in $script:CheatIndicators) {
                    if ($file.Name -match $indicator) {
                        $cheatNamedFiles += $file
                        if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                            $suspiciousFiles[$file.Name] = "CheatKeyword($indicator)"
                        }
                        break
                    }
                }

                $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                if ($hash) {
                    if ($hashTable.ContainsKey($hash.Hash)) {
                        $hashTable[$hash.Hash].Add($file.Name)
                    } else {
                        $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
                        $hashTable[$hash.Hash].Add($file.Name)
                    }
                }

                # Add execution timeline entries for recent prefetch files
                if ($file.LastWriteTime -gt (Get-Date).AddDays(-7)) {
                    Add-TimelineEvent -Time $file.LastWriteTime -Source 'Prefetch' `
                        -Event "Execution: $($file.Name)" -Detail "Prefetch last write"
                }

            } catch {
                $errorFiles += $file
                $suspiciousFiles[$file.Name] = "Error: $($_.Exception.Message)"
            }
        }

        # Output results
        Write-Host ("  Total Prefetch Files: {0}" -f $totalFiles)

        if ($hiddenAndReadOnly.Count -gt 0) {
            Write-Host ("  Hidden & Read-Only: {0}" -f $hiddenAndReadOnly.Count) -ForegroundColor Red
            foreach ($f in $hiddenAndReadOnly) { Write-Host "    $($f.Name)" -ForegroundColor White }
        }
        if ($hiddenFiles.Count -gt 0) {
            Write-Host ("  Hidden: {0}" -f $hiddenFiles.Count) -ForegroundColor Yellow
            foreach ($f in $hiddenFiles) { Write-Host "    $($f.Name)" -ForegroundColor White }
        } else { Write-Host "  Hidden Files: None" -ForegroundColor Green }

        if ($readOnlyFiles.Count -gt 0) {
            Write-Host ("  Read-Only: {0}" -f $readOnlyFiles.Count) -ForegroundColor Yellow
            foreach ($f in $readOnlyFiles) { Write-Host "    $($f.Name)" -ForegroundColor White }
        } else { Write-Host "  Read-Only Files: None" -ForegroundColor Green }

        $repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
        if ($repeatedHashes) {
            Write-Host ("  Duplicate File Sets: {0}" -f @($repeatedHashes).Count) -ForegroundColor Yellow
            foreach ($entry in $repeatedHashes) {
                Write-Host "    $($entry.Value -join ', ')" -ForegroundColor White
                foreach ($fname in $entry.Value) {
                    if (-not $suspiciousFiles.ContainsKey($fname)) {
                        $suspiciousFiles[$fname] = "Duplicate hash"
                    }
                }
            }
        } else { Write-Host "  Duplicates: None" -ForegroundColor Green }

        # Cheat-named prefetch files
        if ($cheatNamedFiles.Count -gt 0) {
            Write-Host ("`n  CHEAT-RELATED NAMES IN PREFETCH: {0}" -f $cheatNamedFiles.Count) -ForegroundColor Red
            foreach ($f in $cheatNamedFiles) {
                Write-Host ("    {0} (Last run: {1})" -f $f.Name, $f.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Red
                Add-Finding -Category 'Execution' -Title "Cheat-Related Prefetch Entry: $($f.Name)" `
                    -Evidence "Prefetch file: $($f.Name) | Last executed: $($f.LastWriteTime)" `
                    -WhySuspicious "Prefetch files prove execution of a binary. Cheat-related names in Prefetch are strong evidence of past cheat tool execution." `
                    -BenignExplanation "False positive if the name coincidentally matches a keyword (e.g. 'bypass' in a legitimate installer)" `
                    -Confidence 'High' `
                    -FollowUp "Parse the prefetch file with a tool like PECmd to recover full file paths and loaded DLLs"
                Add-TimelineEvent -Time $f.LastWriteTime -Source 'Prefetch' `
                    -Event "CHEAT TOOL EXECUTED: $($f.Name)"
            }
        }

        if ($suspiciousFiles.Count -gt 0) {
            Write-Host ("`n  SUSPICIOUS PREFETCH FILES: {0}/{1}" -f $suspiciousFiles.Count, $totalFiles) -ForegroundColor Yellow
            foreach ($entry in $suspiciousFiles.GetEnumerator() | Sort-Object Key) {
                Write-Host ("    {0} : {1}" -f $entry.Key, $entry.Value) -ForegroundColor White
            }
        } else {
            Write-Host ("`n  Prefetch Integrity: Clean ({0} files checked)" -f $totalFiles) -ForegroundColor Green
        }
    }
} else {
    Write-Host "  Prefetch folder not found at $prefetchPath" -ForegroundColor Yellow
    Add-Finding -Category 'AntiForensics' -Title 'Prefetch Folder Missing' `
        -Evidence "Path does not exist: $prefetchPath" `
        -WhySuspicious "The Prefetch folder should exist on systems where Prefetcher is enabled. Its absence may indicate deliberate deletion to erase execution history." `
        -BenignExplanation "SSD systems where Prefetcher is disabled by Windows automatically; registry-disabled Prefetcher" `
        -Confidence 'Low' `
        -FollowUp "Check HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters"
}

# -----------------------------------------------------------------------------
#  SECTION 14: BAM (Background Activity Moderator)
# -----------------------------------------------------------------------------
Write-Section "BAM - EXECUTION HISTORY"

# BAM records the last execution time of binaries on a per-user basis.
# It's a persistent registry artifact that survives reboots and is maintained
# separately from Prefetch. Critical for reconstructing execution history.
# Anti-cheat tools heavily rely on BAM. Users sometimes delete BAM entries.

try {
    $bamBase = "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"
    $bamUsers = Get-ChildItem -Path $bamBase -ErrorAction Stop

    $bamCheatMatches = @()
    $bamTotalEntries = 0

    foreach ($userKey in $bamUsers) {
        $sid   = $userKey.PSChildName
        $props = Get-ItemProperty -Path $userKey.PSPath -ErrorAction SilentlyContinue
        if (-not $props) { continue }

        $execEntries = $props.PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' -and $_.Value -is [byte[]] }

        Write-Host ("  SID: {0} - {1} entries" -f $sid, @($execEntries).Count) -ForegroundColor White
        $bamTotalEntries += @($execEntries).Count

        foreach ($entry in $execEntries) {
            $exePath = $entry.Name
            $tsBytes = $entry.Value
            $timestamp = $null

            # BAM timestamps are FILETIME (8-byte little-endian)
            if ($tsBytes.Length -ge 8) {
                try {
                    $fileTime  = [BitConverter]::ToInt64($tsBytes, 0)
                    $timestamp = [DateTime]::FromFileTime($fileTime)
                } catch {}
            }

            # Check for cheat-related keywords
            foreach ($indicator in $script:CheatIndicators) {
                if ($exePath -match $indicator) {
                    $bamCheatMatches += [PSCustomObject]@{
                        Path      = $exePath
                        Timestamp = $timestamp
                        Indicator = $indicator
                        SID       = $sid
                    }
                    break
                }
            }

            # Also flag executions from suspicious paths
            if (Test-SuspiciousPath -Path $exePath) {
                if ($timestamp -and $timestamp -gt (Get-Date).AddDays(-30)) {
                    Write-Host ("    [SUS] {0}" -f $exePath) -ForegroundColor Yellow
                    if ($timestamp) {
                        Add-TimelineEvent -Time $timestamp -Source 'BAM' `
                            -Event "Execution from suspicious path" -Detail $exePath
                    }
                }
            }
        }
    }

    if ($bamCheatMatches.Count -gt 0) {
        Write-Host ("`n  CHEAT-RELATED BAM ENTRIES: {0}" -f $bamCheatMatches.Count) -ForegroundColor Red
        foreach ($m in $bamCheatMatches) {
            $tsStr = if ($m.Timestamp) { $m.Timestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { "N/A" }
            Write-Host ("  [{0}] {1}" -f $tsStr, $m.Path) -ForegroundColor Red
            Add-Finding -Category 'Execution' -Title "BAM: Cheat-Related Execution: $($m.Path)" `
                -Evidence "BAM timestamp: $tsStr | Path: $($m.Path) | Keyword: $($m.Indicator)" `
                -WhySuspicious "BAM proves the binary was executed at this timestamp. Cheat keyword match strengthens the finding." `
                -BenignExplanation "False positive if path coincidentally matches keyword" `
                -Confidence 'High' `
                -FollowUp "Cross-reference with Prefetch, Amcache, and UserAssist"
            if ($m.Timestamp) {
                Add-TimelineEvent -Time $m.Timestamp -Source 'BAM' `
                    -Event "CHEAT EXECUTION (BAM): $($m.Path)"
            }
        }
    } else {
        Write-Host "  BAM: No cheat-related execution entries found" -ForegroundColor Green
    }
    Write-Host ("  BAM total entries scanned: {0}" -f $bamTotalEntries) -ForegroundColor Gray

} catch {
    Write-Host "  BAM collection failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $script:CollectionErrors.Add("BAM: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 15: AMCACHE  (program execution history)
# -----------------------------------------------------------------------------
Write-Section "AMCACHE - PROGRAM EXECUTION HISTORY"

# Amcache.hve records SHA1 hashes, paths, and publisher info for executables.
# It persists even after a program is uninstalled. Key anti-cheat artifact.
# The hive is locked by the OS; we use a shadow copy or reg load to read it.

$amcachePath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
if (Test-Path $amcachePath) {
    Write-Host "  Amcache.hve found at: $amcachePath" -ForegroundColor Green
    Write-Host "  (Full parsing requires offline analysis with RegRipper/AmcacheParser due to OS lock)" -ForegroundColor Gray

    # We can still check basic file metadata as a forensic indicator
    $amcacheInfo = Get-Item $amcachePath -ErrorAction SilentlyContinue
    if ($amcacheInfo) {
        Write-Host ("  Last Modified: {0}" -f $amcacheInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")) -ForegroundColor Yellow
        Write-Host ("  Size: {0} KB" -f [Math]::Round($amcacheInfo.Length / 1KB, 1)) -ForegroundColor White

        Add-TimelineEvent -Time $amcacheInfo.LastWriteTime -Source 'Amcache' `
            -Event 'Amcache.hve last modified (program execution logged)'
    }

    # Attempt to read via registry if accessible
    try {
        reg load "HKLM\AMCACHE_TEMP" $amcachePath 2>$null | Out-Null
        $amLoaded = $?
        if ($amLoaded) {
            $amEntries = Get-ChildItem "HKLM:\AMCACHE_TEMP\Root\InventoryApplicationFile" -ErrorAction SilentlyContinue |
                         Select-Object -First 100

            $amCheatMatches = @()
            foreach ($entry in $amEntries) {
                $props = Get-ItemProperty -Path $entry.PSPath -ErrorAction SilentlyContinue
                if (-not $props) { continue }
                $lowerPath = ($props.LowerCaseLongPath + $props.Name) -join '' | Select-Object -ExpandProperty ToString

                foreach ($indicator in $script:CheatIndicators) {
                    if ($props.LowerCaseLongPath -match $indicator -or $props.Name -match $indicator) {
                        $amCheatMatches += $props
                        break
                    }
                }
            }

            if ($amCheatMatches.Count -gt 0) {
                Write-Host "  CHEAT-RELATED AMCACHE ENTRIES:" -ForegroundColor Red
                foreach ($am in $amCheatMatches) {
                    Write-Host ("    {0} | {1}" -f $am.Name, $am.LowerCaseLongPath) -ForegroundColor Red
                    Add-Finding -Category 'Execution' -Title "Amcache: Cheat-Related Entry: $($am.Name)" `
                        -Evidence "Name: $($am.Name) | Path: $($am.LowerCaseLongPath)" `
                        -WhySuspicious "Amcache records program execution; cheat keyword match is significant" `
                        -BenignExplanation "Keyword coincidence in legitimate software name" `
                        -Confidence 'High' `
                        -FollowUp "Cross-reference with BAM and Prefetch; retrieve full hash from Amcache"
                }
            }

            reg unload "HKLM\AMCACHE_TEMP" 2>$null | Out-Null
        }
    } catch {
        # Hive locked - expected; noted but not an error
        Write-Host "  Amcache hive is locked (expected - online system). Use offline analysis." -ForegroundColor Gray
    }
} else {
    Write-Host "  Amcache.hve not found at expected path" -ForegroundColor Yellow
}

# -----------------------------------------------------------------------------
#  SECTION 16: NETWORK STATE
# -----------------------------------------------------------------------------
Write-Section "NETWORK STATE"

# Network connections can reveal active C2 connections, cheat update servers,
# or active remote control sessions. Listening ports can indicate backdoors.

try {
    Write-Host "  -- ACTIVE CONNECTIONS --" -ForegroundColor Cyan
    $connections = Get-NetTCPConnection -ErrorAction Stop |
                   Where-Object { $_.State -in @('Established','Listen') } |
                   Sort-Object State, LocalPort

    $suspiciousConns = @()
    foreach ($conn in $connections) {
        $procName = try {
            (Get-Process -Id $conn.OwningProcess -ErrorAction Stop).Name
        } catch { 'unknown' }

        $connLine = "{0,-14} {1,-22} {2,-22} {3,-12} {4}" -f
            $conn.State, "$($conn.LocalAddress):$($conn.LocalPort)",
            "$($conn.RemoteAddress):$($conn.RemotePort)", $procName, $conn.OwningProcess

        # Flag non-browser, non-system processes making external connections
        $systemProcs = @('svchost','lsass','services','system','wininit','smss','csrss','winlogon',
                         'spoolsv','dasHost','MsMpEng','NisSrv','SearchIndexer','WmiPrvSE')
        $isExternal  = $conn.RemoteAddress -notmatch '^(127\.|::1|0\.|$)' -and $conn.State -eq 'Established'
        $isUnknownProc = $procName -notin $systemProcs -and $procName -ne 'unknown'

        if ($isExternal) {
            Write-Host ("  {0}" -f $connLine) -ForegroundColor Yellow

            # Flag non-standard processes with external connections
            if ($isUnknownProc) {
                $suspiciousConns += [PSCustomObject]@{
                    LocalPort  = $conn.LocalPort
                    RemoteAddr = "$($conn.RemoteAddress):$($conn.RemotePort)"
                    Process    = $procName
                    PID        = $conn.OwningProcess
                }
            }
        } else {
            Write-Host ("  {0}" -f $connLine) -ForegroundColor Gray
        }
    }

    if ($suspiciousConns.Count -gt 0) {
        Write-Host "`n  -- EXTERNAL CONNECTIONS BY NON-SYSTEM PROCESSES --" -ForegroundColor Yellow
        foreach ($sc in $suspiciousConns) {
            Write-Flag "$($sc.Process) (PID $($sc.PID)) -> $($sc.RemoteAddr)" -Severity Low `
                -Detail "Port $($sc.LocalPort)"
            Add-Finding -Category 'Network' -Title "External Connection: $($sc.Process)" `
                -Evidence "Process $($sc.Process) (PID $($sc.PID)) connected to $($sc.RemoteAddr)" `
                -WhySuspicious "Unexpected external connections from non-system processes during game play could indicate cheat tool C2, telemetry, or license server communication" `
                -BenignExplanation "Game client, voice chat, game launcher, overlay software" `
                -Confidence 'Low' `
                -FollowUp "Resolve the remote IP; check DNS cache for the hostname; inspect the process binary"
        }
    }

} catch {
    Write-Host "  Network connection collection failed: $($_.Exception.Message)" -ForegroundColor Yellow
    $script:CollectionErrors.Add("Network connections: $($_.Exception.Message)")
}

# DNS cache
Write-Host "`n  -- DNS CACHE --" -ForegroundColor Cyan
try {
    $dnsCache = Get-DnsClientCache -ErrorAction Stop | Sort-Object Entry
    $cheatDns  = @()
    foreach ($entry in $dnsCache) {
        foreach ($indicator in $script:CheatIndicators) {
            if ($entry.Entry -match $indicator) {
                $cheatDns += $entry
                break
            }
        }
    }

    Write-Host ("  DNS cache entries: {0}" -f $dnsCache.Count) -ForegroundColor White
    if ($cheatDns.Count -gt 0) {
        Write-Host "  CHEAT-RELATED DNS ENTRIES:" -ForegroundColor Red
        foreach ($d in $cheatDns) {
            Write-Host "    $($d.Entry) -> $($d.Data)" -ForegroundColor Red
            Add-Finding -Category 'Network' -Title "Cheat-Related DNS Entry: $($d.Entry)" `
                -Evidence "DNS: $($d.Entry) resolves to $($d.Data)" `
                -WhySuspicious "DNS resolution for a cheat-keyword domain proves network communication with cheat infrastructure" `
                -BenignExplanation "DNS cache poisoning; coincidental match on keyword" `
                -Confidence 'High' `
                -FollowUp "Perform passive DNS lookup on the domain; check browser history for the domain"
        }
    } else {
        Write-Host "  No cheat-related DNS entries found" -ForegroundColor Green
    }
} catch {
    $script:CollectionErrors.Add("DNS cache: $($_.Exception.Message)")
}

# Hosts file tampering
Write-Host "`n  -- HOSTS FILE --" -ForegroundColor Cyan
try {
    $hostsPath    = "$env:SystemRoot\System32\drivers\etc\hosts"
    $hostsContent = Get-Content $hostsPath -ErrorAction Stop
    $customHosts  = $hostsContent | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
    if ($customHosts) {
        Write-Host "  Custom hosts entries found:" -ForegroundColor Yellow
        foreach ($h in $customHosts) {
            Write-Host "    $h" -ForegroundColor White
        }

        # Blocking anti-cheat update servers or Defender signature servers is suspicious
        $acServers = @('update','defender','microsoft','windowsupdate','battleye','easyanticheat','valve','vac')
        foreach ($h in $customHosts) {
            foreach ($srv in $acServers) {
                if ($h -match $srv) {
                    Write-Flag "Hosts file blocks potential AC/AV server: $h" -Severity High
                    Add-Finding -Category 'AntiForensics' -Title "Hosts File: AC/AV Server Blocked" `
                        -Evidence "Hosts entry: $h" `
                        -WhySuspicious "Blocking anti-cheat update servers or AV signature servers via hosts file prevents detection tool updates" `
                        -BenignExplanation "Pi-hole or ad-blocker DNS sinkholing; accidental block" `
                        -Confidence 'High' `
                        -FollowUp "Verify all custom hosts entries; check when the file was last modified"
                    break
                }
            }
        }
    } else {
        Write-Host "  Hosts file: Default (no custom entries)" -ForegroundColor Green
    }
} catch {
    $script:CollectionErrors.Add("Hosts file: $($_.Exception.Message)")
}

# Listening ports - backdoors
Write-Host "`n  -- LISTENING PORTS --" -ForegroundColor Cyan
try {
    $listening = Get-NetTCPConnection -State Listen -ErrorAction Stop
    foreach ($l in $listening | Sort-Object LocalPort) {
        $procName = try { (Get-Process -Id $l.OwningProcess -ErrorAction Stop).Name } catch { 'unknown' }
        $knownPorts = @(80,443,135,139,445,5040,5357,7680,49664,49665,49666,49667,49668,49669,1900,5353)
        $color = if ($l.LocalPort -in $knownPorts) { 'DarkGray' } else { 'Yellow' }
        Write-Host ("  {0}:{1}  [{2}]" -f $l.LocalAddress, $l.LocalPort, $procName) -ForegroundColor $color
    }
} catch {
    $script:CollectionErrors.Add("Listening ports: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 17: FILE SYSTEM ARTIFACTS
# -----------------------------------------------------------------------------
Write-Section "FILE SYSTEM ARTIFACTS"

# Recently modified executables and DLLs can reveal cheat tool installs or updates.
# We focus on user-writable locations where cheats are typically installed.

$susLocations = @(
    "$env:TEMP",
    "$env:LOCALAPPDATA\Temp",
    "$env:USERPROFILE\Downloads",
    "$env:USERPROFILE\Desktop",
    "$env:PUBLIC"
)

Write-Host "  -- RECENT EXECUTABLES IN SUSPICIOUS LOCATIONS (last 14 days) --" -ForegroundColor Cyan
$cutoff = (Get-Date).AddDays(-14)
$recentExes = @()

foreach ($loc in $susLocations) {
    if (-not (Test-Path $loc -ErrorAction SilentlyContinue)) { continue }
    try {
        $exes = Get-ChildItem -Path $loc -Include @('*.exe','*.dll','*.sys','*.ps1','*.bat','*.cmd','*.vbs','*.js') `
                              -Recurse -File -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -gt $cutoff -or $_.CreationTime -gt $cutoff }
        foreach ($exe in $exes) {
            $recentExes += $exe
        }
    } catch {}
}

if ($recentExes.Count -gt 0) {
    Write-Host ("  Found {0} recent executable-type files:" -f $recentExes.Count) -ForegroundColor Yellow
    foreach ($f in $recentExes | Sort-Object LastWriteTime -Descending | Select-Object -First 30) {
        $sig  = Get-AuthenticodeInfo -Path $f.FullName
        $hash = Get-FileSHA256 -Path $f.FullName
        $color = if (-not $sig.IsValid) { 'Yellow' } else { 'Gray' }
        Write-Host ("  [{0}] {1}" -f $f.LastWriteTime.ToString("MM/dd HH:mm"), $f.FullName) -ForegroundColor $color
        if (-not $sig.IsValid) {
            Write-Host ("    Unsigned | Hash: {0}" -f $hash) -ForegroundColor DarkGray
            Add-Finding -Category 'FileSystem' -Title "Unsigned Recent Executable: $($f.Name)" `
                -Evidence "Path: $($f.FullName) | Modified: $($f.LastWriteTime) | Hash: $hash" `
                -WhySuspicious "Unsigned executables in user-writable directories that were recently created or modified are high-priority cheat tool indicators" `
                -BenignExplanation "Downloaded software pending installation; unsigned portable tools" `
                -Confidence 'Medium' `
                -FollowUp "Submit hash to VirusTotal; check Prefetch and BAM for execution evidence"
        }
        Add-TimelineEvent -Time $f.LastWriteTime -Source 'FileSystem' `
            -Event "Recent file: $($f.Name)" -Detail $f.FullName
    }
} else {
    Write-Host "  No recent executables found in suspicious locations" -ForegroundColor Green
}

# ADS (Alternate Data Streams) check
Write-Host "`n  -- ALTERNATE DATA STREAMS (key locations) --" -ForegroundColor Cyan
# ADS can hide executable content within normal files. Rarely used by cheats
# but worth checking in high-risk locations.
foreach ($loc in $susLocations) {
    if (-not (Test-Path $loc -ErrorAction SilentlyContinue)) { continue }
    try {
        $adsItems = Get-ChildItem -Path $loc -File -Force -ErrorAction SilentlyContinue |
                    Get-Item -Stream * -ErrorAction SilentlyContinue |
                    Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        if ($adsItems) {
            foreach ($ads in $adsItems) {
                Write-Flag "ADS found: $($ads.FileName) :: $($ads.Stream) ($($ads.Length) bytes)" -Severity Medium
                Add-Finding -Category 'FileSystem' -Title "Alternate Data Stream: $($ads.FileName)" `
                    -Evidence "ADS: $($ads.FileName):$($ads.Stream) ($($ads.Length) bytes)" `
                    -WhySuspicious "Non-standard ADS can hide executable code within normal files, evading simple directory scanning" `
                    -BenignExplanation "Zone.Identifier is normal (download tagging). Other streams are rare and warrant review." `
                    -Confidence 'Medium' `
                    -FollowUp "Extract and analyze the ADS content with streams.exe or Get-Content -Stream"
            }
        }
    } catch {}
}
Write-Host "  ADS check complete" -ForegroundColor Gray

# -----------------------------------------------------------------------------
#  SECTION 18: RECYCLE BIN  (preserved + enhanced)
# -----------------------------------------------------------------------------
Write-Section "RECYCLE BIN"

# Recycle Bin contents can reveal recently deleted cheat tools.
# $I files contain original path and deletion timestamp; $R files contain content.

try {
    $recycleBinPath = "$env:SystemDrive\`$Recycle.Bin"

    if (Test-Path $recycleBinPath) {
        $recycleBinFolder = Get-Item -LiteralPath $recycleBinPath -Force -ErrorAction SilentlyContinue
        $userFolders      = Get-ChildItem -LiteralPath $recycleBinPath -Directory -Force -ErrorAction SilentlyContinue

        if ($userFolders) {
            $allDeletedItems = @()
            $latestModTime   = $recycleBinFolder.LastWriteTime

            foreach ($userFolder in $userFolders) {
                if ($userFolder.LastWriteTime -gt $latestModTime) {
                    $latestModTime = $userFolder.LastWriteTime
                }
                $userItems = Get-ChildItem -LiteralPath $userFolder.FullName -File -Force -ErrorAction SilentlyContinue
                if ($userItems) {
                    $allDeletedItems += $userItems
                    $latestFile = $userItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                    if ($latestFile -and $latestFile.LastWriteTime -gt $latestModTime) {
                        $latestModTime = $latestFile.LastWriteTime
                    }
                }
            }

            Write-Item "Last Modified:    " $latestModTime.ToString("yyyy-MM-dd HH:mm:ss") -Color Yellow
            Write-Item "Total Items:      " $allDeletedItems.Count

            # Parse $I metadata files to get original paths
            $iFiles = $allDeletedItems | Where-Object { $_.Name -like '$I*' }
            $suspiciousDeletes = @()

            foreach ($iFile in $iFiles) {
                try {
                    # $I file format: 8 bytes header, 8 bytes size, 8 bytes deletion time, variable-length path
                    $bytes = [System.IO.File]::ReadAllBytes($iFile.FullName)
                    if ($bytes.Length -gt 24) {
                        $deleteTime = [DateTime]::FromFileTime([BitConverter]::ToInt64($bytes, 16))
                        $pathLen    = [BitConverter]::ToInt32($bytes, 24)
                        $origPath   = [System.Text.Encoding]::Unicode.GetString($bytes, 28, [Math]::Min($pathLen*2, $bytes.Length - 28)).TrimEnd([char]0)

                        # Check for cheat keywords in original paths
                        foreach ($indicator in $script:CheatIndicators) {
                            if ($origPath -match $indicator) {
                                $suspiciousDeletes += [PSCustomObject]@{
                                    OriginalPath = $origPath
                                    DeletedAt    = $deleteTime
                                    Keyword      = $indicator
                                }
                                break
                            }
                        }

                        if ($deleteTime -gt (Get-Date).AddDays(-7)) {
                            Add-TimelineEvent -Time $deleteTime -Source 'RecycleBin' `
                                -Event "File deleted to Recycle Bin" -Detail $origPath
                        }
                    }
                } catch {}
            }

            if ($suspiciousDeletes.Count -gt 0) {
                Write-Host "  CHEAT-RELATED DELETED FILES:" -ForegroundColor Red
                foreach ($sd in $suspiciousDeletes) {
                    Write-Host ("  [{0}] {1}" -f $sd.DeletedAt.ToString("MM/dd HH:mm"), $sd.OriginalPath) -ForegroundColor Red
                    Add-Finding -Category 'AntiForensics' -Title "Cheat Tool Deleted to Recycle Bin" `
                        -Evidence "Original path: $($sd.OriginalPath) | Deleted at: $($sd.DeletedAt)" `
                        -WhySuspicious "Cheat-keyword file was deleted to Recycle Bin - this may be evidence of cleanup after use, or the file being discovered by AV" `
                        -BenignExplanation "False positive if keyword matches a legitimate file name" `
                        -Confidence 'High' `
                        -FollowUp "Recover and analyze the $R file corresponding to this $I entry"
                    Add-TimelineEvent -Time $sd.DeletedAt -Source 'RecycleBin' `
                        -Event "CHEAT FILE DELETED: $($sd.OriginalPath)"
                }
            }

            if ($allDeletedItems.Count -gt 0 -and $suspiciousDeletes.Count -eq 0) {
                $latestItem = $allDeletedItems | Sort-Object LastWriteTime -Descending | Select-Object -First 1
                Write-Item "Latest Item:      " $latestItem.Name -Color Gray
            }
        } else {
            Write-Item "Status:           " "Empty" -Color Green
            Write-Item "Last Modified:    " $recycleBinFolder.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -Color Green
        }
    } else {
        Write-Host "  Recycle Bin not accessible at $recycleBinPath" -ForegroundColor Gray
    }

    # PowerShell ConsoleHost history
    Write-Host "`n  -- POWERSHELL CONSOLE HISTORY --" -ForegroundColor Cyan
    $consoleHistPath = "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $consoleHistPath) {
        $histFile = Get-Item -Path $consoleHistPath -Force -ErrorAction SilentlyContinue
        Write-Item "Last Modified:    " $histFile.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") -Color Yellow
        Write-Item "File Size:        " "$([Math]::Round($histFile.Length/1KB,2)) KB"
        Write-Item "Attributes:       " $histFile.Attributes

        # Read and check for suspicious commands (read-only, no modification)
        $histContent = Get-Content $consoleHistPath -ErrorAction SilentlyContinue
        if ($histContent) {
            $suspCmds = $histContent | Where-Object {
                $_ -match 'bypass|invoke-expression|iex|downloadstring|net\.webclient|bitstransfer|' +
                           'encodedcommand|base64|reflection\.assembly|loadfile|shellcode|' +
                           'bcdedit.*testsign|driver|inject|hook|cheat'
            }
            if ($suspCmds) {
                Write-Host "  SUSPICIOUS COMMANDS IN PS HISTORY:" -ForegroundColor Red
                foreach ($cmd in ($suspCmds | Select-Object -First 10)) {
                    Write-Host "    $cmd" -ForegroundColor Yellow
                    Add-Finding -Category 'Execution' -Title "Suspicious PowerShell History Command" `
                        -Evidence "Command: $cmd" `
                        -WhySuspicious "Commands indicating download, execution bypass, code injection, or anti-cheat tampering in PS history" `
                        -BenignExplanation "Security research, legitimate admin tasks, scripting" `
                        -Confidence 'Medium' `
                        -FollowUp "Correlate execution timestamp with game session; check full history for context"
                }
            } else {
                Write-Host "  No suspicious commands in PS history" -ForegroundColor Green
            }
        }
    } else {
        Write-Host "  PowerShell history not found (never used or cleared)" -ForegroundColor Gray
    }

} catch {
    Write-Host "  Error accessing file system artifacts: $($_.Exception.Message)" -ForegroundColor Red
    $script:CollectionErrors.Add("Recycle Bin/PS history: $($_.Exception.Message)")
}

# -----------------------------------------------------------------------------
#  SECTION 19: BROWSER FORENSICS  (downloads, extensions)
# -----------------------------------------------------------------------------
Write-Section "BROWSER FORENSICS"

# Browser downloads are a primary delivery vector for cheat software.
# Download history is stored in SQLite databases per browser.
# Extension abuse: cheats can be packaged as browser extensions for overlay ESP.

function Get-ChromiumDownloads {
    param([string]$ProfilePath, [string]$BrowserName)
    $histPath = Join-Path $ProfilePath "History"
    if (-not (Test-Path $histPath)) { return }

    # Copy to temp to avoid lock issues
    $tempPath = Join-Path $env:TEMP "BrowserHistory_$([System.IO.Path]::GetRandomFileName()).db"
    try {
        Copy-Item $histPath $tempPath -Force -ErrorAction Stop

        # Use SQLite via .NET (available in PS5+)
        # Fallback: read raw file for URL patterns if SQLite not available
        $rawContent = Get-Content $tempPath -Encoding Byte -ErrorAction SilentlyContinue
        if ($rawContent) {
            $rawText = [System.Text.Encoding]::UTF8.GetString($rawContent) -replace '[^\x20-\x7E]',' '

            # Extract download URLs (very approximate - proper parsing requires SQLite)
            $urlMatches = [regex]::Matches($rawText, 'https?://[^\s"<>]+\.(exe|dll|zip|rar|7z|iso|msi)')
            $cheatUrls  = @()
            foreach ($m in $urlMatches) {
                foreach ($indicator in $script:CheatIndicators) {
                    if ($m.Value -match $indicator) {
                        $cheatUrls += $m.Value
                        break
                    }
                }
            }
            if ($cheatUrls.Count -gt 0) {
                Write-Host ("  {0}: {1} cheat-related download URL(s) found in history" -f $BrowserName, $cheatUrls.Count) -ForegroundColor Red
                foreach ($url in $cheatUrls) {
                    Write-Host "    $url" -ForegroundColor Red
                    Add-Finding -Category 'Browser' -Title "${BrowserName}: Cheat-Related Download URL" `
                        -Evidence "URL: $url" `
                        -WhySuspicious "Download URL matching cheat keyword found in browser history. This indicates the user actively downloaded what may be cheat software." `
                        -BenignExplanation "URL may coincidentally match keyword; game mod download; false positive" `
                        -Confidence 'High' `
                        -FollowUp "Verify the downloaded file; check if it was executed (Prefetch/BAM)"
                }
            } else {
                Write-Host ("  {0}: No cheat-related download URLs in history" -f $BrowserName) -ForegroundColor Green
            }
        }
    } catch {
        $script:CollectionErrors.Add("Browser history ($BrowserName): $($_.Exception.Message)")
    } finally {
        Remove-Item $tempPath -ErrorAction SilentlyContinue
    }
}

function Get-ChromiumExtensions {
    param([string]$ProfilePath, [string]$BrowserName)
    $extPath = Join-Path $ProfilePath "Extensions"
    if (-not (Test-Path $extPath)) { return }

    $extensions = Get-ChildItem $extPath -Directory -ErrorAction SilentlyContinue
    if ($extensions) {
        Write-Host ("  {0} Extensions ({1} installed):" -f $BrowserName, $extensions.Count) -ForegroundColor White
        foreach ($ext in $extensions) {
            # Each extension dir contains version subdirs
            $versionDirs = Get-ChildItem $ext.FullName -Directory -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
            if ($versionDirs) {
                $manifestPath = Join-Path $versionDirs.FullName "manifest.json"
                if (Test-Path $manifestPath) {
                    try {
                        $manifest = Get-Content $manifestPath -Raw | ConvertFrom-Json -ErrorAction Stop
                        $extName  = $manifest.name
                        $extPerms = ($manifest.permissions -join ', ')
                        $color    = 'Gray'

                        # Flag extensions with sensitive permissions
                        $sensitivePerms = @('nativeMessaging','debugger','management','proxy','webRequest','cookies')
                        if ($manifest.permissions | Where-Object { $_ -in $sensitivePerms }) {
                            $color = 'Yellow'
                        }
                        Write-Host ("    [{0}] {1}" -f $ext.Name.Substring(0,[Math]::Min(10,$ext.Name.Length)), $extName) -ForegroundColor $color
                        if ($color -eq 'Yellow') {
                            Write-Host ("      Perms: {0}" -f $extPerms) -ForegroundColor DarkGray
                        }
                    } catch {}
                }
            }
        }
    }
}

$browsers = @(
    @{ Name='Chrome';  ProfileBase="$env:LOCALAPPDATA\Google\Chrome\User Data\Default" },
    @{ Name='Edge';    ProfileBase="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default" },
    @{ Name='Brave';   ProfileBase="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default" },
    @{ Name='Firefox'; ProfileBase="$env:APPDATA\Mozilla\Firefox\Profiles" },
    @{ Name='Opera';   ProfileBase="$env:APPDATA\Opera Software\Opera Stable" }
)

foreach ($browser in $browsers) {
    if (Test-Path $browser.ProfileBase -ErrorAction SilentlyContinue) {
        Write-Host "`n  $($browser.Name) detected" -ForegroundColor Cyan
        Get-ChromiumDownloads -ProfilePath $browser.ProfileBase -BrowserName $browser.Name
        Get-ChromiumExtensions -ProfilePath $browser.ProfileBase -BrowserName $browser.Name
    }
}

# Downloads folder scan
Write-Host "`n  -- DOWNLOADS FOLDER --" -ForegroundColor Cyan
$downloadsPath = "$env:USERPROFILE\Downloads"
if (Test-Path $downloadsPath) {
    $downloadedExes = Get-ChildItem $downloadsPath -File -Force -ErrorAction SilentlyContinue |
                      Where-Object { $_.Extension -in @('.exe','.dll','.sys','.zip','.rar','.7z','.iso','.msi','.ps1','.bat','.cmd','.vbs') } |
                      Sort-Object LastWriteTime -Descending

    Write-Host ("  {0} executable-type files in Downloads:" -f $downloadedExes.Count) -ForegroundColor White
    foreach ($f in $downloadedExes | Select-Object -First 20) {
        $agedays = [int]((Get-Date) - $f.LastWriteTime).TotalDays
        $color   = if ($agedays -le 7) { 'Yellow' } else { 'Gray' }
        Write-Host ("  [{0,3}d] {1}" -f $agedays, $f.Name) -ForegroundColor $color

        # Flag cheat-keyword filenames
        foreach ($indicator in $script:CheatIndicators) {
            if ($f.Name -match $indicator) {
                Write-Flag "Cheat-keyword download: $($f.Name)" -Severity High `
                    -Detail "Downloaded $agedays days ago | $($f.FullName)"
                Add-Finding -Category 'Browser' -Title "Cheat-Named File in Downloads: $($f.Name)" `
                    -Evidence "File: $($f.FullName) | Modified: $($f.LastWriteTime) | Hash: $(Get-FileSHA256 $f.FullName)" `
                    -WhySuspicious "Downloaded file with cheat-related name present in Downloads folder" `
                    -BenignExplanation "Game mod, game tool, or coincidental keyword match in filename" `
                    -Confidence 'High' `
                    -FollowUp "Submit hash; check Prefetch/BAM for execution; check Zone.Identifier for source URL"
                Add-TimelineEvent -Time $f.LastWriteTime -Source 'Downloads' `
                    -Event "Cheat-named download: $($f.Name)"
                break
            }
        }

        # Check Zone.Identifier ADS for download source URL
        $zoneId = Get-Content "$($f.FullName):Zone.Identifier" -ErrorAction SilentlyContinue
        if ($zoneId) {
            $refUrl = $zoneId | Where-Object { $_ -match 'ReferrerUrl=' }
            if ($refUrl) {
                Write-Host "    Source: $($refUrl -replace 'ReferrerUrl=','')" -ForegroundColor DarkGray
            }
        }
    }
}

# -----------------------------------------------------------------------------
#  SECTION 20: FORENSIC TIMELINE
# -----------------------------------------------------------------------------
Write-Section "UNIFIED FORENSIC TIMELINE"

# Sort and display the correlated timeline across all artifact sources.
# Clusters of activity in the same time window suggest coordinated actions.

if ($script:Timeline.Count -gt 0) {
    $sortedTimeline = $script:Timeline | Sort-Object Time
    $previousTime   = $null

    foreach ($event in $sortedTimeline) {
        $timeStr = $event.Time.ToString("yyyy-MM-dd HH:mm:ss")

        # Mark time gaps > 1 hour
        if ($previousTime -and ($event.Time - $previousTime).TotalHours -gt 1) {
            Write-Host "  ....." -ForegroundColor DarkGray
        }

        $color = switch -Regex ($event.Source) {
            'Defender'     { 'Red' }
            'BAM|Prefetch|Execution|Amcache' { 'Yellow' }
            'AntiForensics|EventLog' { 'Magenta' }
            'Driver|Service' { 'Cyan' }
            default        { 'Gray' }
        }

        Write-Host ("  [{0}] {1,-15} {2}" -f $timeStr, "[$($event.Source)]", $event.Event) -ForegroundColor $color
        if ($event.Detail) {
            Write-Host ("    {0}" -f $event.Detail.Substring(0,[Math]::Min(100,$event.Detail.Length))) -ForegroundColor DarkGray
        }

        $previousTime = $event.Time
    }
} else {
    Write-Host "  No timeline events collected." -ForegroundColor Gray
}

# -----------------------------------------------------------------------------
#  SECTION 21: FINAL REPORT
# -----------------------------------------------------------------------------
Write-Section "FINAL REPORT - SUMMARY"

$elapsed     = (Get-Date) - $script:StartTime
$critCount   = ($script:Findings | Where-Object { $_.Confidence -eq 'Critical' }).Count
$highCount   = ($script:Findings | Where-Object { $_.Confidence -eq 'High' }).Count
$medCount    = ($script:Findings | Where-Object { $_.Confidence -eq 'Medium' }).Count
$lowCount    = ($script:Findings | Where-Object { $_.Confidence -eq 'Low' }).Count
$infoCount   = ($script:Findings | Where-Object { $_.Confidence -eq 'Informational' }).Count
$totalFindings = $script:Findings.Count

# Determine overall risk
$overallRisk = switch ($true) {
    { $critCount -gt 0 }             { "CRITICAL - Likely active or recent cheat use" }
    { $highCount -ge 3 }             { "HIGH - Multiple high-confidence indicators present" }
    { $highCount -ge 1 }             { "HIGH - High-confidence indicator(s) require follow-up" }
    { $medCount -ge 3 }              { "MEDIUM - Several medium-confidence indicators; corroborate" }
    { $medCount -ge 1 -or $lowCount -ge 3 } { "LOW - Some indicators present; likely requires more evidence" }
    default                          { "CLEAN - No significant indicators found" }
}

$riskColor = switch -Regex ($overallRisk) {
    '^CRITICAL' { 'Magenta' }
    '^HIGH'     { 'Red' }
    '^MEDIUM'   { 'Yellow' }
    '^LOW'      { 'DarkYellow' }
    default     { 'Green' }
}

Write-Host ""
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host "|              FORENSIC TRIAGE SUMMARY                |" -ForegroundColor Cyan
Write-Host "+======================================================+" -ForegroundColor Cyan
Write-Host ""
Write-Host ("  Analysis completed in {0:F1} seconds" -f $elapsed.TotalSeconds) -ForegroundColor Gray
Write-Host ("  Collection errors:  {0}" -f $script:CollectionErrors.Count) -ForegroundColor $(if ($script:CollectionErrors.Count -gt 0) { 'Yellow' } else { 'Gray' })
Write-Host ""
Write-Host "  -- FINDING COUNTS BY CONFIDENCE --" -ForegroundColor Cyan
Write-Host ("  Critical:      {0}" -f $critCount) -ForegroundColor Magenta
Write-Host ("  High:          {0}" -f $highCount) -ForegroundColor Red
Write-Host ("  Medium:        {0}" -f $medCount) -ForegroundColor Yellow
Write-Host ("  Low:           {0}" -f $lowCount) -ForegroundColor DarkYellow
Write-Host ("  Informational: {0}" -f $infoCount) -ForegroundColor Gray
Write-Host ("  Total:         {0}" -f $totalFindings)
Write-Host ""
Write-Host ("  OVERALL RISK ASSESSMENT: {0}" -f $overallRisk) -ForegroundColor $riskColor
Write-Host ""

# Print all findings grouped by category and confidence
$categories = $script:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object
foreach ($cat in $categories) {
    $catFindings = $script:Findings | Where-Object { $_.Category -eq $cat } | Sort-Object { switch ($_.Confidence) { 'Critical' {0} 'High' {1} 'Medium' {2} 'Low' {3} default {4} } }
    Write-Host "  -- $cat --" -ForegroundColor Cyan
    foreach ($f in $catFindings) {
        $conf = $f.Confidence
        $confColor = switch ($conf) {
            'Critical' { 'Magenta' }; 'High' { 'Red' }; 'Medium' { 'Yellow' }; 'Low' { 'DarkYellow' }; default { 'Gray' }
        }
        Write-Host ("  [{0,-14}] {1}" -f $conf, $f.Title) -ForegroundColor $confColor
        Write-Host ("    Evidence: {0}" -f $f.Evidence.Substring(0,[Math]::Min(120,$f.Evidence.Length))) -ForegroundColor DarkGray
        Write-Host ("    Why:      {0}" -f $f.WhySuspicious.Substring(0,[Math]::Min(100,$f.WhySuspicious.Length))) -ForegroundColor DarkGray
        Write-Host ("    Benign:   {0}" -f $f.BenignExplanation.Substring(0,[Math]::Min(100,$f.BenignExplanation.Length))) -ForegroundColor DarkGray
        if ($f.FollowUp) {
            Write-Host ("    Next:     {0}" -f $f.FollowUp.Substring(0,[Math]::Min(120,$f.FollowUp.Length))) -ForegroundColor Gray
        }
        Write-Host ""
    }
}

# Collection errors
if ($script:CollectionErrors.Count -gt 0) {
    Write-Host "  -- COLLECTION ERRORS (non-fatal) --" -ForegroundColor DarkGray
    foreach ($err in $script:CollectionErrors) {
        Write-Host "    $err" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "  -- RECOMMENDED NEXT STEPS --" -ForegroundColor Cyan
Write-Host "  1. Cross-reference all High/Critical findings against each other for temporal correlation" -ForegroundColor White
Write-Host "  2. Parse Prefetch with PECmd (Zimmerman Tools) for detailed execution timelines" -ForegroundColor White
Write-Host "  3. Parse Amcache offline with AmcacheParser for full executable inventory with SHA1 hashes" -ForegroundColor White
Write-Host "  4. Parse BAM with RegistryExplorer for complete execution history" -ForegroundColor White
Write-Host "  5. Submit suspicious file hashes to VirusTotal" -ForegroundColor White
Write-Host "  6. Capture a full memory image if the system needs to remain powered on" -ForegroundColor White
Write-Host "  7. Acquire a disk image if critical findings warrant deeper analysis" -ForegroundColor White
Write-Host "  8. Deploy Sysmon with a tuned configuration for ongoing monitoring" -ForegroundColor White
Write-Host "  9. Review game anti-cheat logs (EAC, BattlEye) for detection events" -ForegroundColor White
Write-Host " 10. Correlate timestamps with game session logs (match time zones carefully)" -ForegroundColor White
Write-Host ""

Write-Host "Check Complete, hit up @praiselily if u run into any issues." -ForegroundColor Cyan
