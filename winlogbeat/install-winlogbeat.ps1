#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Downloads, installs, configures, and starts WinLogBeat on the Windows DC.
    Also applies all audit policies and registry settings required to generate
    the Security/AD event IDs collected by winlogbeat.yml.

.USAGE
    Set-ExecutionPolicy Bypass -Scope Process -Force
    .\install-winlogbeat.ps1

    # Override defaults:
    .\install-winlogbeat.ps1 -LogstashHost "192.168.68.61" -LogstashPort 5044
#>

param(
    [string]$LogstashHost      = "192.168.68.61",
    [int]   $LogstashPort      = 5044,
    [string]$WinLogBeatVersion = "8.17.0",
    [string]$InstallDir        = "C:\Program Files\winlogbeat"
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"

Write-Host ""
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host "  WinLogBeat Installer - target: ${LogstashHost}:${LogstashPort}" -ForegroundColor Cyan
Write-Host "===========================================================" -ForegroundColor Cyan
Write-Host ""

# =============================================================================
# STEP 1 - Download and extract WinLogBeat
# =============================================================================
$zipName = "winlogbeat-$WinLogBeatVersion-windows-x86_64.zip"
$zipUrl  = "https://artifacts.elastic.co/downloads/beats/winlogbeat/$zipName"
$zipPath = "$env:TEMP\$zipName"

if (-not (Test-Path "$InstallDir\winlogbeat.exe")) {
    Write-Host "[1/5] Downloading WinLogBeat $WinLogBeatVersion ..."
    Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath -UseBasicParsing

    Write-Host "[1/5] Extracting to $InstallDir ..."
    $extractDir = "$env:TEMP\winlogbeat-extract"
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extractDir -Force
    $extracted = Get-ChildItem $extractDir | Select-Object -First 1
    if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
    Move-Item $extracted.FullName $InstallDir
    Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host "[1/5] WinLogBeat extracted." -ForegroundColor Green
} else {
    Write-Host "[1/5] WinLogBeat already present at $InstallDir - skipping download."
}

# =============================================================================
# STEP 2 - Deploy winlogbeat.yml config
# =============================================================================
Write-Host "[2/5] Deploying winlogbeat.yml ..."
$configSrc = Join-Path $PSScriptRoot "winlogbeat.yml"
$configDst = Join-Path $InstallDir  "winlogbeat.yml"

if (Test-Path $configSrc) {
    $cfg = Get-Content $configSrc -Raw
    $cfg = $cfg -replace '192\.168\.68\.61', $LogstashHost
    $cfg = $cfg -replace '5044',             $LogstashPort
    Set-Content -Path $configDst -Value $cfg -Encoding UTF8
    Write-Host "[2/5] Config written to $configDst" -ForegroundColor Green
} else {
    Write-Warning "[2/5] winlogbeat.yml not found beside installer - using bundled default."
}

# =============================================================================
# STEP 3 - Apply audit policies (auditpol)
# Required so the Security event IDs in winlogbeat.yml actually get logged.
# =============================================================================
Write-Host "[3/5] Applying Windows audit policies ..."

$policies = @(
    # Category                                       Sub-category                          Success  Failure
    # ---- Logon / Logoff ----------------------------------------------------------------
    @("Logon/Logoff", "Logon",                                           "enable", "enable"),
    @("Logon/Logoff", "Logoff",                                          "enable", "disable"),
    @("Logon/Logoff", "Account Lockout",                                 "enable", "disable"),
    @("Logon/Logoff", "Special Logon",                                   "enable", "disable"),
    @("Logon/Logoff", "Other Logon/Logoff Events",                       "enable", "enable"),
    @("Logon/Logoff", "Network Policy Server",                           "enable", "enable"),
    # ---- Account Management ------------------------------------------------------------
    @("Account Management", "User Account Management",                   "enable", "enable"),
    @("Account Management", "Computer Account Management",               "enable", "enable"),
    @("Account Management", "Security Group Management",                 "enable", "enable"),
    @("Account Management", "Distribution Group Management",             "enable", "enable"),
    @("Account Management", "Application Group Management",              "enable", "enable"),
    @("Account Management", "Other Account Management Events",           "enable", "enable"),
    # ---- Account Logon -----------------------------------------------------------------
    @("Account Logon", "Credential Validation",                          "enable", "enable"),
    @("Account Logon", "Kerberos Service Ticket Operations",             "enable", "enable"),
    @("Account Logon", "Kerberos Authentication Service",                "enable", "enable"),
    @("Account Logon", "Other Account Logon Events",                     "enable", "enable"),
    # ---- DS Access (AD replication, DCSync) --------------------------------------------
    @("DS Access", "Directory Service Access",                           "enable", "enable"),
    @("DS Access", "Directory Service Changes",                          "enable", "enable"),
    @("DS Access", "Directory Service Replication",                      "enable", "enable"),
    @("DS Access", "Detailed Directory Service Replication",             "enable", "enable"),
    # ---- Object Access -----------------------------------------------------------------
    @("Object Access", "File System",                                    "enable", "enable"),
    @("Object Access", "Registry",                                       "enable", "enable"),
    @("Object Access", "Kernel Object",                                  "enable", "disable"),
    @("Object Access", "SAM",                                            "enable", "enable"),
    @("Object Access", "Certification Services",                         "enable", "enable"),
    @("Object Access", "Other Object Access Events",                     "enable", "enable"),
    # ---- Policy Change -----------------------------------------------------------------
    @("Policy Change", "Audit Policy Change",                            "enable", "enable"),
    @("Policy Change", "Authentication Policy Change",                   "enable", "enable"),
    @("Policy Change", "Authorization Policy Change",                    "enable", "enable"),
    @("Policy Change", "MPSSVC Rule-Level Policy Change",                "enable", "enable"),
    @("Policy Change", "Filtering Platform Policy Change",               "enable", "enable"),
    @("Policy Change", "Other Policy Change Events",                     "enable", "enable"),
    # ---- Privilege Use -----------------------------------------------------------------
    @("Privilege Use", "Sensitive Privilege Use",                        "enable", "enable"),
    @("Privilege Use", "Non Sensitive Privilege Use",                    "disable", "disable"),
    # ---- Process Tracking (4688 process creation) -------------------------------------
    @("Detailed Tracking", "Process Creation",                           "enable", "disable"),
    @("Detailed Tracking", "Process Termination",                        "enable", "disable"),
    @("Detailed Tracking", "DPAPI Activity",                             "enable", "enable"),
    @("Detailed Tracking", "Token Right Adjusted Events",                "enable", "enable"),
    # ---- System Events -----------------------------------------------------------------
    @("System", "Security State Change",                                 "enable", "enable"),
    @("System", "Security System Extension",                             "enable", "enable"),
    @("System", "System Integrity",                                      "enable", "enable"),
    @("System", "IPsec Driver",                                          "enable", "enable"),
    @("System", "Other System Events",                                   "enable", "enable")
)

foreach ($p in $policies) {
    $cat  = $p[0]
    $sub  = $p[1]
    $succ = $p[2]
    $fail = $p[3]
    auditpol /set /subcategory:"$sub" /success:$succ /failure:$fail | Out-Null
}
Write-Host "[3/5] Audit policies applied." -ForegroundColor Green

# =============================================================================
# STEP 4 - Additional Group Policy / registry settings
# =============================================================================
Write-Host "[4/5] Configuring additional security settings ..."

# 4a. Process creation command line in 4688 events
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord

# 4b. PowerShell Script Block Logging (fires 4104 for every script block)
$psLogPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
if (-not (Test-Path $psLogPath)) { New-Item -Path $psLogPath -Force | Out-Null }
Set-ItemProperty -Path $psLogPath -Name "EnableScriptBlockLogging" -Value 1 -Type DWord

# 4c. PowerShell Module Logging (fires 4103 for every module/command)
$psModPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
if (-not (Test-Path $psModPath)) { New-Item -Path $psModPath -Force | Out-Null }
Set-ItemProperty -Path $psModPath -Name "EnableModuleLogging" -Value 1 -Type DWord

# 4d. Enable PowerShell Transcription (optional but useful)
$psTxPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
if (-not (Test-Path $psTxPath)) { New-Item -Path $psTxPath -Force | Out-Null }
Set-ItemProperty -Path $psTxPath -Name "EnableTranscripting" -Value 1 -Type DWord
Set-ItemProperty -Path $psTxPath -Name "OutputDirectory"      -Value "C:\PSTranscripts" -Type String
Set-ItemProperty -Path $psTxPath -Name "EnableInvocationHeader" -Value 1 -Type DWord

# 4e. Expand Security event log size to 512 MB
wevtutil sl Security /ms:536870912

# 4f. Expand other key logs
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:104857600
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:104857600
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:104857600

# 4f-ii. Enable logs that are disabled by default on Server/DC SKUs.
#        wevtutil sl <channel> /e:true   — enable channel
#        wevtutil sl <channel> /ms:<bytes> — set max size
$logsToEnable = @(
    # DNS Client operational — outbound queries from this host (DGA, C2 beaconing)
    "Microsoft-Windows-DNS-Client/Operational",
    # Code Integrity / WDAC — unsigned driver/DLL blocks, BYOVD detection
    "Microsoft-Windows-CodeIntegrity/Operational",
    # WMI activity — remote execution, persistent WMI subscriptions
    "Microsoft-Windows-WMI-Activity/Operational",
    # Certificate lifecycle (user context) — ESC/shadow credential follow-on
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational",
    # LSA operational — SSP injection, auth anomalies (memssp)
    "Microsoft-Windows-LSA/Operational",
    # CAPI2 — PKI chain building, private key access, PKINIT auth
    "Microsoft-Windows-CAPI2/Operational",
    # Kernel time — clock manipulation (log timeline / Kerberos abuse)
    "Microsoft-Windows-Kernel-General/Operational",
    # PnP device config — USB hardware implants, rogue peripherals
    "Microsoft-Windows-Kernel-PnP/Device Configuration",
    # AppLocker packaged app execution
    "Microsoft-Windows-AppLocker/Packaged app-Execution",
    # PowerShell PSSession events (8193/8194/8197) — PSRemoting lateral movement
    "Microsoft-Windows-PowerShell/Operational",
    # RDP channels — session auth/logon/disconnect and source IP attribution (several disabled by default)
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-TerminalServices-RDPClient/Operational",
    # SMB server/client security — admin share access, payload write patterns
    "Microsoft-Windows-SmbServer/Security",
    "Microsoft-Windows-SmbClient/Security",
    # BITS Client — stealth payload downloads and C2 fetch via background service
    "Microsoft-Windows-Bits-Client/Operational",
    # Group Policy — GPO startup script deployment, policy tampering
    "Microsoft-Windows-GroupPolicy/Operational",
    # Authentication policy — Protected Users failures; PAW/tier silo violations (DC-only)
    "Microsoft-Windows-Authentication/ProtectedUser-Client",
    "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController",
    "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController",
    "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController",
    # AppCompat shim engine — shim persistence, UAC bypass via shimming
    "Microsoft-Windows-Kernel-ShimEngine/Operational",
    # Windows Update — patch suppression and servicing abuse context
    "Microsoft-Windows-WindowsUpdateClient/Operational",
    # Print Service — Print Nightmare (CVE-2021-34527), spooler exploitation
    "Microsoft-Windows-PrintService/Operational"
)
foreach ($log in $logsToEnable) {
    try {
        $state = (wevtutil gl "$log" 2>$null) -match 'enabled: true'
        if (-not $state) {
            wevtutil sl "$log" /e:true 2>&1 | Out-Null
            Write-Host "    Enabled: $log" -ForegroundColor Green
        }
        wevtutil sl "$log" /ms:52428800 2>&1 | Out-Null  # 50 MB cap
    } catch {
        Write-Warning "Could not enable log channel: $log — $($_.Exception.Message)"
    }
}

# 4g. Enable DNS Server debug/audit logging (if DNS role is installed)
if (Get-WindowsFeature DNS -ErrorAction SilentlyContinue | Where-Object Installed) {
    Set-DnsServerDiagnostics -All $true -ErrorAction SilentlyContinue
}

# 4h. Enable NTLM auditing (logs 4776 NTLM authentications and 5827/5828 blocks)
$ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
Set-ItemProperty -Path $ntlmPath -Name "AuditReceivingNTLMTraffic"  -Value 2 -Type DWord
Set-ItemProperty -Path $ntlmPath -Name "AuditNTLMInDomain"           -Value 7 -Type DWord

# 4i. SACL on domain root: audit replication extended rights (fires 4662)
#     These SACLs are required for DCSync detection - without them, 4662 does
#     NOT fire when replication rights are exercised by a non-DC account.
#     Extended Right GUIDs:
#       1131f6aa - DS-Replication-Get-Changes
#       1131f6ab - DS-Replication-Get-Changes-All
#       89e95b76 - DS-Replication-Get-Changes-In-Filtered-Set
Write-Host "[4/5] Setting DCSync detection SACLs on domain root ..."
try {
    $replGuids = @(
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",
        "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2",
        "89e95b76-444d-4c62-991a-0facbeda640c"
    )
    $domainObj  = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainDN   = "LDAP://DC=" + ($domainObj.Name -replace "\.", ",DC=")
    $de         = New-Object System.DirectoryServices.DirectoryEntry($domainDN)
    # SecurityMasks MUST be set before accessing ObjectSecurity, otherwise
    # the SACL is not loaded from AD and AddAuditRule throws "not retrieved
    # from the backend store".
    $de.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
    $de.psbase.RefreshCache(@("nTSecurityDescriptor"))
    $everyone   = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
    $emptyGuid  = [System.Guid]"00000000-0000-0000-0000-000000000000"
    foreach ($guidStr in $replGuids) {
        $objectGuid = [System.Guid]$guidStr
        $auditRule  = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
            $everyone,
            [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
            [System.Security.AccessControl.AuditFlags]::Success,
            $objectGuid,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
            $emptyGuid
        )
        $de.ObjectSecurity.AddAuditRule($auditRule)
    }
    $de.psbase.CommitChanges()
    $de.Dispose()
    Write-Host "    DCSync detection SACLs applied (4662 will fire for replication rights)." -ForegroundColor Green
} catch {
    Write-Warning "Could not set DCSync SACLs: $($_.Exception.Message)"
    Write-Warning "Run this step manually or re-run the installer on a DC."
}

Write-Host "[4/5] Additional settings applied." -ForegroundColor Green

# =============================================================================
# STEP 4j - Ensure WinLogBeat service can read the Security event log
# =============================================================================
# On Domain Controllers the Default Domain Controllers Policy can override
# local user rights and strip SeSecurityPrivilege from LocalSystem.
# Without SeSecurityPrivilege, WinLogBeat silently collects nothing from
# the Security log even though the service is running.
Write-Host "[4/5] Granting Security log read rights to WinLogBeat service ..."

# a) Add the service account to Event Log Readers (grants non-Security logs)
try {
    Add-LocalGroupMember -Group "Event Log Readers" -Member "NT AUTHORITY\SYSTEM" -ErrorAction Stop
    Write-Host "    NT AUTHORITY\SYSTEM added to Event Log Readers."
} catch {
    # Already a member or group not found - not fatal
}

# b) Use secedit to grant SeSecurityPrivilege to SYSTEM in local policy.
#    This is a belt-and-suspenders measure in case DC GPO strips it.
$tmpInf  = "$env:TEMP\winlogbeat_secedit.inf"
$tmpDb   = "$env:TEMP\winlogbeat_secedit.sdb"
$tmpLog  = "$env:TEMP\winlogbeat_secedit.log"
$infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeSecurityPrivilege = *S-1-5-18,*S-1-5-19,*S-1-5-20
"@
Set-Content -Path $tmpInf -Value $infContent -Encoding Unicode
secedit /configure /db $tmpDb /cfg $tmpInf /areas USER_RIGHTS /log $tmpLog /quiet 2>&1 | Out-Null
Remove-Item $tmpInf, $tmpDb, $tmpLog -Force -ErrorAction SilentlyContinue
Write-Host "    SeSecurityPrivilege granted to SYSTEM/LocalService/NetworkService." -ForegroundColor Green

# c) Apply immediately without requiring a reboot
gpupdate /force /target:computer 2>&1 | Select-String "successfully" | ForEach-Object { Write-Host "    $_" }

# =============================================================================
# STEP 5 - Install and start the WinLogBeat service
# =============================================================================
Write-Host "[5/5] Installing WinLogBeat Windows service ..."
$installScript = Join-Path $InstallDir "install-service-winlogbeat.ps1"
& $installScript

$svc = Get-Service -Name "winlogbeat" -ErrorAction SilentlyContinue
if ($null -ne $svc -and $svc.Status -eq "Running") {
    Restart-Service -Name "winlogbeat" -Force
} else {
    Start-Service -Name "winlogbeat"
}
Start-Sleep -Seconds 3

$svc = Get-Service -Name "winlogbeat"
Write-Host ""
if ($svc.Status -eq "Running") {
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "  WinLogBeat is RUNNING" -ForegroundColor Green
    Write-Host "  Shipping events  ->  ${LogstashHost}:${LogstashPort}" -ForegroundColor Green
    Write-Host "  Logs             ->  C:\ProgramData\winlogbeat\logs\" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Event sources now active:" -ForegroundColor Cyan
    Write-Host "    Security log        - logon, account mgmt, Kerberos, NTLM,"
    Write-Host "                          privilege use, process creation (4688),"
    Write-Host "                          AD replication / DCSync detection (4928-4937),"
    Write-Host "                          DS object changes (5136/5137),"
    Write-Host "                          policy changes, cert services"
    Write-Host "    Directory Service   - AD replication failures and schema changes"
    Write-Host "    DNS Server          - DNS query/zone errors"
    Write-Host "    Windows Defender    - malware detections and engine events"
    Write-Host "    PowerShell          - script block (4104) and module (4103) logging"
    Write-Host "    Task Scheduler      - scheduled task registration and execution"
    Write-Host "    NTLM/Operational    - NTLM authentication details"
    Write-Host "    WinRM/Operational   - PowerShell remoting sessions"
    Write-Host "    AppLocker           - blocked execution events (if policy set)"
    Write-Host "    Windows Firewall    - rule and config changes"
    Write-Host "    Sysmon              - process/network/registry detail (if installed)"
    Write-Host "    WMI-Activity        - remote WMI execution and persistent subscriptions"
    Write-Host "    DNS-Client          - outbound DNS queries with process context"
    Write-Host "    CodeIntegrity       - unsigned driver/DLL blocks, BYOVD detection"
    Write-Host "    CertLifecycle-User  - ESC/shadow credential certificate enrollment"
    Write-Host "    LSA/Operational     - SSP injection and auth anomalies"
    Write-Host "    CAPI2/Operational   - PKI chain builds and private key access"
    Write-Host "    Kernel-General      - clock manipulation events"
    Write-Host "    Kernel-PnP          - USB/hardware device installation"
    Write-Host "    RDP (4 channels)    - session logon/disconnect/reconnect + source IP attribution"
    Write-Host "    SMB Server/Client   - admin share access and payload write patterns"
    Write-Host "    BITS-Client         - stealth payload downloads, C2 fetch via background service"
    Write-Host "    GroupPolicy         - GPO startup/logon scripts, policy tampering indicators"
    Write-Host "    Auth Policy (4ch)   - Protected Users failures; PAW silo violations"
    Write-Host "    Kernel-ShimEngine   - AppCompat shim persistence and UAC bypass"
    Write-Host "    WindowsUpdateClient - patch suppression and servicing abuse"
    Write-Host "    PrintService        - Print Nightmare / spooler exploitation"
    Write-Host ""
    Write-Host "  NOTE: A reboot or 'gpupdate /force' is recommended to ensure" -ForegroundColor Yellow
    Write-Host "        all Group Policy audit settings take full effect." -ForegroundColor Yellow
    Write-Host ""
} else {
    Write-Warning "Service status: $($svc.Status)"
    Write-Warning "Check C:\ProgramData\winlogbeat\logs\ for errors."
}
