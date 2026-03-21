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
#        wevtutil sl <channel> /e:true    --  enable channel
#        wevtutil sl <channel> /ms:<bytes>  --  set max size
$logsToEnable = @(
    # DNS Client operational  --  outbound queries from this host (DGA, C2 beaconing)
    "Microsoft-Windows-DNS-Client/Operational",
    # Code Integrity / WDAC  --  unsigned driver/DLL blocks, BYOVD detection
    "Microsoft-Windows-CodeIntegrity/Operational",
    # WMI activity  --  remote execution, persistent WMI subscriptions
    "Microsoft-Windows-WMI-Activity/Operational",
    # Certificate lifecycle (user context)  --  ESC/shadow credential follow-on
    "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational",
    # LSA operational  --  SSP injection, auth anomalies (memssp)
    "Microsoft-Windows-LSA/Operational",
    # CAPI2  --  PKI chain building, private key access, PKINIT auth
    "Microsoft-Windows-CAPI2/Operational",
    # Kernel time  --  clock manipulation (log timeline / Kerberos abuse)
    "Microsoft-Windows-Kernel-General/Operational",
    # PnP device config  --  USB hardware implants, rogue peripherals
    "Microsoft-Windows-Kernel-PnP/Device Configuration",
    # AppLocker packaged app execution
    "Microsoft-Windows-AppLocker/Packaged app-Execution",
    # PowerShell PSSession events (8193/8194/8197)  --  PSRemoting lateral movement
    "Microsoft-Windows-PowerShell/Operational",
    # RDP channels  --  session auth/logon/disconnect and source IP attribution (several disabled by default)
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "Microsoft-Windows-TerminalServices-RDPClient/Operational",
    # SMB server/client security  --  admin share access, payload write patterns
    "Microsoft-Windows-SmbServer/Security",
    "Microsoft-Windows-SmbClient/Security",
    # BITS Client  --  stealth payload downloads and C2 fetch via background service
    "Microsoft-Windows-Bits-Client/Operational",
    # Group Policy  --  GPO startup script deployment, policy tampering
    "Microsoft-Windows-GroupPolicy/Operational",
    # Authentication policy  --  Protected Users failures; PAW/tier silo violations (DC-only)
    "Microsoft-Windows-Authentication/ProtectedUser-Client",
    "Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController",
    "Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController",
    "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController",
    # AppCompat shim engine  --  shim persistence, UAC bypass via shimming
    "Microsoft-Windows-Kernel-ShimEngine/Operational",
    # Windows Update  --  patch suppression and servicing abuse context
    "Microsoft-Windows-WindowsUpdateClient/Operational",
    # Print Service  --  Print Nightmare (CVE-2021-34527), spooler exploitation
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
        Write-Warning "Could not enable log channel: $log  --  $($_.Exception.Message)"
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
# STEP 4k - AD object SACLs for sensitive objects
# =============================================================================
# These SACLs cause Security 4662 / 5136 / 4670 to fire for writes to
# high-value AD objects that would otherwise produce no events even with
# "Directory Service Changes" audit policy enabled.
#
# Objects covered:
#   AdminSDHolder      - nTSecurityDescriptor/member writes (ACL persistence T1484)
#   krbtgt             - attribute changes (Golden Ticket prep, password manipulation)
#   GPO policies CN    - child creation / attribute writes (GPO-based persistence T1484.001)
#   Built-in DA group  - member adds (T1098.003)  --  belt-and-suspenders for 4728
#   Domain root DACL   - WRITE_DAC audit catches 4670 (permission changes on root object)
# =============================================================================
Write-Host "[4/5] Setting AD object SACLs for sensitive objects ..."
try {
    $domainObj = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domainName = $domainObj.Name
    $domainDC   = "DC=" + ($domainName -replace "\.", ",DC=")

    $everyone  = [System.Security.Principal.SecurityIdentifier]"S-1-1-0"
    $emptyGuid = [System.Guid]"00000000-0000-0000-0000-000000000000"
    $allProps  = [System.Guid]"00000000-0000-0000-0000-000000000000"

    # Helper: open a DirectoryEntry with SACL read/write, add an audit rule, commit
    function Add-ADAuditRule {
        param([string]$LdapPath, [string]$Label,
              [System.DirectoryServices.ActiveDirectoryRights]$Rights,
              [System.Guid]$ObjectGuid = [System.Guid]"00000000-0000-0000-0000-000000000000")
        try {
            $de = New-Object System.DirectoryServices.DirectoryEntry($LdapPath)
            $de.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
            $de.psbase.RefreshCache(@("nTSecurityDescriptor"))
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
                $everyone, $Rights,
                [System.Security.AccessControl.AuditFlags]::Success,
                $ObjectGuid,
                [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
                $emptyGuid
            )
            $de.ObjectSecurity.AddAuditRule($rule)
            $de.psbase.CommitChanges()
            $de.Dispose()
            Write-Host "    SACL set: $Label" -ForegroundColor Green
        } catch {
            Write-Warning "    SACL skipped ($Label): $($_.Exception.Message)"
        }
    }

    $writeProps = [System.DirectoryServices.ActiveDirectoryRights]::WriteProperty
    $writeDac   = [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl
    $writeAll   = $writeProps -bor $writeDac -bor
                  [System.DirectoryServices.ActiveDirectoryRights]::WriteOwner

    # AdminSDHolder  --  detect ACL tamper used for persistence (T1484)
    Add-ADAuditRule "LDAP://CN=AdminSDHolder,CN=System,$domainDC" `
        "AdminSDHolder write (ACL persistence / T1484)" $writeAll

    # krbtgt  --  detect attribute or password manipulation (Golden Ticket prep)
    Add-ADAuditRule "LDAP://CN=krbtgt,CN=Users,$domainDC" `
        "krbtgt attribute write (Golden Ticket prep)" $writeAll

    # GPO policies container  --  detect new GPO creation / GPO attribute tamper
    Add-ADAuditRule "LDAP://CN=Policies,CN=System,$domainDC" `
        "GPO Policies container write (T1484.001)" `
        ($writeProps -bor [System.DirectoryServices.ActiveDirectoryRights]::CreateChild `
                     -bor [System.DirectoryServices.ActiveDirectoryRights]::DeleteChild)

    # Domain Admins group  --  belt-and-suspenders for 4728 member adds
    $daName = "Domain Admins"
    $searcher = New-Object System.DirectoryServices.DirectorySearcher
    $searcher.Filter = "(&(objectClass=group)(cn=$daName))"
    $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDC")
    $daResult = $searcher.FindOne()
    if ($daResult) {
        Add-ADAuditRule $daResult.Path `
            "Domain Admins member write (T1098.003)" $writeProps
    }

    # Domain root  --  WRITE_DAC audits 4670 (permission change on domain object)
    $domainDE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDC")
    $domainDE.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
    $domainDE.psbase.RefreshCache(@("nTSecurityDescriptor"))
    $dacRule = New-Object System.DirectoryServices.ActiveDirectoryAuditRule(
        $everyone, $writeDac,
        [System.Security.AccessControl.AuditFlags]::Success,
        $emptyGuid,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None,
        $emptyGuid
    )
    $domainDE.ObjectSecurity.AddAuditRule($dacRule)
    $domainDE.psbase.CommitChanges()
    $domainDE.Dispose()
    Write-Host "    SACL set: domain root WRITE_DAC (4670 permission change)" -ForegroundColor Green

} catch {
    Write-Warning "AD object SACL step failed: $($_.Exception.Message)"
    Write-Warning "This step requires Domain Admin rights on a DC."
}

# =============================================================================
# STEP 4l - File system SACLs for high-value paths (fires 4663)
# =============================================================================
# Required for 4663 (object access) to fire for sensitive file paths:
#   C:\Windows\NTDS\        --  NTDS.dit access = credential dumping (T1003.003)
#   C:\Windows\SYSVOL\      --  GPO/script reads = lateral prep, GPO hijack (T1484)
#   C:\Windows\System32\config\  --  SAM/SECURITY hive = offline credential theft
# =============================================================================
Write-Host "[4/5] Setting file system SACLs on sensitive paths ..."

$fileSacls = @(
    @{
        Path   = "C:\Windows\NTDS"
        Label  = "NTDS folder (NTDS.dit credential dump detection T1003.003)"
        Rights = "Read,Write"
        Audit  = "Success"
    },
    @{
        Path   = "C:\Windows\SYSVOL"
        Label  = "SYSVOL (GPO/script access and staging T1484, T1021.002)"
        Rights = "Write"
        Audit  = "Success"
    },
    @{
        Path   = "C:\Windows\System32\config"
        Label  = "SAM/SECURITY hive directory (offline credential theft T1003)"
        Rights = "Read,Write"
        Audit  = "Success"
    }
)

foreach ($entry in $fileSacls) {
    $path = $entry.Path
    if (-not (Test-Path $path)) {
        Write-Host "    Skipped (path not found): $path"
        continue
    }
    try {
        # icacls sets SACL via /audit switch:
        #   /audit:S:(AU;OICINPFA;<perms>;;;WD)  --  WD = World/Everyone
        # Using icacls because PowerShell's Set-Acl on directories requires
        # loading the entire DACL first, risking inadvertent DACL changes.
        $aceFlags = "OI CI NP FA"  # OI=object inherit, CI=container inherit, NP=no propagate, FA=full audit
        $rights   = $entry.Rights
        # Convert to icacls permission string
        $permStr = switch ($rights) {
            "Read,Write" { "(OI)(CI)(NP)(RA)" }   # Read + Write audit
            "Write"      { "(OI)(CI)(NP)(WD)" }   # Write-only audit (quieter, avoids 4663 flood on reads)
            default      { "(OI)(CI)(NP)(FA)" }
        }
        # Use auditpol-style icacls SACL syntax:
        # /audit Everyone:<flags>  where flags = r for read, w for write
        $icaclsFlags = switch ($rights) {
            "Read,Write" { "R,W" }
            "Write"      { "W"   }
            default      { "F"   }
        }
        $result = icacls "$path" /grant:r "Everyone:(OI)(CI)(DE,DC,S,SD,RC,WD,WO,GA)" 2>&1
        # Proper SACL approach via PowerShell ACL:
        $acl  = Get-Acl -Path $path -Audit
        $everyoneNT = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $auditRights = switch ($rights) {
            "Read,Write" { [System.Security.AccessControl.FileSystemRights]"Read,Write" }
            "Write"      { [System.Security.AccessControl.FileSystemRights]"Write" }
            default      { [System.Security.AccessControl.FileSystemRights]"FullControl" }
        }
        $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
            $everyoneNT,
            $auditRights,
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        $acl.AddAuditRule($auditRule)
        Set-Acl -Path $path -AclObject $acl
        Write-Host "    SACL set: $($entry.Label)" -ForegroundColor Green
    } catch {
        Write-Warning "    SACL skipped ($path): $($_.Exception.Message)"
    }
}

# =============================================================================
# STEP 4m - Registry SACLs for persistence and tamper paths (fires 4657)
# =============================================================================
# Required for Security 4657 (registry value modified) to fire.
# Without these SACLs, registry-based persistence and security tool tamper
# are completely invisible in the Security log.
#
# Paths covered:
#   Run/RunOnce keys        --  classic persistence (T1547.001)
#   Services key            --  service-based persistence and BYOVD helper (T1543.003)
#   IFEO                    --  debugger hijack / accessibility persistence (T1546.012)
#   LSA                     --  SSP/auth package injection (T1547.005)
#   Defender policy         --  Defender config tamper via registry (T1562.001)
#   WinLogon                --  logon provider / userinit tampering (T1547.004)
# =============================================================================
Write-Host "[4/5] Setting registry SACLs on persistence and security-critical paths ..."

# Helper: open a registry key, add an audit rule, save it back
function Add-RegistryAuditRule {
    param([string]$KeyPath, [string]$Label)
    try {
        # Split hive prefix from subkey path
        $hive    = $KeyPath -replace '^HKLM:\\', '' -replace '^HKCU:\\', ''
        $regKey  = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            ($KeyPath -replace '^HKLM:\\', ''),
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,
            [System.Security.AccessControl.RegistryRights]::ChangePermissions
        )
        if ($null -eq $regKey) {
            Write-Warning "    SACL skipped (key not found): $KeyPath"
            return
        }
        $acl        = $regKey.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Audit)
        $everyoneNT = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $auditRule  = New-Object System.Security.AccessControl.RegistryAuditRule(
            $everyoneNT,
            [System.Security.AccessControl.RegistryRights]"SetValue,CreateSubKey,DeleteSubKey,Delete",
            [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit",
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AuditFlags]::Success
        )
        $acl.AddAuditRule($auditRule)
        $regKey.SetAccessControl($acl)
        $regKey.Close()
        Write-Host "    SACL set: $Label" -ForegroundColor Green
    } catch {
        Write-Warning "    SACL skipped ($Label): $($_.Exception.Message)"
    }
}

$registrySacls = @(
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
      "HKCU Run key (T1547.001 run-key persistence)"),
    @("HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
      "HKLM RunOnce key (T1547.001 run-key persistence)"),
    @("HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
      "HKLM WOW64 Run key (T1547.001 32-bit run-key persistence)"),
    @("HKLM:\SYSTEM\CurrentControlSet\Services",
      "Services key (T1543.003 service-based persistence / BYOVD)"),
    @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
      "IFEO (T1546.012 debugger hijack / accessibility persistence)"),
    @("HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
      "LSA key (T1547.005 SSP/auth package injection + Mimikatz memssp)"),
    @("HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
      "Defender policy key (T1562.001 AV tamper via registry)"),
    @("HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
      "Winlogon (T1547.004 userinit/shell/logon provider tamper)")
)

foreach ($entry in $registrySacls) {
    $keyPath = $entry[0]
    $label   = $entry[1]
    if (-not (Test-Path $keyPath)) {
        # Create the key so the SACL can be applied (e.g. Defender policy may not exist)
        New-Item -Path $keyPath -Force | Out-Null
    }
    Add-RegistryAuditRule -KeyPath $keyPath -Label $label
}

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
