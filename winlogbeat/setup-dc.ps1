#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Promotes a Windows Server VM to Domain Controller and builds all lab objects.
    Run this script BEFORE install-winlogbeat.ps1.

.DESCRIPTION
    Two-phase script (reboot between phases is automatic):

    Phase 1  -- run manually:
        - Renames the computer if needed
        - Installs AD DS / DNS / GPMC / RSAT roles
        - Schedules Phase 2 to auto-run after the next reboot
        - Promotes to DC (Install-ADDSForest) and reboots

    Phase 2  -- auto-runs via Scheduled Task after reboot:
        - Creates OU structure + lab accounts (attacker, svc_sql)
        - Sets SPN on svc_sql (Kerberoasting target)
        - Configures DNS forwarder
        - Relaxes domain password policy for lab use
        - Sets RC4 encryption on svc_sql (enables AS-REP/TGS roast)
        - Verifies firewall rules for Kali reachability
        - Removes scheduled task, prints summary

.USAGE
    # Option A -- download to disk (recommended, avoids iex limitations):
    iwr "http://192.168.68.61:9090/setup-dc.ps1" -OutFile C:\setup-dc.ps1
    Set-ExecutionPolicy Bypass -Scope Process -Force
    C:\setup-dc.ps1

    # Option B -- run directly from URL:
    Set-ExecutionPolicy Bypass -Scope Process -Force
    iex (iwr "http://192.168.68.61:9090/setup-dc.ps1" -UseBasicParsing).Content

    # Override any default:
    .\setup-dc.ps1 -DomainName "corp.local" -DomainNetBIOS "CORP" `
                   -ComputerName "DC01" -LogstashHost "10.0.0.5"

.NOTES
    SafeModePassword = DSRM recovery password (required for AD DS promotion).
    Tested on Windows Server 2019 / 2022.
#>

param(
    [string]$DomainName       = "insane.local",
    [string]$DomainNetBIOS    = "INSANE",
    [string]$ComputerName     = "Kql-lab-DC",
    [string]$LogstashHost     = "192.168.68.61",
    [securestring]$SafeModePassword = (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force),
    [switch]$Phase2           # set internally by the scheduled task after reboot
)

$ErrorActionPreference = "Stop"
$ProgressPreference    = "SilentlyContinue"
$LogFile               = "C:\setup-dc.log"

# When run via iex from a URL, MyCommand.Path is empty.
# In that case we save ourselves to disk so the scheduled task has a real path.
$ScriptPath = $MyInvocation.MyCommand.Path
if (-not $ScriptPath -and -not $Phase2) {
    $ScriptPath = "C:\setup-dc.ps1"
    if (-not (Test-Path $ScriptPath)) {
        Copy-Item -Path $MyInvocation.MyCommand.Source -Destination $ScriptPath -ErrorAction SilentlyContinue
        # MyCommand.Source is also empty for iex — fall back to re-downloading
        if (-not (Test-Path $ScriptPath)) {
            $ScriptUrl = "http://${LogstashHost}:9090/setup-dc.ps1"
            Invoke-WebRequest -Uri $ScriptUrl -OutFile $ScriptPath -UseBasicParsing -ErrorAction SilentlyContinue
        }
    }
}

function Write-Step {
    param([string]$Msg, [string]$Color = "Cyan")
    $line = "[$(Get-Date -Format 'HH:mm:ss')] $Msg"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Write-OK   { param([string]$M) Write-Step "  OK  $M" "Green"   }
function Write-Warn { param([string]$M) Write-Step "  !!  $M" "Yellow"  }
function Write-Fail { param([string]$M) Write-Step "FAIL  $M" "Red"     }

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2  (auto-runs after reboot from scheduled task)
# ─────────────────────────────────────────────────────────────────────────────
if ($Phase2) {
    Write-Step "=== DC Lab Setup -- Phase 2 (post-promotion) ===" "Magenta"

    # Wait for AD DS to be fully ready before issuing any LDAP/AD calls.
    Write-Step "Waiting for Active Directory services to be ready ..."
    $adReady = $false
    for ($i = 1; $i -le 24; $i++) {   # up to 4 minutes
        Start-Sleep -Seconds 10
        try {
            $null = Get-ADDomain -ErrorAction Stop
            $adReady = $true
            Write-OK "Active Directory is ready (attempt $i)"
            break
        } catch {
            Write-Warn "AD not ready yet (attempt $i/24) -- retrying in 10s ..."
        }
    }
    if (-not $adReady) {
        Write-Fail "AD DS did not become ready after 4 minutes. Check DCPROMO logs."
        exit 1
    }

    # ── 2a. Create OU structure ────────────────────────────────────────────
    Write-Step "[2a] Creating OU structure ..."
    $domainDN = "DC=" + ($DomainName -replace "\.", ",DC=")

    $ous = @(
        @{ Name = "Lab";         Path = $domainDN },
        @{ Name = "LabUsers";    Path = "OU=Lab,$domainDN" },
        @{ Name = "LabServices"; Path = "OU=Lab,$domainDN" },
        @{ Name = "LabComputers";Path = "OU=Lab,$domainDN" }
    )
    foreach ($ou in $ous) {
        $existing = Get-ADOrganizationalUnit -Filter "Name -eq '$($ou.Name)'" -SearchBase $ou.Path -SearchScope OneLevel -ErrorAction SilentlyContinue
        if (-not $existing) {
            New-ADOrganizationalUnit -Name $ou.Name -Path $ou.Path -ProtectedFromAccidentalDeletion $false
            Write-OK "Created OU: OU=$($ou.Name),$($ou.Path)"
        } else {
            Write-Warn "OU already exists: OU=$($ou.Name),$($ou.Path)"
        }
    }

    # ── 2b. Create lab user accounts ──────────────────────────────────────
    Write-Step "[2b] Creating lab user accounts ..."

    $users = @(
        @{
            # Low-priv attacker account used from Kali for Kerberoasting / BloodHound
            SamAccountName    = "attacker"
            GivenName         = "Lab"
            Surname           = "Attacker"
            UserPrincipalName = "attacker@$DomainName"
            Password          = "Pass123!"
            Description       = "Lab attacker account -- Kali simulation"
            Path              = "OU=LabUsers,OU=Lab,$domainDN"
            Groups            = @("Domain Users")
        },
        @{
            # Service account with SPN -- Kerberoasting target
            SamAccountName    = "svc_sql"
            GivenName         = "SQL"
            Surname           = "Service"
            UserPrincipalName = "svc_sql@$DomainName"
            Password          = "SqlS3rv1ce!2024"
            Description       = "SQL service account (Kerberoasting target)"
            Path              = "OU=LabServices,OU=Lab,$domainDN"
            Groups            = @("Domain Users")
        },
        @{
            # High-priv admin used for lateral movement simulation
            SamAccountName    = "labadmin"
            GivenName         = "Lab"
            Surname           = "Admin"
            UserPrincipalName = "labadmin@$DomainName"
            Password          = "LabAdm1n!2024"
            Description       = "Lab admin account -- DA for privilege escalation scenarios"
            Path              = "OU=LabUsers,OU=Lab,$domainDN"
            Groups            = @("Domain Admins", "Domain Users")
        }
    )

    foreach ($u in $users) {
        $existing = Get-ADUser -Filter "SamAccountName -eq '$($u.SamAccountName)'" -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Warn "User already exists: $($u.SamAccountName)"
        } else {
            $secPwd = ConvertTo-SecureString $u.Password -AsPlainText -Force
            New-ADUser `
                -SamAccountName    $u.SamAccountName `
                -GivenName         $u.GivenName `
                -Surname           $u.Surname `
                -UserPrincipalName $u.UserPrincipalName `
                -AccountPassword   $secPwd `
                -Description       $u.Description `
                -Path              $u.Path `
                -Enabled           $true `
                -PasswordNeverExpires $true `
                -CannotChangePassword $false
            Write-OK "Created user: $($u.SamAccountName)"
        }
        # Group membership
        foreach ($grp in $u.Groups) {
            try {
                Add-ADGroupMember -Identity $grp -Members $u.SamAccountName -ErrorAction Stop
                Write-OK "  $($u.SamAccountName) -> $grp"
            } catch {
                Write-Warn "  Group add skipped ($grp): already member or group not found"
            }
        }
    }

    # ── 2c. Set SPN on svc_sql (Kerberoasting target) ─────────────────────
    Write-Step "[2c] Setting SPN on svc_sql (Kerberoasting target) ..."
    $spns = @(
        "MSSQLSvc/sql01.$DomainName",
        "MSSQLSvc/sql01.$DomainName`:1433"
    )
    foreach ($spn in $spns) {
        try {
            Set-ADUser -Identity "svc_sql" -ServicePrincipalNames @{Add = $spn}
            Write-OK "SPN set: $spn"
        } catch {
            Write-Warn "SPN skipped ($spn): $($_.Exception.Message)"
        }
    }

    # ── 2d. Set RC4 encryption on svc_sql (required for 0x17 TGS) ────────
    # msDS-SupportedEncryptionTypes = 4 means RC4_HMAC only.
    # Impacket's GetUserSPNs will request RC4 which produces the 0x17 ticket
    # shown in event 4769 TicketEncryptionType -- the Kerberoasting detection signal.
    Write-Step "[2d] Setting RC4-only encryption on svc_sql ..."
    try {
        Set-ADUser -Identity "svc_sql" -Replace @{"msDS-SupportedEncryptionTypes" = 4}
        Write-OK "svc_sql msDS-SupportedEncryptionTypes = 4 (RC4_HMAC)"
    } catch {
        Write-Fail "Could not set encryption type: $($_.Exception.Message)"
    }

    # ── 2e. Domain password policy (relax for lab use) ────────────────────
    # Complexity off + no expiry = simple passwords work without fighting the policy.
    Write-Step "[2e] Setting permissive domain password policy (lab only) ..."
    try {
        Set-ADDefaultDomainPasswordPolicy `
            -Identity              $DomainName `
            -MinPasswordLength     8 `
            -MaxPasswordAge        0 `
            -MinPasswordAge        0 `
            -PasswordHistoryCount  0 `
            -ComplexityEnabled     $false `
            -ReversibleEncryptionEnabled $false
        Write-OK "Password policy: complexity=off, expiry=never, history=0, minlen=8"
    } catch {
        Write-Fail "Password policy update failed: $($_.Exception.Message)"
    }

    # ── 2f. DNS forwarder ─────────────────────────────────────────────────
    Write-Step "[2f] Configuring DNS forwarder ..."
    try {
        Add-DnsServerForwarder -IPAddress "8.8.8.8" -ErrorAction SilentlyContinue
        Add-DnsServerForwarder -IPAddress "1.1.1.1" -ErrorAction SilentlyContinue
        Write-OK "DNS forwarders: 8.8.8.8, 1.1.1.1"
    } catch {
        Write-Warn "DNS forwarder: $($_.Exception.Message)"
    }

    # ── 2g. Reverse DNS zone (helps Kali tools resolve by IP) ─────────────
    Write-Step "[2g] Creating reverse DNS zone ..."
    try {
        # Derive subnet from current IP (best-effort)
        $dcIP = (Get-NetIPAddress -AddressFamily IPv4 |
                 Where-Object { $_.PrefixOrigin -ne "WellKnown" } |
                 Select-Object -First 1).IPAddress
        if ($dcIP) {
            $parts   = $dcIP.Split(".")
            $reverse = "$($parts[2]).$($parts[1]).$($parts[0]).in-addr.arpa"
            Add-DnsServerPrimaryZone -NetworkID "$($parts[0]).$($parts[1]).$($parts[2]).0/24" `
                -ReplicationScope "Domain" -ErrorAction SilentlyContinue
            Write-OK "Reverse zone: $reverse"
        }
    } catch {
        Write-Warn "Reverse zone: $($_.Exception.Message)"
    }

    # ── 2h. Firewall -- verify attack-surface rules are open ──────────────
    # AD DS role installer enables most of these; this step makes them explicit
    # and re-enables any that may have been disabled.
    Write-Step "[2h] Verifying firewall rules for lab reachability ..."
    $rules = @(
        "Kerberos Key Distribution Center",                     # 88 TCP/UDP
        "Active Directory Domain Controller - LDAP (TCP-In)",  # 389 TCP
        "Active Directory Domain Controller - LDAP (UDP-In)",  # 389 UDP
        "Active Directory Domain Controller - Secure LDAP (TCP-In)", # 636
        "Active Directory Domain Controller - SAM/LSA (NP-TCP-In)",  # 445
        "DNS (TCP, Incoming)",                                  # 53 TCP
        "DNS (UDP, Incoming)"                                   # 53 UDP
    )
    foreach ($name in $rules) {
        try {
            Enable-NetFirewallRule -DisplayName $name -ErrorAction Stop
            Write-OK "Firewall rule enabled: $name"
        } catch {
            Write-Warn "Firewall rule not found (may use different name): $name"
        }
    }

    # RPC dynamic ports for AD replication / DCOM enumeration (BloodHound)
    try {
        Enable-NetFirewallRule -Group "@FirewallAPI.dll,-32752" -ErrorAction SilentlyContinue  # Remote Event Log
        Enable-NetFirewallRule -Group "@FirewallAPI.dll,-32758" -ErrorAction SilentlyContinue  # Remote Service Mgmt
        Enable-NetFirewallRule -Group "@FirewallAPI.dll,-28502" -ErrorAction SilentlyContinue  # File and Printer Sharing
        Write-OK "RPC / file sharing groups enabled"
    } catch {
        Write-Warn "RPC group rules: $($_.Exception.Message)"
    }

    # ── 2i. WinRM for lab convenience (PS Remoting from Kali/Linux tools) ─
    Write-Step "[2i] Enabling WinRM ..."
    try {
        Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
        Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
        Set-Service WinRM -StartupType Automatic
        Write-OK "WinRM enabled"
    } catch {
        Write-Warn "WinRM: $($_.Exception.Message)"
    }

    # ── 2j. Disable IE Enhanced Security (stops browser security dialogs) ─
    Write-Step "[2j] Disabling IE Enhanced Security Configuration ..."
    try {
        $adminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
        $userKey  = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
        Set-ItemProperty -Path $adminKey -Name "IsInstalled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Set-ItemProperty -Path $userKey  -Name "IsInstalled" -Value 0 -Type DWord -ErrorAction SilentlyContinue
        Write-OK "IE ESC disabled"
    } catch {
        Write-Warn "IE ESC: $($_.Exception.Message)"
    }

    # ── 2k. Disable Windows Firewall for Domain profile (lab only) ────────
    # Comment this out if you want to keep firewall on and test rule-based detection.
    Write-Step "[2k] Disabling Windows Firewall on Domain profile (lab convenience) ..."
    try {
        Set-NetFirewallProfile -Profile Domain -Enabled False
        Write-OK "Domain firewall profile disabled"
    } catch {
        Write-Warn "Firewall profile: $($_.Exception.Message)"
    }

    # ── 2l. Remove scheduled task (cleanup) ───────────────────────────────
    Write-Step "[2l] Removing Phase 2 scheduled task ..."
    Unregister-ScheduledTask -TaskName "SetupDC-Phase2" -Confirm:$false -ErrorAction SilentlyContinue
    Write-OK "Scheduled task removed"

    # ── Summary ───────────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host "  DC Lab Setup COMPLETE" -ForegroundColor Green
    Write-Host "===========================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Domain     : $DomainName ($DomainNetBIOS)" -ForegroundColor Cyan
    Write-Host "  DC         : $env:COMPUTERNAME.$DomainName" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Lab accounts created:" -ForegroundColor Cyan
    Write-Host "    attacker / Pass123!          -- low-priv attacker (Kali simulation)"
    Write-Host "    svc_sql  / SqlS3rv1ce!2024   -- service acct, SPN set, RC4 forced"
    Write-Host "    labadmin / LabAdm1n!2024     -- Domain Admin (privilege esc target)"
    Write-Host ""
    Write-Host "  SPNs on svc_sql:"
    Write-Host "    MSSQLSvc/sql01.$DomainName"
    Write-Host "    MSSQLSvc/sql01.$DomainName`:1433"
    Write-Host ""
    Write-Host "  Next step: run install-winlogbeat.ps1 to ship events to logstash." -ForegroundColor Yellow
    Write-Host "  Log: $LogFile" -ForegroundColor Yellow
    Write-Host ""
    exit 0
}

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1  (run manually — installs roles, promotes DC, schedules Phase 2)
# ─────────────────────────────────────────────────────────────────────────────

# If this machine is already a DC, skip promotion and run Phase 2 directly.
$alreadyDC = $false
try { $null = Get-ADDomain -ErrorAction Stop; $alreadyDC = $true } catch { }
if ($alreadyDC) {
    Write-Step "Server is already a Domain Controller -- skipping promotion, jumping to Phase 2." "Yellow"
    $Phase2 = $true
}

Write-Step "=== DC Lab Setup -- Phase 1 ===" "Magenta"
Write-Step "Domain    : $DomainName ($DomainNetBIOS)"
Write-Step "Computer  : $ComputerName"
Write-Step "Logstash  : $LogstashHost"
Write-Host ""

# ── 1a. Rename computer if needed ─────────────────────────────────────────
if ($env:COMPUTERNAME -ne $ComputerName) {
    Write-Step "[1a] Renaming computer from '$env:COMPUTERNAME' to '$ComputerName' ..."
    Rename-Computer -NewName $ComputerName -Force -ErrorAction Stop
    Write-OK "Computer renamed -- rebooting to apply name change, then promotion will continue."
    Write-Step "      Re-run the script after reboot to complete promotion." "Yellow"
    # Register a task to re-run Phase 1 (promotion) after reboot automatically.
    $psExe   = "$PSHOME\powershell.exe"
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" " +
               "-DomainName `"$DomainName`" " +
               "-DomainNetBIOS `"$DomainNetBIOS`" " +
               "-ComputerName `"$ComputerName`" " +
               "-LogstashHost `"$LogstashHost`""
    $action    = New-ScheduledTaskAction  -Execute $psExe -Argument $argList
    $trigger   = New-ScheduledTaskTrigger -AtStartup
    $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
    Register-ScheduledTask -TaskName "SetupDC-Phase1-PostRename" `
        -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-OK "Scheduled task registered -- promotion will run automatically after reboot."
    Start-Sleep -Seconds 3
    Restart-Computer -Force
    exit 0
} else {
    Write-Step "[1a] Computer name already '$ComputerName' -- skipping rename."
}

# Remove the post-rename task if it exists (we're past the rename now)
Unregister-ScheduledTask -TaskName "SetupDC-Phase1-PostRename" -Confirm:$false -ErrorAction SilentlyContinue

# ── 1b. Install Windows features ──────────────────────────────────────────
Write-Step "[1b] Installing AD DS, DNS, GPMC and RSAT tools ..."
$features = @(
    "AD-Domain-Services",     # Active Directory Domain Services
    "DNS",                    # DNS Server
    "GPMC",                   # Group Policy Management Console
    "RSAT-AD-Tools",          # AD PowerShell module + ADUC
    "RSAT-AD-PowerShell",     # AD PowerShell module
    "RSAT-DNS-Server"         # DNS Manager RSAT
)
foreach ($f in $features) {
    $installed = Get-WindowsFeature -Name $f
    if ($installed.Installed) {
        Write-OK "Already installed: $f"
    } else {
        Write-Step "  Installing: $f ..."
        Install-WindowsFeature -Name $f -IncludeManagementTools | Out-Null
        Write-OK "Installed: $f"
    }
}

# ── 1c. Register Phase 2 as a scheduled task (runs once after reboot) ──────
Write-Step "[1c] Registering Phase 2 scheduled task ..."
$psExe   = "$PSHOME\powershell.exe"
$argList = "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" " +
           "-DomainName `"$DomainName`" " +
           "-DomainNetBIOS `"$DomainNetBIOS`" " +
           "-ComputerName `"$ComputerName`" " +
           "-LogstashHost `"$LogstashHost`" " +
           "-Phase2"

$action  = New-ScheduledTaskAction  -Execute $psExe -Argument $argList
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings= New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 30)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount

Register-ScheduledTask `
    -TaskName  "SetupDC-Phase2" `
    -Action    $action `
    -Trigger   $trigger `
    -Settings  $settings `
    -Principal $principal `
    -Force | Out-Null

Write-OK "Scheduled task 'SetupDC-Phase2' registered (runs as SYSTEM at next startup)"

# ── 1d. Promote to Domain Controller ──────────────────────────────────────
Write-Step "[1d] Promoting server to Domain Controller ..."
Write-Step "      Forest: $DomainName  |  NetBIOS: $DomainNetBIOS"
Write-Step "      The server will REBOOT automatically after promotion."
Write-Step "      Phase 2 will run automatically on the next startup."
Write-Host ""

Import-Module ADDSDeployment -ErrorAction Stop

$addsParams = @{
    DomainName                    = $DomainName
    DomainNetbiosName             = $DomainNetBIOS
    DomainMode                    = "WinThreshold"
    ForestMode                    = "WinThreshold"
    InstallDns                    = $true
    SafeModeAdministratorPassword = $SafeModePassword
    NoRebootOnCompletion          = $true
    Force                         = $true
}
Install-ADDSForest @addsParams | Out-Null

# Install-ADDSForest sometimes does not auto-reboot when run inside iex or
# a remote session. Force the reboot explicitly so the scheduled task fires.
Write-Step "[1d] Promotion complete -- rebooting now ..."
Start-Sleep -Seconds 3
Restart-Computer -Force
