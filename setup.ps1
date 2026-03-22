#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Idempotent setup for Windows Event Log -> Kustainer pipeline (Windows host).

.DESCRIPTION
    1. Pre-flight checks (Docker Desktop, AVX2, RAM, disk, vm.max_map_count)
    2. Starts ADX + Logstash + relay via docker compose
    3. Waits for Kustainer to become healthy
    4. Creates database schema, table, mapping, and streaming ingest policy
    5. Sends a test event to verify end-to-end ingest

    Re-run safely at any time - all schema commands are idempotent.

.NOTES
    Requires: Docker Desktop for Windows (WSL2 backend), PowerShell 5.1+
    Run as Administrator (needed only to set vm.max_map_count in WSL2).
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir    = Split-Path -Parent $MyInvocation.MyCommand.Path
$ADX_URL      = 'http://localhost:8080'
$DB           = 'NetDefaultDB'
$MAX_WAIT_SEC = 180

# -- Helpers ------------------------------------------------------------------
function log  { param($m) Write-Host "[setup] $m" -ForegroundColor Green  }
function warn { param($m) Write-Host "[ warn] $m" -ForegroundColor Yellow }
function info { param($m) Write-Host "[ info] $m" -ForegroundColor Cyan   }
function fail {
    param($m)
    Write-Host "[error] $m" -ForegroundColor Red
    exit 1
}

# -- Load .env -----------------------------------------------------------------
$envFile = Join-Path $ScriptDir '.env'
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#=]+?)\s*=\s*(.*)\s*$') {
            [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }
}
$DATA_RETENTION_DAYS = if ($env:DATA_RETENTION_DAYS) { [int]$env:DATA_RETENTION_DAYS } else { 7 }
$DATA_MAX_GB         = if ($env:DATA_MAX_GB)         { [double]$env:DATA_MAX_GB }       else { 5.0 }
$DATA_WARN_GB        = if ($env:DATA_WARN_GB)        { [double]$env:DATA_WARN_GB }      else { 2.0 }
$DATA_MIN_FREE_GB    = if ($env:DATA_MIN_FREE_GB)    { [double]$env:DATA_MIN_FREE_GB }  else { 1.0 }

Write-Host ''
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host '  Windows Event Logs -> Kustainer - Setup (Windows host)'          -ForegroundColor Cyan
Write-Host '==================================================================' -ForegroundColor Cyan
Write-Host ''

# -- 0. Pre-flight -------------------------------------------------------------

# AVX2 - libKusto.NativeInfra.so requires AVX2; crashes instantly without it
try {
    # Works on PowerShell 7 / .NET 5+
    Add-Type -TypeDefinition @'
using System.Runtime.Intrinsics.X86;
public static class CpuCheck { public static bool HasAvx2 => Avx2.IsSupported; }
'@ -ErrorAction Stop
    if (-not [CpuCheck]::HasAvx2) {
        fail "AVX2 not available on this CPU - Kustainer requires AVX2.`nEnsure you are running on a physical host or a VM with CPU passthrough enabled."
    }
    info "AVX2: present - OK."
} catch {
    warn "Could not verify AVX2 via .NET intrinsics (requires PowerShell 7+). Proceeding - will fail at container start if AVX2 is missing."
}

# RAM
$totalRAMGB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
if ($totalRAMGB -lt 4) {
    fail "Only ${totalRAMGB} GB RAM - Kustainer requires at least 4 GB (6 GB+ recommended)."
} elseif ($totalRAMGB -lt 6) {
    warn "RAM: ${totalRAMGB} GB - Kustainer may be slow or unstable below 6 GB."
} else {
    info "RAM: ${totalRAMGB} GB - OK."
}

# Docker Desktop
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    fail "docker not found.`nInstall Docker Desktop: https://docs.docker.com/desktop/install/windows-install/"
}
# Use 'docker ps' -- simpler than 'docker info' and less noisy on stderr.
# Capture output and exit code in isolation to avoid $LASTEXITCODE bleed from prior commands.
$dockerTest = $null
$dockerTest = & cmd /c "docker ps >nul 2>&1 && echo OK || echo FAIL" 2>&1
if ($dockerTest -notmatch 'OK') {
    $dockerErr = (& docker ps 2>&1 | Select-Object -First 2) -join ' '
    $hint = if ($dockerErr -match 'LinuxEngine|linux') {
        "Docker Desktop is in Windows containers mode.`n  Right-click the tray icon -> 'Switch to Linux containers...' then retry."
    } else {
        "Docker Desktop is not ready. Wait for the tray icon to stop animating, then retry.`n  Run: docker ps"
    }
    fail "Cannot connect to Docker Desktop.`n  $hint`n  Error: $dockerErr"
}
& docker compose version 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    fail "'docker compose' plugin not found. Update Docker Desktop to 4.x+."
}
info "Docker: OK."

# Disk space
$driveLetter = (Split-Path -Qualifier $ScriptDir).TrimEnd(':')
$disk   = Get-PSDrive -Name $driveLetter
$freeGB = [math]::Round($disk.Free / 1GB, 1)
if ($freeGB -lt $DATA_MIN_FREE_GB) {
    fail "Only ${freeGB} GB free - need at least ${DATA_MIN_FREE_GB} GB."
} elseif ($freeGB -lt $DATA_WARN_GB) {
    warn "Low disk space: ${freeGB} GB free (threshold: ${DATA_WARN_GB} GB). Monitor closely."
} else {
    info "Disk space: ${freeGB} GB free - OK."
}

# Data directory size
$dataDir = Join-Path $ScriptDir 'data'
if (Test-Path $dataDir) {
    $_files     = Get-ChildItem $dataDir -Recurse -File -ErrorAction SilentlyContinue
    $_measured  = if ($_files) { ($_files | Measure-Object -Property Length -Sum).Sum } else { 0 }
    $dataSizeGB = [math]::Round([double]$_measured / 1GB, 1)
    if ($dataSizeGB -gt $DATA_MAX_GB) {
        warn ".\data\ is ${dataSizeGB} GB - over the ${DATA_MAX_GB} GB cap. Run .\teardown.ps1 --purge to reclaim space."
    } else {
        info "Data directory: ${dataSizeGB} GB / ${DATA_MAX_GB} GB cap."
    }
}
info "Retention policy: $DATA_RETENTION_DAYS days (set DATA_RETENTION_DAYS in .env to change)."

# vm.max_map_count - Docker Desktop uses WSL2; the kernel param must be set there.
# Runtime: wsl -d docker-desktop; Persistent: ~/.wslconfig kernelCommandLine.
$MIN_MAP = 262144
$TARGET_MAP = 524288
try {
    $curMap = [int](wsl -d docker-desktop sysctl -n vm.max_map_count 2>$null)
    if ($curMap -lt $MIN_MAP) {
        warn "vm.max_map_count is $curMap (need >= $MIN_MAP) - fixing now ..."
        wsl -d docker-desktop sysctl -w vm.max_map_count=$TARGET_MAP 2>$null | Out-Null
        info "vm.max_map_count set to $TARGET_MAP for this session."
    } else {
        info "vm.max_map_count: $curMap - OK."
    }
} catch {
    warn "Could not set vm.max_map_count via WSL2 - Kustainer may crash if it is too low."
}

# Persist vm.max_map_count across Docker Desktop restarts via .wslconfig
$wslConfig = "$env:USERPROFILE\.wslconfig"
$wslLine   = 'kernelCommandLine = sysctl.vm.max_map_count=524288'
if (Test-Path $wslConfig) {
    $wslContent = Get-Content $wslConfig -Raw
    if ($wslContent -notmatch 'vm\.max_map_count') {
        if ($wslContent -match '\[wsl2\]') {
            $wslContent = $wslContent -replace '(\[wsl2\])', "`$1`n$wslLine"
        } else {
            $wslContent += "`n`[wsl2`]`n$wslLine`n"
        }
        Set-Content $wslConfig $wslContent
        info "vm.max_map_count persisted in $wslConfig."
    }
} else {
    "`[wsl2`]`n$wslLine`n" | Set-Content $wslConfig
    info "Created $wslConfig with vm.max_map_count=524288."
}

Set-Location $ScriptDir

# -- 1. Directory layout -------------------------------------------------------
log "Ensuring directory layout ..."
@('data', 'logstash\pipeline', 'logstash\config', 'winlogbeat', 'schemas') | ForEach-Object {
    New-Item -ItemType Directory -Path (Join-Path $ScriptDir $_) -Force | Out-Null
}

# -- 2. Start the stack --------------------------------------------------------
log "Starting ADX + Logstash via docker compose ..."
docker compose up -d
Write-Host ''

# -- 3. Wait for Kustainer ----------------------------------------------------
log "Waiting for Kustainer to become healthy (max ${MAX_WAIT_SEC}s) ..."
$elapsed = 0
$ready   = $false
$mgmtBody = '{"db":"NetDefaultDB","csl":".show version"}'
while ($elapsed -lt $MAX_WAIT_SEC) {
    try {
        Invoke-RestMethod -Uri "$ADX_URL/v1/rest/mgmt" -Method Post `
            -ContentType 'application/json' -Body $mgmtBody -ErrorAction Stop | Out-Null
        $ready = $true
        break
    } catch {
        Start-Sleep -Seconds 5
        $elapsed += 5
        Write-Host -NoNewline '.'
    }
}
Write-Host ''
if (-not $ready) { fail "Kustainer did not become ready within ${MAX_WAIT_SEC}s. Check: docker logs adx" }
log "Kustainer is ready."
Write-Host ''

# -- 4. Schema init ------------------------------------------------------------
log "Initialising schema in Kustainer ..."

function Invoke-KustoMgmt {
    param([string]$Csl, [string]$Label = '')
    $body = "{`"db`":`"$DB`",`"csl`":$(($Csl | ConvertTo-Json))}"
    try {
        Invoke-RestMethod -Uri "$ADX_URL/v1/rest/mgmt" -Method Post `
            -ContentType 'application/json' -Body $body -ErrorAction Stop | Out-Null
        if ($Label) { Write-Host "  [OK]  $Label" }
    } catch {
        $msg = $_.ToString()
        if ($msg -match 'already.?exists|entityalreadyexists|alreadyexists') {
            if ($Label) { Write-Host "  [OK]  $Label (already exists)" }
        } else {
            Write-Host "  [FAIL]  ${Label}: $msg" -ForegroundColor Red
            throw
        }
    }
}

# Table
Invoke-KustoMgmt -Label 'table     WindowsEvents' -Csl (
    '.create-merge table WindowsEvents ' +
    '( TimeCreated:datetime, Computer:string, EventId:int, Level:string,' +
    '  Channel:string, Provider:string, Message:string,' +
    '  EventData:dynamic, RawEvent:dynamic )')

# JSON ingestion mapping
$mappingObj = @(
    @{ column='TimeCreated'; path='$["@timestamp"]';       datatype='datetime' }
    @{ column='Computer';    path='$.winlog.computer_name'; datatype='string'   }
    @{ column='EventId';     path='$.winlog.event_id';      datatype='int'      }
    @{ column='Level';       path='$.log.level';            datatype='string'   }
    @{ column='Channel';     path='$.winlog.channel';       datatype='string'   }
    @{ column='Provider';    path='$.winlog.provider_name'; datatype='string'   }
    @{ column='Message';     path='$.message';              datatype='string'   }
    @{ column='EventData';   path='$.winlog.event_data';    datatype='dynamic'  }
    @{ column='RawEvent';    path='$';                      datatype='dynamic'  }
)
$mappingJson = ($mappingObj | ConvertTo-Json -Compress).Replace("'", "''")
Invoke-KustoMgmt -Label 'mapping   winlogbeat_mapping' -Csl (
    ".create-or-alter table WindowsEvents ingestion json mapping `"winlogbeat_mapping`" @'$mappingJson'")

# Streaming ingest policy
Invoke-KustoMgmt -Label 'policy    streaming ingestion' -Csl (
    '.alter table WindowsEvents policy streamingingestion enable')

# Retention policy
$retJson = "{`"SoftDeletePeriod`":`"${DATA_RETENTION_DAYS}.00:00:00`",`"Recoverability`":`"Disabled`"}".Replace("'", "''")
Invoke-KustoMgmt -Label "policy    retention -> $DATA_RETENTION_DAYS days" -Csl (
    ".alter table WindowsEvents policy retention @'$retJson'")

# Cache policy
$cacheDays = [math]::Min($DATA_RETENTION_DAYS, 3)
Invoke-KustoMgmt -Label "policy    hot cache -> $cacheDays days" -Csl (
    ".alter table WindowsEvents policy caching hot = ${cacheDays}d")

Write-Host ''
Write-Host '  Schema initialisation complete.'
Write-Host ''

# -- 5. Test ingest via relay -------------------------------------------------
log "Testing ingest via relay container ..."
Start-Sleep -Seconds 3
$testEvent = '{"@timestamp":"2026-03-20T00:00:00.000Z","winlog":{"computer_name":"setup-test","event_id":1,"channel":"SetupTest","provider_name":"KQL-Lab-Setup","event_data":{"note":"setup verification"}},"log":{"level":"information"},"message":"Setup verification event - safe to delete"}'
try {
    $r = Invoke-WebRequest -Uri 'http://localhost:9001/ingest' -Method Post `
        -ContentType 'application/json' -Body $testEvent `
        -UseBasicParsing -ErrorAction Stop
    log "Relay ingest test PASSED (HTTP $($r.StatusCode))."
} catch {
    warn "Relay returned an error: $_"
    warn "Check: docker logs relay"
}
Write-Host ''

# -- 6. Package winlogbeat zip -------------------------------------------------
log "Packaging winlogbeat-dc.zip ..."
$zipDest = Join-Path $ScriptDir 'winlogbeat-dc.zip'
if (Test-Path $zipDest) { Remove-Item $zipDest -Force }
Compress-Archive -Path (Join-Path $ScriptDir 'winlogbeat\*') -DestinationPath $zipDest
log "winlogbeat-dc.zip ready (for manual DC deployment - see step 7 for automated option)."
Write-Host ''

# -- 7. DC provisioning -------------------------------------------------------
$DC_HOST = if ($env:DC_HOST) { $env:DC_HOST } else { $null }
$DC_USER = if ($env:DC_USER) { $env:DC_USER } else { 'Administrator' }

# Detect host IP - used by DC provisioning and summary.
# When DC_HOST is set, ask Windows which source IP it would use to reach the DC
# (Find-NetRoute picks the correct interface even when VPNs are active).
# Fall back to metric-sorted list if Find-NetRoute is unavailable.
$hostIP = $null
if ($DC_HOST) {
    try {
        $route  = Find-NetRoute -RemoteIPAddress $DC_HOST -ErrorAction Stop
        $hostIP = ($route | Select-Object -First 1).IPAddress
    } catch { }
}
if (-not $hostIP) {
    $hostIP = (Get-NetIPAddress -AddressFamily IPv4 |
        Where-Object { $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and $_.PrefixOrigin -ne 'WellKnown' } |
        Sort-Object InterfaceMetric |
        Select-Object -First 1).IPAddress
}
$dcProvisionOk = $false

if (-not $DC_HOST) {
    info 'DC_HOST not set in .env - skipping automated DC provisioning.'
    info '  Add DC_HOST=<ip-or-hostname>  (and optionally DC_USER=<username>)  to .env and re-run.'
} else {
    log "Provisioning DC at $DC_HOST ..."

    # Add DC to PSRemoting TrustedHosts on this machine (required for NTLM auth to IP/hostname)
    try {
        $curTrusted = (Get-Item 'WSMan:\localhost\Client\TrustedHosts' -ErrorAction Stop).Value
        if ($curTrusted -ne '*' -and $curTrusted -notmatch [regex]::Escape($DC_HOST)) {
            $newTrusted = if ($curTrusted) { "$curTrusted,$DC_HOST" } else { $DC_HOST }
            Set-Item 'WSMan:\localhost\Client\TrustedHosts' -Value $newTrusted -Force -ErrorAction Stop
        }
    } catch {
        warn "Could not update WSMan TrustedHosts: $_ -- PSRemoting may fail if DC is not in a trusted zone."
    }

    $dcCred = Get-Credential -UserName $DC_USER `
                  -Message "Enter DC admin credentials for $DC_HOST  (e.g. Administrator or DOMAIN\Administrator)"

    $sess = $null
    try {
        $sopts = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck `
                                     -OperationTimeout 900000
        $sess  = New-PSSession -ComputerName $DC_HOST -Credential $dcCred `
                     -Authentication Negotiate -SessionOption $sopts -ErrorAction Stop
        log '  PSRemoting session established.'

        # Create staging directory on DC
        $remoteDir = 'C:\setup-dc-lab'
        Invoke-Command -Session $sess -ScriptBlock {
            param($d)
            if (-not (Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }
        } -ArgumentList $remoteDir

        # Copy scripts to DC
        log '  Copying scripts to DC ...'
        foreach ($f in @('setup-dc.ps1', 'install-winlogbeat.ps1', 'winlogbeat.yml')) {
            Copy-Item -Path (Join-Path $ScriptDir "winlogbeat\$f") `
                      -Destination "$remoteDir\$f" `
                      -ToSession $sess -Force
        }
        log "  Scripts staged at $remoteDir on DC."

        # Phase 2: create AD lab objects (OUs, users, SPNs, RC4, password policy, DNS, WinRM, firewall)
        log '  Running AD lab setup on DC (Phase 2: OUs, users, SPNs, RC4, policy, DNS) ...'
        Invoke-Command -Session $sess -ScriptBlock {
            param($d, $lsHost)
            Set-ExecutionPolicy Bypass -Scope Process -Force
            & "$d\setup-dc.ps1" -Phase2 -LogstashHost $lsHost
        } -ArgumentList $remoteDir, $hostIP
        log '  AD lab objects provisioned.'

        # Install WinLogBeat on DC (downloads ~80 MB from elastic.co - takes a few minutes)
        log "  Installing WinLogBeat on DC (Logstash target: ${hostIP}:5044) ..."
        log '  Downloading ~80 MB from elastic.co - may take a few minutes ...'
        Invoke-Command -Session $sess -ScriptBlock {
            param($d, $lsHost)
            Set-ExecutionPolicy Bypass -Scope Process -Force
            & "$d\install-winlogbeat.ps1" -LogstashHost $lsHost
        } -ArgumentList $remoteDir, $hostIP
        log '  WinLogBeat installed and started on DC.'

        $dcProvisionOk = $true

    } catch {
        warn "DC provisioning failed: $_"
        warn '  Ensure WinRM is enabled on the DC:  winrm quickconfig -q'
        warn '  Then re-run setup.ps1, or provision manually using winlogbeat-dc.zip.'
    } finally {
        if ($sess) { Remove-PSSession $sess -ErrorAction SilentlyContinue }
    }
}
Write-Host ''

# -- 8. Summary ----------------------------------------------------------------
$sep = '=' * 66
Write-Host $sep -ForegroundColor Green
Write-Host '  Setup Complete' -ForegroundColor Green
Write-Host $sep -ForegroundColor Green
Write-Host "  Kustainer REST API   http://localhost:8080" -ForegroundColor Green
Write-Host "  Logstash Beats port  ${hostIP}:5044  (WinLogBeat target)" -ForegroundColor Green
Write-Host '  Database             NetDefaultDB' -ForegroundColor Green
Write-Host '  Table                WindowsEvents' -ForegroundColor Green
Write-Host $sep -ForegroundColor Green
if ($dcProvisionOk) {
    Write-Host '  DC provisioned       AD objects + WinLogBeat installed [OK]' -ForegroundColor Green
    Write-Host '  Wait ~30 s then query Kustainer:' -ForegroundColor Green
    Write-Host '    WindowsEvents | take 10' -ForegroundColor Green
} elseif ($DC_HOST) {
    Write-Host '  DC provisioning      FAILED - check errors above and re-run setup.ps1' -ForegroundColor Yellow
    Write-Host '  Manual fallback: copy winlogbeat-dc.zip to the DC and run:' -ForegroundColor Yellow
    Write-Host ('    .\setup-dc.ps1 -Phase2 -LogstashHost ' + $hostIP) -ForegroundColor Yellow
    Write-Host ('    .\install-winlogbeat.ps1 -LogstashHost ' + $hostIP) -ForegroundColor Yellow
} else {
    Write-Host '  Windows DC steps (run as Administrator on the DC):' -ForegroundColor Green
    Write-Host '   1.  Copy winlogbeat-dc.zip to the DC and extract it' -ForegroundColor Green
    Write-Host ('   2.  Run:  .\setup-dc.ps1 -Phase2 -LogstashHost ' + $hostIP) -ForegroundColor Green
    Write-Host ('   3.  Run:  .\install-winlogbeat.ps1 -LogstashHost ' + $hostIP) -ForegroundColor Green
    Write-Host '   4.  Wait ~30 s, then in Kustainer:' -ForegroundColor Green
    Write-Host '         WindowsEvents | take 10' -ForegroundColor Green
    Write-Host '  Tip: add DC_HOST=<ip> to .env and re-run to automate DC provisioning.' -ForegroundColor Green
}
Write-Host $sep -ForegroundColor Green
Write-Host '  Useful commands:' -ForegroundColor Green
Write-Host '   docker logs -f logstash   -- watch Logstash output' -ForegroundColor Green
Write-Host '   docker logs -f adx        -- watch Kustainer output' -ForegroundColor Green
Write-Host '   .\teardown.ps1            -- stop the stack' -ForegroundColor Green
Write-Host '   .\teardown.ps1 --purge    -- stop + wipe all ingested data' -ForegroundColor Green
Write-Host $sep -ForegroundColor Green
Write-Host ''
