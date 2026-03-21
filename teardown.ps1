#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stop the Windows Event Log → Kustainer pipeline.

.PARAMETER Purge
    Stop containers AND permanently delete .\data\ (irreversible).

.EXAMPLE
    .\teardown.ps1              # stop containers, keep data
    .\teardown.ps1 --purge      # stop containers and wipe data
#>
param(
    [switch]$Purge
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

Write-Host 'Stopping docker compose services ...' -ForegroundColor Cyan
docker compose down

if ($Purge) {
    Write-Host ''
    Write-Host 'WARNING: --purge will permanently delete all Kustainer data in .\data\' -ForegroundColor Yellow
    $confirm = Read-Host 'Are you sure? [y/N]'
    if ($confirm -match '^[Yy]$') {
        Write-Host 'Purging .\data\ ...' -ForegroundColor Cyan
        Remove-Item -Path (Join-Path $ScriptDir 'data\*') -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host 'Data purged.' -ForegroundColor Green
    } else {
        Write-Host 'Purge cancelled — data is intact.' -ForegroundColor Green
    }
}

Write-Host 'Teardown complete.' -ForegroundColor Green
