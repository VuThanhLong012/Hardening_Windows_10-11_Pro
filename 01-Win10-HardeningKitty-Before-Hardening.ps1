#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Audit BEFORE, backup, HailMary, and restart for Windows 10 22H2.

.NOTES
    Create a VMware snapshot before running this script.
    The 0x6d69636b lists target Windows 11 25H2 and are excluded by default.
#>

[CmdletBinding()]
param(
    [string]$HardeningKittyRoot = 'C:\Lab\HardeningKitty',
    [string]$HKLabRoot = 'C:\HKLab',
    [switch]$SnapshotCreated,
    [switch]$CurrentUserConfirmed,
    [switch]$IncludeIncompatible0xLists,
    [switch]$AllowVersionMismatch,
    [switch]$SkipRestart
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Assert-WindowsVersion {
    $CV = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $Build = [int]$CV.CurrentBuildNumber
    Write-Host "Detected OS: $($CV.ProductName) $($CV.DisplayVersion), build $Build" -ForegroundColor Cyan

    if (($Build -ne 19045) -and (-not $AllowVersionMismatch)) {
        throw "Windows 10 22H2 build 19045 is required. Detected build: $Build."
    }

    return [pscustomobject]@{
        ProductName = [string]$CV.ProductName
        DisplayVersion = [string]$CV.DisplayVersion
        Build = $Build
    }
}

function Confirm-VMwareSnapshot {
    if ($SnapshotCreated) {
        return
    }

    Write-Warning 'This script cannot create a VMware snapshot from inside Windows.'
    $Answer = Read-Host 'Create BEFORE-HARDENINGKITTY, then type YES'
    if ($Answer -cne 'YES') {
        throw 'Snapshot was not confirmed. No hardening changes were made.'
    }
}

function Confirm-CurrentUser {
    $IdentityName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    Write-Warning "USER finding lists affect HKCU for: $IdentityName"

    if ($CurrentUserConfirmed) {
        return
    }

    $Answer = Read-Host 'Type YES if this is the intended daily user account'
    if ($Answer -cne 'YES') {
        throw 'The current user context was not confirmed.'
    }
}

function Import-HardeningKittyModule {
    if (-not (Test-Path -LiteralPath $HardeningKittyRoot -PathType Container)) {
        throw "Directory not found: $HardeningKittyRoot"
    }

    $ModulePath = Join-Path $HardeningKittyRoot 'HardeningKitty.psd1'
    if (-not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
        throw "Module manifest not found: $ModulePath"
    }

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Get-ChildItem -LiteralPath $HardeningKittyRoot -Recurse -File | Unblock-File
    Import-Module -Name $ModulePath -Force -ErrorAction Stop
    Get-Command -Name Invoke-HardeningKitty -ErrorAction Stop | Out-Host
}

function Get-FindingLists {
    $Names = @(
        # Microsoft first.
        'finding_list_msft_security_baseline_windows_10_22h2_machine.csv'
        'finding_list_msft_security_baseline_windows_10_22h2_user.csv'

        # CIS last, so CIS values win when settings conflict.
        'finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_machine.csv'
        'finding_list_cis_microsoft_windows_10_enterprise_22h2_3.0.0_user.csv'
    )

    if ($IncludeIncompatible0xLists) {
        Write-Warning 'The 0x6d69636b lists target Windows 11 25H2, not Windows 10.'
        $Answer = Read-Host 'Type INCLUDE-0X to accept this version mismatch'
        if ($Answer -cne 'INCLUDE-0X') {
            throw 'The incompatible 0x lists were not confirmed.'
        }

        $Names = @(
            'finding_list_0x6d69636b_machine.csv'
            'finding_list_0x6d69636b_user.csv'
        ) + $Names
    }

    $ListsDirectory = Join-Path $HardeningKittyRoot 'lists'
    $Items = foreach ($Name in $Names) {
        Get-Item -LiteralPath (Join-Path $ListsDirectory $Name) -ErrorAction Stop
    }

    return [System.IO.FileInfo[]]$Items
}

function Assert-File {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Expected file was not created: $Path"
    }
    if ((Get-Item -LiteralPath $Path).Length -eq 0) {
        throw "Expected file is empty: $Path"
    }
}

function Invoke-Audits {
    param(
        [System.IO.FileInfo[]]$FindingLists,
        [string]$OutputDirectory,
        [string]$Stage,
        [System.ConsoleColor]$Color
    )

    foreach ($File in $FindingLists) {
        Write-Host ('Auditing {0}: {1}' -f $Stage, $File.Name) -ForegroundColor $Color
        $LogPath = Join-Path $OutputDirectory "$($File.BaseName).log"
        $ReportPath = Join-Path $OutputDirectory "$($File.BaseName).csv"
        $Parameters = @{
            Mode = 'Audit'
            FileFindingList = $File.FullName
            Log = $true
            LogFile = $LogPath
            Report = $true
            ReportFile = $ReportPath
        }

        Invoke-HardeningKitty @Parameters
        Assert-File -Path $LogPath
        Assert-File -Path $ReportPath
    }
}

function Invoke-Backups {
    param([System.IO.FileInfo[]]$FindingLists, [string]$OutputDirectory)

    foreach ($File in $FindingLists) {
        Write-Host "Backing up: $($File.Name)" -ForegroundColor Yellow
        $BackupPath = Join-Path $OutputDirectory "$($File.BaseName).csv"
        $Parameters = @{
            Mode = 'Config'
            Backup = $true
            BackupFile = $BackupPath
            FileFindingList = $File.FullName
        }

        Invoke-HardeningKitty @Parameters
        Assert-File -Path $BackupPath
    }
}

function Invoke-Hardening {
    param([System.IO.FileInfo[]]$FindingLists, [string]$OutputDirectory)

    foreach ($File in $FindingLists) {
        Write-Host "Hardening: $($File.Name)" -ForegroundColor Red
        $LogPath = Join-Path $OutputDirectory "$($File.BaseName).log"
        $ReportPath = Join-Path $OutputDirectory "$($File.BaseName).csv"
        $Parameters = @{
            Mode = 'HailMary'
            FileFindingList = $File.FullName
            SkipRestorePoint = $true
            Log = $true
            LogFile = $LogPath
            Report = $true
            ReportFile = $ReportPath
        }

        Invoke-HardeningKitty @Parameters
        Assert-File -Path $LogPath
        Assert-File -Path $ReportPath
    }
}

$WindowsInfo = Assert-WindowsVersion
Confirm-VMwareSnapshot
Confirm-CurrentUser

$ReportBefore = Join-Path $HKLabRoot 'Reports_Before'
$ReportHardening = Join-Path $HKLabRoot 'Reports_Hardening'
$ReportAfter = Join-Path $HKLabRoot 'Reports_After'
$BackupDirectory = Join-Path $HKLabRoot 'Backup'
$StateFile = Join-Path $HKLabRoot 'HardeningKitty-Win10-State.json'

foreach ($Directory in @(
    $HKLabRoot,
    $ReportBefore,
    $ReportHardening,
    $ReportAfter,
    $BackupDirectory
)) {
    New-Item -Path $Directory -ItemType Directory -Force | Out-Null
}

Set-Location -LiteralPath $HardeningKittyRoot
Import-HardeningKittyModule
$Lists = Get-FindingLists

Write-Host 'Finding lists, in application order:' -ForegroundColor Cyan
$Lists | Select-Object Name,FullName | Format-Table -AutoSize

$State = [ordered]@{
    SchemaVersion = 1
    CreatedAt = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    UserName = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    ProductName = $WindowsInfo.ProductName
    DisplayVersion = $WindowsInfo.DisplayVersion
    Build = $WindowsInfo.Build
    HardeningKittyRoot = $HardeningKittyRoot
    HKLabRoot = $HKLabRoot
    FindingListNames = @($Lists.Name)
    IncludedIncompatible0xLists = [bool]$IncludeIncompatible0xLists
}

$State | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StateFile -Encoding UTF8
Assert-File -Path $StateFile

Invoke-Audits -FindingLists $Lists -OutputDirectory $ReportBefore -Stage 'BEFORE' -Color Cyan
Invoke-Backups -FindingLists $Lists -OutputDirectory $BackupDirectory
Invoke-Hardening -FindingLists $Lists -OutputDirectory $ReportHardening

Write-Host ''
Write-Host 'Hardening completed successfully.' -ForegroundColor Green
Write-Host "State file: $StateFile"
Write-Host "BEFORE reports: $ReportBefore"
Write-Host "Backups: $BackupDirectory"
Write-Host "Hardening reports: $ReportHardening"
Write-Host 'After reboot, run 02-Win10-HardeningKitty-Audit-After.ps1.' -ForegroundColor Yellow

if ($SkipRestart) {
    Write-Warning 'Restart was skipped. Restart Windows before running the AFTER script.'
    return
}

Restart-Computer