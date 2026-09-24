#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Runs Audit AFTER following the reboot performed by the first script.

.DESCRIPTION
    Reads C:\HKLab\HardeningKitty-Win10-State.json and audits exactly the same
    finding lists used by 01-Win10-HardeningKitty-Before-Hardening.ps1.
#>

[CmdletBinding()]
param(
    [string]$StateFile = 'C:\HKLab\HardeningKitty-Win10-State.json',
    [switch]$AllowDifferentComputer,
    [switch]$AllowDifferentUser,
    [switch]$AllowVersionMismatch
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-WindowsInformation {
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

function Import-HardeningKittyModule {
    param([Parameter(Mandatory = $true)][string]$Root)

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Directory not found: $Root"
    }

    $ModulePath = Join-Path $Root 'HardeningKitty.psd1'
    if (-not (Test-Path -LiteralPath $ModulePath -PathType Leaf)) {
        throw "Module manifest not found: $ModulePath"
    }

    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
    Get-ChildItem -LiteralPath $Root -Recurse -File | Unblock-File
    Import-Module -Name $ModulePath -Force -ErrorAction Stop
    Get-Command -Name Invoke-HardeningKitty -ErrorAction Stop | Out-Host
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

if (-not (Test-Path -LiteralPath $StateFile -PathType Leaf)) {
    throw (
        "State file not found: $StateFile. Run " +
        '01-Win10-HardeningKitty-Before-Hardening.ps1 first.'
    )
}

$State = Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json
$WindowsInfo = Get-WindowsInformation

if (($State.ComputerName -ne $env:COMPUTERNAME) -and (-not $AllowDifferentComputer)) {
    throw (
        "The first script ran on '$($State.ComputerName)', but this computer " +
        "is '$env:COMPUTERNAME'."
    )
}

$CurrentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if (($State.UserName -ne $CurrentUser) -and (-not $AllowDifferentUser)) {
    throw (
        "The first script ran as '$($State.UserName)', but this script is " +
        "running as '$CurrentUser'. USER-list results would target a different HKCU."
    )
}

if (([int]$State.Build -ne $WindowsInfo.Build) -and (-not $AllowVersionMismatch)) {
    throw (
        "The first script recorded build $($State.Build), but the current " +
        "build is $($WindowsInfo.Build)."
    )
}

$HardeningKittyRoot = [string]$State.HardeningKittyRoot
$HKLabRoot = [string]$State.HKLabRoot
$ReportAfter = Join-Path $HKLabRoot 'Reports_After'
$ListsDirectory = Join-Path $HardeningKittyRoot 'lists'

New-Item -Path $ReportAfter -ItemType Directory -Force | Out-Null

Set-Location -LiteralPath $HardeningKittyRoot
Import-HardeningKittyModule -Root $HardeningKittyRoot

$ResolvedLists = foreach ($Name in @($State.FindingListNames)) {
    Get-Item -LiteralPath (Join-Path $ListsDirectory ([string]$Name)) -ErrorAction Stop
}
$Lists = [System.IO.FileInfo[]]$ResolvedLists

Write-Host 'Auditing the same finding lists used before reboot:' -ForegroundColor Cyan
$Lists | Select-Object Name,FullName | Format-Table -AutoSize

foreach ($File in $Lists) {
    Write-Host "Auditing AFTER: $($File.Name)" -ForegroundColor Green

    $LogPath = Join-Path $ReportAfter "$($File.BaseName).log"
    $ReportPath = Join-Path $ReportAfter "$($File.BaseName).csv"
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

Write-Host ''
Write-Host 'Audit AFTER completed successfully.' -ForegroundColor Green
Write-Host "AFTER reports: $ReportAfter"

Get-ChildItem -LiteralPath $ReportAfter -File |
    Select-Object Name,Length,LastWriteTime |
    Sort-Object Name |
    Format-Table -AutoSize