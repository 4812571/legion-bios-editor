<#
.SYNOPSIS
    ERASES a USB disk and turns it into a UEFI boot stick for routecfg.

.DESCRIPTION
    Wipes ALL data on the given disk, creates one FAT32 partition (MBR, up to
    32 GB), and copies routecfg.efi to EFI\BOOT\BOOTX64.EFI.

    Memtest86+ is downloaded from memtest.org (pinned version, SHA-256 checked)
    and placed at EFI\tools\memtest.efi, where the routecfg menu launches it.
    It is fetched and verified BEFORE the disk is touched. Use -MemTest to supply
    a local binary instead, or -NoMemTest to skip it. An optional UEFI shell goes
    to EFI\tools\shell.efi.

    Refuses to run unless the disk number AND its friendly name match, and the
    disk is a non-boot, non-system USB disk. Check with Get-Disk first.

    -FetchOnly <dir> only downloads and verifies Memtest86+ into <dir>; no disk
    is touched and no admin rights are needed.

.EXAMPLE
    Get-Disk
    .\make-usb.ps1 -DiskNumber 1 -ExpectedName 'SanDisk Cruzer Glide' -RouteCfg ..\routecfg\target\x86_64-unknown-uefi\release\routecfg.efi -Shell .\shellx64.efi

.EXAMPLE
    .\make-usb.ps1 -FetchOnly .\memtest
#>
[CmdletBinding(DefaultParameterSetName = 'Usb')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Usb')] [int] $DiskNumber,
    [Parameter(Mandatory, ParameterSetName = 'Usb')] [string] $ExpectedName,
    [Parameter(Mandatory, ParameterSetName = 'Usb')] [string] $RouteCfg,
    [Parameter(ParameterSetName = 'Usb')] [string] $Shell,
    [Parameter(ParameterSetName = 'Usb')] [string] $MemTest,
    [Parameter(ParameterSetName = 'Usb')] [switch] $NoMemTest,
    [Parameter(Mandatory, ParameterSetName = 'Fetch')] [string] $FetchOnly
)

$ErrorActionPreference = 'Stop'

$MemTestVersion = '9.00'
$MemTestZipUrl = "https://memtest.org/download/v$MemTestVersion/mt86plus_$MemTestVersion.binaries.zip"
$MemTestZipSha256 = '7b2e294c5f30ddc8a01bbfce0dba7370765a867b745e0494ff811de4463eeb5d'
$MemTestZipEntry = 'mt86p_' + $MemTestVersion.Replace('.', '') + '_x86_64'

function Get-MemTest {
    param([Parameter(Mandatory)] [string] $Destination)

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $work = Join-Path ([IO.Path]::GetTempPath()) ("make-usb-" + [Guid]::NewGuid())
    New-Item -ItemType Directory -Path $work | Out-Null
    try {
        $zip = Join-Path $work 'memtest.zip'
        Write-Host "Downloading Memtest86+ $MemTestVersion from $MemTestZipUrl"
        Invoke-WebRequest -Uri $MemTestZipUrl -OutFile $zip -UseBasicParsing
        $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $MemTestZipSha256) {
            throw "Memtest86+ download hash mismatch: got $actual, expected $MemTestZipSha256. Aborting."
        }
        Expand-Archive -Path $zip -DestinationPath (Join-Path $work 'x')
        $binary = Join-Path $work "x\$MemTestZipEntry"
        if (-not (Test-Path $binary)) { throw "'$MemTestZipEntry' not found in the Memtest86+ archive." }
        Copy-Item $binary $Destination -Force
        Write-Host "Memtest86+ $MemTestVersion verified (zip SHA-256 $actual) -> $Destination"
    } finally {
        Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($PSCmdlet.ParameterSetName -eq 'Fetch') {
    New-Item -ItemType Directory -Path $FetchOnly -Force | Out-Null
    Get-MemTest -Destination (Join-Path $FetchOnly 'memtest.efi')
    return
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { throw 'Run this from an elevated PowerShell (it partitions a disk).' }

$disk = Get-Disk -Number $DiskNumber
if ($disk.FriendlyName -ne $ExpectedName -or $disk.BusType -ne 'USB' -or $disk.IsBoot -or $disk.IsSystem) {
    throw "Disk $DiskNumber is '$($disk.FriendlyName)' ($($disk.BusType), boot=$($disk.IsBoot), system=$($disk.IsSystem)); expected USB disk '$ExpectedName'. Aborting."
}
foreach ($f in @($RouteCfg) + @($Shell, $MemTest | Where-Object { $_ })) {
    if (-not (Test-Path $f)) { throw "File not found: $f" }
}

$staged = $null
if (-not $NoMemTest) {
    if ($MemTest) {
        $staged = $MemTest
    } else {
        $staged = Join-Path ([IO.Path]::GetTempPath()) ("memtest-" + [Guid]::NewGuid() + '.efi')
        Get-MemTest -Destination $staged
    }
}

try {
    Clear-Disk -Number $DiskNumber -RemoveData -RemoveOEM -Confirm:$false
    $disk = Get-Disk -Number $DiskNumber
    if ($disk.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $DiskNumber -PartitionStyle MBR }
    elseif ($disk.PartitionStyle -ne 'MBR') { Set-Disk -Number $DiskNumber -PartitionStyle MBR }

    $size = [Math]::Min(32GB, $disk.Size - 1MB)
    $volume = New-Partition -DiskNumber $DiskNumber -Size $size -IsActive -AssignDriveLetter |
        Format-Volume -FileSystem FAT32 -NewFileSystemLabel UEFISHELL -Confirm:$false
    $root = "$($volume.DriveLetter):\"

    New-Item -ItemType Directory -Path (Join-Path $root 'EFI\BOOT') -Force | Out-Null
    Copy-Item $RouteCfg (Join-Path $root 'EFI\BOOT\BOOTX64.EFI')
    Copy-Item $RouteCfg (Join-Path $root 'routecfg.efi')
    if ($Shell -or $staged) {
        New-Item -ItemType Directory -Path (Join-Path $root 'EFI\tools') -Force | Out-Null
    }
    if ($Shell) { Copy-Item $Shell (Join-Path $root 'EFI\tools\shell.efi') }
    if ($staged) { Copy-Item $staged (Join-Path $root 'EFI\tools\memtest.efi') }

    Get-ChildItem $root -Recurse -File | Select-Object FullName, Length | Format-Table -AutoSize
} finally {
    if ($staged -and -not $MemTest) { Remove-Item $staged -Force -ErrorAction SilentlyContinue }
}
