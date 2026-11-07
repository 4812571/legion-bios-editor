#Requires -RunAsAdministrator
<#
.SYNOPSIS
    ERASES a USB disk and turns it into a UEFI boot stick for routecfg.

.DESCRIPTION
    Wipes ALL data on the given disk, creates one FAT32 partition (MBR, up to
    32 GB), and copies routecfg.efi to EFI\BOOT\BOOTX64.EFI. If a UEFI shell is
    given, it is copied to EFI\tools\shell.efi (launched from the routecfg menu).

    Refuses to run unless the disk number AND its friendly name match, and the
    disk is a non-boot, non-system USB disk. Check with Get-Disk first.

.EXAMPLE
    Get-Disk
    .\make-usb.ps1 -DiskNumber 1 -ExpectedName 'SanDisk Cruzer Glide' -RouteCfg ..\routecfg\target\x86_64-unknown-uefi\release\routecfg.efi -Shell .\shellx64.efi
#>
param(
    [Parameter(Mandatory)] [int] $DiskNumber,
    [Parameter(Mandatory)] [string] $ExpectedName,
    [Parameter(Mandatory)] [string] $RouteCfg,
    [string] $Shell
)

$ErrorActionPreference = 'Stop'

$disk = Get-Disk -Number $DiskNumber
if ($disk.FriendlyName -ne $ExpectedName -or $disk.BusType -ne 'USB' -or $disk.IsBoot -or $disk.IsSystem) {
    throw "Disk $DiskNumber is '$($disk.FriendlyName)' ($($disk.BusType), boot=$($disk.IsBoot), system=$($disk.IsSystem)); expected USB disk '$ExpectedName'. Aborting."
}
foreach ($f in @($RouteCfg) + @($Shell | Where-Object { $_ })) {
    if (-not (Test-Path $f)) { throw "File not found: $f" }
}

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
if ($Shell) {
    New-Item -ItemType Directory -Path (Join-Path $root 'EFI\tools') -Force | Out-Null
    Copy-Item $Shell (Join-Path $root 'EFI\tools\shell.efi')
}

Get-ChildItem $root -Recurse -File | Select-Object FullName, Length | Format-Table -AutoSize
