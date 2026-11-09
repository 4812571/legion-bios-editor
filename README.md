# legion-bios-editor

Set the DDR5 memory speed on a **Lenovo Legion 5 15AGP11** (AMD, Insyde H2O firmware), where the BIOS memory-speed option doesn't stick.

> ⚠️ **Use at your own risk.** This writes firmware settings on real hardware. It uses the firmware's own save path and only changes two bytes, but a bad memory setting can leave the machine retraining or falling back to defaults. It has been tested on **one** machine running BIOS **T3CN37WW**. Other models or BIOS versions will have different offsets, and the tool refuses to write if its checks don't match.

## The problem

The hidden advanced BIOS menu (Fn+R+N in setup) exposes AMD CBS → UMC → DDR Options → *Memory Target Speed*, but saving it has no effect: the value reverts to Auto and memory keeps training at the DIMMs' rated speed. Disassembling the firmware shows that only the CBS driver's HII **RouteConfig** handler turns a CBS change into the APCB data the memory-training firmware reads, and the setup UI's save never reaches it with the change.

## How `routecfg` works

`routecfg` is a small UEFI application, written in Rust against `uefi-raw` only. It:

1. Locates `EFI_HII_CONFIG_ROUTING_PROTOCOL`.
2. Calls `ExtractConfig` for the CBS `AmdSetup` storage, using the CBS driver's exact config header (GUID, name and vendor device path).
3. Parses the per-question `OFFSET/WIDTH/VALUE` response itself. The firmware's `ConfigToBlock` rejects responses containing `ALTCFG` sections.
4. **Refuses to write** unless every parsed element matches the live `AmdSetup` variable byte for byte, and the request would touch only bytes `0x58..0x5A`.
5. Calls `RouteConfig` with a minimal request: `0x58` = timing mode (`01` = manual, `FF` = auto) and `0x59` = target speed in MT/s. The CBS driver applies it onto its in-memory copy, saves the variable, and pushes the block to SMM, which updates the APCB.
6. Reads the variable back and reports every changed byte.

On the next boot the memory retrains (expect a long black screen) at the new speed.

## Usage

Boot the USB stick (Secure Boot off, F12 boot menu). It opens a menu that shows:
- the current CBS setting;
- the running memory speed (when the firmware reports it);
- the CMOS APCB-recovery marker;
- the last action.

Options: **4800**, **5200**, custom speed, restore **Auto**, memory test, status/history, UEFI shell, reboot, power off. The memory test launches [Memtest86+](https://memtest.org) from `EFI\tools\memtest.efi`, which `make-usb.ps1` downloads for you.

**Apply + test.** After a successful apply, choose **[T] Reboot + memory test**:
1. routecfg creates a temporary `Boot2Exx` entry for the stick. It's not added to `BootOrder`.
2. It sets the one-shot `BootNext` variable and leaves a marker in `\routecfg\pending.txt`.
3. It reboots. The memory retrains at the new speed, and the firmware boots the stick again.
4. routecfg deletes the marker and its boot entry, only touching an entry with its own description. It logs the setting and running speed to `history.txt`, then starts Memtest86+ after a 5-second countdown. Any key returns to the menu.

If the firmware rejects the boot variables, it says so; pick the stick with F12 after the reboot and the test still runs.

From a UEFI shell:

```
routecfg.efi                 # menu
routecfg.efi read            # read-only diagnostics
routecfg.efi apply [speed]   # manual speed (default 4800)
routecfg.efi auto            # back to stock
```

Output and history are written to `\routecfg\` on the stick.

## Build

```powershell
rustup target add x86_64-unknown-uefi
.\routecfg\build.ps1
# -> routecfg\target\x86_64-unknown-uefi\release\routecfg.efi
```

`build.ps1` is a plain release build with `--remap-path-prefix`, so the binary doesn't embed your home directory. Plain `cargo build` leaks it through dependency panic-location strings. Run it from PowerShell: in Git Bash, `link` resolves to coreutils.

No host C toolchain is needed: there are no proc-macros or build scripts, and the UEFI target links with the bundled `rust-lld`. Note that `uefi-raw` 0.14 declares `ConfigToBlock`'s `Block` parameter as `*mut *const u8`. The spec type is `UINT8 *`, so this project defines its own protocol struct.

### USB stick

```powershell
Get-Disk   # find your stick's number and FriendlyName
# elevated PowerShell:
.\tools\make-usb.ps1 -DiskNumber 1 -ExpectedName 'SanDisk Cruzer Glide' `
    -RouteCfg .\routecfg\target\x86_64-unknown-uefi\release\routecfg.efi -Shell .\shellx64.efi
```

`make-usb.ps1` **erases** the disk and lays out:
- `EFI\BOOT\BOOTX64.EFI`: routecfg;
- `EFI\tools\memtest.efi`: Memtest86+;
- `EFI\tools\shell.efi`: optional, a UEFI shell such as pbatard's UEFI-Shell builds.

It requires the disk number and name, and refuses non-USB, boot or system disks.

Memtest86+ is **not redistributed by this repo**. The script downloads the official `mt86plus_9.00.binaries.zip` from memtest.org and checks it against the SHA-256 published in memtest.org's `sha256sum.txt`. That all happens **before** the disk is erased, and a mismatch aborts. Options:
- `-MemTest <file>` uses a local binary instead;
- `-NoMemTest` skips it;
- `-FetchOnly <dir>` only downloads and verifies, needing no admin rights and touching no disk.

Memtest86+ is GPL-2.0 and is a separate program; routecfg just launches it.

## Analysis tools (`tools/`)

These are Python helpers used to reverse-engineer the firmware. They expect a working directory containing an extracted image: `bios/t3.bin` plus the LZMA-decompressed DXE volume at `bios/lz/b1.bin`.

| Script | Purpose |
|---|---|
| `ifr.py`, `ifrdump.py` | Parse HII string/form packages; dump forms with suppress/grayout conditions |
| `fw.py` | Find the PE image enclosing an offset |
| `fwdis.py` | PE loader + Capstone disassembly with RIP-relative string annotation |
| `dumpmod.py`, `summ.py` | Disassemble the functions referencing given UTF-16 strings; condensed call/string summaries |

Module offsets in the scripts are specific to T3CN37WW.

## Not included

This repo contains no firmware images, flash dumps, vendor tools or disassembly of vendor code. Flash dumps contain machine-specific data (serials, UUIDs, MAC addresses, embedded product keys), and vendor binaries are copyrighted.

## License

MIT. See [LICENSE](LICENSE).
