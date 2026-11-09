//! One-shot "boot this stick next" via a temporary Boot#### entry + BootNext.
//! The entry is never added to BootOrder and is removed on the next start.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use uefi_raw::{Guid, guid};

use crate::efi::Efi;

const GLOBAL_VARIABLE: Guid = guid!("8be4df61-93ca-11d2-aa0d-00e098032b8c");
const FIRST_SLOT: u16 = 0x2E00;
const SLOT_RANGE: u16 = 0x100;
const LOAD_OPTION_ACTIVE: u32 = 0x1;
const DESCRIPTION: &str = "routecfg memory test";
const SELF_PATH: &str = "\\EFI\\BOOT\\BOOTX64.EFI";

fn option_name(slot: u16) -> String {
    format!("Boot{slot:04X}")
}

fn description_utf16() -> Vec<u8> {
    DESCRIPTION.encode_utf16().chain(core::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}

fn is_ours(option: &[u8]) -> bool {
    let desc = description_utf16();
    option.get(6..6 + desc.len()) == Some(desc.as_slice())
}

/// Creates a temporary boot entry for this stick and points BootNext at it.
pub fn schedule_self(efi: &Efi) -> Result<u16, String> {
    let slot = (FIRST_SLOT..FIRST_SLOT + SLOT_RANGE)
        .find(|&n| efi.get_variable(&option_name(n), &GLOBAL_VARIABLE).is_err())
        .ok_or("no free Boot#### slot")?;
    let path = efi.file_device_path(SELF_PATH)?;
    let path_len = u16::try_from(path.len()).map_err(|_| "device path too long")?;

    let mut option = Vec::new();
    option.extend_from_slice(&LOAD_OPTION_ACTIVE.to_le_bytes());
    option.extend_from_slice(&path_len.to_le_bytes());
    option.extend_from_slice(&description_utf16());
    option.extend_from_slice(&path);

    efi.set_variable(&option_name(slot), &GLOBAL_VARIABLE, &option)?;
    if let Err(e) = efi.set_variable("BootNext", &GLOBAL_VARIABLE, &slot.to_le_bytes()) {
        let _ = efi.delete_variable(&option_name(slot), &GLOBAL_VARIABLE);
        return Err(e);
    }
    Ok(slot)
}

/// Removes the temporary entry (only if it is ours) and any BootNext still pointing at it.
pub fn remove_entry(efi: &Efi, slot: u16) -> Result<(), String> {
    if let Ok(next) = efi.get_variable("BootNext", &GLOBAL_VARIABLE) {
        if next.get(..2) == Some(slot.to_le_bytes().as_slice()) {
            efi.delete_variable("BootNext", &GLOBAL_VARIABLE)?;
        }
    }
    match efi.get_variable(&option_name(slot), &GLOBAL_VARIABLE) {
        Ok(option) if is_ours(&option) => efi.delete_variable(&option_name(slot), &GLOBAL_VARIABLE),
        Ok(_) => Err(format!("{} is not a routecfg entry; left untouched", option_name(slot))),
        Err(_) => Ok(()),
    }
}
