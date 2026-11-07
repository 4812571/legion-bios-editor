use alloc::string::String;
use alloc::vec::Vec;

use crate::efi::Efi;

const FILE: &str = "history.txt";

pub fn append(efi: &Efi, line: &str) {
    let mut data = efi.read_file(FILE).unwrap_or_default();
    data.extend_from_slice(line.as_bytes());
    data.extend_from_slice(b"\r\n");
    efi.save(FILE, &data);
}

pub fn recent(efi: &Efi, count: usize) -> Vec<String> {
    let Some(data) = efi.read_file(FILE) else { return Vec::new() };
    let text = String::from_utf8_lossy(&data);
    let lines: Vec<String> = text.lines().filter(|l| !l.trim().is_empty()).map(String::from).collect();
    let skip = lines.len().saturating_sub(count);
    lines.into_iter().skip(skip).collect()
}
