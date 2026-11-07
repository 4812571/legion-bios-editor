//! HII `<ConfigResp>` element parsing and rendering.
//!
//! VALUE strings are the element's bytes in reverse order (EDK2 convention),
//! verified against a live `AmdSetup` read on the target laptop.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

pub struct Element {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

/// Parses the OFFSET/WIDTH/VALUE triples of the first config section, stopping
/// at the next `&GUID=` (where ALTCFG default sections begin).
pub fn parse_main_section(resp: &str) -> Result<Vec<Element>, String> {
    let lower = resp.to_ascii_lowercase();
    let body_start = lower.find("&offset=").ok_or("no OFFSET elements in response")?;
    let body = &lower[body_start..];
    let body = match body.find("&guid=") {
        Some(end) => &body[..end],
        None => body,
    };

    let mut elements = Vec::new();
    let mut fields = body.split('&').filter(|f| !f.is_empty());
    while let Some(f) = fields.next() {
        let offset = field(f, "offset=")?;
        let width = field(fields.next().ok_or("truncated element (WIDTH)")?, "width=")?;
        let value = fields.next().ok_or("truncated element (VALUE)")?;
        let hex = value.strip_prefix("value=").ok_or_else(|| format!("expected VALUE, got '{value}'"))?;
        let mut bytes = hex_bytes(hex)?;
        if bytes.len() != width {
            return Err(format!("element at {offset:#x}: WIDTH {width} but VALUE has {} bytes", bytes.len()));
        }
        bytes.reverse();
        elements.push(Element { offset, bytes });
    }
    Ok(elements)
}

pub fn render_elements(elements: &[Element]) -> String {
    let mut out = String::new();
    for e in elements {
        let value: String = e.bytes.iter().rev().map(|b| format!("{b:02x}")).collect();
        out.push_str(&format!("&OFFSET={:04x}&WIDTH={:04x}&VALUE={value}", e.offset, e.bytes.len()));
    }
    out
}

pub fn apply_elements(block: &mut [u8], elements: &[Element]) -> Result<(), String> {
    for e in elements {
        let dst = block
            .get_mut(e.offset..e.offset + e.bytes.len())
            .ok_or_else(|| format!("element at {:#x} is outside the block", e.offset))?;
        dst.copy_from_slice(&e.bytes);
    }
    Ok(())
}

fn field(f: &str, key: &str) -> Result<usize, String> {
    let hex = f.strip_prefix(key).ok_or_else(|| format!("expected {key}, got '{f}'"))?;
    usize::from_str_radix(hex, 16).map_err(|_| format!("bad hex in '{f}'"))
}

fn hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if hex.len() % 2 != 0 {
        return Err(format!("odd-length VALUE '{hex}'"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| format!("bad hex in VALUE '{hex}'")))
        .collect()
}
