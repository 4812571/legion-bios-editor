//! AMD CBS `AmdSetup` access through the HII ConfigRouting protocol.
//!
//! Writes go through the CBS driver's own RouteConfig, which updates its
//! in-memory copy, saves the variable and pushes the block to SMM (APCB).

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;

use uefi_raw::{Guid, Status, guid};

use crate::config::{Element, apply_elements, parse_main_section, render_elements};
use crate::efi::{self, Efi, println};

const ROUTING_GUID: Guid = guid!("587e72d7-cc50-4f79-8209-ca291fc1a10f");
const AMD_SETUP_GUID: Guid = guid!("3a997502-647a-4c82-998e-52ef9486a247");
const AMD_SETUP_SIZE: usize = 0x670;

pub const OFF_TIMING_MODE: usize = 0x58;
pub const OFF_TARGET_SPEED: usize = 0x59;
const OFF_SYNC_SIG: usize = 0x08;
pub const TIMING_ENABLED: u8 = 0x01;
pub const TIMING_AUTO: u8 = 0xFF;
pub const SPEED_DEFAULT: u16 = 3200;

const CBS_HDR_GUID: &str = "0275993a7a64824c998e52ef9486a247";
const CBS_HDR_NAME: &str = "0041006d006400530065007400750070";
const CBS_HDR_PATH: &str = "010414000275993a7a64824c998e52ef9486a2477fff0400";

#[repr(C)]
struct ConfigRouting {
    extract_config: unsafe extern "efiapi" fn(
        this: *const ConfigRouting,
        request: *const u16,
        progress: *mut *const u16,
        results: *mut *mut u16,
    ) -> Status,
    export_config: unsafe extern "efiapi" fn(this: *const ConfigRouting, results: *mut *mut u16) -> Status,
    route_config: unsafe extern "efiapi" fn(
        this: *const ConfigRouting,
        configuration: *const u16,
        progress: *mut *const u16,
    ) -> Status,
    block_to_config: *const c_void,
    config_to_block: *const c_void,
    get_alt_cfg: *const c_void,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Manual(u16),
    Auto,
}

impl Target {
    fn bytes(self) -> (u8, u16) {
        match self {
            Target::Manual(speed) => (TIMING_ENABLED, speed),
            Target::Auto => (TIMING_AUTO, SPEED_DEFAULT),
        }
    }

    pub fn describe(self) -> String {
        match self {
            Target::Manual(s) => format!("Manual {s} MT/s"),
            Target::Auto => "Auto (stock, sticks' rated speed)".to_string(),
        }
    }

    pub fn tag(self) -> String {
        match self {
            Target::Manual(s) => format!("apply {s}"),
            Target::Auto => "auto".to_string(),
        }
    }
}

pub fn valid_speed(speed: u16) -> bool {
    speed == 2000 || speed == 2400 || ((3200..=12000).contains(&speed) && speed % 200 == 0)
}

#[derive(Clone, Copy)]
pub struct Setting {
    pub timing: u8,
    pub speed: u16,
    pub sig: u32,
}

impl Setting {
    fn from_block(b: &[u8]) -> Setting {
        Setting {
            timing: b[OFF_TIMING_MODE],
            speed: u16::from_le_bytes([b[OFF_TARGET_SPEED], b[OFF_TARGET_SPEED + 1]]),
            sig: u32::from_le_bytes([b[OFF_SYNC_SIG], b[OFF_SYNC_SIG + 1], b[OFF_SYNC_SIG + 2], b[OFF_SYNC_SIG + 3]]),
        }
    }

    pub fn describe(&self) -> String {
        match self.timing {
            TIMING_AUTO => "Auto (stock)".to_string(),
            TIMING_ENABLED => format!("Manual {} MT/s", self.speed),
            other => format!("unknown mode {other:#04x}, speed {}", self.speed),
        }
    }

    pub fn matches(&self, target: Target) -> bool {
        let (timing, speed) = target.bytes();
        self.timing == timing && (timing == TIMING_AUTO || self.speed == speed)
    }
}

pub struct Session<'a> {
    efi: &'a Efi,
    routing: &'a ConfigRouting,
    header: String,
    var: Vec<u8>,
    elements: Vec<Element>,
}

pub struct ApplyReport {
    pub route_status: Status,
    pub after: Setting,
    pub changed: Vec<usize>,
    pub landed: bool,
}

pub fn read_setting(efi: &Efi) -> Result<Setting, String> {
    Ok(Setting::from_block(&read_var(efi)?))
}

impl<'a> Session<'a> {
    /// Reads the variable and the driver's view of it, and checks they agree.
    pub fn open(efi: &'a Efi) -> Result<Session<'a>, String> {
        let routing: &ConfigRouting = unsafe { &*efi.locate_protocol(&ROUTING_GUID)?.cast() };
        let header = format!("GUID={CBS_HDR_GUID}&NAME={CBS_HDR_NAME}&PATH={CBS_HDR_PATH}");
        let var = read_var(efi)?;
        efi.save("var_before.bin", &var);
        let resp = extract(efi, routing, &header)?;
        efi.save("extract.txt", resp.as_bytes());
        let elements = parse_main_section(&resp)?;
        Ok(Session { efi, routing, header, var, elements })
    }

    pub fn setting(&self) -> Setting {
        Setting::from_block(&self.var)
    }

    pub fn element_count(&self) -> usize {
        self.elements.len()
    }

    pub fn mismatches(&self) -> Vec<String> {
        self.elements
            .iter()
            .filter(|e| self.var.get(e.offset..e.offset + e.bytes.len()) != Some(e.bytes.as_slice()))
            .map(|e| format!("offset {:#x} width {}", e.offset, e.bytes.len()))
            .collect()
    }

    fn covers(&self, off: usize) -> bool {
        self.elements.iter().any(|e| e.offset <= off && off < e.offset + e.bytes.len())
    }

    pub fn covers_memory_fields(&self) -> bool {
        self.covers(OFF_TIMING_MODE) && self.covers(OFF_TARGET_SPEED)
    }

    /// Lists the AmdSetup headers the firmware exports (diagnostic).
    pub fn survey_export(&self) -> String {
        let mut results: *mut u16 = ptr::null_mut();
        let status = unsafe { (self.routing.export_config)(self.routing, &mut results) };
        if status.is_error() || results.is_null() {
            return format!("ExportConfig: {status:?}");
        }
        let all = self.efi.take_fw_string(results);
        self.efi.save("export.txt", all.as_bytes());
        let lower = all.to_ascii_lowercase();
        let needle = format!("guid={CBS_HDR_GUID}&name={CBS_HDR_NAME}&path=");
        let paths: Vec<&str> = lower
            .match_indices(&needle)
            .map(|(i, _)| {
                let start = i + needle.len();
                let end = lower[start..].find('&').map_or(lower.len(), |j| start + j);
                &lower[start..end]
            })
            .collect();
        let cbs = paths.iter().filter(|p| **p == CBS_HDR_PATH).count();
        format!("ExportConfig: {} chars, {} AmdSetup header(s), {cbs} with the CBS driver path", all.len(), paths.len())
    }

    /// Writes the memory timing mode and target speed through RouteConfig.
    pub fn apply(&self, target: Target) -> Result<ApplyReport, String> {
        let mismatches = self.mismatches();
        if self.elements.is_empty() || !mismatches.is_empty() || !self.covers_memory_fields() {
            return Err(format!(
                "safety check failed ({} elements, {} mismatches, covers 0x58/0x59: {}). Not writing.",
                self.elements.len(),
                mismatches.len(),
                self.covers_memory_fields()
            ));
        }
        let (timing, speed) = target.bytes();
        let changes = [
            Element { offset: OFF_TIMING_MODE, bytes: vec![timing] },
            Element { offset: OFF_TARGET_SPEED, bytes: speed.to_le_bytes().to_vec() },
        ];
        let config = format!("{}{}", self.header, render_elements(&changes));
        self.efi.save("route.txt", config.as_bytes());

        let mut expected = self.var.clone();
        apply_elements(&mut expected, &parse_main_section(&config)?)?;
        let intended = diff_offsets(&self.var, &expected);
        if intended.iter().any(|&o| !(OFF_TIMING_MODE..=OFF_TARGET_SPEED + 1).contains(&o)) {
            return Err("safety check failed: request would touch bytes other than 0x58..0x5A. Not writing.".to_string());
        }

        let route_status = route(self.routing, &config)?;
        let after_var = read_var(self.efi)?;
        self.efi.save("var_after.bin", &after_var);
        let after = Setting::from_block(&after_var);
        Ok(ApplyReport {
            route_status,
            changed: diff_offsets(&self.var, &after_var),
            landed: after.matches(target),
            after,
        })
    }
}

fn read_var(efi: &Efi) -> Result<Vec<u8>, String> {
    let data = efi.get_variable("AmdSetup", &AMD_SETUP_GUID)?;
    if data.len() != AMD_SETUP_SIZE {
        return Err(format!("AmdSetup is {} bytes, expected {AMD_SETUP_SIZE}", data.len()));
    }
    Ok(data)
}

fn extract(efi: &Efi, routing: &ConfigRouting, header: &str) -> Result<String, String> {
    let req = efi::to_u16z(header);
    let mut progress: *const u16 = ptr::null();
    let mut results: *mut u16 = ptr::null_mut();
    let status = unsafe { (routing.extract_config)(routing, req.as_ptr(), &mut progress, &mut results) };
    if status.is_error() || results.is_null() {
        return Err(format!(
            "ExtractConfig failed: {status:?}, progress at char {}",
            efi::progress_index(&req, progress)
        ));
    }
    Ok(efi.take_fw_string(results))
}

fn route(routing: &ConfigRouting, config: &str) -> Result<Status, String> {
    let cfg16 = efi::to_u16z(config);
    let mut progress: *const u16 = ptr::null();
    let status = unsafe { (routing.route_config)(routing, cfg16.as_ptr(), &mut progress) };
    let at = efi::progress_index(&cfg16, progress);
    println!("RouteConfig: {status:?}, progress at char {at} of {}", cfg16.len() - 1);
    if status.is_error() {
        let tail: String = config.chars().skip(at).take(80).collect();
        return Err(format!("RouteConfig failed: {status:?} near '{tail}'"));
    }
    Ok(status)
}

pub fn diff_offsets(a: &[u8], b: &[u8]) -> Vec<usize> {
    a.iter().zip(b).enumerate().filter(|(_, (x, y))| x != y).map(|(i, _)| i).collect()
}

pub fn fmt_offsets(offsets: &[usize]) -> String {
    if offsets.is_empty() {
        return "none".to_string();
    }
    let shown: Vec<String> = offsets.iter().take(16).map(|o| format!("{o:#x}")).collect();
    let more = offsets.len().saturating_sub(16);
    if more > 0 { format!("{} (+{more} more)", shown.join(" ")) } else { shown.join(" ") }
}
