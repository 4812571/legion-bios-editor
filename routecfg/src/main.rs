#![no_std]
#![no_main]

extern crate alloc;

mod boot;
mod cbs;
mod config;
mod efi;
mod history;
mod ui;

use alloc::format;
use alloc::string::{String, ToString};

use cbs::{Session, Target, fmt_offsets, valid_speed};
use efi::{Efi, println};
use uefi_raw::{Handle, Status, table::system::SystemTable};

enum Mode {
    Menu,
    Read,
    Apply(Target),
}

#[unsafe(no_mangle)]
pub extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    let efi = unsafe { Efi::init(image, system_table) };
    let mode = match parse_mode(&efi.load_options()) {
        Ok(m) => m,
        Err(e) => {
            println!("routecfg: {e}");
            return Status::INVALID_PARAMETER;
        }
    };
    if let Mode::Menu = mode {
        ui::run(&efi);
        return Status::SUCCESS;
    }
    let status = match run_cli(&efi, mode) {
        Ok(()) => {
            println!("routecfg: done.");
            Status::SUCCESS
        }
        Err(e) => {
            println!("routecfg: ERROR: {e}");
            Status::ABORTED
        }
    };
    efi.save("log.txt", efi::take_log().as_bytes());
    status
}

fn parse_mode(options: &str) -> Result<Mode, String> {
    let opts = options.to_ascii_lowercase();
    let mut words = opts.split_whitespace().skip(1);
    match words.next() {
        None | Some("menu") => Ok(Mode::Menu),
        Some("read") => Ok(Mode::Read),
        Some("auto") => Ok(Mode::Apply(Target::Auto)),
        Some("apply") => {
            let speed = match words.next() {
                None => 4800,
                Some(s) => s.parse::<u16>().map_err(|_| format!("bad speed '{s}'"))?,
            };
            if !valid_speed(speed) {
                return Err(format!("speed {speed} is not a valid CBS value (2000, 2400, 3200..12000 step 200)"));
            }
            Ok(Mode::Apply(Target::Manual(speed)))
        }
        Some(other) => Err(format!("unknown mode '{other}' (use: [menu] | read | apply [speed] | auto)")),
    }
}

fn run_cli(efi: &Efi, mode: Mode) -> Result<(), String> {
    let session = Session::open(efi)?;
    println!("{}", session.survey_export());
    let s = session.setting();
    println!("AmdSetup: {} (0x58={:#04x} 0x59={} sig={:#010x})", s.describe(), s.timing, s.speed, s.sig);
    let mismatches = session.mismatches();
    println!(
        "ExtractConfig: {} elements, {} mismatch the variable, covers 0x58/0x59: {}",
        session.element_count(),
        mismatches.len(),
        session.covers_memory_fields()
    );
    for m in mismatches.iter().take(8) {
        println!("  mismatch: {m}");
    }
    let Mode::Apply(target) = mode else {
        println!("Read-only run: nothing written. Files saved under {}\\", efi::OUT_DIR);
        return Ok(());
    };
    let report = session.apply(target)?;
    let changed = fmt_offsets(&report.changed);
    history::append(
        efi,
        &format!("{} | {} | {:?} | now {} | changed {changed}", efi.now(), target.tag(), report.route_status, report.after.describe()),
    );
    println!("AmdSetup after: {}; changed offsets: {changed}", report.after.describe());
    if report.landed {
        println!("Setting saved. Reboot: a long black screen (memory retrain) means the APCB changed.");
        Ok(())
    } else {
        Err("setting did not read back as requested".to_string())
    }
}
