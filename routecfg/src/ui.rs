use alloc::format;
use alloc::string::String;

use uefi_raw::table::runtime::ResetType;

use crate::cbs::{self, Session, Target, fmt_offsets, valid_speed};
use crate::efi::{Efi, SCAN_DOWN, SCAN_ESC, SCAN_UP, color, print, println};
use crate::history;

const SHELL_PATH: &str = "\\EFI\\tools\\shell.efi";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy)]
enum Action {
    Set(u16),
    Custom,
    Auto,
    Status,
    Shell,
    Reboot,
    PowerOff,
}

const MENU: [(&str, Action); 8] = [
    ("Set 4800 MT/s", Action::Set(4800)),
    ("Set 5200 MT/s", Action::Set(5200)),
    ("Set custom speed...", Action::Custom),
    ("Restore stock (Auto)", Action::Auto),
    ("Status & history", Action::Status),
    ("UEFI Shell", Action::Shell),
    ("Reboot", Action::Reboot),
    ("Power off", Action::PowerOff),
];

pub fn run(efi: &Efi) {
    efi.cursor(false);
    let mut selected = 0usize;
    loop {
        crate::efi::take_log();
        draw_main(efi, selected);
        let key = efi.read_key();
        let digit = char::from_u32(u32::from(key.unicode_char)).and_then(|c| c.to_digit(10));
        match (key.scan_code, key.unicode_char) {
            (SCAN_UP, _) => selected = (selected + MENU.len() - 1) % MENU.len(),
            (SCAN_DOWN, _) => selected = (selected + 1) % MENU.len(),
            (_, 0x0D) => perform(efi, MENU[selected].1),
            _ => {
                if let Some(d) = digit.map(|d| d as usize).filter(|d| (1..=MENU.len()).contains(d)) {
                    selected = d - 1;
                    perform(efi, MENU[selected].1);
                }
            }
        }
    }
}

fn perform(efi: &Efi, action: Action) {
    match action {
        Action::Set(speed) => apply_flow(efi, Target::Manual(speed)),
        Action::Custom => {
            if let Some(speed) = prompt_speed(efi) {
                apply_flow(efi, Target::Manual(speed));
            }
        }
        Action::Auto => apply_flow(efi, Target::Auto),
        Action::Status => status_screen(efi),
        Action::Shell => {
            efi.clear();
            efi.cursor(true);
            if let Err(e) = efi.launch(SHELL_PATH) {
                message(efi, color::BAD, &format!("Could not start the shell: {e}"));
            }
            efi.cursor(false);
        }
        Action::Reboot => {
            if confirm(efi, "Reboot now?") {
                efi.reset(ResetType::COLD);
            }
        }
        Action::PowerOff => {
            if confirm(efi, "Power off now?") {
                efi.reset(ResetType::SHUTDOWN);
            }
        }
    }
}

fn draw_main(efi: &Efi, selected: usize) {
    efi.clear();
    efi.color(color::TITLE);
    println!(" routecfg {VERSION} - Legion 5 RAM speed (AMD CBS via RouteConfig)");
    efi.color(color::NORMAL);
    println!(" ------------------------------------------------------------------");
    draw_state(efi);
    println!();
    for (i, (label, _)) in MENU.iter().enumerate() {
        efi.color(if i == selected { color::SELECTED } else { color::NORMAL });
        print!("  {}. {:<24}", i + 1, label);
        efi.color(color::NORMAL);
        println!();
    }
    println!();
    efi.color(color::NORMAL);
    println!(" Up/Down + Enter, or press a number.");
}

fn draw_state(efi: &Efi) {
    match cbs::read_setting(efi) {
        Ok(s) => {
            label(" CBS setting    : ");
            efi.color(color::BRIGHT);
            println!("{}", s.describe());
        }
        Err(e) => {
            label(" CBS setting    : ");
            efi.color(color::BAD);
            println!("unreadable ({e})");
        }
    }
    efi.color(color::NORMAL);
    label(" Running now    : ");
    match efi.memory_summary() {
        Some(m) if m.dimms > 0 => {
            efi.color(color::BRIGHT);
            let speed = m.configured_mts.map_or(String::from("unknown speed"), |v| format!("{v} MT/s"));
            println!("{speed}, {} DIMM(s), {} GB", m.dimms, m.total_mb / 1024);
        }
        _ => println!("not reported by firmware (check Task Manager in Windows)"),
    }
    efi.color(color::NORMAL);
    label(" Recovery marker: ");
    let (attr, text) = recovery_marker(efi);
    efi.color(attr);
    println!("{text}");
    efi.color(color::NORMAL);
    label(" Last action    : ");
    match history::recent(efi, 1).pop() {
        Some(line) => println!("{line}"),
        None => println!("none recorded"),
    }
}

fn recovery_marker(efi: &Efi) -> (usize, String) {
    let (b6, b7) = (efi.ext_cmos(6), efi.ext_cmos(7));
    match (b6, b7) {
        (0x5A, 0xA5) => (color::WARN, format!("{b6:02X} {b7:02X} - APCB recovery has run since last cleared")),
        (0x55, 0x55) => (color::WARN, format!("{b6:02X} {b7:02X} - recovery disabled by firmware")),
        (0x00, 0x00) => (color::GOOD, format!("{b6:02X} {b7:02X} - clear")),
        _ => (color::NORMAL, format!("{b6:02X} {b7:02X}")),
    }
}

fn label(text: &str) {
    print!("{text}");
}

fn apply_flow(efi: &Efi, target: Target) {
    let current = cbs::read_setting(efi).map(|s| s.describe()).unwrap_or_else(|e| e);
    efi.clear();
    efi.color(color::TITLE);
    println!(" Change memory speed");
    efi.color(color::NORMAL);
    println!();
    println!("   Current : {current}");
    efi.color(color::BRIGHT);
    println!("   New     : {}", target.describe());
    efi.color(color::NORMAL);
    println!();
    if !confirm_inline(efi, "   Apply this setting? [Y/N] ") {
        return;
    }

    println!();
    println!(" Working...");
    let result = Session::open(efi).and_then(|session| session.apply(target));
    let stamp = efi.now();
    println!();
    match result {
        Ok(report) => {
            let changed = fmt_offsets(&report.changed);
            history::append(
                efi,
                &format!(
                    "{stamp} | {} | {:?} | now {} | changed {changed}",
                    target.tag(),
                    report.route_status,
                    report.after.describe()
                ),
            );
            if report.landed {
                efi.color(color::GOOD);
                println!(" Saved: {} (changed bytes: {changed})", report.after.describe());
                efi.color(color::NORMAL);
                println!(" The new speed takes effect after a reboot. Expect a long black");
                println!(" screen while the memory retrains - leave it alone.");
            } else {
                efi.color(color::BAD);
                println!(" RouteConfig returned {:?} but the setting reads back as", report.route_status);
                println!(" {} (changed bytes: {changed}).", report.after.describe());
                efi.color(color::NORMAL);
            }
            efi.save("log.txt", crate::efi::take_log().as_bytes());
            println!();
            if report.landed && confirm_inline(efi, " Reboot now? [Y/N] ") {
                efi.reset(ResetType::COLD);
            }
            if !report.landed {
                wait_key(efi);
            }
        }
        Err(e) => {
            history::append(efi, &format!("{stamp} | {} | FAILED | {e}", target.tag()));
            efi.color(color::BAD);
            println!(" Not applied: {e}");
            efi.color(color::NORMAL);
            efi.save("log.txt", crate::efi::take_log().as_bytes());
            wait_key(efi);
        }
    }
}

fn prompt_speed(efi: &Efi) -> Option<u16> {
    let mut input = String::new();
    let mut error: Option<String> = None;
    loop {
        efi.clear();
        efi.color(color::TITLE);
        println!(" Custom memory speed");
        efi.color(color::NORMAL);
        println!();
        println!("   Valid: 2000, 2400, or 3200-12000 in steps of 200 (MT/s).");
        println!("   Enter = confirm, Esc = cancel.");
        println!();
        if let Some(e) = &error {
            efi.color(color::BAD);
            println!("   {e}");
            efi.color(color::NORMAL);
        }
        print!("   Speed: {input}_");
        let key = efi.read_key();
        match (key.scan_code, key.unicode_char) {
            (SCAN_ESC, _) => return None,
            (_, 0x0D) => match input.parse::<u16>() {
                Ok(v) if valid_speed(v) => return Some(v),
                _ => error = Some(format!("'{input}' is not a valid speed.")),
            },
            (_, 0x08) => {
                input.pop();
            }
            (_, c) => {
                if let Some(ch) = char::from_u32(u32::from(c)).filter(|ch| ch.is_ascii_digit()) {
                    if input.len() < 5 {
                        input.push(ch);
                    }
                }
            }
        }
    }
}

fn status_screen(efi: &Efi) {
    efi.clear();
    efi.color(color::TITLE);
    println!(" Status & history");
    efi.color(color::NORMAL);
    println!(" ------------------------------------------------------------------");
    draw_state(efi);
    if let Ok(s) = cbs::read_setting(efi) {
        println!(
            " AmdSetup bytes : 0x58={:#04x} 0x59={} sync sig={:#010x}",
            s.timing, s.speed, s.sig
        );
    }
    if let Some(m) = efi.memory_summary() {
        if let Some(r) = m.rated_mts {
            println!(" DIMM rating    : {r} MT/s (SMBIOS)");
        }
    }
    println!(" CMOS ext 3/6/7 : {:02X} {:02X} {:02X}", efi.ext_cmos(3), efi.ext_cmos(6), efi.ext_cmos(7));
    println!();
    efi.color(color::TITLE);
    println!(" Recent actions (\\routecfg\\history.txt):");
    efi.color(color::NORMAL);
    let lines = history::recent(efi, 10);
    if lines.is_empty() {
        println!("   none recorded");
    }
    for line in lines {
        let shown: String = line.chars().take(76).collect();
        println!("   {shown}");
    }
    wait_key(efi);
}

fn confirm(efi: &Efi, question: &str) -> bool {
    efi.clear();
    println!();
    confirm_inline(efi, &format!(" {question} [Y/N] "))
}

fn confirm_inline(efi: &Efi, prompt: &str) -> bool {
    print!("{prompt}");
    efi.flush_keys();
    loop {
        let key = efi.read_key();
        match char::from_u32(u32::from(key.unicode_char)).map(|c| c.to_ascii_lowercase()) {
            Some('y') => {
                println!("Y");
                return true;
            }
            Some('n') => {
                println!("N");
                return false;
            }
            _ if key.scan_code == SCAN_ESC => {
                println!("N");
                return false;
            }
            _ => {}
        }
    }
}

fn message(efi: &Efi, attr: usize, text: &str) {
    println!();
    efi.color(attr);
    println!(" {text}");
    efi.color(color::NORMAL);
    wait_key(efi);
}

fn wait_key(efi: &Efi) {
    println!();
    print!(" Press any key...");
    efi.flush_keys();
    let _ = efi.read_key();
}
