use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::fmt::Write;
use core::ptr;

use uefi_raw::protocol::console::{InputKey, SimpleTextInputProtocol, SimpleTextOutputProtocol};
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::protocol::file_system::{FileAttribute, FileMode, FileProtocolV1, SimpleFileSystemProtocol};
use uefi_raw::protocol::loaded_image::LoadedImageProtocol;
use uefi_raw::table::boot::{BootServices, MemoryType};
use uefi_raw::table::runtime::{ResetType, RuntimeServices, VariableAttributes};
use uefi_raw::table::system::SystemTable;
use uefi_raw::time::Time;
use uefi_raw::{Boolean, Guid, Handle, Status, guid};

macro_rules! println {
    () => {{
        let _ = core::fmt::Write::write_str(&mut $crate::efi::ConsoleWriter, "\n");
    }};
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::efi::ConsoleWriter, format_args!($($arg)*));
        let _ = core::fmt::Write::write_str(&mut $crate::efi::ConsoleWriter, "\n");
    }};
}
pub(crate) use println;

macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::efi::ConsoleWriter, format_args!($($arg)*));
    }};
}
pub(crate) use print;

pub const OUT_DIR: &str = "\\routecfg";

const SMBIOS3_GUID: Guid = guid!("f2fd1544-9794-4a2c-992e-e5bbcf20e394");
const SMBIOS_GUID: Guid = guid!("eb9d2d31-2d88-11d3-9a16-0090273fc14d");

pub const SCAN_UP: u16 = 0x01;
pub const SCAN_DOWN: u16 = 0x02;
pub const SCAN_ESC: u16 = 0x17;

pub mod color {
    pub const NORMAL: usize = 0x07;
    pub const BRIGHT: usize = 0x0F;
    pub const TITLE: usize = 0x0B;
    pub const GOOD: usize = 0x0A;
    pub const WARN: usize = 0x0E;
    pub const BAD: usize = 0x0C;
    pub const SELECTED: usize = 0x1F;
}

static mut SYSTEM_TABLE: *mut SystemTable = ptr::null_mut();
static mut IMAGE: Handle = ptr::null_mut();
static mut LOG: String = String::new();

pub fn take_log() -> String {
    unsafe { core::mem::take(&mut *ptr::addr_of_mut!(LOG)) }
}

fn system_table() -> Option<&'static SystemTable> {
    unsafe { SYSTEM_TABLE.as_ref() }
}

fn boot_services() -> Option<&'static BootServices> {
    system_table().and_then(|st| unsafe { st.boot_services.as_ref() })
}

pub struct MemorySummary {
    pub dimms: usize,
    pub total_mb: u64,
    pub configured_mts: Option<u32>,
    pub rated_mts: Option<u32>,
}

pub struct Efi {
    _private: (),
}

impl Efi {
    /// # Safety
    /// Must be called once, first thing in `efi_main`, with the firmware-provided arguments.
    pub unsafe fn init(image: Handle, st: *mut SystemTable) -> Efi {
        unsafe {
            SYSTEM_TABLE = st;
            IMAGE = image;
        }
        let efi = Efi { _private: () };
        efi.disable_watchdog();
        efi
    }

    fn bs(&self) -> &'static BootServices {
        boot_services().expect("boot services")
    }

    fn rt(&self) -> &'static RuntimeServices {
        let st = system_table().expect("system table");
        unsafe { st.runtime_services.as_ref() }.expect("runtime services")
    }

    fn stdout(&self) -> *mut SimpleTextOutputProtocol {
        system_table().map_or(ptr::null_mut(), |st| st.stdout)
    }

    fn stdin(&self) -> *mut SimpleTextInputProtocol {
        system_table().map_or(ptr::null_mut(), |st| st.stdin)
    }

    fn disable_watchdog(&self) {
        let _ = unsafe { (self.bs().set_watchdog_timer)(0, 0, 0, ptr::null()) };
    }

    pub fn locate_protocol(&self, guid: &Guid) -> Result<*mut c_void, String> {
        let mut iface: *mut c_void = ptr::null_mut();
        let status = unsafe { (self.bs().locate_protocol)(guid, ptr::null_mut(), &mut iface) };
        if status.is_error() || iface.is_null() {
            return Err(format!("LocateProtocol({guid}) failed: {status:?}"));
        }
        Ok(iface)
    }

    fn handle_protocol(&self, handle: Handle, guid: &Guid) -> Result<*mut c_void, String> {
        let mut iface: *mut c_void = ptr::null_mut();
        let status = unsafe { (self.bs().handle_protocol)(handle, guid, &mut iface) };
        if status.is_error() || iface.is_null() {
            return Err(format!("HandleProtocol({guid}) failed: {status:?}"));
        }
        Ok(iface)
    }

    fn loaded_image(&self) -> Result<&'static LoadedImageProtocol, String> {
        let p = self.handle_protocol(unsafe { IMAGE }, &LoadedImageProtocol::GUID)?;
        Ok(unsafe { &*(p as *const LoadedImageProtocol) })
    }

    pub fn load_options(&self) -> String {
        let Ok(li) = self.loaded_image() else { return String::new() };
        if li.load_options.is_null() || li.load_options_size < 2 {
            return String::new();
        }
        let units = li.load_options_size as usize / 2;
        let slice = unsafe { core::slice::from_raw_parts(li.load_options as *const u16, units) };
        let end = slice.iter().position(|&c| c == 0).unwrap_or(units);
        String::from_utf16_lossy(&slice[..end])
    }

    pub fn get_variable(&self, name: &str, vendor: &Guid) -> Result<Vec<u8>, String> {
        let name16 = to_u16z(name);
        let mut buf = vec![0u8; 0x2000];
        let mut size = buf.len();
        let mut attrs = VariableAttributes::empty();
        let status =
            unsafe { (self.rt().get_variable)(name16.as_ptr(), vendor, &mut attrs, &mut size, buf.as_mut_ptr()) };
        if status.is_error() {
            return Err(format!("GetVariable({name}) failed: {status:?} (size {size:#x})"));
        }
        buf.truncate(size);
        Ok(buf)
    }

    pub fn take_fw_string(&self, p: *mut u16) -> String {
        if p.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        unsafe {
            while *p.add(len) != 0 && len < (16 << 20) {
                len += 1;
            }
        }
        let s = String::from_utf16_lossy(unsafe { core::slice::from_raw_parts(p, len) });
        let _ = unsafe { (self.bs().free_pool)(p.cast()) };
        s
    }

    // ---- console ----------------------------------------------------------

    pub fn clear(&self) {
        let out = self.stdout();
        if !out.is_null() {
            unsafe {
                let _ = ((*out).set_attribute)(out, color::NORMAL);
                let _ = ((*out).clear_screen)(out);
            }
        }
    }

    pub fn color(&self, attr: usize) {
        let out = self.stdout();
        if !out.is_null() {
            let _ = unsafe { ((*out).set_attribute)(out, attr) };
        }
    }

    pub fn cursor(&self, visible: bool) {
        let out = self.stdout();
        if !out.is_null() {
            let v = if visible { Boolean::TRUE } else { Boolean::FALSE };
            let _ = unsafe { ((*out).enable_cursor)(out, v) };
        }
    }

    /// Blocks until a key is pressed.
    pub fn read_key(&self) -> InputKey {
        let inp = self.stdin();
        let mut key = InputKey::default();
        if inp.is_null() {
            return key;
        }
        loop {
            let mut event = unsafe { (*inp).wait_for_key };
            let mut index = 0usize;
            let _ = unsafe { (self.bs().wait_for_event)(1, &mut event, &mut index) };
            if !unsafe { ((*inp).read_key_stroke)(inp, &mut key) }.is_error() {
                return key;
            }
        }
    }

    pub fn flush_keys(&self) {
        let inp = self.stdin();
        if inp.is_null() {
            return;
        }
        let mut key = InputKey::default();
        while !unsafe { ((*inp).read_key_stroke)(inp, &mut key) }.is_error() {}
    }

    // ---- platform ---------------------------------------------------------

    pub fn reset(&self, kind: ResetType) -> ! {
        unsafe { (self.rt().reset_system)(kind, Status::SUCCESS, 0, ptr::null()) }
    }

    pub fn now(&self) -> String {
        let mut t = Time::invalid();
        let status = unsafe { (self.rt().get_time)(&mut t, ptr::null_mut()) };
        if status.is_error() {
            return String::from("????-??-?? ??:??");
        }
        format!("{:04}-{:02}-{:02} {:02}:{:02}", t.year, t.month, t.day, t.hour, t.minute)
    }

    /// Reads an extended-bank CMOS byte (index port 0x72, data port 0x73).
    pub fn ext_cmos(&self, index: u8) -> u8 {
        unsafe {
            outb(0x72, index);
            inb(0x73)
        }
    }

    /// Summarises SMBIOS type 17 (Memory Device) records, if the firmware publishes them.
    pub fn memory_summary(&self) -> Option<MemorySummary> {
        let (start, len) = self.smbios_table()?;
        let table = unsafe { core::slice::from_raw_parts(start, len) };
        let mut summary = MemorySummary { dimms: 0, total_mb: 0, configured_mts: None, rated_mts: None };
        let mut pos = 0usize;
        while pos + 4 <= table.len() {
            let kind = table[pos];
            let hdr_len = table[pos + 1] as usize;
            if hdr_len < 4 || pos + hdr_len > table.len() {
                break;
            }
            let s = &table[pos..pos + hdr_len];
            if kind == 17 {
                record_dimm(&mut summary, s);
            }
            if kind == 127 {
                break;
            }
            let mut next = pos + hdr_len;
            while next + 1 < table.len() && !(table[next] == 0 && table[next + 1] == 0) {
                next += 1;
            }
            pos = next + 2;
        }
        Some(summary)
    }

    fn smbios_table(&self) -> Option<(*const u8, usize)> {
        let st = system_table()?;
        let entries =
            unsafe { core::slice::from_raw_parts(st.configuration_table, st.number_of_configuration_table_entries) };
        if let Some(e) = entries.iter().find(|e| e.vendor_guid == SMBIOS3_GUID) {
            let ep = e.vendor_table as *const u8;
            let max_len = unsafe { (ep.add(0x0C) as *const u32).read_unaligned() } as usize;
            let addr = unsafe { (ep.add(0x10) as *const u64).read_unaligned() } as usize;
            return Some((addr as *const u8, max_len));
        }
        let e = entries.iter().find(|e| e.vendor_guid == SMBIOS_GUID)?;
        let ep = e.vendor_table as *const u8;
        let len = unsafe { (ep.add(0x16) as *const u16).read_unaligned() } as usize;
        let addr = unsafe { (ep.add(0x18) as *const u32).read_unaligned() } as usize;
        Some((addr as *const u8, len))
    }

    /// Loads and runs another EFI image from the volume this app was loaded from.
    pub fn launch(&self, path: &str) -> Result<(), String> {
        let li = self.loaded_image()?;
        let dev = self.handle_protocol(li.device_handle, &DevicePathProtocol::GUID)? as *const u8;
        let mut dp = device_path_prefix(dev);
        let name: Vec<u16> = to_u16z(path);
        let node_len = 4 + name.len() * 2;
        dp.extend_from_slice(&[0x04, 0x04, (node_len & 0xFF) as u8, (node_len >> 8) as u8]);
        for c in &name {
            dp.extend_from_slice(&c.to_le_bytes());
        }
        dp.extend_from_slice(&[0x7F, 0xFF, 0x04, 0x00]);

        let mut child: Handle = ptr::null_mut();
        let status = unsafe {
            (self.bs().load_image)(
                Boolean::FALSE,
                IMAGE,
                dp.as_ptr() as *const DevicePathProtocol,
                ptr::null(),
                0,
                &mut child,
            )
        };
        if status.is_error() {
            return Err(format!("LoadImage({path}) failed: {status:?}"));
        }
        let status = unsafe { (self.bs().start_image)(child, ptr::null_mut(), ptr::null_mut()) };
        if status.is_error() {
            return Err(format!("{path} exited with {status:?}"));
        }
        Ok(())
    }

    // ---- files (under OUT_DIR on the boot volume) -------------------------

    /// Writes `data` to `\routecfg\<name>`, replacing any existing file.
    pub fn save(&self, name: &str, data: &[u8]) {
        if let Err(e) = self.try_save(name, data) {
            println!("  (could not save {name}: {e})");
        }
    }

    pub fn read_file(&self, name: &str) -> Option<Vec<u8>> {
        let dir = self.out_dir().ok()?;
        let file = dir.open(name, FileMode::READ, FileAttribute::empty()).ok()?;
        let mut out = Vec::new();
        let mut chunk = vec![0u8; 4096];
        loop {
            let mut size = chunk.len();
            let status = unsafe { ((*file.0).read)(file.0, &mut size, chunk.as_mut_ptr().cast()) };
            if status.is_error() || size == 0 {
                break;
            }
            out.extend_from_slice(&chunk[..size]);
        }
        Some(out)
    }

    fn out_dir(&self) -> Result<FileGuard, String> {
        let li = self.loaded_image()?;
        let sfs =
            self.handle_protocol(li.device_handle, &SimpleFileSystemProtocol::GUID)? as *mut SimpleFileSystemProtocol;
        let mut root: *mut FileProtocolV1 = ptr::null_mut();
        check(unsafe { ((*sfs).open_volume)(sfs, &mut root) }, "OpenVolume")?;
        let root = FileGuard(root);
        root.open(OUT_DIR, FileMode::READ | FileMode::WRITE | FileMode::CREATE, FileAttribute::DIRECTORY)
    }

    fn try_save(&self, name: &str, data: &[u8]) -> Result<(), String> {
        let dir = self.out_dir()?;
        if let Ok(existing) = dir.open(name, FileMode::READ | FileMode::WRITE, FileAttribute::empty()) {
            existing.delete();
        }
        let file = dir.open(name, FileMode::READ | FileMode::WRITE | FileMode::CREATE, FileAttribute::empty())?;
        let mut size = data.len();
        check(unsafe { ((*file.0).write)(file.0, &mut size, data.as_ptr().cast()) }, "Write")?;
        if size != data.len() {
            return Err(format!("short write {size}/{}", data.len()));
        }
        Ok(())
    }
}

fn record_dimm(summary: &mut MemorySummary, s: &[u8]) {
    let word = |o: usize| (o + 2 <= s.len()).then(|| u16::from_le_bytes([s[o], s[o + 1]]));
    let dword = |o: usize| (o + 4 <= s.len()).then(|| u32::from_le_bytes([s[o], s[o + 1], s[o + 2], s[o + 3]]));
    let size_mb = match word(0x0C) {
        None | Some(0) | Some(0xFFFF) => return,
        Some(0x7FFF) => u64::from(dword(0x1C).unwrap_or(0) & 0x7FFF_FFFF),
        Some(v) if v & 0x8000 != 0 => u64::from(v & 0x7FFF) / 1024,
        Some(v) => u64::from(v),
    };
    summary.dimms += 1;
    summary.total_mb += size_mb;
    let speed = |base: usize, ext: usize| match word(base) {
        Some(0) | None => None,
        Some(0xFFFF) => dword(ext).filter(|&v| v != 0),
        Some(v) => Some(u32::from(v)),
    };
    if let Some(v) = speed(0x20, 0x58) {
        summary.configured_mts = Some(v);
    }
    if let Some(v) = speed(0x15, 0x54) {
        summary.rated_mts = Some(v);
    }
}

fn device_path_prefix(dev: *const u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut p = dev;
    loop {
        let (kind, sub) = unsafe { (*p, *p.add(1)) };
        let len = unsafe { u16::from_le_bytes([*p.add(2), *p.add(3)]) } as usize;
        if kind == 0x7F && sub == 0xFF || len < 4 {
            break;
        }
        out.extend_from_slice(unsafe { core::slice::from_raw_parts(p, len) });
        p = unsafe { p.add(len) };
    }
    out
}

unsafe fn outb(port: u16, value: u8) {
    unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags)) };
}

unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    unsafe { core::arch::asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags)) };
    value
}

struct FileGuard(*mut FileProtocolV1);

impl FileGuard {
    fn open(&self, name: &str, mode: FileMode, attrs: FileAttribute) -> Result<FileGuard, String> {
        let name16 = to_u16z(name);
        let mut h: *mut FileProtocolV1 = ptr::null_mut();
        check(unsafe { ((*self.0).open)(self.0, &mut h, name16.as_ptr(), mode, attrs) }, "Open")?;
        Ok(FileGuard(h))
    }

    fn delete(self) {
        let h = self.0;
        core::mem::forget(self);
        let _ = unsafe { ((*h).delete)(h) };
    }
}

impl Drop for FileGuard {
    fn drop(&mut self) {
        let _ = unsafe { ((*self.0).close)(self.0) };
    }
}

fn check(status: Status, what: &str) -> Result<(), String> {
    if status.is_error() { Err(format!("{what}: {status:?}")) } else { Ok(()) }
}

pub fn to_u16z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

pub fn progress_index(base: &[u16], progress: *const u16) -> usize {
    let start = base.as_ptr() as usize;
    let at = progress as usize;
    if progress.is_null() || at < start || at >= start + base.len() * 2 {
        return 0;
    }
    (at - start) / 2
}

pub struct ConsoleWriter;

impl Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        unsafe { (*ptr::addr_of_mut!(LOG)).push_str(s) };
        let Some(st) = system_table() else { return Ok(()) };
        if st.stdout.is_null() {
            return Ok(());
        }
        let mut buf: Vec<u16> = Vec::with_capacity(s.len() + 8);
        for c in s.encode_utf16() {
            if c == u16::from(b'\n') {
                buf.push(u16::from(b'\r'));
            }
            buf.push(c);
        }
        buf.push(0);
        let _ = unsafe { ((*st.stdout).output_string)(st.stdout, buf.as_ptr()) };
        Ok(())
    }
}

struct PoolAllocator;

unsafe impl GlobalAlloc for PoolAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let Some(bs) = boot_services() else { return ptr::null_mut() };
        let align = layout.align();
        let mut raw: *mut u8 = ptr::null_mut();
        if align <= 8 {
            let status = unsafe { (bs.allocate_pool)(MemoryType::LOADER_DATA, layout.size().max(1), &mut raw) };
            return if status.is_error() { ptr::null_mut() } else { raw };
        }
        let status = unsafe { (bs.allocate_pool)(MemoryType::LOADER_DATA, layout.size() + align, &mut raw) };
        if status.is_error() {
            return ptr::null_mut();
        }
        let offset = align - (raw as usize % align);
        unsafe {
            let aligned = raw.add(offset);
            aligned.cast::<*mut u8>().sub(1).write(raw);
            aligned
        }
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let Some(bs) = boot_services() else { return };
        let raw = if layout.align() <= 8 { p } else { unsafe { p.cast::<*mut u8>().sub(1).read() } };
        let _ = unsafe { (bs.free_pool)(raw) };
    }
}

#[global_allocator]
static ALLOCATOR: PoolAllocator = PoolAllocator;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    println!("routecfg: PANIC: {info}");
    loop {
        core::hint::spin_loop();
    }
}
