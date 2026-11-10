//! Windows metric collection through the native Win32 APIs.
//!
//! This module uses system-information, IP Helper, registry and file-system
//! APIs instead of shelling out to PowerShell or depending on localized output.

use std::collections::HashMap;
use std::ffi::c_void;
use std::mem::{align_of, size_of};
use std::net::IpAddr;
use std::ptr::{null, null_mut};
use std::slice;
use std::time::{Duration, Instant};

use serde::Serialize;
use windows_sys::core::GUID;
use windows_sys::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemTimeOfDayInformation};
use windows_sys::Wdk::System::SystemServices::RtlGetVersion;
use windows_sys::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, FILETIME, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetAdaptersAddresses, GetIfTable2, GetTcpStatisticsEx, GetUdpStatisticsEx,
    GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_TCPSTATS_LH, MIB_UDPSTATS,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKET_ADDRESS,
};
use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDrives};
use windows_sys::Win32::System::ProcessStatus::{GetPerformanceInfo, PERFORMANCE_INFORMATION};
use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_SZ,
};
use windows_sys::Win32::System::SystemInformation::{
    ComputerNamePhysicalDnsHostname, GetComputerNameExW, GetSystemTimeAsFileTime, GetTickCount64,
    GlobalMemoryStatusEx, MEMORYSTATUSEX, OSVERSIONINFOW,
};
use windows_sys::Win32::System::Threading::GetSystemTimes;
use windows_sys::Win32::System::WindowsProgramming::SYSTEM_TIMEOFDAY_INFORMATION;

#[path = "collector_worker.rs"]
mod collector_worker;
pub use collector_worker::WorkerCollector;

// All kernel/registry-derived allocations have an application-level ceiling.
const MAX_INTERFACES: usize = 4096;
const MAX_ADAPTER_BYTES: usize = 4 * 1024 * 1024;
const MAX_ADAPTER_ADDRESSES: usize = 16384;
const MAX_ALIAS_WORDS: usize = 1024;
const MAX_REGISTRY_BYTES: u32 = 16 * 1024;
const DISK_REFRESH: Duration = Duration::from_secs(60);
const DRIVE_FIXED: u32 = 3;
const WINDOWS_FILETIME_UNIX_OFFSET: u64 = 11644473600 * 10_000_000;
const LOAD_WINDOWS: [f32; 3] = [60.0, 300.0, 900.0];
const SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS: i32 = 90;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct SystemBootEnvironmentInfo {
    boot_identifier: GUID,
    _firmware_type: u32,
    _boot_flags: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Ifaces {
    spec: String,
    only: Vec<String>,
    skip: Vec<String>,
}

impl Ifaces {
    pub fn parse(spec: &str) -> Result<Self, String> {
        if spec.chars().any(char::is_control) {
            return Err("--iface: control characters are not valid in adapter aliases".into());
        }
        let entries: Vec<&str> = spec.split(',').map(str::trim).filter(|entry| !entry.is_empty()).collect();
        let mut ifaces = Self { spec: entries.join(","), ..Self::default() };
        for entry in entries {
            let (list, name) = match entry.strip_prefix('-') {
                Some(name) => (&mut ifaces.skip, name),
                None => (&mut ifaces.only, entry),
            };
            if name.is_empty() || name.starts_with('-') || name.chars().any(char::is_control) {
                return Err(format!("--iface: {entry:?} is not a valid adapter alias"));
            }
            list.push(name.to_owned());
        }
        Ok(ifaces)
    }

    pub fn from_legacy(nics: Vec<String>) -> Self {
        Self { spec: nics.join(","), only: nics, skip: Vec::new() }
    }

    pub fn spec(&self) -> &str {
        &self.spec
    }

    #[cfg(test)]
    pub fn only(&self) -> &[String] {
        &self.only
    }

    fn counts(&self, row: &MIB_IF_ROW2) -> bool {
        let name = interface_name(row);
        if self.skip.iter().any(|excluded| excluded == &name) {
            return false;
        }
        if !self.only.is_empty() {
            return self.only.iter().any(|selected| selected == &name);
        }
        row.Type != 24 && row.Type != 131 && !skip_iface(&name)
    }
}

fn epoch<'a>(boot_id: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut names: Vec<&str> = names.collect();
    names.sort_unstable();
    let digest = names
        .join("\n")
        .bytes()
        .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3));
    format!("{boot_id}/{digest:016x}")
}

pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, _] = v4.octets();
            !(v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || a == 0
                || a >= 224
                || (a == 100 && b & 0xc0 == 64)
                || (a == 192 && b == 0 && c == 0)
                || (a == 198 && b & 0xfe == 18))
        }
        IpAddr::V6(v6) => v6.segments()[0] & 0xe000 == 0x2000,
    }
}

const VIRTUAL_INTERFACE_WORDS: &[&str] = &[
    "loopback",
    "teredo",
    "isatap",
    "6to4",
    "wsl",
    "veth",
    "vethernet",
    "docker",
    "virtualbox",
    "vmware",
    "wireguard",
    "tailscale",
    "zerotier",
    "tap-windows",
    "hyper-v",
    "default switch",
];

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Facts {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub virt: String,
    pub cpu_name: String,
    pub cpu_cores: u32,
    pub mem_total: u64,
    pub swap_total: u64,
    pub disk_total: u64,
    pub agent_version: String,
    pub ipv4: String,
    pub ipv6: String,
}

#[derive(Serialize, Debug, Clone, Default, PartialEq)]
pub struct Metrics {
    pub boot_id: String,
    pub iface: String,
    pub uptime: u64,
    pub cpu: f32,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    pub net_rx_total: u64,
    pub net_tx_total: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub tcp: u32,
    pub udp: u32,
    pub procs: u32,
}

pub struct Collector {
    ifaces: Ifaces,
    prev_cpu: Option<(u64, u64)>,
    prev_net_at: Option<Instant>,
    prev_net: HashMap<String, (u64, u64)>,
    boot_id: String,
    load: [f32; 3],
    load_at: Option<Instant>,
    cpu_info: Option<(String, u32)>,
    disk: (u64, u64),
    disk_at: Option<Instant>,
    sample_valid: bool,
}

impl Collector {
    pub fn new(ifaces: Ifaces) -> Self {
        Self {
            ifaces,
            prev_cpu: None,
            prev_net_at: None,
            prev_net: HashMap::new(),
            boot_id: boot_id(),
            load: [0.0; 3],
            load_at: None,
            cpu_info: None,
            disk: (0, 0),
            disk_at: None,
            sample_valid: false,
        }
    }

    pub fn facts(&mut self) -> Facts {
        let (ipv4, ipv6) = addresses();
        let (mem_total, _, swap_total, _) = memory();
        let (disk_total, _) = self.disk_usage();
        let (cpu_name, cpu_cores) = self.cpu_info.get_or_insert_with(cpuinfo).clone();
        let version = windows_version();
        Facts {
            hostname: hostname(),
            os: "Windows".into(),
            kernel: version,
            arch: std::env::consts::ARCH.into(),
            virt: virtualization(),
            cpu_name,
            cpu_cores,
            mem_total,
            swap_total,
            disk_total,
            agent_version: env!("CARGO_PKG_VERSION").into(),
            ipv4,
            ipv6,
        }
    }

    pub fn collect(&mut self) -> Metrics {
        let (mem_total, mem_used, swap_total, swap_used) = memory();
        let counted: Vec<(String, u64, u64)> = interface_table()
            .iter()
            .filter(|row| self.ifaces.counts(row))
            .map(|row| (interface_name(row), row.InOctets, row.OutOctets))
            .collect();
        let (rx_total, tx_total) = counted
            .iter()
            .fold((0u64, 0u64), |(rx, tx), (_, r, t)| (rx.saturating_add(*r), tx.saturating_add(*t)));
        let boot_id = epoch(&self.boot_id, counted.iter().map(|(name, ..)| name.as_str()));
        let now = Instant::now();
        let baseline_ready =
            self.prev_net_at.is_some_and(|at| now.saturating_duration_since(at) >= Duration::from_secs(1));
        let (net_rx, net_tx) = self.net_rate(&counted, now);
        let cpu_sample = self.cpu_percent();
        let cpu = cpu_sample.unwrap_or(0.0);
        self.sample_valid = baseline_ready && cpu_sample.is_some();
        if self.sample_valid {
            self.update_load(cpu, now);
        }
        // Capture rate counters before a potentially slow disk refresh so
        // its delay cannot contaminate this sample's CPU/net/load baseline.
        let (disk_total, disk_used) = self.disk_usage();
        let (tcp, udp) = conn_counts();
        Metrics {
            boot_id,
            iface: self.ifaces.spec().to_owned(),
            uptime: uptime(),
            cpu,
            load: self.load,
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            disk_total,
            disk_used,
            net_rx_total: rx_total,
            net_tx_total: tx_total,
            net_rx,
            net_tx,
            tcp,
            udp,
            procs: proc_count(),
        }
    }

    /// Discard every rate/load sample from the previous WebSocket session.
    fn reset_session(&mut self) {
        self.prev_cpu = None;
        self.prev_net_at = None;
        self.prev_net.clear();
        self.load = [0.0; 3];
        self.load_at = None;
        self.sample_valid = false;
    }

    fn begin_session_baseline(&mut self) {
        self.reset_session();
        let counted: Vec<_> = interface_table()
            .iter()
            .filter(|row| self.ifaces.counts(row))
            .map(|row| (interface_name(row), row.InOctets, row.OutOctets))
            .collect();
        self.net_rate(&counted, Instant::now());
        self.prev_cpu = system_times();
        // Do not initialize load with the baseline's synthetic zero CPU.
    }

    fn disk_usage(&mut self) -> (u64, u64) {
        if self.disk_at.is_none_or(|at| at.elapsed() >= DISK_REFRESH) {
            self.disk = disk_usage();
            self.disk_at = Some(Instant::now());
        }
        self.disk
    }

    fn cpu_percent(&mut self) -> Option<f32> {
        let now = system_times()?;
        let previous = self.prev_cpu.replace(now)?;
        (now.0 > previous.0).then(|| busy_percent(previous, now))
    }

    fn update_load(&mut self, cpu: f32, now: Instant) {
        let target = cpu * self.cpu_info.get_or_insert_with(cpuinfo).1 as f32 / 100.0;
        let Some(previous) = self.load_at.replace(now) else {
            self.load = [target; 3];
            return;
        };
        let elapsed = now.saturating_duration_since(previous).as_secs_f32();
        for (load, window) in self.load.iter_mut().zip(LOAD_WINDOWS) {
            let alpha = 1.0 - (-elapsed / window).exp();
            *load += (target - *load) * alpha;
        }
    }

    fn net_rate(&mut self, counted: &[(String, u64, u64)], now: Instant) -> (u64, u64) {
        let rate = match self.prev_net_at {
            Some(previous) => {
                let secs = now.saturating_duration_since(previous).as_secs_f64();
                if secs <= 0.0 {
                    (0, 0)
                } else {
                    let (rx, tx) = counted
                        .iter()
                        .filter_map(|(name, rx, tx)| {
                            let (prev_rx, prev_tx) = self.prev_net.get(name)?;
                            Some((rx.saturating_sub(*prev_rx), tx.saturating_sub(*prev_tx)))
                        })
                        .fold((0u64, 0u64), |(rx, tx), (delta_rx, delta_tx)| {
                            (rx.saturating_add(delta_rx), tx.saturating_add(delta_tx))
                        });
                    ((rx as f64 / secs) as u64, (tx as f64 / secs) as u64)
                }
            }
            None => (0, 0),
        };
        self.prev_net = counted.iter().map(|(name, rx, tx)| (name.clone(), (*rx, *tx))).collect();
        self.prev_net_at = Some(now);
        rate
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_string(value: &[u16]) -> String {
    let end = value.iter().position(|&c| c == 0).unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
}

fn hostname() -> String {
    let mut buffer = [0u16; 256];
    let mut size = buffer.len() as u32;
    // SAFETY: fixed UTF-16 output buffer and its capacity are valid for the call.
    let ok = unsafe { GetComputerNameExW(ComputerNamePhysicalDnsHostname, buffer.as_mut_ptr(), &mut size) };
    if ok != 0 && size > 0 && size as usize <= buffer.len() {
        String::from_utf16_lossy(&buffer[..size as usize])
    } else {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
    }
}

fn windows_version() -> String {
    let mut info =
        OSVERSIONINFOW { dwOSVersionInfoSize: size_of::<OSVERSIONINFOW>() as u32, ..Default::default() };
    // SAFETY: info is writable and declares its exact structure size.
    let status = unsafe { RtlGetVersion(&mut info) };
    if status == 0 {
        format!("{}.{}.{}", info.dwMajorVersion, info.dwMinorVersion, info.dwBuildNumber)
    } else {
        "unknown".into()
    }
}

fn memory() -> (u64, u64, u64, u64) {
    let mut status = MEMORYSTATUSEX { dwLength: size_of::<MEMORYSTATUSEX>() as u32, ..Default::default() };
    // SAFETY: initialized, writable structure with the required dwLength.
    if unsafe { GlobalMemoryStatusEx(&mut status) } == 0 {
        return (0, 0, 0, 0);
    }
    // Windows exposes the commit limit as "TotalPageFile": physical memory
    // plus page files. Subtracting physical memory keeps the wire field's
    // swap meaning instead of reporting all RAM as swap.
    let commit_total = status.ullTotalPageFile;
    let commit_used = commit_total.saturating_sub(status.ullAvailPageFile);
    let physical_used = status.ullTotalPhys.saturating_sub(status.ullAvailPhys);
    let swap_total = commit_total.saturating_sub(status.ullTotalPhys);
    let swap_used = commit_used.saturating_sub(physical_used).min(swap_total);
    (status.ullTotalPhys, physical_used, swap_total, swap_used)
}

fn system_times() -> Option<(u64, u64)> {
    let (mut idle, mut kernel, mut user) = (FILETIME::default(), FILETIME::default(), FILETIME::default());
    // SAFETY: all three FILETIME output pointers are valid and distinct.
    if unsafe { GetSystemTimes(&mut idle, &mut kernel, &mut user) } == 0 {
        return None;
    }
    let idle = filetime(idle);
    let total = filetime(kernel).saturating_add(filetime(user));
    Some((total, idle))
}

fn filetime(value: FILETIME) -> u64 {
    ((value.dwHighDateTime as u64) << 32) | value.dwLowDateTime as u64
}

fn busy_percent(previous: (u64, u64), current: (u64, u64)) -> f32 {
    let ((previous_total, previous_idle), (total, idle)) = (previous, current);
    if total <= previous_total {
        return 0.0;
    }
    let total_delta = (total - previous_total) as f32;
    let idle_delta = idle.saturating_sub(previous_idle) as f32;
    ((total_delta - idle_delta) / total_delta * 100.0).clamp(0.0, 100.0)
}

fn uptime() -> u64 {
    // SAFETY: GetTickCount64 has no pointer arguments or preconditions.
    unsafe { GetTickCount64() / 1000 }
}

fn boot_guid(guid: GUID) -> Option<String> {
    if guid.data1 == 0 && guid.data2 == 0 && guid.data3 == 0 && guid.data4 == [0; 8] {
        return None;
    }
    let [d0, d1, d2, d3, d4, d5, d6, d7] = guid.data4;
    Some(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1, guid.data2, guid.data3, d0, d1, d2, d3, d4, d5, d6, d7
    ))
}

fn query_boot_guid() -> Option<String> {
    let mut info = SystemBootEnvironmentInfo::default();
    let mut returned = 0;
    // SAFETY: info is a writable buffer of the advertised length and matches
    // the selected information class; returned is a valid length out-pointer.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_BOOT_ENVIRONMENT_INFORMATION_CLASS,
            (&mut info as *mut SystemBootEnvironmentInfo).cast(),
            size_of::<SystemBootEnvironmentInfo>() as u32,
            &mut returned,
        )
    };
    (status >= 0 && returned as usize >= size_of::<SystemBootEnvironmentInfo>())
        .then(|| boot_guid(info.boot_identifier))
        .flatten()
}

fn query_boot_time() -> Option<u64> {
    let mut info = SYSTEM_TIMEOFDAY_INFORMATION::default();
    let mut returned = 0;
    // SAFETY: info is a writable buffer of the advertised length and matches
    // the selected information class; returned is a valid length out-pointer.
    let status = unsafe {
        NtQuerySystemInformation(
            SystemTimeOfDayInformation,
            (&mut info as *mut SYSTEM_TIMEOFDAY_INFORMATION).cast(),
            size_of::<SYSTEM_TIMEOFDAY_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if status < 0 || (returned as usize) < size_of::<SYSTEM_TIMEOFDAY_INFORMATION>() {
        return None;
    }
    let boot_time = i64::from_ne_bytes(info.Reserved1[..8].try_into().ok()?);
    let sleep_bias = u64::from_ne_bytes(info.Reserved1[40..48].try_into().ok()?);
    (boot_time > 0)
        .then_some((boot_time as u64).saturating_sub(sleep_bias).saturating_sub(WINDOWS_FILETIME_UNIX_OFFSET))
}

fn boot_id() -> String {
    if let Some(id) = query_boot_guid() {
        return format!("guid:{id}");
    }
    if let Some(boot_time) = query_boot_time() {
        return format!("time:{boot_time}");
    }

    let mut now = FILETIME::default();
    // SAFETY: now points to a writable FILETIME.
    unsafe { GetSystemTimeAsFileTime(&mut now) };
    let now = filetime(now);
    // SAFETY: GetTickCount64 has no preconditions.
    let elapsed = unsafe { GetTickCount64() }.saturating_mul(10_000);
    format!("estimate:{}", now.saturating_sub(elapsed).saturating_sub(WINDOWS_FILETIME_UNIX_OFFSET))
}

fn cpuinfo() -> (String, u32) {
    let name = registry_string(r"HARDWARE\DESCRIPTION\System\CentralProcessor\0", "ProcessorNameString")
        .unwrap_or_else(|| "unknown".into());
    let cores =
        std::thread::available_parallelism().map(|n| n.get().min(u32::MAX as usize) as u32).unwrap_or(1);
    (name.trim().to_owned(), cores.max(1))
}

fn pick_address(held: &[IpAddr], ipv6: bool) -> String {
    held.iter()
        .filter(|ip| ip.is_ipv6() == ipv6)
        .min_by_key(|ip| !is_public(**ip))
        .map_or_else(String::new, ToString::to_string)
}

/// A single bounded allocation, with at most three attempts if interfaces change.
/// u64 storage provides the alignment required by the Windows structures.
struct AdapterBuffer {
    words: Vec<u64>,
    bytes: usize,
}

// Every permitted type has a valid representation for arbitrary initialized
// bytes. Keep this list closed: no bools, references or owning Rust values.
trait BufferValue: Copy {}
impl BufferValue for u16 {}
impl BufferValue for SOCKADDR {}
impl BufferValue for SOCKADDR_IN {}
impl BufferValue for SOCKADDR_IN6 {}
impl BufferValue for IP_ADAPTER_ADDRESSES_LH {}
impl BufferValue for IP_ADAPTER_UNICAST_ADDRESS_LH {}

impl AdapterBuffer {
    fn new(bytes: usize) -> Option<Self> {
        if !(size_of::<IP_ADAPTER_ADDRESSES_LH>()..=MAX_ADAPTER_BYTES).contains(&bytes) {
            return None;
        }
        let count = bytes.div_ceil(size_of::<u64>());
        let mut words = Vec::new();
        words.try_reserve_exact(count).ok()?;
        words.resize(count, 0);
        Some(Self { words, bytes })
    }

    fn contains(&self, pointer: *const u8, bytes: usize) -> bool {
        let start = self.words.as_ptr() as usize;
        let at = pointer as usize;
        !pointer.is_null()
            && at >= start
            && at.checked_add(bytes).is_some_and(|end| end <= start + self.bytes)
    }

    fn read<T: BufferValue>(&self, pointer: *const T) -> Option<T> {
        if !self.contains(pointer.cast(), size_of::<T>()) {
            return None;
        }
        // SAFETY: the entire Copy Win32 structure is inside this live buffer.
        // read_unaligned also handles malformed/misaligned linked-list offsets.
        Some(unsafe { pointer.read_unaligned() })
    }

    fn alias(&self, pointer: *const u16) -> Option<String> {
        let mut words = Vec::new();
        for i in 0..MAX_ALIAS_WORDS {
            // wrapping_add never creates an out-of-allocation reference; read
            // verifies the byte range before any dereference.
            let word = self.read(pointer.wrapping_add(i))?;
            if word == 0 {
                return Some(String::from_utf16_lossy(&words));
            }
            words.push(word);
        }
        None
    }

    fn ip(&self, address: SOCKET_ADDRESS) -> Option<IpAddr> {
        let len = usize::try_from(address.iSockaddrLength).ok()?;
        if !self.contains(address.lpSockaddr.cast(), len) || len < size_of::<SOCKADDR>() {
            return None;
        }
        let family = self.read::<SOCKADDR>(address.lpSockaddr)?.sa_family;
        match family {
            AF_INET if len >= size_of::<SOCKADDR_IN>() => {
                let socket = self.read(address.lpSockaddr.cast::<SOCKADDR_IN>())?;
                // SAFETY: all IN_ADDR union representations contain the same
                // initialized four address bytes returned by Winsock.
                let bytes = unsafe { socket.sin_addr.S_un.S_addr }.to_ne_bytes();
                Some(IpAddr::V4(bytes.into()))
            }
            AF_INET6 if len >= size_of::<SOCKADDR_IN6>() => {
                let socket = self.read(address.lpSockaddr.cast::<SOCKADDR_IN6>())?;
                // SAFETY: Byte is the initialized 16-byte IPv6 representation.
                Some(IpAddr::V6(unsafe { socket.sin6_addr.u.Byte }.into()))
            }
            _ => None,
        }
    }
}

fn adapter_buffer() -> Option<AdapterBuffer> {
    let mut bytes = 15 * 1024;
    for _ in 0..3 {
        let mut buffer = AdapterBuffer::new(bytes as usize)?;
        // SAFETY: aligned, writable buffer has the advertised capacity; the
        // reserved pointer is null and no returned pointer escapes its owner.
        let status = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER,
                null(),
                buffer.words.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut bytes,
            )
        };
        if status == NO_ERROR {
            if bytes as usize > buffer.bytes {
                return None;
            }
            buffer.bytes = bytes as usize;
            return Some(buffer);
        }
        if status != ERROR_BUFFER_OVERFLOW {
            return None;
        }
    }
    None
}

fn addresses() -> (String, String) {
    let Some(buffer) = adapter_buffer() else { return (String::new(), String::new()) };
    addresses_from_buffer(&buffer)
}

fn addresses_from_buffer(buffer: &AdapterBuffer) -> (String, String) {
    let mut held = Vec::new();
    let mut pointer = buffer.words.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    let mut remaining = MAX_ADAPTER_ADDRESSES;
    for _ in 0..MAX_INTERFACES {
        let Some(adapter) = buffer.read(pointer) else { break };
        // SAFETY: Anonymous is the Length/IfIndex view of the API union.
        if (unsafe { adapter.Anonymous1.Anonymous.Length } as usize) < size_of::<IP_ADAPTER_ADDRESSES_LH>() {
            break;
        }
        if adapter.OperStatus == IfOperStatusUp {
            if let Some(alias) = buffer.alias(adapter.FriendlyName) {
                let mut unicast = adapter.FirstUnicastAddress;
                while remaining > 0 {
                    let Some(address) = buffer.read(unicast) else { break };
                    remaining -= 1;
                    // SAFETY: Length is the initialized header view of this union.
                    if (unsafe { address.Anonymous.Anonymous.Length } as usize)
                        < size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>()
                    {
                        break;
                    }
                    if let Some(ip) = buffer.ip(address.Address) {
                        let link_local = match ip {
                            IpAddr::V4(ip) => ip.is_link_local(),
                            IpAddr::V6(ip) => ip.is_unicast_link_local(),
                        };
                        if !link_local && lends_address(&alias, ip) {
                            held.push(ip);
                        }
                    }
                    unicast = address.Next;
                }
            }
        }
        pointer = adapter.Next;
        if remaining == 0 {
            break;
        }
    }
    (pick_address(&held, false), pick_address(&held, true))
}

/// Whether an address on this adapter may be the machine's own. A filtered
/// adapter lends none: its addresses belong to the containers, guests or
/// overlay behind it.
///
/// Cloudflare WARP's `2606:4700::/32` IPv6 range is shared and not reachable
/// from outside, so it is rejected regardless of the adapter alias. WireGuard
/// is otherwise the exception for a public IPv6 address: a machine without
/// IPv6 of its own may have a routed prefix through the tunnel.
///
/// Windows adapter aliases carry the tunnel's name rather than a kernel name,
/// `wg0` by default and a name holding `wireguard` when a user spelled it so;
/// both are recognised here.
fn lends_address(name: &str, ip: IpAddr) -> bool {
    if matches!(ip, IpAddr::V6(v6) if v6.segments()[..2] == [0x2606, 0x4700]) {
        return false;
    }
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("wg") || lower.contains("wireguard") {
        return matches!(ip, IpAddr::V6(_) if is_public(ip));
    }
    !skip_iface(name)
}

struct MibTable(*mut MIB_IF_TABLE2);

impl Drop for MibTable {
    fn drop(&mut self) {
        // SAFETY: this owner is created only for a non-null GetIfTable2 result;
        // FreeMibTable is called exactly once, including early-return paths.
        unsafe { FreeMibTable(self.0.cast::<c_void>()) };
    }
}

fn interface_table() -> Vec<MIB_IF_ROW2> {
    let mut table: *mut MIB_IF_TABLE2 = null_mut();
    // SAFETY: table is a writable out-pointer; the API allocates the table.
    let status = unsafe { GetIfTable2(&mut table) };
    if status != NO_ERROR || table.is_null() {
        return Vec::new();
    }
    let table = MibTable(table);
    if !(table.0 as usize).is_multiple_of(align_of::<MIB_IF_TABLE2>()) {
        return Vec::new();
    }
    // SAFETY: successful GetIfTable2 returns a live, aligned table header.
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > MAX_INTERFACES || count.checked_mul(size_of::<MIB_IF_ROW2>()).is_none() {
        return Vec::new();
    }
    let mut rows = Vec::new();
    if rows.try_reserve_exact(count).is_err() {
        return rows;
    }
    // SAFETY: GetIfTable2 guarantees NumEntries initialized rows. The count
    // was capped and checked above; the owner remains alive during the copy.
    let source = unsafe { slice::from_raw_parts((*table.0).Table.as_ptr(), count) };
    rows.extend_from_slice(source);
    rows
}

fn interface_name(row: &MIB_IF_ROW2) -> String {
    let alias = wide_string(&row.Alias);
    if alias.is_empty() {
        wide_string(&row.Description)
    } else {
        alias
    }
}

#[cfg(test)]
fn counted(row: &MIB_IF_ROW2, ifaces: &Ifaces) -> bool {
    ifaces.counts(row)
}

fn skip_iface(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    VIRTUAL_INTERFACE_WORDS.iter().any(|word| lower.contains(word))
}

fn disk_usage() -> (u64, u64) {
    // SAFETY: GetLogicalDrives has no pointer arguments.
    let drives = unsafe { GetLogicalDrives() };
    let mut total = 0u64;
    let mut used = 0u64;
    for bit in 0..26 {
        if drives & (1 << bit) == 0 {
            continue;
        }
        let path = [(b'A' + bit as u8) as u16, b':' as u16, b'\\' as u16, 0];
        // SAFETY: path is a live NUL-terminated drive root.
        if unsafe { GetDriveTypeW(path.as_ptr()) } != DRIVE_FIXED {
            continue;
        }
        let (mut available, mut capacity, mut free) = (0, 0, 0);
        // SAFETY: path is NUL-terminated and all u64 output pointers are valid.
        if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut available, &mut capacity, &mut free) } != 0 {
            total = total.saturating_add(capacity);
            used = used.saturating_add(capacity.saturating_sub(free));
        }
    }
    (total, used)
}

fn conn_counts() -> (u32, u32) {
    let mut tcp = 0u32;
    let mut udp = 0u32;
    for family in [AF_INET as u32, AF_INET6 as u32] {
        let mut tcp_stats = MIB_TCPSTATS_LH::default();
        // SAFETY: initialized statistics output and a supported address family.
        if unsafe { GetTcpStatisticsEx(&mut tcp_stats, family) } == NO_ERROR {
            tcp = tcp.saturating_add(tcp_stats.dwNumConns);
        }
        let mut udp_stats = MIB_UDPSTATS::default();
        // SAFETY: initialized statistics output and a supported address family.
        if unsafe { GetUdpStatisticsEx(&mut udp_stats, family) } == NO_ERROR {
            udp = udp.saturating_add(udp_stats.dwNumAddrs);
        }
    }
    (tcp, udp)
}

fn proc_count() -> u32 {
    let mut info =
        PERFORMANCE_INFORMATION { cb: size_of::<PERFORMANCE_INFORMATION>() as u32, ..Default::default() };
    // SAFETY: writable structure with the exact cb/size required by the API.
    if unsafe { GetPerformanceInfo(&mut info, size_of::<PERFORMANCE_INFORMATION>() as u32) } != 0 {
        info.ProcessCount
    } else {
        0
    }
}

struct RegistryKey(HKEY);

impl Drop for RegistryKey {
    fn drop(&mut self) {
        // SAFETY: this is an owned key from a successful RegOpenKeyExW and
        // never a predefined root handle; Drop closes it exactly once.
        unsafe { RegCloseKey(self.0) };
    }
}

fn valid_registry_bytes(kind: u32, bytes: u32, capacity: usize) -> bool {
    kind == REG_SZ
        && bytes >= 2
        && bytes <= MAX_REGISTRY_BYTES
        && bytes.is_multiple_of(2)
        && bytes as usize <= capacity
}

fn registry_string(path: &str, value: &str) -> Option<String> {
    let path = wide(path);
    let value = wide(value);
    let mut key: HKEY = null_mut();
    // SAFETY: both names are NUL-terminated, and key is a valid out-pointer.
    let status = unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.as_ptr(), 0, KEY_READ, &mut key) };
    if status != NO_ERROR || key.is_null() {
        return None;
    }
    let key = RegistryKey(key);
    let mut kind = 0;
    let mut bytes = 0u32;
    // SAFETY: key is live; null data requests only the type and byte length.
    let status =
        unsafe { RegQueryValueExW(key.0, value.as_ptr(), null(), &mut kind, null_mut(), &mut bytes) };
    if status != NO_ERROR || !valid_registry_bytes(kind, bytes, MAX_REGISTRY_BYTES as usize) {
        return None;
    }
    let mut data = Vec::<u16>::new();
    data.try_reserve_exact(bytes as usize / 2).ok()?;
    data.resize(bytes as usize / 2, 0);
    // SAFETY: the live UTF-16 allocation is aligned and has bytes capacity;
    // RegQueryValueExW receives that capacity and cannot write beyond it.
    let status = unsafe {
        RegQueryValueExW(key.0, value.as_ptr(), null(), &mut kind, data.as_mut_ptr().cast(), &mut bytes)
    };
    // Recheck type and actual length: the value can change between the calls.
    if status != NO_ERROR || !valid_registry_bytes(kind, bytes, data.len() * 2) {
        return None;
    }
    let data = &data[..bytes as usize / 2];
    // REG_SZ is expected to be terminated; reject malformed/truncated data.
    if data.last() != Some(&0) {
        return None;
    }
    Some(wide_string(data))
}

/// The virtualization this system runs under, `none` on bare metal. A
/// container is not told from the machine whose kernel it shares: Windows
/// containers are not this agent's target.
fn virtualization() -> String {
    hypervisor().unwrap_or("none").into()
}

/// The hypervisor beneath this system, `None` on bare metal. A hypervisor
/// names itself in CPUID leaf 0x40000000, behind the hypervisor bit of leaf 1;
/// one that clears the bit leaves its guest reported as bare metal. Its DMI
/// strings are the provider's to choose -- `KVM`, `QEMU`, a cloud's own name
/// -- and would name one hypervisor several ways.
fn hypervisor() -> Option<&'static str> {
    let signature = cpuid_signature()?;
    match signature_name(&signature) {
        // The one signature a guest shares with its host: the root partition
        // of a Hyper-V machine, and a bare machine whose VBS runs the OS under
        // the same hypervisor, read Microsoft's beside their own OEM firmware.
        Some("hyper-v") => firmware_named_hypervisor(),
        Some(name) => Some(name),
        None => Some("vm"),
    }
}

/// The 12-byte vendor signature of CPUID leaf 0x40000000, `None` where leaf 1
/// reports no hypervisor.
// __cpuid was unsafe on older stable toolchains and is safe on newer ones.
// Keep the explicit boundary for both; suppress only this compatibility lint.
#[allow(unused_unsafe)]
fn cpuid_signature() -> Option<[u8; 12]> {
    use std::arch::x86_64::__cpuid;
    // SAFETY: CPUID is guaranteed on x86-64; leaf 1 exists on every supported
    // CPU and does not access caller memory.
    if unsafe { __cpuid(1) }.ecx >> 31 == 0 {
        return None;
    }
    // SAFETY: CPUID is supported and the hypervisor-present bit was checked.
    // An unknown hypervisor leaf returns register values, not memory pointers.
    let leaf = unsafe { __cpuid(0x4000_0000) };
    let mut signature = [0; 12];
    for (bytes, reg) in signature.chunks_mut(4).zip([leaf.ebx, leaf.ecx, leaf.edx]) {
        bytes.copy_from_slice(&reg.to_le_bytes());
    }
    Some(signature)
}

/// The hypervisor a 12-byte CPUID signature names, `None` for a signature
/// that is none of these (reported as a plain `vm`).
fn signature_name(signature: &[u8; 12]) -> Option<&'static str> {
    Some(match signature {
        b"KVMKVMKVM\0\0\0" | b"Linux KVM Hv" => "kvm",
        b"TCGTCGTCGTCG" => "qemu",
        b"Microsoft Hv" => "hyper-v",
        b"VMwareVMware" => "vmware",
        b"VBoxVBoxVBox" => "virtualbox",
        b"XenVMMXenVMM" => "xen",
        b"bhyve bhyve " => "bhyve",
        _ => return None,
    })
}

/// The hypervisor a Microsoft CPUID signature hides, told from the firmware
/// strings an administrator reads in `msinfo32`. A Xen guest offered the
/// Hyper-V interface still names Xen, and AWS and Google run their instances
/// on KVM. `None` when they name no hypervisor: that is the root partition of
/// a Hyper-V machine, or a bare machine with VBS on.
fn firmware_named_hypervisor() -> Option<&'static str> {
    let text = [
        registry_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemManufacturer"),
        registry_string(r"HARDWARE\DESCRIPTION\System\BIOS", "SystemProductName"),
    ]
    .iter()
    .filter_map(Option::as_deref)
    .collect::<Vec<_>>()
    .join(" ")
    .to_ascii_lowercase();
    [("xen", "xen"), ("amazon", "kvm"), ("google", "kvm"), ("virtual machine", "hyper-v")]
        .into_iter()
        .find_map(|(needle, name)| text.contains(needle).then_some(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reconnect_discards_cpu_network_and_load_history() {
        let mut collector = Collector::new(Ifaces::default());
        collector.cpu_info = Some(("test CPU".into(), 8));
        collector.prev_cpu = Some((1000, 900));
        collector.prev_net.insert("Ethernet".into(), (10, 20));
        collector.prev_net_at = Some(Instant::now());
        collector.load = [42.0; 3];
        collector.load_at = Some(Instant::now() - Duration::from_secs(300));
        collector.reset_session();
        assert_eq!(collector.prev_cpu, None);
        assert_eq!(collector.prev_net_at, None);
        assert!(collector.prev_net.is_empty());
        assert_eq!(collector.load_at, None);
        assert_eq!(collector.load, [0.0; 3]);
        // The first valid one-second delta initializes load directly, without
        // exponentially blending either baseline zero or a disconnected mean.
        collector.update_load(50.0, Instant::now());
        assert_eq!(collector.load, [4.0; 3]);
    }

    #[test]
    fn session_baseline_does_not_seed_load_with_synthetic_cpu_zero() {
        let mut collector = Collector::new(Ifaces::default());
        collector.begin_session_baseline();
        assert_eq!(collector.load_at, None);
        assert_eq!(collector.load, [0.0; 3]);
        assert!(collector.prev_net_at.is_some());
    }

    #[test]
    fn disk_and_cpu_caches_avoid_per_sample_disk_and_registry_reads() {
        let mut collector = Collector::new(Ifaces::default());
        collector.cpu_info = Some(("cached CPU".into(), 4));
        collector.disk = (1234, 1000);
        collector.disk_at = Some(Instant::now());
        assert_eq!(collector.disk_usage(), (1234, 1000));
        collector.update_load(50.0, Instant::now());
        assert_eq!(collector.load, [2.0; 3]);
        assert_eq!(collector.cpu_info.as_ref().unwrap().0, "cached CPU");
    }

    #[test]
    fn registry_length_type_and_second_read_capacity_are_bounded() {
        assert!(valid_registry_bytes(REG_SZ, 2, 2));
        assert!(valid_registry_bytes(REG_SZ, MAX_REGISTRY_BYTES, MAX_REGISTRY_BYTES as usize));
        for bytes in [0, 1, 3, MAX_REGISTRY_BYTES + 2, u32::MAX] {
            assert!(!valid_registry_bytes(REG_SZ, bytes, usize::MAX), "{bytes}");
        }
        assert!(!valid_registry_bytes(REG_SZ, 4, 2), "value grew between reads");
        assert!(!valid_registry_bytes(3, 4, 4), "REG_BINARY is not a string");
    }

    #[test]
    fn adapter_allocation_and_pointer_reads_are_bounded() {
        assert!(AdapterBuffer::new(MAX_ADAPTER_BYTES + 1).is_none());
        assert!(AdapterBuffer::new(0).is_none());
        let buffer = AdapterBuffer::new(2048).unwrap();
        assert!(buffer.read::<u16>(null()).is_none());
        let end = buffer.words.as_ptr().cast::<u8>().wrapping_add(buffer.bytes);
        assert!(buffer.read::<u16>(end.cast()).is_none());
        assert!(!buffer.contains(usize::MAX as *const u8, 2));
        assert!(buffer
            .ip(SOCKET_ADDRESS { lpSockaddr: buffer.words.as_ptr().cast_mut().cast(), iSockaddrLength: -1 })
            .is_none());
    }

    #[test]
    fn bounded_adapter_socket_decoding_preserves_network_byte_order() {
        let mut buffer = AdapterBuffer::new(4096).unwrap();
        let pointer = buffer.words.as_mut_ptr().cast::<SOCKADDR_IN>();
        let mut socket = SOCKADDR_IN { sin_family: AF_INET, ..Default::default() };
        socket.sin_addr.S_un.S_addr = u32::from_ne_bytes([8, 8, 4, 4]);
        // SAFETY: pointer is aligned and the allocation exceeds this structure.
        unsafe { pointer.write(socket) };
        let address =
            SOCKET_ADDRESS { lpSockaddr: pointer.cast(), iSockaddrLength: size_of::<SOCKADDR_IN>() as i32 };
        assert_eq!(buffer.ip(address), Some("8.8.4.4".parse().unwrap()));
        assert!(buffer.ip(SOCKET_ADDRESS { iSockaddrLength: 2, ..address }).is_none());
        let pointer = buffer.words.as_mut_ptr().cast::<SOCKADDR_IN6>();
        let mut socket = SOCKADDR_IN6 { sin6_family: AF_INET6, ..Default::default() };
        let ip = "2001:4860:4860::8888".parse::<std::net::Ipv6Addr>().unwrap();
        socket.sin6_addr.u.Byte = ip.octets();
        // SAFETY: pointer is aligned and the allocation exceeds this structure.
        unsafe { pointer.write(socket) };
        assert_eq!(
            buffer.ip(SOCKET_ADDRESS {
                lpSockaddr: pointer.cast(),
                iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32,
            }),
            Some(IpAddr::V6(ip))
        );
    }

    #[test]
    fn unterminated_adapter_alias_and_linked_list_cycles_are_bounded() {
        let mut buffer = AdapterBuffer::new(4096).unwrap();
        buffer.words.fill(u64::MAX);
        assert!(buffer.alias(buffer.words.as_ptr().cast()).is_none());
        buffer.words.fill(0);
        let pointer = buffer.words.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let mut adapter = IP_ADAPTER_ADDRESSES_LH {
            Next: pointer, // Deliberately cyclic kernel-derived list.
            OperStatus: IfOperStatusUp,
            FriendlyName: usize::MAX as *mut u16,
            ..Default::default()
        };
        adapter.Anonymous1.Anonymous =
            windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_ADDRESSES_LH_0_0 {
                Length: size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32,
                IfIndex: 0,
            };
        // SAFETY: pointer is aligned, writable and has space for this Copy
        // structure; all pointers in the fake structure are range-checked.
        unsafe { pointer.write(adapter) };
        assert_eq!(addresses_from_buffer(&buffer), (String::new(), String::new()));
    }

    #[test]
    fn bounded_adapter_parser_checks_both_union_lengths() {
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            IP_ADAPTER_ADDRESSES_LH_0, IP_ADAPTER_ADDRESSES_LH_0_0, IP_ADAPTER_UNICAST_ADDRESS_LH_0,
            IP_ADAPTER_UNICAST_ADDRESS_LH_0_0,
        };
        let mut buffer = AdapterBuffer::new(4096).unwrap();
        let base = buffer.words.as_mut_ptr().cast::<u8>();
        let adapter_pointer = base.cast::<IP_ADAPTER_ADDRESSES_LH>();
        let unicast_pointer = base.wrapping_add(1024).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
        let alias_pointer = base.wrapping_add(2048).cast::<u16>();
        let socket_pointer = base.wrapping_add(3072).cast::<SOCKADDR_IN>();
        let mut adapter = IP_ADAPTER_ADDRESSES_LH {
            Anonymous1: IP_ADAPTER_ADDRESSES_LH_0 {
                Anonymous: IP_ADAPTER_ADDRESSES_LH_0_0 {
                    Length: size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32,
                    IfIndex: 1,
                },
            },
            FirstUnicastAddress: unicast_pointer,
            FriendlyName: alias_pointer,
            OperStatus: IfOperStatusUp,
            ..Default::default()
        };
        let mut unicast = IP_ADAPTER_UNICAST_ADDRESS_LH {
            Anonymous: IP_ADAPTER_UNICAST_ADDRESS_LH_0 {
                Anonymous: IP_ADAPTER_UNICAST_ADDRESS_LH_0_0 {
                    Length: size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32,
                    Flags: 0,
                },
            },
            Address: SOCKET_ADDRESS {
                lpSockaddr: socket_pointer.cast::<SOCKADDR>(),
                iSockaddrLength: size_of::<SOCKADDR_IN>() as i32,
            },
            ..Default::default()
        };
        let mut socket = SOCKADDR_IN { sin_family: AF_INET, ..Default::default() };
        socket.sin_addr.S_un.S_addr = u32::from_ne_bytes([8, 8, 4, 4]);
        let alias = wide("Ethernet");
        // SAFETY: all objects occupy distinct, aligned ranges of the 4 KiB
        // allocation. Their pointers remain valid for the parser below.
        unsafe {
            adapter_pointer.write(adapter);
            unicast_pointer.write(unicast);
            socket_pointer.write(socket);
            std::ptr::copy_nonoverlapping(alias.as_ptr(), alias_pointer, alias.len());
        }
        assert_eq!(addresses_from_buffer(&buffer), ("8.8.4.4".into(), String::new()));
        unicast.Anonymous.Anonymous = IP_ADAPTER_UNICAST_ADDRESS_LH_0_0 { Length: 8, Flags: 0 };
        // SAFETY: same live, aligned unicast output slot as above.
        unsafe { unicast_pointer.write(unicast) };
        assert_eq!(addresses_from_buffer(&buffer), (String::new(), String::new()));
        adapter.Anonymous1.Anonymous = IP_ADAPTER_ADDRESSES_LH_0_0 { Length: 8, IfIndex: 1 };
        // SAFETY: same live, aligned adapter output slot as above.
        unsafe { adapter_pointer.write(adapter) };
        assert_eq!(addresses_from_buffer(&buffer), (String::new(), String::new()));
    }

    #[test]
    fn busy_percent_uses_system_time_deltas() {
        assert_eq!(busy_percent((1000, 900), (1200, 950)), 75.0);
        assert_eq!(busy_percent((1000, 900), (1200, 1100)), 0.0);
        assert_eq!(busy_percent((1000, 900), (500, 400)), 0.0);
    }

    #[test]
    fn boot_guid_formats_as_a_stable_identifier() {
        let guid = GUID {
            data1: 0x0123_4567,
            data2: 0x89ab,
            data3: 0xcdef,
            data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
        };
        assert_eq!(boot_guid(guid).as_deref(), Some("01234567-89ab-cdef-0123-456789abcdef"));
        assert_eq!(boot_guid(GUID::default()), None);

        assert!(
            query_boot_guid().is_some() || query_boot_time().is_some(),
            "a kernel boot-time API must be available"
        );
        if let Some(first) = query_boot_guid() {
            assert_eq!(query_boot_guid(), Some(first));
        }
        if let Some(first) = query_boot_time() {
            assert_eq!(query_boot_time(), Some(first));
        }
        assert_eq!(boot_id(), boot_id(), "the OS boot id must not vary between samples");
    }

    #[test]
    fn iface_is_in_the_metrics_protocol() {
        let metrics = Metrics { iface: "Ethernet,-vEthernet (WSL)".into(), ..Metrics::default() };
        let json = serde_json::to_value(metrics).unwrap();
        assert_eq!(json["iface"], "Ethernet,-vEthernet (WSL)");
    }

    #[test]
    fn public_addresses_win_within_each_family() {
        let held: [IpAddr; 4] = [
            "10.0.0.2".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            "2001:4860:4860::8888".parse().unwrap(),
        ];
        assert_eq!(pick_address(&held, false), "8.8.8.8");
        assert_eq!(pick_address(&held, true), "2001:4860:4860::8888");
        assert!(is_public("8.8.8.8".parse().unwrap()));
        assert!(!is_public("100.64.1.2".parse().unwrap()));
        assert!(!is_public("198.18.0.1".parse().unwrap()));
        assert!(!is_public("fd00::1".parse().unwrap()));
    }

    #[test]
    fn interface_filters_support_inclusions_exclusions_and_legacy_names() {
        let mut row = MIB_IF_ROW2::default();
        let alias = wide("vEthernet (WSL)");
        row.Alias[..alias.len()].copy_from_slice(&alias);
        assert!(!counted(&row, &Ifaces::default()));
        assert!(counted(&row, &Ifaces::parse("vEthernet (WSL)").unwrap()));
        assert!(!counted(&row, &Ifaces::parse("Ethernet,-vEthernet (WSL)").unwrap()));
        assert!(!counted(&row, &Ifaces::parse("-vEthernet (WSL)").unwrap()));
        assert!(counted(&row, &Ifaces::from_legacy(vec!["vEthernet (WSL)".into()])));
        row.Type = 131;
        let tunnel_alias = wide("Secure Gateway");
        row.Alias[..tunnel_alias.len()].copy_from_slice(&tunnel_alias);
        assert!(!counted(&row, &Ifaces::default()), "tunnels are excluded by default");
        assert!(
            counted(&row, &Ifaces::parse("Secure Gateway").unwrap()),
            "explicit selection overrides defaults"
        );
    }

    #[test]
    fn iface_parser_normalizes_lists_and_rejects_ambiguous_names() {
        let ifaces = Ifaces::parse(" Ethernet , Wi-Fi, -vEthernet (WSL), ").unwrap();
        assert_eq!(ifaces.spec(), "Ethernet,Wi-Fi,-vEthernet (WSL)");
        assert_eq!(ifaces.only(), ["Ethernet", "Wi-Fi"]);
        for invalid in ["-", "--Ethernet", "eth0,\ninvalid"] {
            assert!(Ifaces::parse(invalid).is_err(), "{invalid:?}");
        }
        assert!(Ifaces::parse(" , ").unwrap().spec().is_empty());
    }

    #[test]
    fn interface_epoch_tracks_the_sorted_counted_set() {
        let value = |names: &[&str]| epoch("boot", names.iter().copied());
        assert_ne!(value(&["Ethernet"]), value(&["Ethernet", "Wi-Fi"]));
        assert_ne!(value(&["Ethernet"]), value(&[]));
        assert_eq!(value(&["Wi-Fi", "Ethernet"]), value(&["Ethernet", "Wi-Fi"]));
    }

    #[test]
    fn network_rates_ignore_joining_adapters_and_counter_resets() {
        let start = Instant::now();
        let mut collector = Collector::new(Ifaces::default());
        collector.prev_net_at = Some(start);
        collector.prev_net.insert("Ethernet".into(), (100, 200));
        let current = vec![("Ethernet".into(), 150, 270), ("Wi-Fi".into(), 900, 900)];
        assert_eq!(collector.net_rate(&current, start + std::time::Duration::from_secs(1)), (50, 70));
        let reset = vec![("Ethernet".into(), 5, 10)];
        assert_eq!(collector.net_rate(&reset, start + std::time::Duration::from_secs(2)), (0, 0));
    }

    #[test]
    fn a_cpuid_signature_is_named_as_the_linux_agent_names_it() {
        for (signature, name) in [
            (b"KVMKVMKVM\0\0\0", "kvm"),
            (b"Linux KVM Hv", "kvm"),
            (b"TCGTCGTCGTCG", "qemu"),
            (b"Microsoft Hv", "hyper-v"),
            (b"VMwareVMware", "vmware"),
            (b"VBoxVBoxVBox", "virtualbox"),
            (b"XenVMMXenVMM", "xen"),
            (b"bhyve bhyve ", "bhyve"),
        ] {
            assert_eq!(signature_name(signature), Some(name), "{signature:?}");
        }
        assert_eq!(signature_name(b"GenuineIntel"), None);
    }

    #[test]
    fn virtual_interfaces_are_not_billed_by_default() {
        for name in ["vEthernet (WSL)", "Loopback Pseudo-Interface 1", "Tailscale"] {
            assert!(skip_iface(name), "{name}");
        }
        assert!(!skip_iface("Ethernet"));
    }

    #[test]
    fn a_wireguard_link_lends_only_a_public_v6() {
        let ip = |s: &str| s.parse::<IpAddr>().unwrap();
        assert!(lends_address("wg0", ip("2001:db8::2")), "a routed prefix through the tunnel");
        assert!(!lends_address("wg0", ip("203.0.113.9")), "only v6 is asked of a tunnel");
        assert!(!lends_address("wg0", ip("10.0.0.2")), "a VPN's own address is not the machine's");
        assert!(!lends_address("wg0", ip("fd00::2")));
        for name in ["wgcf", "warp", "CloudflareWARP", "Ethernet"] {
            assert!(
                !lends_address(name, ip("2606:4700:110:8a36::1")),
                "WARP's shared address is excluded on every adapter ({name})"
            );
        }
        assert!(lends_address("WireGuard Home", ip("2001:db8::2")), "the word names the same tunnel");
        assert!(!lends_address("WireGuard Home", ip("10.7.0.2")));
        assert!(!lends_address("vEthernet (WSL)", ip("2001:db8::1")), "a virtual adapter lends nothing");
        assert!(lends_address("Ethernet", ip("2001:db8::2")), "ordinary adapters lend public IPv6");

        // What `addresses` makes of a machine with a private v4 and a v6 only
        // through WireGuard.
        let held: Vec<IpAddr> = [("Ethernet", "10.0.0.2"), ("wg0", "10.9.0.2"), ("wg0", "2001:db8::2")]
            .into_iter()
            .filter(|(name, address)| lends_address(name, ip(address)))
            .map(|(_, address)| ip(address))
            .collect();
        assert_eq!(pick_address(&held, false), "10.0.0.2");
        assert_eq!(pick_address(&held, true), "2001:db8::2");
    }

    #[test]
    fn listed_adapter_alias_overrides_default_filtering() {
        let mut row = MIB_IF_ROW2 { Type: 24, ..Default::default() };
        let alias = wide("Loopback Pseudo-Interface 1");
        row.Alias[..alias.len()].copy_from_slice(&alias);
        assert!(!counted(&row, &Ifaces::default()));
        assert!(counted(&row, &Ifaces::parse("Loopback Pseudo-Interface 1").unwrap()));
    }
}
