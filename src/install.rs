//! Protected Windows configuration and transactional service installation.
use super::{
    Args, CONFIG_DIR_NAME, CONFIG_FILE_NAME, DEFAULT_SERVICE_NAME, LOG_FILE_NAME, SERVICE_DESCRIPTION,
    SERVICE_DISPLAY_NAME,
};
use crate::secure_fs;
use anyhow::{anyhow, bail, Context, Result};
use std::os::windows::ffi::OsStringExt;
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use windows_service::{
    service::{
        ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
        ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

pub(super) fn default_config_path(service_name: &str) -> PathBuf {
    // Preserve the infallible legacy API: failure produces a non-writable sentinel,
    // never an environment fallback. All privileged operations resolve it again.
    let root = secure_fs::program_data().unwrap_or_else(|_| PathBuf::from(r"\\?\INVALID-KNOWN-FOLDER"));
    let root = root.join(CONFIG_DIR_NAME);
    if service_name.eq_ignore_ascii_case(DEFAULT_SERVICE_NAME) {
        root.join(CONFIG_FILE_NAME)
    } else {
        root.join(format!("{service_name}.env"))
    }
}

pub(super) fn validate_service_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 80
        || name.ends_with('.')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        bail!("invalid service name: use 1-80 ASCII letters, digits, '-', '_' or '.', with no trailing dot");
    }
    let lower = name.to_ascii_lowercase();
    let stem = lower.split('.').next().unwrap_or_default();
    if lower == "agent"
        || matches!(stem, "con" | "prn" | "aux" | "nul" | "clock$" | "conin$" | "conout$")
        || ((stem.starts_with("com") || stem.starts_with("lpt"))
            && stem.len() == 4
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
    {
        bail!("reserved Windows device or agent configuration/log name");
    }
    Ok(())
}

pub(super) fn parse_service_name<I>(args: I) -> Result<String>
where
    I: IntoIterator<Item = String>,
{
    let mut name = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "service" => {}
            "--service-name" => {
                name = Some(it.next().ok_or_else(|| anyhow!("missing value for --service-name"))?);
            }
            "--config" => {
                it.next().ok_or_else(|| anyhow!("missing value for --config"))?;
            }
            other => bail!("unknown service option: {other}"),
        }
    }
    let name = name.unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_owned());
    validate_service_name(&name)?;
    Ok(name)
}

pub(super) fn absolute_path(path: &Path) -> Result<PathBuf> {
    secure_fs::absolute(path)
}

pub(super) fn read_config(path: &Path) -> Result<HashMap<String, zeroize::Zeroizing<String>>> {
    let bytes = secure_fs::read_secret(path, MAX_CONFIG_BYTES as u64)?;
    parse_config_bytes(bytes.as_slice())
}
/// Upgrade compatibility only; runtime/service callers must use read_config.
pub(super) fn read_config_for_install(path: &Path) -> Result<HashMap<String, zeroize::Zeroizing<String>>> {
    let bytes = secure_fs::read_for_install(path, MAX_CONFIG_BYTES as u64)?;
    parse_config_bytes(bytes.as_slice())
}

const MAX_CONFIG_BYTES: usize = 64 * 1024;
const KNOWN_CONFIG_KEYS: &[&str] = &[
    "MONITOR_SERVICE_NAME",
    "MONITOR_SERVER",
    "MONITOR_TOKEN",
    "MONITOR_INTERVAL",
    "MONITOR_IFACE",
    "MONITOR_NICS",
    "MONITOR_INSECURE",
    "MONITOR_PROBE_ALLOW",
];
fn parse_config_bytes(bytes: &[u8]) -> Result<HashMap<String, zeroize::Zeroizing<String>>> {
    if bytes.len() > MAX_CONFIG_BYTES {
        bail!("configuration exceeds 64 KiB");
    }
    let content = std::str::from_utf8(bytes).context("configuration must be UTF-8")?;
    let mut values = HashMap::new();
    for (index, line) in content.lines().enumerate() {
        if index >= 256 || line.len() > 8192 {
            bail!("configuration line/count limit exceeded");
        }
        if line.chars().any(|c| c.is_control() && c != '\t') {
            bail!("control character in configuration");
        }
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').context("invalid configuration line")?;
        let (key, value) = (key.trim(), value.trim());
        if key.len() > 64 || value.chars().any(char::is_control) {
            bail!("invalid configuration field");
        }
        if !KNOWN_CONFIG_KEYS.contains(&key) {
            bail!("unknown configuration key (possible typo)");
        }
        if values.insert(key.to_owned(), zeroize::Zeroizing::new(value.to_owned())).is_some() {
            bail!("duplicate configuration key");
        }
    }
    Ok(values)
}

pub(super) fn parse_bool(value: &str) -> Result<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => bail!("invalid boolean value"),
    }
}

pub(super) fn validate_config_value(name: &str, value: &str) -> Result<()> {
    if value.len() > 8192 || value.chars().any(char::is_control) {
        bail!("{name} contains control characters or is too long");
    }
    Ok(())
}

#[allow(dead_code)] // Retained installation helper API; transaction stages config before committing.
pub(super) fn write_config(args: &Args) -> Result<()> {
    let parent = args.config_path.parent().context("configuration needs parent")?;
    let _guard = secure_fs::ensure_private_dir(parent)?;
    config_stage(args)?.commit(&args.config_path)
}
fn config_stage(args: &Args) -> Result<secure_fs::Stage> {
    validate_service_name(&args.service_name)?;
    validate_config_value("server", &args.server)?;
    validate_config_value("token", args.token.as_str())?;
    validate_config_value("iface", args.ifaces.spec())?;
    validate_config_value("probe allow", &args.probe_allow)?;
    let content = zeroize::Zeroizing::new(format!("MONITOR_SERVICE_NAME={}\nMONITOR_SERVER={}\nMONITOR_TOKEN={}\nMONITOR_INTERVAL={}\nMONITOR_IFACE={}\nMONITOR_INSECURE={}\nMONITOR_PROBE_ALLOW={}\n",
        args.service_name, args.server, args.token.as_str(), args.interval, args.ifaces.spec(), u8::from(args.insecure), args.probe_allow));
    parse_config_bytes(content.as_bytes())?;
    let stage = secure_fs::Stage::new(args.config_path.parent().context("missing config parent")?)?;
    // Exact protected DACL is already installed before the first secret byte.
    stage.write_all(content.as_bytes())?;
    stage.file().sync_all()?;
    harden_config(&stage.path)?;
    Ok(stage)
}

pub(super) fn system_icacls_path() -> Result<PathBuf> {
    let mut buffer = vec![0u16; 260];
    loop {
        let length = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if length == 0 {
            return Err(std::io::Error::last_os_error()).context("get Windows system directory");
        }
        let length = length as usize;
        if length < buffer.len() {
            buffer.truncate(length);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)).join("icacls.exe"));
        }
        buffer.resize(length + 1, 0);
    }
}

pub(super) fn harden_config(path: &Path) -> Result<()> {
    // Setting, not merely granting, the exact protected DACL is handled by secure_fs
    // at file creation. Keep the absolute system icacls validation business rule.
    let mut child = Command::new(system_icacls_path()?)
        .arg(path)
        .arg("/verify")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("run system icacls verification")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    bail!("system icacls configuration verification failed");
                }
                break;
            }
            Ok(None) if std::time::Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                if let Err(e) = result {
                    return Err(e).context("wait for system icacls");
                }
                bail!("system icacls verification exceeded 15 seconds");
            }
        }
    }
    Ok(())
}

pub(super) fn current_service_name() -> String {
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if arg == "--service-name" {
            if let Some(name) = it.next() {
                if validate_service_name(&name).is_ok() {
                    return name;
                }
            }
        }
    }
    DEFAULT_SERVICE_NAME.to_owned()
}

pub(super) fn log_path() -> PathBuf {
    let service_name = current_service_name();
    let filename = if service_name.eq_ignore_ascii_case(DEFAULT_SERVICE_NAME) {
        LOG_FILE_NAME.to_owned()
    } else {
        format!("{service_name}.log")
    };
    default_config_path(&service_name).with_file_name(filename)
}

pub(super) fn service_display_name(service_name: &str) -> String {
    if service_name.eq_ignore_ascii_case(DEFAULT_SERVICE_NAME) {
        SERVICE_DISPLAY_NAME.to_owned()
    } else {
        format!("{SERVICE_DISPLAY_NAME} ({service_name})")
    }
}

pub(super) fn installed_binary_path() -> PathBuf {
    default_config_path(DEFAULT_SERVICE_NAME).with_file_name("monitor-agent.exe")
}

pub(super) fn prepare_binary_copy() -> Result<(PathBuf, Option<secure_fs::Stage>)> {
    let source = std::env::current_exe()?;
    let target = installed_binary_path();
    secure_fs::check_destination(&target)?;
    if secure_fs::os_eq(source.as_os_str(), target.as_os_str()) {
        return Ok((target, None));
    }
    let stage = secure_fs::Stage::new(target.parent().context("missing installation root")?)?;
    let mut source = fs::File::open(source)?;
    stage.copy_from(&mut source)?;
    stage.file().sync_all()?;
    Ok((target, Some(stage)))
}

pub(super) fn commit_binary_copy(pending: Option<secure_fs::Stage>, target: &Path) -> Result<()> {
    if let Some(stage) = pending {
        stage.commit(target)?;
    }
    Ok(())
}

pub(super) fn service_info(args: &Args, binary_path: &Path) -> Result<ServiceInfo> {
    Ok(ServiceInfo {
        name: OsString::from(&args.service_name),
        display_name: OsString::from(service_display_name(&args.service_name)),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: binary_path.to_owned(),
        launch_arguments: vec![
            OsString::from("service"),
            OsString::from("--config"),
            args.config_path.as_os_str().to_owned(),
            OsString::from("--service-name"),
            OsString::from(&args.service_name),
        ],
        dependencies: Vec::new(),
        account_name: None,
        account_password: None,
    })
}

pub(super) fn open_service(
    service_name: &str,
    access: ServiceAccess,
) -> Result<windows_service::service::Service> {
    validate_service_name(service_name)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = manager.open_service(service_name, access | ServiceAccess::QUERY_CONFIG)?;
    verify_service(&service, service_name)?;
    Ok(service)
}
fn service_is_missing(error: &windows_service::Error) -> bool {
    matches!(error, windows_service::Error::Winapi(e) if e.raw_os_error()==Some(1060))
}
fn verify_service(service: &windows_service::service::Service, name: &str) -> Result<()> {
    let config = service.query_config()?;
    let arguments = secure_fs::command_arguments(&config.executable_path)?;
    let expected = installed_binary_path();
    if arguments.len() != 6
        || !secure_fs::os_eq(&arguments[0], expected.as_os_str())
        || arguments[1] != "service"
        || arguments[2] != "--config"
        || arguments[4] != "--service-name"
        || !secure_fs::os_eq(&arguments[5], OsStr::new(name))
        || config.display_name != OsString::from(service_display_name(name))
        || config.service_type != ServiceType::OWN_PROCESS
        || !config.account_name.as_ref().is_some_and(|v| {
            secure_fs::os_eq(v, OsStr::new("LocalSystem"))
                || secure_fs::os_eq(v, OsStr::new(r"NT AUTHORITY\SYSTEM"))
        })
    {
        bail!("refusing to modify service {name}: not an identified monitor-agent service");
    }
    secure_fs::absolute(Path::new(&arguments[3]))?;
    Ok(())
}

pub(super) fn configured_service_names() -> Result<Vec<String>> {
    // SCM enumeration also finds instances using administrator-selected custom configs.
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let mut names = Vec::new();
    for name in enumerate_service_names()? {
        let service = manager.open_service(&name, ServiceAccess::QUERY_CONFIG)?;
        let config = service.query_config()?;
        let args = secure_fs::command_arguments(&config.executable_path)?;
        if args.first().is_some_and(|v| secure_fs::os_eq(v, installed_binary_path().as_os_str())) {
            validate_service_name(&name)?;
            verify_service(&service, &name)?;
            names.push(name);
        }
    }
    Ok(names)
}

#[allow(dead_code)] // Retained helper API; durable install records full running set before stopping.
pub(super) fn stop_running_services() -> Result<Vec<String>> {
    let mut stopped = Vec::new();
    let result = (|| -> Result<()> {
        for name in configured_service_names()? {
            let service = open_service(&name, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
            if service.query_status()?.current_state != ServiceState::Stopped {
                // Record BEFORE stopping: a timeout may still result in a late successful stop.
                stopped.push(name.clone());
                stop_and_wait(&service, &name)?;
            }
        }
        Ok(())
    })();
    if let Err(error) = result {
        let recovery = restart_services(&stopped);
        return match recovery {
            Ok(()) => Err(error),
            Err(e) => Err(error.context(format!("service recovery also failed: {e}"))),
        };
    }
    Ok(stopped)
}

pub(super) fn restart_services(names: &[String]) -> Result<()> {
    let mut failures = Vec::new();
    for name in names {
        let result = (|| -> Result<()> {
            let service = open_service(name, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
            let mut requested = false;
            for _ in 0..30 {
                match service.query_status()?.current_state {
                    ServiceState::Running => return Ok(()),
                    ServiceState::Stopped if !requested => {
                        service.start::<&OsStr>(&[])?;
                        requested = true;
                    }
                    ServiceState::Stopped => bail!("{name} stopped again during recovery start"),
                    ServiceState::StopPending | ServiceState::StartPending => {}
                    _ => bail!("{name} is not in a recoverable running/stopped state"),
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            bail!("{name} did not reach Running within 30 seconds")
        })();
        if let Err(e) = result {
            failures.push(format!("{name}: {e}"));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        bail!("could not restore services: {}", failures.join("; "))
    }
}

pub(super) fn stop_and_wait(service: &windows_service::service::Service, service_name: &str) -> Result<()> {
    if service.query_status()?.current_state == ServiceState::Stopped {
        return Ok(());
    }
    if service.query_status()?.current_state != ServiceState::StopPending {
        service.stop()?;
    }
    for _ in 0..30 {
        if service.query_status()?.current_state == ServiceState::Stopped {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    bail!("service {service_name} did not stop within 30 seconds")
}

pub(super) fn install_service(args: Args) -> Result<()> {
    validate_service_name(&args.service_name)?;
    let root = secure_fs::program_data()?.join(CONFIG_DIR_NAME);
    let _root_guard = secure_fs::ensure_private_dir(&root)?;
    let _lock =
        secure_fs::lock(&root).context("another installer is active or installation lock is unsafe")?;
    // Replay BEFORE garbage collection or touching new installation state.
    recover_previous_install(&root)?;
    secure_fs::cleanup_stages(&root)?;
    validate_install_config_path(&args.config_path, &args.service_name, &root)?;
    let config_parent = args.config_path.parent().context("missing config parent")?;
    let _config_guard = secure_fs::ensure_private_dir(config_parent)?;
    if !secure_fs::os_eq(config_parent.as_os_str(), root.as_os_str()) {
        secure_fs::cleanup_stages(config_parent)?;
    }
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::DELETE;
    let existing = match manager.open_service(&args.service_name, access) {
        Ok(service) => {
            verify_service(&service, &args.service_name)?;
            Some(service)
        }
        Err(e) if service_is_missing(&e) => None,
        Err(e) => return Err(e.into()),
    };
    let names = configured_service_names()?;
    for name in &names {
        if name.eq_ignore_ascii_case(&args.service_name) {
            continue;
        }
        let other = manager.open_service(name, ServiceAccess::QUERY_CONFIG)?;
        let argv = secure_fs::command_arguments(&other.query_config()?.executable_path)?;
        if secure_fs::os_eq(&argv[3], args.config_path.as_os_str()) {
            bail!("configuration path is already owned by another agent instance");
        }
    }
    let (binary_path, pending_binary) = prepare_binary_copy()?;
    let staged_config = config_stage(&args)?;
    let old_service =
        existing.as_ref().map(|service| ScmSnapshot::capture(service, &args.service_name)).transpose()?;
    let info = service_info(&args, &binary_path)?;
    // Snapshot every previously running instance BEFORE stopping ANY of them.
    let mut running = Vec::new();
    for name in names {
        if pending_binary.is_none() && !name.eq_ignore_ascii_case(&args.service_name) {
            continue;
        }
        let service = open_service(&name, ServiceAccess::QUERY_STATUS)?;
        if service.query_status()?.current_state != ServiceState::Stopped {
            running.push(name);
        }
    }
    let backup = secure_fs::backup(&args.config_path)?.map(|stage| stage.persist()).transpose()?;
    let mut manifest = RecoveryManifest {
        version: 1,
        committed: false,
        target: args.service_name.clone(),
        config_path: os_units(args.config_path.as_os_str()),
        config_backup: backup.as_ref().map(|path| os_units(path.as_os_str())),
        old_service,
        running,
    };
    if let Err(e) = persist_manifest(&root, &manifest) {
        if let Some(path) = backup {
            let _ = secure_fs::remove_private_file(&path);
        }
        return Err(e);
    }
    let mut service = existing;
    let result = (|| -> Result<()> {
        for name in &manifest.running {
            let service = open_service(name, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
            stop_and_wait(&service, name)?;
        }
        // Complete atomic exe is safe to retain after an interrupted upgrade;
        // config and SCM are restored together from the durable record.
        commit_binary_copy(pending_binary, &binary_path)?;
        staged_config.commit(&args.config_path)?;
        if service.is_none() {
            service = Some(manager.create_service(&info, access)?);
        }
        let service = service.as_ref().context("missing installed service")?;
        service.change_config(&info)?;
        service.set_description(SERVICE_DESCRIPTION)?;
        service.set_delayed_auto_start(true)?;
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86_400)),
            reboot_msg: None,
            command: None,
            actions: Some(vec![
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(5) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(30) },
                ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
                ServiceAction { action_type: ServiceActionType::None, delay: Duration::ZERO },
            ]),
        })?;
        service.set_failure_actions_on_non_crash_failures(true)?;
        restart_services(std::slice::from_ref(&args.service_name))?;
        manifest.committed = true;
        persist_manifest(&root, &manifest)?;
        Ok(())
    })();
    // A failed commit-record write leaves the durable record uncommitted, so replay
    // safely rolls back. A completed record only retries outstanding restarts.
    if let Err(error) = result {
        drop(service);
        return match recover_previous_install(&root) {
            Ok(()) => {
                Err(error
                    .context("installation failed; original configuration/SCM/running instances restored"))
            }
            Err(recovery) => Err(error.context(format!(
                "recovery incomplete; durable record retained for next install: {recovery}"
            ))),
        };
    }
    restart_services(&manifest.running)
        .context("installed; recovery record retained to retry instance restarts on next install")?;
    clear_manifest(&root, &manifest)?;
    println!("installed and started {}", args.service_name);
    println!("binary: {}", binary_path.display());
    println!("config: {}", args.config_path.display());
    Ok(())
}

pub(super) fn stop_service(service_name: &str) -> Result<()> {
    let service = open_service(service_name, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)?;
    stop_and_wait(&service, service_name)?;
    println!("stopped {service_name}");
    Ok(())
}

pub(super) fn start_service(service_name: &str) -> Result<()> {
    let service = open_service(service_name, ServiceAccess::QUERY_STATUS | ServiceAccess::START)?;
    if service.query_status()?.current_state == ServiceState::Stopped {
        service.start::<&OsStr>(&[])?;
    }
    println!("started {service_name}");
    Ok(())
}

pub(super) fn uninstall_service(service_name: &str) -> Result<()> {
    let service = open_service(
        service_name,
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    )?;
    stop_and_wait(&service, service_name)?;
    service.delete()?;
    println!("removed {service_name}; config was kept");
    Ok(())
}

pub(super) fn status_service(service_name: &str) -> Result<()> {
    let service = open_service(service_name, ServiceAccess::QUERY_STATUS)?;
    println!("{service_name}: {:?}", service.query_status()?.current_state);
    Ok(())
}

/// Bounded SCM enumeration, independent of configuration directory contents.
fn enumerate_service_names() -> Result<Vec<String>> {
    use std::{ffi::c_void, os::windows::ffi::OsStringExt, ptr};
    type Handle = *mut c_void;
    #[repr(C)]
    struct Entry {
        name: *const u16,
        display: *const u16,
        status: [u32; 9],
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> Handle;
        fn EnumServicesStatusExW(
            manager: Handle,
            level: u32,
            kind: u32,
            state: u32,
            buffer: *mut u8,
            size: u32,
            needed: *mut u32,
            count: *mut u32,
            resume: *mut u32,
            group: *const u16,
        ) -> i32;
        fn CloseServiceHandle(handle: Handle) -> i32;
    }
    struct Manager(Handle);
    impl Drop for Manager {
        fn drop(&mut self) {
            unsafe {
                CloseServiceHandle(self.0);
            }
        }
    }
    let h = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), 4) };
    if h.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let manager = Manager(h);
    // Vec<usize> aligns the OS-written pointers in ENUM_SERVICE_STATUS_PROCESSW.
    let mut buffer = vec![0usize; 256 * 1024 / std::mem::size_of::<usize>()];
    let mut resume = 0;
    let mut names = Vec::new();
    for _ in 0..64 {
        let (mut needed, mut count) = (0, 0);
        let ok = unsafe {
            EnumServicesStatusExW(
                manager.0,
                0,
                0x30,
                3,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * std::mem::size_of::<usize>()) as u32,
                &mut needed,
                &mut count,
                &mut resume,
                ptr::null(),
            )
        };
        let error = std::io::Error::last_os_error();
        if ok == 0 && error.raw_os_error() != Some(234) {
            return Err(error.into());
        }
        let base = buffer.as_ptr() as usize;
        let end = base + buffer.len() * std::mem::size_of::<usize>();
        if count as usize > buffer.len() * std::mem::size_of::<usize>() / std::mem::size_of::<Entry>() {
            bail!("SCM returned invalid record count");
        }
        for i in 0..count as usize {
            let entry = unsafe { &*buffer.as_ptr().cast::<Entry>().add(i) };
            let p = entry.name as usize;
            if p < base || p >= end || !p.is_multiple_of(2) {
                bail!("SCM returned invalid service name pointer");
            }
            let max = ((end - p) / 2).min(257);
            let len = unsafe { (0..max).find(|&n| *entry.name.add(n) == 0) }
                .context("SCM service name exceeds limit")?;
            let name = OsString::from_wide(unsafe { std::slice::from_raw_parts(entry.name, len) })
                .into_string()
                .map_err(|_| anyhow!("non-UTF8 SCM service name"))?;
            names.push(name);
            if names.len() > 4096 {
                bail!("too many installed services to safely enumerate");
            }
        }
        if ok != 0 {
            return Ok(names);
        }
        if count == 0 {
            bail!("SCM enumeration made no progress");
        }
    }
    bail!("SCM enumeration iteration limit exceeded")
}

fn validate_install_config_path(path: &Path, name: &str, root: &Path) -> Result<()> {
    let path = secure_fs::absolute(path)?;
    let filename = path
        .file_name()
        .and_then(OsStr::to_str)
        .context("configuration filename must be UTF-8")?
        .to_ascii_lowercase();
    if filename.ends_with(".log")
        || filename.ends_with(".exe")
        || filename.starts_with(".stage-")
        || filename == ".install.lock"
        || filename == RECOVERY_FILE
    {
        bail!("configuration path conflicts with protected executable, log or installer files");
    }
    if path.parent().is_some_and(|p| secure_fs::os_eq(p.as_os_str(), root.as_os_str()))
        && !secure_fs::os_eq(path.as_os_str(), default_config_path(name).as_os_str())
    {
        bail!("configuration in shared agent root must use this service's own reserved filename");
    }
    Ok(())
}

const RECOVERY_FILE: &str = ".install-recovery.json";
const MAX_RECOVERY_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ScmSnapshot {
    name: String,
    command: Vec<Vec<u16>>,
    display: Vec<u16>,
    start_type: u32,
    error_control: u32,
    dependencies: Vec<Vec<u16>>,
    account: Option<Vec<u16>>,
    description: Vec<u16>,
    delayed: bool,
    failure_reset: u32,
    reboot_message: Vec<u16>,
    failure_command: Vec<u16>,
    actions: Vec<(i32, u32)>,
    non_crash: bool,
}
fn os_units(value: &OsStr) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    value.encode_wide().collect()
}
impl ScmSnapshot {
    fn capture(service: &windows_service::service::Service, name: &str) -> Result<Self> {
        let c = service.query_config()?;
        let args = secure_fs::command_arguments(&c.executable_path)?;
        let (description, delayed) = query_description_delayed(service)?;
        let failure = service.get_failure_actions()?;
        Ok(Self {
            name: name.to_owned(),
            command: args.iter().map(|s| os_units(s)).collect(),
            display: os_units(&c.display_name),
            start_type: c.start_type.to_raw(),
            error_control: c.error_control.to_raw(),
            dependencies: c.dependencies.iter().map(|v| os_units(&v.to_system_identifier())).collect(),
            account: c.account_name.as_ref().map(|v| os_units(v)),
            description,
            delayed,
            failure_reset: failure.reset_period.to_raw(),
            reboot_message: os_units(failure.reboot_msg.as_deref().unwrap_or_default()),
            failure_command: os_units(failure.command.as_deref().unwrap_or_default()),
            actions: failure
                .actions
                .unwrap_or_default()
                .iter()
                .map(|v| {
                    Ok((
                        v.action_type.to_raw(),
                        u32::try_from(v.delay.as_millis()).context("failure action delay overflow")?,
                    ))
                })
                .collect::<Result<_>>()?,
            non_crash: service.get_failure_actions_on_non_crash_failures()?,
        })
    }
    fn info(&self) -> Result<ServiceInfo> {
        validate_service_name(&self.name)?;
        if self.command.len() != 6 {
            bail!("invalid recovery command");
        }
        let command: Vec<_> = self.command.iter().map(|v| OsString::from_wide(v)).collect();
        if !secure_fs::os_eq(&command[0], installed_binary_path().as_os_str())
            || command[1] != "service"
            || command[2] != "--config"
            || command[4] != "--service-name"
            || !secure_fs::os_eq(&command[5], OsStr::new(&self.name))
        {
            bail!("invalid recovery service identity");
        }
        secure_fs::absolute(Path::new(&command[3]))?;
        Ok(ServiceInfo {
            name: self.name.clone().into(),
            display_name: OsString::from_wide(&self.display),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::from_raw(self.start_type)?,
            error_control: ServiceErrorControl::from_raw(self.error_control)?,
            executable_path: PathBuf::from(&command[0]),
            launch_arguments: command[1..].to_vec(),
            dependencies: self
                .dependencies
                .iter()
                .map(|v| {
                    windows_service::service::ServiceDependency::from_system_identifier(OsString::from_wide(
                        v,
                    ))
                })
                .collect(),
            account_name: self.account.as_ref().map(|v| OsString::from_wide(v)),
            account_password: None,
        })
    }
    /// Attempt every property even when an earlier SCM write fails.
    fn restore(&self, service: &windows_service::service::Service) -> Result<()> {
        let mut errors = Vec::new();
        let info = self.info()?;
        if let Err(e) = service.change_config(&info) {
            errors.push(format!("base configuration: {e}"));
        }
        if let Err(e) = service.set_description(OsString::from_wide(&self.description)) {
            errors.push(format!("description: {e}"));
        }
        if let Err(e) = service.set_delayed_auto_start(self.delayed) {
            errors.push(format!("delayed start: {e}"));
        }
        // Some(empty), NOT None: None means leave the current command/message/actions unchanged.
        let failure = ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::from_raw(self.failure_reset),
            reboot_msg: Some(OsString::from_wide(&self.reboot_message)),
            command: Some(OsString::from_wide(&self.failure_command)),
            actions: Some(
                self.actions
                    .iter()
                    .map(|(kind, delay)| {
                        Ok(ServiceAction {
                            action_type: ServiceActionType::from_raw(*kind)?,
                            delay: Duration::from_millis(u64::from(*delay)),
                        })
                    })
                    .collect::<Result<_>>()?,
            ),
        };
        if let Err(e) = service.update_failure_actions(failure) {
            errors.push(format!("failure actions: {e}"));
        }
        if let Err(e) = service.set_failure_actions_on_non_crash_failures(self.non_crash) {
            errors.push(format!("non-crash failures: {e}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            bail!("SCM rollback errors: {}", errors.join("; "))
        }
    }
}

/// Aligned storage plus the exact validated Win32 byte extent; allocation padding
/// is NEVER considered part of the OS-returned payload.
struct Config2Buffer {
    words: Vec<usize>,
    valid: usize,
}
fn query_config2_buffer(
    minimum: usize,
    mut query: impl FnMut(&mut [u8], &mut u32) -> std::io::Result<()>,
) -> Result<Config2Buffer> {
    let mut size = minimum;
    for _ in 0..4 {
        if !(minimum..=64 * 1024).contains(&size) {
            bail!("SCM extended configuration size limit exceeded");
        }
        let mut words = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
        // Expose precisely size bytes, never the extra zero-filled alignment tail.
        let bytes = unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), size) };
        let mut needed = 0;
        match query(bytes, &mut needed) {
            Ok(()) => {
                // pcbBytesNeeded may remain zero on success. The supplied bytes
                // are initialized and valid; a nonzero count must fit that extent.
                let valid = if needed == 0 { size } else { needed as usize };
                if valid < minimum || valid > size {
                    bail!("invalid successful SCM configuration length");
                }
                return Ok(Config2Buffer { words, valid });
            }
            Err(e) if e.raw_os_error() == Some(122) => {
                let next = needed as usize;
                if next <= size || next > 64 * 1024 {
                    bail!("invalid SCM buffer growth request");
                }
                size = next;
            }
            Err(e) => return Err(e.into()),
        }
    }
    bail!("SCM configuration changed too often during bounded query")
}
fn config2_description(buffer: &Config2Buffer) -> Result<Vec<u16>> {
    if buffer.valid < std::mem::size_of::<*const u16>() {
        bail!("truncated SCM description header");
    }
    let string = unsafe { *buffer.words.as_ptr().cast::<*const u16>() };
    if string.is_null() {
        return Ok(Vec::new());
    }
    let base = buffer.words.as_ptr() as usize;
    let end = base.checked_add(buffer.valid).context("SCM description extent overflow")?;
    let p = string as usize;
    if p < base + std::mem::size_of::<*const u16>() || p >= end || !p.is_multiple_of(2) {
        bail!("invalid SCM description pointer");
    }
    let length = unsafe { (0..(end - p) / 2).find(|&i| *string.add(i) == 0) }
        .context("unterminated SCM description")?;
    Ok(unsafe { std::slice::from_raw_parts(string, length) }.to_vec())
}
/// QueryConfig2 pointers are consumed only while their aligned backing storage lives.
fn query_description_delayed(service: &windows_service::service::Service) -> Result<(Vec<u16>, bool)> {
    use std::ffi::c_void;
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn QueryServiceConfig2W(
            service: *mut c_void,
            level: u32,
            buffer: *mut u8,
            size: u32,
            needed: *mut u32,
        ) -> i32;
    }
    let query = |level, minimum| {
        query_config2_buffer(minimum, |bytes, needed| {
            if unsafe {
                QueryServiceConfig2W(
                    service.raw_handle(),
                    level,
                    bytes.as_mut_ptr(),
                    bytes.len() as u32,
                    needed,
                )
            } == 0
            {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        })
    };
    let description = query(1, std::mem::size_of::<*const u16>())?;
    let units = config2_description(&description)?;
    let delayed = query(3, std::mem::size_of::<i32>())?;
    let flag = unsafe { *delayed.words.as_ptr().cast::<i32>() } != 0;
    Ok((units, flag))
}

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryManifest {
    version: u32,
    /// true means all config/SCM writes and initial target start have succeeded;
    /// subsequent recovery only restores the original running-instance set.
    committed: bool,
    target: String,
    config_path: Vec<u16>,
    config_backup: Option<Vec<u16>>,
    old_service: Option<ScmSnapshot>,
    running: Vec<String>,
}
fn persist_manifest(root: &Path, manifest: &RecoveryManifest) -> Result<()> {
    let bytes = zeroize::Zeroizing::new(serde_json::to_vec(manifest)?);
    if bytes.len() as u64 > MAX_RECOVERY_BYTES {
        bail!("recovery record size limit exceeded");
    }
    let stage = secure_fs::Stage::new(root)?;
    stage.write_all(&bytes)?;
    stage.commit(&root.join(RECOVERY_FILE))
}
fn restore_config_record(manifest: &RecoveryManifest) -> Result<()> {
    let path = PathBuf::from(OsString::from_wide(&manifest.config_path));
    let _guard = secure_fs::directory(path.parent().context("missing recovery config parent")?, false)?;
    if let Some(backup) = manifest.config_backup.as_ref() {
        let backup = PathBuf::from(OsString::from_wide(backup));
        if backup.parent() != path.parent()
            || !backup
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|n| n.starts_with(".stage-") && n.len() == 39)
        {
            bail!("invalid recovery backup path");
        }
        // Preserve the backup until ALL recovery operations succeed, making replay idempotent.
        let stage = secure_fs::backup_secret(&backup)?.context("recovery configuration backup is missing")?;
        stage.commit(&path)?;
    } else {
        secure_fs::remove_private_file(&path)?;
    }
    Ok(())
}
fn clear_manifest(root: &Path, manifest: &RecoveryManifest) -> Result<()> {
    // Remove the record before its backup: a crash can leave only a stale stage,
    // never a live record referring to a deleted backup.
    secure_fs::remove_private_file(&root.join(RECOVERY_FILE))?;
    if let Some(backup) = &manifest.config_backup {
        secure_fs::remove_private_file(Path::new(&OsString::from_wide(backup)))?;
    }
    Ok(())
}
fn recover_previous_install(root: &Path) -> Result<()> {
    let bytes = match secure_fs::read(&root.join(RECOVERY_FILE), MAX_RECOVERY_BYTES) {
        Ok(v) => v,
        Err(e) if secure_fs::is_missing(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    let manifest: RecoveryManifest =
        serde_json::from_slice(&bytes).context("invalid installation recovery record")?;
    if manifest.version != 1 || manifest.running.len() > 4096 {
        bail!("unsupported/oversized recovery record");
    }
    validate_service_name(&manifest.target)?;
    for name in &manifest.running {
        validate_service_name(name)?;
    }
    let path = PathBuf::from(OsString::from_wide(&manifest.config_path));
    validate_install_config_path(&path, &manifest.target, root)?;
    let _config_guard =
        secure_fs::directory(path.parent().context("missing recovery config parent")?, false)?;
    if let Some(old) = &manifest.old_service {
        if !old.name.eq_ignore_ascii_case(&manifest.target) {
            bail!("recovery target/snapshot mismatch");
        }
        old.info()?;
    }
    if let Some(backup) = &manifest.config_backup {
        let backup = PathBuf::from(OsString::from_wide(backup));
        if backup.parent() != path.parent()
            || !backup.file_name().and_then(OsStr::to_str).is_some_and(|n| {
                n.starts_with(".stage-") && n.len() == 39 && n[7..].bytes().all(|b| b.is_ascii_hexdigit())
            })
        {
            bail!("invalid recovery backup reference");
        }
    }
    let mut errors = Vec::new();
    if !manifest.committed {
        let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::QUERY_CONFIG
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG
            | ServiceAccess::DELETE;
        let service = match manager.open_service(&manifest.target, access) {
            Ok(v) => Some(v),
            Err(e) if service_is_missing(&e) => None,
            Err(e) => return Err(e.into()),
        };
        if let Some(service) = &service {
            verify_service(service, &manifest.target)?;
            if let Err(e) = stop_and_wait(service, &manifest.target) {
                errors.push(format!("recovery stop: {e}"));
            }
        }
        // Never overwrite a live service's config after a failed stop.
        if errors.is_empty() {
            if let Err(e) = restore_config_record(&manifest) {
                errors.push(format!("recovery config: {e}"));
            }
            if let Some(service) = &service {
                let result = if let Some(old) = &manifest.old_service {
                    old.restore(service)
                } else {
                    service.delete().map_err(Into::into)
                };
                if let Err(e) = result {
                    errors.push(format!("recovery SCM: {e}"));
                }
            } else if manifest.old_service.is_some() {
                errors.push("original service was externally deleted; manual restoration required".into());
            }
        }
    }
    // If restoring the target's config/SCM failed, do not launch it against a
    // potentially mismatched token/config. Still restore every other instance.
    let restart: Vec<_> = manifest
        .running
        .iter()
        .filter(|name| {
            manifest.committed || errors.is_empty() || !name.eq_ignore_ascii_case(&manifest.target)
        })
        .cloned()
        .collect();
    if let Err(e) = restart_services(&restart) {
        errors.push(format!("recovery restart: {e}"));
    }
    if !errors.is_empty() {
        bail!("previous installation recovery incomplete (record retained): {}", errors.join("; "));
    }
    clear_manifest(root, &manifest)
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn config2_success_zero_needed_accepts_empty_description_and_boolean() {
        let empty = query_config2_buffer(std::mem::size_of::<usize>(), |_, needed| {
            *needed = 0;
            Ok(())
        })
        .unwrap();
        assert!(config2_description(&empty).unwrap().is_empty());
        let flag = query_config2_buffer(4, |bytes, needed| {
            bytes.copy_from_slice(&1i32.to_ne_bytes());
            *needed = 0;
            Ok(())
        })
        .unwrap();
        assert_eq!(flag.valid, 4);
        assert_eq!(unsafe { *flag.words.as_ptr().cast::<i32>() }, 1);
    }

    #[test]
    fn config2_growth_and_valid_extent_exclude_alignment_padding() {
        let header = std::mem::size_of::<usize>();
        let payload = header + 3; // odd extent intentionally leaves an incomplete WCHAR
        let mut calls = 0;
        let buffer = query_config2_buffer(header, |bytes, needed| {
            calls += 1;
            *needed = payload as u32;
            if bytes.len() < payload {
                return Err(std::io::Error::from_raw_os_error(122));
            }
            let string = unsafe { bytes.as_mut_ptr().add(header).cast::<u16>() };
            bytes[..header].copy_from_slice(&(string as usize).to_ne_bytes());
            bytes[header..header + 2].copy_from_slice(&65u16.to_ne_bytes());
            // trailing byte and zero-filled allocation padding must not supply NUL.
            Ok(())
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(buffer.valid, payload);
        assert!(config2_description(&buffer).is_err());
        assert!(query_config2_buffer(4, |_, needed| {
            *needed = 8;
            Ok(())
        })
        .is_err());
        assert!(query_config2_buffer(4, |_, needed| {
            *needed = 4;
            Err(std::io::Error::from_raw_os_error(122))
        })
        .is_err());
        assert!(query_config2_buffer(4, |_, needed| {
            *needed = 65537;
            Err(std::io::Error::from_raw_os_error(122))
        })
        .is_err());
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_schema_drift() {
        let record = RecoveryManifest {
            version: 1,
            committed: false,
            target: DEFAULT_SERVICE_NAME.into(),
            config_path: os_units(OsStr::new(r"C:\ProgramData\monitor-agent\agent.env")),
            config_backup: None,
            old_service: None,
            running: vec![DEFAULT_SERVICE_NAME.into()],
        };
        let bytes = serde_json::to_vec(&record).unwrap();
        let decoded: RecoveryManifest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded.running, record.running);
        assert!(!decoded.committed);
        let mut value = serde_json::to_value(record).unwrap();
        value.as_object_mut().unwrap().insert("unrecognized".into(), true.into());
        assert!(serde_json::from_value::<RecoveryManifest>(value).is_err());
    }

    /// Run explicitly on an elevated Windows CI job. Does not start the service.
    #[test]
    #[ignore = "requires elevated Windows SCM create/delete privileges"]
    fn full_scm_snapshot_restores_every_changed_property() {
        let name = format!("monitor-agent-audit-{}", std::process::id());
        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .unwrap();
        let info = ServiceInfo {
            name: name.clone().into(),
            display_name: service_display_name(&name).into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: installed_binary_path(),
            launch_arguments: vec![
                "service".into(),
                "--config".into(),
                default_config_path(&name).into_os_string(),
                "--service-name".into(),
                name.clone().into(),
            ],
            dependencies: Vec::new(),
            account_name: None,
            account_password: None,
        };
        struct DeleteOnDrop(windows_service::service::Service);
        impl Drop for DeleteOnDrop {
            fn drop(&mut self) {
                let _ = self.0.delete();
            }
        }
        let service = DeleteOnDrop(
            manager
                .create_service(
                    &info,
                    // Restart failure actions require SERVICE_START even though this
                    // regression never starts the service itself.
                    ServiceAccess::QUERY_CONFIG
                        | ServiceAccess::CHANGE_CONFIG
                        | ServiceAccess::START
                        | ServiceAccess::DELETE,
                )
                .unwrap(),
        );
        service.0.set_description("original description").expect("SCM fixture: set original description");
        service.0.set_delayed_auto_start(false).expect("SCM fixture: clear delayed start");
        service
            .0
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(99)),
                reboot_msg: Some(OsString::new()),
                command: Some(OsString::new()),
                actions: Some(Vec::new()),
            })
            .unwrap();
        service.0.set_failure_actions_on_non_crash_failures(false).unwrap();
        let old =
            ScmSnapshot::capture(&service.0, &name).expect("SCM fixture: capture full original settings");
        let persisted = serde_json::to_vec(&old).unwrap();
        let old: ScmSnapshot = serde_json::from_slice(&persisted).unwrap();
        service.0.set_description("new description").unwrap();
        service.0.set_delayed_auto_start(true).unwrap();
        service
            .0
            .update_failure_actions(ServiceFailureActions {
                reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(3600)),
                reboot_msg: Some("changed".into()),
                command: Some("unused.exe".into()),
                actions: Some(vec![ServiceAction {
                    action_type: ServiceActionType::Restart,
                    delay: Duration::from_secs(3),
                }]),
            })
            .expect("SCM regression: set Restart failure action with SERVICE_START access");
        service.0.set_failure_actions_on_non_crash_failures(true).unwrap();
        old.restore(&service.0).expect("SCM regression: restore all original settings");
        assert_eq!(
            old,
            ScmSnapshot::capture(&service.0, &name).expect("SCM regression: recapture restored settings")
        );
    }

    #[test]
    #[ignore = "requires elevated Windows token and NTFS protected directory"]
    fn durable_config_backup_survives_drop_and_replays_idempotently() {
        let root = secure_fs::program_data()
            .unwrap()
            .join(format!("monitor-agent-recovery-test-{}", std::process::id()));
        let guard = secure_fs::ensure_private_dir(&root).unwrap();
        let config = root.join("config.env");
        let old = secure_fs::Stage::new(&root).unwrap();
        old.write_all(b"MONITOR_TOKEN=old\n").unwrap();
        old.commit(&config).unwrap();
        let backup = secure_fs::backup(&config).unwrap().unwrap().persist().unwrap();
        let new = secure_fs::Stage::new(&root).unwrap();
        new.write_all(b"MONITOR_TOKEN=new\n").unwrap();
        new.commit(&config).unwrap();
        let record = RecoveryManifest {
            version: 1,
            committed: false,
            target: DEFAULT_SERVICE_NAME.into(),
            config_path: os_units(config.as_os_str()),
            config_backup: Some(os_units(backup.as_os_str())),
            old_service: None,
            running: Vec::new(),
        };
        persist_manifest(&root, &record).unwrap();
        drop(record);
        let bytes = secure_fs::read(&root.join(RECOVERY_FILE), MAX_RECOVERY_BYTES).unwrap();
        let record: RecoveryManifest = serde_json::from_slice(&bytes).unwrap();
        restore_config_record(&record).unwrap();
        restore_config_record(&record).unwrap();
        assert_eq!(secure_fs::read(&config, 1024).unwrap().as_slice(), b"MONITOR_TOKEN=old\n");
        assert!(backup.exists());
        clear_manifest(&root, &record).unwrap();
        assert!(!backup.exists());
        assert!(!root.join(RECOVERY_FILE).exists());
        secure_fs::remove_private_file(&config).unwrap();
        drop(guard);
        std::fs::remove_dir(root).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reject_reserved_names_and_collisions() {
        for s in [
            "agent", "AGENT", "Agent", "CON", "con.txt", "prn", "AUX", "NUL", "com1", "COM9.foo", "LPT1",
            "lpt9.env", ".", "..", "ends.", "../bad",
        ] {
            assert!(validate_service_name(s).is_err(), "{s}");
        }
        for s in ["monitor-agent", "MONITOR-AGENT", "edge-01", "foo_bar", "COM10", "service.v2"] {
            assert!(validate_service_name(s).is_ok(), "{s}");
        }
        assert_eq!(default_config_path("MONITOR-AGENT"), default_config_path("monitor-agent"));
        assert_ne!(default_config_path("edge-01"), default_config_path("monitor-agent"));
    }
    #[test]
    fn bounded_known_configuration_and_probe_policy() {
        assert!(parse_config_bytes(&vec![b' '; MAX_CONFIG_BYTES + 1]).is_err());
        assert!(parse_config_bytes(b"MONITOR_TOKEN=a\nMONITOR_TOKEN=b").is_err());
        assert!(parse_config_bytes(b"NOT_A_KEY=secret").is_err());
        assert!(parse_config_bytes(b"MONITOR_TOKEN=a\0b").is_err());
        assert!(parse_config_bytes(&vec![b'\n'; 257]).is_err());
        let v = parse_config_bytes(
            b"MONITOR_TOKEN=secret\nMONITOR_PROBE_ALLOW=10.0.0.0/8:443\nMONITOR_NICS=Ethernet\n",
        )
        .unwrap();
        assert_eq!(v["MONITOR_PROBE_ALLOW"].as_str(), "10.0.0.0/8:443");
        assert_eq!(v["MONITOR_NICS"].as_str(), "Ethernet");
        assert!(validate_config_value("probe_allow", "x\r\nMONITOR_TOKEN=evil").is_err());
    }
    #[test]
    fn reject_redirected_and_non_normal_paths() {
        for p in [
            r"\\server\share\secret.env",
            r"\\?\C:\secret.env",
            r"C:\safe\..\bad",
            r"C:\secret.env:stream",
            r"C:\safe.\secret.env",
        ] {
            assert!(secure_fs::absolute(Path::new(p)).is_err(), "{p}");
        }
    }
}
