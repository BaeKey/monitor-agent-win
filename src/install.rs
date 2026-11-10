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
    let bytes = secure_fs::read(path, MAX_CONFIG_BYTES as u64)?;
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
            for _ in 0..30 {
                match service.query_status()?.current_state {
                    ServiceState::StopPending => std::thread::sleep(Duration::from_secs(1)),
                    ServiceState::Stopped => {
                        service.start::<&OsStr>(&[])?;
                        return Ok(());
                    }
                    _ => return Ok(()),
                }
            }
            bail!("{name} still stopping during recovery")
        })();
        if let Err(e) = result {
            failures.push(format!("{name}: {e}"));
        }
    }
    if !failures.is_empty() {
        bail!("could not restore services: {}", failures.join("; "));
    }
    Ok(())
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
    validate_install_config_path(&args.config_path, &args.service_name, &root)?;
    let _config_guard =
        secure_fs::ensure_private_dir(args.config_path.parent().context("missing config parent")?)?;
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
    for name in configured_service_names()? {
        if name.eq_ignore_ascii_case(&args.service_name) {
            continue;
        }
        let other = manager.open_service(&name, ServiceAccess::QUERY_CONFIG)?;
        let argv = secure_fs::command_arguments(&other.query_config()?.executable_path)?;
        if secure_fs::os_eq(&argv[3], args.config_path.as_os_str()) {
            bail!("configuration path is already owned by another agent instance");
        }
    }
    let (binary_path, pending_binary) = prepare_binary_copy()?;
    let staged_config = config_stage(&args)?;
    let old_config = secure_fs::backup(&args.config_path)?;
    let old_binary = if pending_binary.is_some() { secure_fs::backup(&binary_path)? } else { None };
    let old_info = existing
        .as_ref()
        .map(|service| -> Result<ServiceInfo> {
            let c = service.query_config()?;
            let argv = secure_fs::command_arguments(&c.executable_path)?;
            Ok(ServiceInfo {
                name: args.service_name.clone().into(),
                display_name: c.display_name,
                service_type: c.service_type,
                start_type: c.start_type,
                error_control: c.error_control,
                executable_path: PathBuf::from(&argv[0]),
                launch_arguments: argv[1..].to_vec(),
                dependencies: c.dependencies,
                account_name: c.account_name,
                account_password: None,
            })
        })
        .transpose()?;
    let info = service_info(&args, &binary_path)?;
    let mut stopped = if pending_binary.is_some() { stop_running_services()? } else { Vec::new() };
    let mut service = existing;
    let mut created = false;
    let mut config_committed = false;
    let mut binary_committed = false;
    let result = (|| -> Result<()> {
        if let Some(s) = service.as_ref() {
            if s.query_status()?.current_state != ServiceState::Stopped {
                if !stopped.iter().any(|n| n.eq_ignore_ascii_case(&args.service_name)) {
                    stopped.push(args.service_name.clone());
                }
                stop_and_wait(s, &args.service_name)?;
            }
        }
        let replacing_binary = pending_binary.is_some();
        commit_binary_copy(pending_binary, &binary_path)?;
        binary_committed = replacing_binary;
        staged_config.commit(&args.config_path)?;
        config_committed = true;
        if service.is_none() {
            service = Some(manager.create_service(&info, access)?);
            created = true;
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
        if service.query_status()?.current_state == ServiceState::Stopped {
            service.start::<&OsStr>(&[])?;
        }
        Ok(())
    })();
    let mut recovery_errors = Vec::new();
    if result.is_err() {
        if let Some(s) = service.as_ref() {
            if let Err(e) = stop_and_wait(s, &args.service_name) {
                recovery_errors.push(format!("stop for rollback: {e}"));
            }
            if created {
                if let Err(e) = s.delete() {
                    recovery_errors.push(format!("remove new service: {e}"));
                }
            } else if let Some(old) = old_info.as_ref() {
                if let Err(e) = s.change_config(old) {
                    recovery_errors.push(format!("restore service configuration: {e}"));
                }
            }
        }
        if config_committed {
            let r = match old_config {
                Some(stage) => stage.commit(&args.config_path),
                None => fs::remove_file(&args.config_path).map_err(Into::into),
            };
            if let Err(e) = r {
                recovery_errors.push(format!("restore config: {e}"));
            }
        }
        if binary_committed {
            let r = match old_binary {
                Some(stage) => stage.commit(&binary_path),
                None => fs::remove_file(&binary_path).map_err(Into::into),
            };
            if let Err(e) = r {
                recovery_errors.push(format!("restore executable: {e}"));
            }
        }
    }
    if let Err(e) = restart_services(&stopped) {
        recovery_errors.push(e.to_string());
    }
    if let Err(e) = result {
        return Err(
            e.context(format!("installation rolled back; recovery errors: {}", recovery_errors.join("; ")))
        );
    }
    if !recovery_errors.is_empty() {
        bail!("installed but service recovery failed: {}", recovery_errors.join("; "));
    }
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
            if p < base || p >= end || p % 2 != 0 {
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
