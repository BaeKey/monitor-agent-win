//! Windows installation boundary. No environment-derived privileged paths.
use anyhow::{bail, Context, Result};
use std::{
    ffi::{c_void, OsString},
    fs::File,
    io::{Read, Write},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle},
    },
    path::{Component, Path, PathBuf},
    ptr,
};

type Handle = *mut c_void;
#[repr(C)]
struct Guid {
    a: u32,
    b: u16,
    c: u16,
    d: [u8; 8],
}
#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: Handle,
    inherit: i32,
}
#[repr(C)]
struct FileInfo {
    attributes: u32,
    creation: [u32; 2],
    access: [u32; 2],
    write: [u32; 2],
    volume: u32,
    size_high: u32,
    size_low: u32,
    links: u32,
    index_high: u32,
    index_low: u32,
}
#[repr(C)]
struct AclInfo {
    count: u32,
    used: u32,
    free: u32,
}
#[repr(C)]
struct Ace {
    kind: u8,
    flags: u8,
    size: u16,
    mask: u32,
    sid: u32,
}
#[link(name = "shell32")]
unsafe extern "system" {
    fn SHGetKnownFolderPath(id: *const Guid, flags: u32, token: Handle, path: *mut *mut u16) -> i32;
    fn CommandLineToArgvW(command: *const u16, count: *mut i32) -> *mut *mut u16;
}
#[link(name = "ole32")]
unsafe extern "system" {
    fn CoTaskMemFree(p: Handle);
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        s: *const u16,
        revision: u32,
        sd: *mut Handle,
        size: *mut u32,
    ) -> i32;
    fn GetSecurityDescriptorDacl(sd: Handle, present: *mut i32, acl: *mut Handle, defaulted: *mut i32)
        -> i32;
    fn GetSecurityDescriptorOwner(sd: Handle, owner: *mut Handle, defaulted: *mut i32) -> i32;
    fn GetSecurityInfo(
        h: Handle,
        kind: u32,
        info: u32,
        owner: *mut Handle,
        group: *mut Handle,
        acl: *mut Handle,
        sacl: *mut Handle,
        sd: *mut Handle,
    ) -> u32;
    fn SetSecurityInfo(
        h: Handle,
        kind: u32,
        info: u32,
        owner: Handle,
        group: Handle,
        acl: Handle,
        sacl: Handle,
    ) -> u32;
    fn GetAclInformation(acl: Handle, info: Handle, size: u32, class: u32) -> i32;
    fn GetAce(acl: Handle, index: u32, ace: *mut Handle) -> i32;
    fn EqualSid(a: Handle, b: Handle) -> i32;
    fn ConvertStringSidToSidW(s: *const u16, sid: *mut Handle) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(p: Handle) -> Handle;
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        sa: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn CreateDirectoryW(path: *const u16, sa: *const SecurityAttributes) -> i32;
    fn GetFileInformationByHandle(h: Handle, info: *mut FileInfo) -> i32;
    fn MoveFileExW(old: *const u16, new: *const u16, flags: u32) -> i32;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, len: u32, flags: u32) -> i32;
}

struct Local(Handle);
impl Drop for Local {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(p: &std::ffi::OsStr) -> Result<Vec<u16>> {
    let mut v: Vec<_> = p.encode_wide().collect();
    if v.contains(&0) {
        bail!("NUL in Windows path");
    }
    v.push(0);
    Ok(v)
}
fn descriptor(directory: bool) -> Result<Local> {
    let s = if directory {
        "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
    } else {
        "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
    };
    let s = wide(std::ffi::OsStr::new(s))?;
    let mut sd = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(s.as_ptr(), 1, &mut sd, ptr::null_mut())
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(Local(sd))
}
pub fn program_data() -> Result<PathBuf> {
    const ID: Guid =
        Guid { a: 0x62ab5d82, b: 0xfdc1, c: 0x4dc3, d: [0xa9, 0xdd, 0x07, 0x0d, 0x1d, 0x49, 0x5d, 0x97] };
    let mut raw = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&ID, 0x4000, ptr::null_mut(), &mut raw) } < 0 {
        bail!("cannot resolve trusted ProgramData known folder");
    }
    // The API allocates a NUL-terminated string. Bound the scan before conversion.
    if raw.is_null() {
        bail!("KnownFolder API returned NULL");
    }
    let result = unsafe {
        (0..32768)
            .find(|&n| *raw.add(n) == 0)
            .map(|n| PathBuf::from(OsString::from_wide(std::slice::from_raw_parts(raw, n))))
    };
    unsafe {
        CoTaskMemFree(raw.cast());
    }
    result.context("ProgramData path exceeds Windows path limit")
}
pub fn absolute(path: &Path) -> Result<PathBuf> {
    let p = if path.is_absolute() { path.to_owned() } else { std::env::current_dir()?.join(path) };
    let mut components = p.components();
    if !matches!(components.next(), Some(Component::Prefix(v)) if matches!(v.kind(), std::path::Prefix::Disk(_)))
        || !matches!(components.next(), Some(Component::RootDir))
    {
        bail!("only local absolute drive paths are supported");
    }
    for c in components {
        match c {
            Component::Normal(n) => {
                let s = n.to_string_lossy();
                if s.contains(':') || s.ends_with(['.', ' ']) || s.len() > 255 || is_device(&s) {
                    bail!("unsafe Windows path component");
                }
            }
            _ => bail!("non-normal Windows path"),
        }
    }
    wide(p.as_os_str())?;
    Ok(p)
}
fn open(path: &Path, write: bool, create: bool, directory: bool, share_delete: bool) -> Result<File> {
    let path = wide(path.as_os_str())?;
    let sd = descriptor(directory)?;
    let sa = SecurityAttributes {
        length: std::mem::size_of::<SecurityAttributes>() as u32,
        descriptor: sd.0,
        inherit: 0,
    };
    // READ_CONTROL | WRITE_DAC. Creation has its final protected DACL BEFORE data is written.
    let access = 0x20000
        | if directory {
            if write {
                0x40000
            } else {
                0
            }
        } else if write {
            0x40000 | 0x40000000
        } else {
            0x80000000
        };
    let h = unsafe {
        CreateFileW(
            path.as_ptr(),
            access,
            1 | if share_delete { 4 } else { 0 },
            &sa,
            if create { 1 } else { 3 },
            0x00200000 | if directory { 0x02000000 } else { 0 },
            ptr::null_mut(),
        )
    };
    if h as isize == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    // Own the successful handle immediately, including all validation error paths.
    let f = unsafe { File::from_raw_handle(h) };
    let validation = check_type(&f, directory).and_then(|()| check_owner(&f, directory));
    if let Err(e) = validation {
        drop(f);
        // CREATE_NEW succeeded, so this is our own empty protected stage only.
        if create {
            let _ = std::fs::remove_file(Path::new(&OsString::from_wide(&path[..path.len() - 1])));
        }
        return Err(e);
    }
    Ok(f)
}
fn check_type(f: &File, directory: bool) -> Result<()> {
    let mut info: FileInfo = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(f.as_raw_handle(), &mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.attributes & 0x400 != 0
        || (info.attributes & 0x10 != 0) != directory
        || (!directory && info.links != 1)
    {
        bail!("reparse point, hard link or unexpected file type rejected");
    }
    Ok(())
}
fn security(f: &File) -> Result<(Local, Handle, Handle)> {
    let (mut sd, mut owner, mut acl) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    let status = unsafe {
        GetSecurityInfo(
            f.as_raw_handle(),
            1,
            5,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    Ok((Local(sd), owner, acl))
}
fn trusted_sids() -> Result<(Local, Handle, Handle)> {
    let sd = descriptor(false)?;
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) } == 0 {
        bail!("invalid internal security descriptor");
    }
    let mut acl = ptr::null_mut();
    let mut present = 0;
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } == 0 {
        bail!("invalid internal DACL");
    }
    let mut ace = ptr::null_mut();
    if unsafe { GetAce(acl, 0, &mut ace) } == 0 {
        bail!("invalid internal ACE");
    }
    let system = unsafe { ptr::addr_of_mut!((*(ace as *mut Ace)).sid).cast() };
    Ok((sd, owner, system))
}
fn check_owner(f: &File, ancestor: bool) -> Result<()> {
    let (_sd, owner, _) = security(f)?;
    let (_trusted, admin, system) = trusted_sids()?;
    if owner.is_null() {
        bail!("missing owner");
    }
    if unsafe { EqualSid(owner, admin) != 0 || EqualSid(owner, system) != 0 } {
        return Ok(());
    }
    if ancestor {
        let sid =
            wide(std::ffi::OsStr::new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"))?;
        let mut installer = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(sid.as_ptr(), &mut installer) } == 0 {
            bail!("cannot construct TrustedInstaller SID");
        }
        let _sid = Local(installer);
        if unsafe { EqualSid(owner, installer) } != 0 {
            return Ok(());
        }
    }
    bail!("untrusted file/directory owner")
}
fn check_directory_acl(f: &File, ancestor: bool) -> Result<()> {
    let (_sd, _, acl) = security(f)?;
    if acl.is_null() {
        bail!("NULL directory DACL rejected");
    }
    let (_trusted, admin, system) = trusted_sids()?;
    let mut info: AclInfo = unsafe { std::mem::zeroed() };
    if unsafe {
        GetAclInformation(acl, ptr::addr_of_mut!(info).cast(), std::mem::size_of::<AclInfo>() as u32, 2)
    } == 0
    {
        bail!("cannot inspect directory DACL");
    }
    for i in 0..info.count {
        let mut raw = ptr::null_mut();
        if unsafe { GetAce(acl, i, &mut raw) } == 0 {
            bail!("cannot inspect ACE");
        }
        #[repr(C)]
        struct Header {
            kind: u8,
            flags: u8,
            size: u16,
        }
        let header = unsafe { &*(raw as *const Header) };
        if header.flags & 8 != 0 {
            continue;
        } // INHERIT_ONLY cannot grant access here.
        if header.kind == 1 {
            continue;
        } // A denial is not an additional grant.
        if header.kind != 0 || (header.size as usize) < std::mem::size_of::<Ace>() + 4 {
            bail!("unsupported or truncated directory ACE");
        }
        let ace = unsafe { &*(raw as *const Ace) };
        let sid = ptr::addr_of!(ace.sid) as Handle;
        let mut trusted = unsafe { EqualSid(sid, admin) != 0 || EqualSid(sid, system) != 0 };
        if ancestor && !trusted {
            let text =
                wide(std::ffi::OsStr::new("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"))?;
            let mut installer = ptr::null_mut();
            if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut installer) } == 0 {
                bail!("cannot construct TrustedInstaller SID");
            }
            let _owner = Local(installer);
            trusted = unsafe { EqualSid(sid, installer) != 0 };
        }
        // ProgramData/drive ancestors may permit child creation, never child deletion or ACL takeover.
        let mask = if ancestor {
            0x10000000 | 0x10000 | 0x40000 | 0x80000 | 0x40
        } else {
            0x10000000 | 0x40000000 | 0x10000 | 0x40000 | 0x80000 | 0x2 | 0x4 | 0x10 | 0x40 | 0x100
        };
        if !trusted && ace.mask & mask != 0 {
            bail!("directory grants untrusted mutation access");
        }
    }
    Ok(())
}
pub fn protect(f: &File, directory: bool) -> Result<()> {
    let sd = descriptor(directory)?;
    let (mut present, mut defaulted) = (0, 0);
    let mut acl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) } == 0 {
        bail!("invalid protected DACL");
    }
    let status = unsafe {
        SetSecurityInfo(
            f.as_raw_handle(),
            1,
            0x80000004,
            ptr::null_mut(),
            ptr::null_mut(),
            acl,
            ptr::null_mut(),
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32).into());
    }
    Ok(())
}
/// Retain no-delete-share handles for EVERY ancestor until the caller finishes.
pub struct DirectoryGuard {
    _handles: Vec<File>,
}
pub fn directory(path: &Path, create: bool) -> Result<DirectoryGuard> {
    let path = absolute(path)?;
    let mut handles = Vec::new();
    let mut prefix = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    for (i, c) in components.iter().enumerate() {
        prefix.push(c.as_os_str());
        if i == 0 {
            continue;
        }
        let last = i + 1 == components.len();
        match open(&prefix, last && create, false, true, false) {
            Ok(f) => {
                if last {
                    check_owner(&f, false)?;
                }
                check_directory_acl(&f, !last)?;
                if last && create {
                    protect(&f, true)?;
                }
                handles.push(f);
            }
            Err(e) => {
                if !last || !create || !is_missing(&e) {
                    return Err(e).with_context(|| format!("unsafe directory {}", prefix.display()));
                }
                let sd = descriptor(true)?;
                let sa = SecurityAttributes {
                    length: std::mem::size_of::<SecurityAttributes>() as u32,
                    descriptor: sd.0,
                    inherit: 0,
                };
                if unsafe { CreateDirectoryW(wide(prefix.as_os_str())?.as_ptr(), &sa) } == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let f = open(&prefix, true, false, true, false)?;
                check_directory_acl(&f, false)?;
                protect(&f, true)?;
                handles.push(f);
            }
        }
    }
    Ok(DirectoryGuard { _handles: handles })
}
pub fn is_missing(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.raw_os_error(), Some(2 | 3)))
}
pub fn read(path: &Path, limit: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let _guard = directory(path.parent().context("missing config parent")?, false)?;
    let f = open(path, false, false, false, false)?;
    check_directory_acl(&f, false)?;
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    f.take(limit.checked_add(1).context("read limit overflow")?).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("configuration exceeds size limit");
    }
    Ok(bytes)
}
fn inspect(path: &Path, write_dac: bool) -> Result<File> {
    let p = wide(path.as_os_str())?;
    // Metadata-only handle interoperates with the live append writer. It does not
    // grant a second writer; broad sharing here only accepts preexisting access.
    let h = unsafe {
        CreateFileW(
            p.as_ptr(),
            0x20000 | if write_dac { 0x40000 } else { 0 },
            1 | 2 | 4,
            ptr::null(),
            3,
            0x00200000,
            ptr::null_mut(),
        )
    };
    if h as isize == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    let f = unsafe { File::from_raw_handle(h) };
    check_type(&f, false)?;
    check_owner(&f, false)?;
    check_directory_acl(&f, false)?;
    Ok(f)
}
/// Exact protected DACL, never an additive grant. Caller pins parent for rotations.
pub fn harden(path: &Path) -> Result<()> {
    let _guard = directory(path.parent().context("missing parent")?, false)?;
    let f = inspect(path, true)?;
    protect(&f, false)
}
pub fn check_destination(path: &Path) -> Result<()> {
    match inspect(path, false) {
        Ok(_) => Ok(()),
        Err(e) if is_missing(&e) => Ok(()),
        Err(e) => Err(e),
    }
}
/// A protected create-new stage. Drop cleans up on every ordinary error path.
pub struct Stage {
    pub path: PathBuf,
    file: Option<File>,
}
impl Stage {
    pub fn new(parent: &Path) -> Result<Self> {
        let mut random = [0u8; 16];
        if unsafe { BCryptGenRandom(ptr::null_mut(), random.as_mut_ptr(), 16, 2) } < 0 {
            bail!("secure random generation failed");
        }
        let name = random.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let path = parent.join(format!(".stage-{name}"));
        let file = open(&path, true, true, false, false)?;
        let stage = Self { path, file: Some(file) };
        protect(stage.file(), false)?;
        Ok(stage)
    }
    pub fn file(&self) -> &File {
        self.file.as_ref().expect("stage file open before commit")
    }
    pub fn write_all(&self, bytes: &[u8]) -> Result<()> {
        let mut file = self.file();
        file.write_all(bytes)?;
        Ok(())
    }
    pub fn copy_from(&self, source: &mut impl Read) -> Result<u64> {
        let mut file = self.file();
        Ok(std::io::copy(source, &mut file)?)
    }
    pub fn commit(mut self, target: &Path) -> Result<()> {
        self.file().sync_all()?;
        check_destination(target)?;
        drop(self.file.take());
        // Parent DirectoryGuard pins the protected directory throughout this operation.
        if unsafe {
            MoveFileExW(wide(self.path.as_os_str())?.as_ptr(), wide(target.as_os_str())?.as_ptr(), 1 | 8)
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = std::fs::remove_file(&self.path);
    }
}
pub fn ensure_private_dir(path: &Path) -> Result<DirectoryGuard> {
    directory(path, true)
}
/// Caller keeps an ensure_private_dir guard alive across writes and rotations.
/// No delete-sharing: a live writer cannot silently move to an attacker-chosen file.
pub fn open_log(path: &Path) -> Result<File> {
    let _guard = ensure_private_dir(path.parent().context("missing log parent")?)?;
    let file = match open(path, true, true, false, false) {
        Ok(f) => f,
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|v| v.raw_os_error() == Some(80)) => {
            open(path, true, false, false, false)?
        }
        Err(e) => return Err(e),
    };
    protect(&file, false)?;
    // Use FILE_APPEND_DATA, not a seek followed by a write (which races other writers).
    drop(file);
    let p = wide(path.as_os_str())?;
    let h = unsafe { CreateFileW(p.as_ptr(), 0x4 | 0x20000, 1, ptr::null(), 3, 0x00200000, ptr::null_mut()) };
    if h as isize == -1 {
        return Err(std::io::Error::last_os_error().into());
    }
    let f = unsafe { File::from_raw_handle(h) };
    check_type(&f, false)?;
    check_owner(&f, false)?;
    Ok(f)
}
/// Snapshot a preexisting protected regular file for rollback, without reading it all into RAM.
pub fn backup(path: &Path) -> Result<Option<Stage>> {
    let source = match open(path, false, false, false, false) {
        Ok(f) => f,
        Err(e) if is_missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    let stage = Stage::new(path.parent().context("missing backup parent")?)?;
    stage.copy_from(&mut &source)?;
    stage.file().sync_all()?;
    Ok(Some(stage))
}
pub fn lock(parent: &Path) -> Result<File> {
    let path = parent.join(".install.lock");
    let f = match open(&path, true, true, false, false) {
        Ok(f) => f,
        Err(e) if e.downcast_ref::<std::io::Error>().is_some_and(|v| v.raw_os_error() == Some(80)) => {
            open(&path, true, false, false, false)?
        }
        Err(e) => return Err(e),
    };
    protect(&f, false)?;
    Ok(f)
}
pub fn command_arguments(command: &Path) -> Result<Vec<OsString>> {
    let wide = wide(command.as_os_str())?;
    let mut count = 0;
    let raw = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let _guard = Local(raw.cast());
    if !(1..=4096).contains(&count) {
        bail!("unexpected service command line");
    }
    let mut result = Vec::new();
    for i in 0..count as usize {
        let s = unsafe { *raw.add(i) };
        let len = unsafe { (0..32768).find(|&n| *s.add(n) == 0) }.context("oversized service argument")?;
        result.push(OsString::from_wide(unsafe { std::slice::from_raw_parts(s, len) }));
    }
    Ok(result)
}

/// ASCII case-folding for local Windows paths and our ASCII service-name grammar.
pub fn os_eq(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    fn lower(c: u16) -> u16 {
        if (b'A' as u16..=b'Z' as u16).contains(&c) {
            c + 32
        } else {
            c
        }
    }
    a.encode_wide().map(lower).eq(b.encode_wide().map(lower))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Elevated Windows runner only: real DACL, links, sharing, replace and cleanup.
    /// Run: cargo test secure_fs::tests::protected_filesystem_regression -- --ignored
    #[test]
    #[ignore = "requires elevated Windows administrator token and real NTFS"]
    fn protected_filesystem_regression() {
        let root =
            program_data().unwrap().join(format!("monitor-agent-security-test-{}", std::process::id()));
        let guard = ensure_private_dir(&root).unwrap();
        let target = root.join("test.env");
        let abandoned;
        {
            let stage = Stage::new(&root).unwrap();
            abandoned = stage.path.clone();
            stage.write_all(b"MONITOR_TOKEN=old\n").unwrap();
        }
        assert!(!abandoned.exists(), "stage leaked on ordinary drop");
        let stage = Stage::new(&root).unwrap();
        stage.write_all(b"MONITOR_TOKEN=old\n").unwrap();
        stage.commit(&target).unwrap();
        assert_eq!(read(&target, 1024).unwrap().as_slice(), b"MONITOR_TOKEN=old\n");
        let old = backup(&target).unwrap().unwrap();
        let stage = Stage::new(&root).unwrap();
        stage.write_all(b"MONITOR_TOKEN=new\n").unwrap();
        stage.commit(&target).unwrap();
        assert_eq!(read(&target, 1024).unwrap().as_slice(), b"MONITOR_TOKEN=new\n");
        old.commit(&target).unwrap();
        assert_eq!(read(&target, 1024).unwrap().as_slice(), b"MONITOR_TOKEN=old\n");
        let alias = root.join("hardlink.env");
        std::fs::hard_link(&target, &alias).unwrap();
        assert!(read(&alias, 1024).is_err());
        assert!(check_destination(&target).is_err());
        std::fs::remove_file(&alias).unwrap();
        assert!(read(&target, 1).is_err());
        let junction = root.join("redirect");
        std::os::windows::fs::symlink_dir(&root, &junction).unwrap();
        assert!(ensure_private_dir(&junction).is_err());
        assert!(read(&junction.join("test.env"), 1024).is_err());
        std::fs::remove_dir(&junction).unwrap();
        // Explicit untrusted read ACE is eliminated by exact DACL replacement.
        let descriptor = descriptor(false).unwrap();
        let file = open(&target, true, false, false, false).unwrap();
        protect(&file, false).unwrap();
        let (_sd, _owner, acl) = security(&file).unwrap();
        let mut info: AclInfo = unsafe { std::mem::zeroed() };
        assert_ne!(
            unsafe {
                GetAclInformation(
                    acl,
                    ptr::addr_of_mut!(info).cast(),
                    std::mem::size_of::<AclInfo>() as u32,
                    2,
                )
            },
            0
        );
        assert_eq!(info.count, 2);
        drop(descriptor);
        drop(file);

        let lockfile = lock(&root).unwrap();
        assert!(lock(&root).is_err());
        drop(lockfile);
        let log_path = root.join("test.log");
        let mut log = open_log(&log_path).unwrap();
        log.write_all(b"entry\n").unwrap();
        assert!(open_log(&log_path).is_err());
        assert!(std::fs::rename(&log_path, root.join("moved.log")).is_err());
        check_destination(&log_path).unwrap();
        harden(&log_path).unwrap();
        drop(log);
        std::fs::remove_file(&log_path).unwrap();
        std::fs::remove_file(&target).unwrap();
        std::fs::remove_file(root.join(".install.lock")).unwrap();
        drop(guard);
        std::fs::remove_dir(&root).unwrap();
    }
}

fn is_device(name: &str) -> bool {
    let n = name.split('.').next().unwrap_or_default().to_ascii_lowercase();
    matches!(n.as_str(), "con" | "prn" | "aux" | "nul" | "conin$" | "conout$" | "clock$")
        || ((n.starts_with("com") || n.starts_with("lpt"))
            && n.len() == 4
            && matches!(n.as_bytes()[3], b'1'..=b'9'))
}
