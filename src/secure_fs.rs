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
#[cfg(test)]
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
    fn ConvertSidToStringSidW(sid: Handle, text: *mut *mut u16) -> i32;
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn LocalFree(p: Handle) -> Handle;
    #[cfg(test)]
    fn CreateFileW(
        path: *const u16,
        access: u32,
        share: u32,
        sa: *const SecurityAttributes,
        creation: u32,
        flags: u32,
        template: Handle,
    ) -> Handle;
    fn GetFileInformationByHandle(h: Handle, info: *mut FileInfo) -> i32;
}
#[link(name = "bcrypt")]
unsafe extern "system" {
    fn BCryptGenRandom(algorithm: Handle, buffer: *mut u8, len: u32, flags: u32) -> i32;
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: Handle,
    name: *mut UnicodeString,
    attributes: u32,
    security: Handle,
    qos: Handle,
}
#[repr(C)]
struct IoStatus {
    status: usize,
    information: usize,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        handle: *mut Handle,
        access: u32,
        attributes: *mut ObjectAttributes,
        status: *mut IoStatus,
        allocation: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: Handle,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        handle: Handle,
        status: *mut IoStatus,
        information: Handle,
        length: u32,
        class: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}
fn nt_result(status: i32) -> Result<()> {
    if status < 0 {
        return Err(std::io::Error::from_raw_os_error(unsafe { RtlNtStatusToDosError(status) } as i32).into());
    }
    Ok(())
}
/// A single component relative to an already-open directory, or the bootstrap
/// drive root only. Never allow a caller to inject another path traversal.
fn native_open(
    root: Handle,
    name: &std::ffi::OsStr,
    access: u32,
    share: u32,
    disposition: u32,
    directory: bool,
) -> Result<File> {
    let mut units: Vec<_> = name.encode_wide().collect();
    if units.is_empty()
        || units.contains(&0)
        || (!root.is_null()
            && (units.iter().any(|c| matches!(*c, 47 | 92 | 58)) || name == "." || name == ".."))
    {
        bail!("invalid relative Windows component");
    }
    let length = u16::try_from(units.len() * 2).context("NT name too long")?;
    let mut unicode = UnicodeString { length, maximum: length, buffer: units.as_mut_ptr() };
    let sd = descriptor(directory)?;
    let mut object = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root,
        name: &mut unicode,
        attributes: 0x40 | if root.is_null() { 0 } else { 0x1000 },
        security: sd.0,
        qos: ptr::null_mut(),
    };
    let mut status = IoStatus { status: 0, information: 0 };
    let mut raw = ptr::null_mut();
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access | 0x100000,
            &mut object,
            &mut status,
            ptr::null(),
            0,
            share,
            disposition,
            0x00200000 | 0x20 | if directory { 1 } else { 0x40 },
            ptr::null_mut(),
            0,
        )
    };
    nt_result(result)?;
    let file = unsafe { File::from_raw_handle(raw) };
    check_type(&file, directory)?;
    check_owner(&file, directory)?;
    Ok(file)
}
fn delete_handle(file: &File) -> Result<()> {
    let mut status = IoStatus { status: 0, information: 0 };
    let mut delete = 1u8;
    nt_result(unsafe {
        NtSetInformationFile(file.as_raw_handle(), &mut status, ptr::addr_of_mut!(delete).cast(), 1, 13)
    })
}
fn rename_handle(file: &File, parent: &File, name: &std::ffi::OsStr, replace: bool) -> Result<()> {
    // FILE_RENAME_INFORMATION: BOOLEAN, HANDLE-aligned RootDirectory, ULONG,
    // WCHAR FileName[]. Allocate pointer-aligned storage for the variable tail.
    let units: Vec<_> = name.encode_wide().collect();
    if units.is_empty() || units.iter().any(|c| matches!(*c, 0 | 47 | 92 | 58)) {
        bail!("invalid rename component");
    }
    let root_offset = std::mem::size_of::<usize>();
    let length_offset = root_offset * 2;
    let name_offset = length_offset + 4;
    let size = (name_offset + units.len() * 2).max(std::mem::size_of::<usize>() * 3);
    let mut data = vec![0usize; size.div_ceil(std::mem::size_of::<usize>())];
    let bytes = unsafe { std::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<u8>(), size) };
    bytes[0] = u8::from(replace);
    bytes[root_offset..length_offset].copy_from_slice(&(parent.as_raw_handle() as usize).to_ne_bytes());
    bytes[length_offset..name_offset].copy_from_slice(&u32::try_from(units.len() * 2)?.to_ne_bytes());
    for (part, unit) in bytes[name_offset..].as_chunks_mut::<2>().0.iter_mut().zip(units) {
        part.copy_from_slice(&unit.to_ne_bytes());
    }
    let mut status = IoStatus { status: 0, information: 0 };
    nt_result(unsafe {
        NtSetInformationFile(file.as_raw_handle(), &mut status, data.as_mut_ptr().cast(), size as u32, 10)
    })
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
fn open(path: &Path, write: bool, create: bool, is_dir: bool, share_delete: bool) -> Result<File> {
    if is_dir {
        let path = absolute(path)?;
        let parent = walk_directory(path.parent().context("missing directory parent")?, false, false)?;
        return native_open(
            parent.final_file().as_raw_handle(),
            path.file_name().context("missing directory name")?,
            0x20080 | if write { 0x40000 } else { 0 },
            3,
            1,
            true,
        );
    }
    let path = absolute(path)?;
    let parent = directory(path.parent().context("missing parent")?, false)?;
    native_open(
        parent.final_file().as_raw_handle(),
        path.file_name().context("missing filename")?,
        0x20080 | if write { 0x40000 | 0x40000000 } else { 0x80000000 },
        1 | if share_delete { 4 } else { 0 },
        if create { 2 } else { 1 },
        false,
    )
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
// FILE_WRITE_DATA/APPEND_DATA/WRITE_EA/WRITE_ATTRIBUTES, DELETE,
// WRITE_DAC/WRITE_OWNER and their generic expansions. Ordinary read is allowed:
// installation may replace an old admin-owned file with an explicit Users-read ACE.
const FILE_MUTATION_MASK: u32 =
    0x2 | 0x4 | 0x10 | 0x100 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000;
fn check_file_mutation_acl(f: &File) -> Result<()> {
    check_mutation_acl(f, false, FILE_MUTATION_MASK)
}
fn check_directory_acl(f: &File, ancestor: bool) -> Result<()> {
    // Normal Windows ancestors grant Users child creation and WRITE_ATTRIBUTES.
    // These are not authority to delete an existing child or take over its ACL.
    // Metadata handles can set reparse data. Safety comes from handle-relative
    // child opens with OBJ_DONT_REPARSE, not an assumed sharing-mode prohibition.
    // Private leaf directories retain the complete mutation mask below.
    let mask =
        if ancestor { 0x10000000 | 0x10000 | 0x40000 | 0x80000 | 0x40 } else { FILE_MUTATION_MASK | 0x40 };
    check_mutation_acl(f, ancestor, mask)
}
fn check_mutation_acl(f: &File, ancestor: bool, mutation_mask: u32) -> Result<()> {
    let (_sd, _, acl) = security(f)?;
    if acl.is_null() {
        bail!("NULL DACL rejected");
    }
    let (_trusted, admin, system) = trusted_sids()?;
    let mut info: AclInfo = unsafe { std::mem::zeroed() };
    if unsafe {
        GetAclInformation(acl, ptr::addr_of_mut!(info).cast(), std::mem::size_of::<AclInfo>() as u32, 2)
    } == 0
    {
        bail!("cannot inspect object DACL");
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
            bail!("unsupported or truncated ACE");
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
        if !trusted && ace.mask & mutation_mask != 0 {
            let mut text = ptr::null_mut();
            let sid_text = if unsafe { ConvertSidToStringSidW(sid, &mut text) } != 0 {
                let _text = Local(text.cast());
                let len =
                    unsafe { (0..256).find(|&n| *text.add(n) == 0) }.context("oversized diagnostic SID")?;
                OsString::from_wide(unsafe { std::slice::from_raw_parts(text, len) })
                    .to_string_lossy()
                    .into_owned()
            } else {
                "<unavailable>".to_owned()
            };
            bail!("object grants untrusted mutation access: SID={sid_text} ACE_mask=0x{:08x} forbidden=0x{:08x} ancestor={ancestor}",ace.mask,ace.mask & mutation_mask);
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
/// Anchored directory identity, NOT a claim that metadata cannot set reparse data.
/// Every child operation uses RootDirectory; a later junction never redirects it.
pub struct DirectoryGuard {
    handles: Vec<File>,
    path: PathBuf,
}
impl DirectoryGuard {
    fn final_file(&self) -> &File {
        self.handles.last().expect("validated drive root")
    }
}
pub fn directory(path: &Path, create: bool) -> Result<DirectoryGuard> {
    walk_directory(path, create, true)
}
fn walk_directory(path: &Path, create: bool, private_leaf: bool) -> Result<DirectoryGuard> {
    let path = absolute(path)?;
    let components: Vec<_> = path.components().collect();
    let drive = components[0].as_os_str().to_string_lossy();
    let native_root = OsString::from(format!(r"\??\{drive}\"));
    // Bootstrap only the local drive root. All remaining names are single
    // components relative to a validated directory handle, never full paths.
    let root = native_open(ptr::null_mut(), &native_root, 0x200a0, 3, 1, true)?;
    check_directory_acl(&root, true).context("unsafe local drive root ACL")?;
    let mut handles = vec![root];
    let mut prefix = PathBuf::from(format!(r"{drive}\"));
    for (index, component) in components.iter().enumerate().skip(2) {
        prefix.push(component.as_os_str());
        let last = index + 1 == components.len();
        let file = native_open(
            handles.last().unwrap().as_raw_handle(),
            component.as_os_str(),
            0x200a0 | if last && create { 0x40000 } else { 0 },
            3,
            if last && create { 3 } else { 1 },
            true,
        )
        .with_context(|| format!("open anchored directory {}", prefix.display()))?;
        if last && private_leaf {
            check_owner(&file, false)?;
        }
        check_directory_acl(&file, !last || !private_leaf)
            .with_context(|| format!("unsafe directory ACL {}", prefix.display()))?;
        if last && create {
            protect(&file, true)?;
        }
        handles.push(file);
    }
    Ok(DirectoryGuard { handles, path })
}

pub fn is_missing(e: &anyhow::Error) -> bool {
    e.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.raw_os_error(), Some(2 | 3)))
}
/// Default is confidential; use the explicitly named upgrade-only API for legacy repair.
pub fn read(path: &Path, limit: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    read_secret(path, limit)
}
pub fn read_secret(path: &Path, limit: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    read_checked(path, limit, true)
}
/// Only installation may read an admin-owned legacy file with untrusted read ACEs.
/// Mutation ACL checks remain mandatory; this never repairs then trusts old content.
pub fn read_for_install(path: &Path, limit: u64) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    read_checked(path, limit, false)
}
fn check_secret_acl(f: &File) -> Result<()> {
    check_mutation_acl(f, false, FILE_MUTATION_MASK | 0x1 | 0x80000000)
}
fn read_checked(path: &Path, limit: u64, secret: bool) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let _guard = directory(path.parent().context("missing config parent")?, false)?;
    let f = open(path, false, false, false, false)?;
    check_file_mutation_acl(&f)?;
    if secret {
        check_secret_acl(&f)?;
    }
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    f.take(limit.checked_add(1).context("read limit overflow")?).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("configuration exceeds size limit");
    }
    Ok(bytes)
}
fn inspect_at(parent: &File, name: &std::ffi::OsStr, write_dac: bool) -> Result<File> {
    let file = native_open(
        parent.as_raw_handle(),
        name,
        0x20080 | if write_dac { 0x40000 } else { 0 },
        7,
        1,
        false,
    )?;
    check_file_mutation_acl(&file)?;
    Ok(file)
}
fn inspect(path: &Path, write_dac: bool) -> Result<File> {
    let path = absolute(path)?;
    let parent = directory(path.parent().context("missing parent")?, false)?;
    inspect_at(parent.final_file(), path.file_name().context("missing filename")?, write_dac)
}
pub fn metadata_len(path: &Path) -> Result<Option<u64>> {
    match inspect(path, false) {
        Ok(file) => Ok(Some(file.metadata()?.len())),
        Err(e) if is_missing(&e) => Ok(None),
        Err(e) => Err(e),
    }
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
    parent: DirectoryGuard,
    cleanup: bool,
}
impl Stage {
    pub fn new(parent: &Path) -> Result<Self> {
        Self::in_directory(directory(parent, false)?)
    }
    fn in_directory(parent: DirectoryGuard) -> Result<Self> {
        let mut random = [0u8; 16];
        if unsafe { BCryptGenRandom(ptr::null_mut(), random.as_mut_ptr(), 16, 2) } < 0 {
            bail!("secure random generation failed");
        }
        let name = OsString::from(format!(
            ".stage-{}",
            random.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ));
        let path = parent.path.join(&name);
        let file = native_open(
            parent.final_file().as_raw_handle(),
            &name,
            0x40000000 | 0x10000 | 0x60080,
            1 | 4,
            2,
            false,
        )?;
        let stage = Self { path, file: Some(file), parent, cleanup: true };
        protect(stage.file(), false)?;
        Ok(stage)
    }
    pub fn file(&self) -> &File {
        self.file.as_ref().expect("stage open until commit")
    }
    pub fn write_all(&self, bytes: &[u8]) -> Result<()> {
        let mut f = self.file();
        f.write_all(bytes)?;
        Ok(())
    }
    pub fn copy_from(&self, source: &mut impl Read) -> Result<u64> {
        let mut f = self.file();
        Ok(std::io::copy(source, &mut f)?)
    }
    pub fn persist(mut self) -> Result<PathBuf> {
        self.file().sync_all()?;
        self.cleanup = false;
        Ok(self.path.clone())
    }
    pub fn commit(mut self, target: &Path) -> Result<()> {
        let target = absolute(target)?;
        if !target.parent().is_some_and(|p| os_eq(p.as_os_str(), self.parent.path.as_os_str())) {
            bail!("stage commit must remain in its original directory");
        }
        let name = target.file_name().context("missing commit filename")?;
        match inspect_at(self.parent.final_file(), name, false) {
            Ok(_) => {}
            Err(e) if is_missing(&e) => {}
            Err(e) => return Err(e),
        }
        self.file().sync_all()?;
        rename_handle(self.file(), self.parent.final_file(), name, true)?;
        self.cleanup = false;
        Ok(())
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        if self.cleanup {
            if let Some(file) = &self.file {
                let _ = delete_handle(file);
            }
        }
    }
}

pub fn ensure_private_dir(path: &Path) -> Result<DirectoryGuard> {
    directory(path, true)
}
/// Caller keeps an ensure_private_dir guard alive across writes and rotations.
/// No delete-sharing: a live writer cannot silently move to an attacker-chosen file.
pub fn open_log(path: &Path) -> Result<File> {
    let path = absolute(path)?;
    let parent = ensure_private_dir(path.parent().context("missing log parent")?)?;
    let name = path.file_name().context("missing log filename")?;
    {
        let file = native_open(parent.final_file().as_raw_handle(), name, 0x60080, 7, 3, false)?;
        check_file_mutation_acl(&file)?;
        protect(&file, false)?;
    }
    let file = native_open(parent.final_file().as_raw_handle(), name, 0x20084, 1, 1, false)?;
    check_file_mutation_acl(&file)?;
    Ok(file)
}

/// Snapshot a preexisting protected regular file for rollback, without reading it all into RAM.
pub fn backup(path: &Path) -> Result<Option<Stage>> {
    let source = match open(path, false, false, false, false) {
        Ok(f) => f,
        Err(e) if is_missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    // Snapshotting must not bless attacker-editable old configuration either.
    check_file_mutation_acl(&source)?;
    let stage = Stage::new(path.parent().context("missing backup parent")?)?;
    stage.copy_from(&mut &source)?;
    stage.file().sync_all()?;
    Ok(Some(stage))
}
pub fn lock(parent: &Path) -> Result<File> {
    let path = parent.join(".install.lock");
    let f = match open(&path, true, true, false, false) {
        Ok(f) => f,
        Err(e)
            if e.downcast_ref::<std::io::Error>()
                .is_some_and(|v| matches!(v.raw_os_error(), Some(80 | 183))) =>
        {
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

fn is_device(name: &str) -> bool {
    let n = name.split('.').next().unwrap_or_default().to_ascii_lowercase();
    matches!(n.as_str(), "con" | "prn" | "aux" | "nul" | "conin$" | "conout$" | "clock$")
        || ((n.starts_with("com") || n.starts_with("lpt"))
            && n.len() == 4
            && matches!(n.as_bytes()[3], b'1'..=b'9'))
}

/// Bounded, fail-closed garbage collection. Caller serializes installation and
/// first replays any recovery manifest, so referenced backups cannot be removed.
pub fn cleanup_stages(parent: &Path) -> Result<()> {
    let _guard = directory(parent, false)?;
    let mut stages = 0;
    for (index, entry) in std::fs::read_dir(parent)?.enumerate() {
        if index >= 4096 {
            bail!("stage cleanup directory entry limit exceeded");
        }
        let entry = entry?;
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else { continue };
        if name.len() != 39
            || !name.starts_with(".stage-")
            || !name[7..].bytes().all(|v| v.is_ascii_hexdigit())
        {
            continue;
        }
        stages += 1;
        if stages > 128 {
            bail!("too many retained stage files; manual inspection required");
        }
        let f = inspect(&path, false)?;
        let age = f.metadata()?.modified()?.elapsed().unwrap_or_default();
        drop(f);
        if age >= std::time::Duration::from_secs(24 * 3600) {
            remove_private_file(&path)?;
        }
    }
    Ok(())
}
/// Remove only a checked regular single-link file, with its directory pinned.
pub fn remove_private_file(path: &Path) -> Result<()> {
    let path = absolute(path)?;
    let parent = directory(path.parent().context("missing parent")?, false)?;
    let file = match native_open(
        parent.final_file().as_raw_handle(),
        path.file_name().context("missing filename")?,
        0x30080,
        1 | 4,
        1,
        false,
    ) {
        Ok(f) => f,
        Err(e) if is_missing(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    check_file_mutation_acl(&file)?;
    delete_handle(&file)
}

/// Same-directory, no-replace rename. Caller pins its protected parent directory
/// across rotations. Missing source is returned unchanged for the caller to handle.
pub fn rename_no_replace(from: &Path, to: &Path) -> Result<()> {
    let from = absolute(from)?;
    let to = absolute(to)?;
    if !from.parent().zip(to.parent()).is_some_and(|(a, b)| os_eq(a.as_os_str(), b.as_os_str())) {
        bail!("rename requires same parent");
    }
    let parent = directory(from.parent().context("missing parent")?, false)?;
    let file = native_open(
        parent.final_file().as_raw_handle(),
        from.file_name().context("missing filename")?,
        0x30080,
        1 | 4,
        1,
        false,
    )?;
    check_file_mutation_acl(&file)?;
    match inspect_at(parent.final_file(), to.file_name().context("missing target name")?, false) {
        Ok(_) => {}
        Err(e) if is_missing(&e) => {}
        Err(e) => return Err(e),
    }
    rename_handle(&file, parent.final_file(), to.file_name().context("missing target name")?, false)
}

/// Verify confidentiality before snapshotting recovery secrets, unlike legacy repair.
pub fn backup_secret(path: &Path) -> Result<Option<Stage>> {
    let _guard = directory(path.parent().context("missing backup parent")?, false)?;
    let source = match open(path, false, false, false, false) {
        Ok(f) => f,
        Err(e) if is_missing(&e) => return Ok(None),
        Err(e) => return Err(e),
    };
    check_file_mutation_acl(&source)?;
    check_secret_acl(&source)?;
    let stage = Stage::new(path.parent().context("missing backup parent")?)?;
    stage.copy_from(&mut &source)?;
    stage.file().sync_all()?;
    Ok(Some(stage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn native_struct_layouts_match_windows_x64_abi() {
        assert_eq!(std::mem::size_of::<UnicodeString>(), 16);
        assert_eq!(std::mem::size_of::<ObjectAttributes>(), 48);
        assert_eq!(std::mem::size_of::<IoStatus>(), 16);
        assert_eq!(std::mem::offset_of!(ObjectAttributes, root), 8);
        assert_eq!(std::mem::offset_of!(ObjectAttributes, name), 16);
        assert_eq!(std::mem::offset_of!(ObjectAttributes, security), 32);
    }

    fn set_test_users_ace(path: &Path, mask: u32) {
        let text = format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x{mask:08x};;;BU)");
        let text = wide(std::ffi::OsStr::new(&text)).unwrap();
        let mut raw = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    1,
                    &mut raw,
                    ptr::null_mut(),
                )
            },
            0
        );
        let sd = Local(raw);
        let mut acl = ptr::null_mut();
        let (mut present, mut defaulted) = (0, 0);
        assert_ne!(unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut acl, &mut defaulted) }, 0);
        let file = open(path, true, false, path.is_dir(), false).unwrap();
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    file.as_raw_handle(),
                    1,
                    0x80000004,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    acl,
                    ptr::null_mut(),
                )
            },
            0
        );
    }

    #[test]
    #[ignore = "requires elevated Windows administrator token and real NTFS"]
    fn reject_admin_owned_config_with_untrusted_mutation_ace_without_hardening() {
        let root =
            program_data().unwrap().join(format!("monitor-agent-file-acl-test-{}", std::process::id()));
        let guard = ensure_private_dir(&root).unwrap();
        let path = root.join("agent.env");
        let stage = Stage::new(&root).unwrap();
        stage.write_all(b"MONITOR_SERVER=https://attacker.invalid\n").unwrap();
        stage.commit(&path).unwrap();
        for mask in [0x2, 0x4, 0x10, 0x100, 0x10000, 0x40000, 0x80000, 0x40000000, 0x10000000] {
            set_test_users_ace(&path, mask);
            assert!(read(&path, 1024).is_err(), "allowed mutation mask {mask:x}");
            assert!(check_destination(&path).is_err(), "allowed unsafe replacement target {mask:x}");
            assert!(backup(&path).is_err(), "backed up untrusted configuration {mask:x}");
            // Detection did not silently remove the bad ACE and trust the contents.
            let file = open(&path, true, false, false, false).unwrap();
            assert!(check_file_mutation_acl(&file).is_err());
            protect(&file, false).unwrap();
        }
        // Read-only data grants are accepted only by the explicit upgrade path.
        for mask in [0x1, 0x80000000] {
            set_test_users_ace(&path, mask);
            assert!(read_for_install(&path, 1024).is_ok());
            assert!(read_secret(&path, 1024).is_err());
            assert!(read(&path, 1024).is_err());
            assert!(backup_secret(&path).is_err());
            // Rejection does not silently harden the file.
            let file = open(&path, true, false, false, false).unwrap();
            assert!(check_secret_acl(&file).is_err());
            protect(&file, false).unwrap();
        }
        set_test_users_ace(&path, 0x80000000);
        assert!(read_for_install(&path, 1024).is_ok());
        assert!(read_secret(&path, 1024).is_err());
        assert!(read(&path, 1024).is_err());
        assert!(backup_secret(&path).is_err());
        check_destination(&path).unwrap();
        harden(&path).unwrap();
        let file = open(&path, false, false, false, false).unwrap();
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
        drop(file);
        remove_private_file(&path).unwrap();
        drop(guard);
        std::fs::remove_dir(root).unwrap();
    }

    #[test]
    #[ignore = "requires elevated Windows token and NTFS protected directory"]
    fn ancestor_allows_normal_windows_metadata_grants_but_rejects_takeover() {
        let root =
            program_data().unwrap().join(format!("monitor-agent-ancestor-acl-test-{}", std::process::id()));
        let guard = ensure_private_dir(&root).unwrap();
        for mask in [0x10000000, 0x10000, 0x40000, 0x80000, 0x40] {
            set_test_users_ace(&root, mask);
            let dir = open(&root, true, false, true, false).unwrap();
            assert!(check_directory_acl(&dir, true).is_err());
            protect(&dir, true).unwrap();
        }
        for mask in [0x2, 0x4, 0x100, 0x40000000] {
            set_test_users_ace(&root, mask);
            let dir = open(&root, true, false, true, false).unwrap();
            assert!(check_directory_acl(&dir, true).is_ok());
            protect(&dir, true).unwrap();
        }
        drop(guard);
        std::fs::remove_dir(root).unwrap();
    }

    /// Metadata handles CAN set junctions. The security invariant is that held
    /// RootDirectory handles still access their original namespace, while fresh
    /// walks reject the redirected component. No share-mode prevention claim.
    #[test]
    #[ignore = "requires elevated Windows token and NTFS reparse-point support"]
    fn pinned_directory_blocks_reparse_mutation_and_preexisting_writer() {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                handle: Handle,
                code: u32,
                input: *const c_void,
                input_len: u32,
                output: Handle,
                output_len: u32,
                returned: *mut u32,
                overlapped: Handle,
            ) -> i32;
        }
        fn write_handle(path: &Path, access: u32) -> std::io::Result<File> {
            let path = wide(path.as_os_str()).unwrap();
            let h = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    access,
                    1 | 2 | 4,
                    ptr::null(),
                    3,
                    0x02000000 | 0x00200000,
                    ptr::null_mut(),
                )
            };
            if h as isize == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_handle(h) })
        }
        fn set_reparse(file: &File, buffer: &[u8]) -> std::io::Result<()> {
            let mut returned = 0;
            if unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    0x000900a4,
                    buffer.as_ptr().cast(),
                    buffer.len() as u32,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        let root =
            program_data().unwrap().join(format!("monitor-agent-reparse-pin-test-{}", std::process::id()));
        let root_guard = ensure_private_dir(&root).unwrap();
        let ancestor = root.join("ancestor");
        let target = root.join("target");
        drop(ensure_private_dir(&ancestor).unwrap());
        drop(ensure_private_dir(&target).unwrap());
        let substitute: Vec<u16> = format!(r"\??\{}", target.display()).encode_utf16().collect();
        let print: Vec<u16> = target.as_os_str().encode_wide().collect();
        let substitute_bytes = (substitute.len() * 2) as u16;
        let print_bytes = (print.len() * 2) as u16;
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xa0000003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
        buffer.extend_from_slice(&(8u16 + substitute_bytes + 2 + print_bytes + 2).to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes()); // reserved
        for value in [0, substitute_bytes, substitute_bytes + 2, print_bytes] {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        for value in substitute.iter().copied().chain([0]).chain(print.iter().copied()).chain([0]) {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        let pin = directory(&ancestor, false).unwrap();
        let stage_parent = directory(&ancestor, false).unwrap();
        let attributes = write_handle(&ancestor, 0x100 | 0x80).unwrap();
        set_reparse(&attributes, &buffer)
            .expect("positive control: metadata handle CAN create junction while guards live");
        assert!(directory(&ancestor, false).is_err(), "new walk must reject redirected ancestor");
        assert!(read_secret(&ancestor.join("guarded.env"), 1024).is_err());
        // Create and commit through the parent handle captured before redirection.
        // The junction is set on an empty directory, as required by NTFS.
        let anchored_stage = Stage::in_directory(stage_parent).unwrap();
        anchored_stage.write_all(b"anchored-before-redirect").unwrap();
        // Existing parent handles must never follow newly attached reparse data.
        anchored_stage.commit(&ancestor.join("guarded.env")).unwrap();
        assert!(!target.join("guarded.env").exists(), "stage rename escaped to attacker directory");
        let original = native_open(
            pin.final_file().as_raw_handle(),
            std::ffi::OsStr::new("guarded.env"),
            0x80030080,
            1 | 4,
            1,
            false,
        )
        .unwrap();
        let mut bytes = Vec::new();
        (&original).read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"anchored-before-redirect");
        let new_stage = Stage::in_directory(directory(&root, false).unwrap()).unwrap();
        new_stage.write_all(b"unrelated root stage").unwrap();
        drop(new_stage);
        let cleanup_stage = Stage::in_directory(DirectoryGuard {
            handles: vec![pin.final_file().try_clone().unwrap()],
            path: ancestor.clone(),
        })
        .unwrap();
        let stage_name = cleanup_stage.path.file_name().unwrap().to_owned();
        drop(cleanup_stage);
        assert!(
            native_open(pin.final_file().as_raw_handle(), &stage_name, 0x20080, 7, 1, false).is_err(),
            "stage drop did not remove original-directory object"
        );
        delete_handle(&original).unwrap();
        drop(original);
        // Remove junction via the same metadata handle; after clearing it,
        // verify the original directory is empty and the target untouched.
        let mut delete_buffer = Vec::new();
        delete_buffer.extend_from_slice(&0xa0000003u32.to_le_bytes());
        delete_buffer.extend_from_slice(&[0; 4]);
        let mut returned = 0;
        assert_ne!(
            unsafe {
                DeviceIoControl(
                    attributes.as_raw_handle(),
                    0x000900ac,
                    delete_buffer.as_ptr().cast(),
                    8,
                    ptr::null_mut(),
                    0,
                    &mut returned,
                    ptr::null_mut(),
                )
            },
            0
        );
        drop(attributes);
        drop(pin);
        assert_eq!(std::fs::read_dir(&ancestor).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&target).unwrap().count(), 0);
        std::fs::remove_dir(&ancestor).unwrap();
        std::fs::remove_dir(&target).unwrap();
        drop(root_guard);
        std::fs::remove_dir(root).unwrap();
    }

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
        let rotated = root.join("test.log.1");
        assert!(
            rename_no_replace(&log_path, &rotated).is_err(),
            "live no-delete-share writer must block rotation"
        );
        drop(log);
        rename_no_replace(&log_path, &rotated).unwrap();
        assert!(!log_path.exists());
        assert!(rotated.exists());
        let new_log = open_log(&log_path).unwrap();
        drop(new_log);
        assert!(rename_no_replace(&log_path, &rotated).is_err(), "rotation must not replace destination");
        assert!(log_path.exists());
        assert!(rotated.exists());
        std::fs::remove_file(&log_path).unwrap();
        let error = rename_no_replace(&log_path, &rotated).unwrap_err();
        assert!(is_missing(&error));
        std::fs::remove_file(&rotated).unwrap();
        std::fs::remove_file(&target).unwrap();
        std::fs::remove_file(root.join(".install.lock")).unwrap();
        drop(guard);
        std::fs::remove_dir(&root).unwrap();
    }
}
