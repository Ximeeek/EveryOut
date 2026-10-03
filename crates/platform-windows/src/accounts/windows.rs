//! Native profile/hive APIs. UNVERIFIED S6: logon transitions can race registry
//! mounting; rechecks refuse observed changes but cannot establish an OS-wide lock.
use super::*;
use crate::native::{self, wide, Handle};
use std::{collections::HashSet, mem::size_of, ptr, time::Duration};
use windows_sys::Win32::{
    Foundation::*,
    NetworkManagement::NetManagement::*,
    Security::{Authentication::Identity::*, Authorization::*, *},
    Storage::FileSystem::*,
    System::{Registry::*, Threading::*},
};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn open(parent: HKEY, name: &str) -> Result<Key> {
    let mut chain: Vec<Key> = Vec::new();
    for component in crate::components(name)? {
        let parent = chain.last().map(|k| k.0).unwrap_or(parent);
        chain.push(open_component(parent, &component)?);
    }
    Ok(chain.pop().expect("nonempty checked key path"))
}
fn open_component(parent: HKEY, name: &str) -> Result<Key> {
    let name = wide(name);
    let mut key = ptr::null_mut();
    let code = unsafe {
        RegOpenKeyExW(
            parent,
            name.as_ptr(),
            REG_OPTION_OPEN_LINK,
            KEY_READ | KEY_WOW64_64KEY,
            &mut key,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(native::error(code));
    }
    let key = Key(key);
    // Reject symbolic keys by querying only their fixed link-value type/size.
    let mut kind = 0;
    let mut bytes = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            wide("SymbolicLinkValue").as_ptr(),
            ptr::null(),
            &mut kind,
            ptr::null_mut(),
            &mut bytes,
        )
    };
    if code == ERROR_SUCCESS && kind == REG_LINK {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    if code != ERROR_SUCCESS && code != ERROR_FILE_NOT_FOUND {
        return Err(native::error(code));
    }
    Ok(key)
}
fn names(key: &Key) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for index in 0..4096 {
        let mut name = [0u16; 256];
        let mut length = name.len() as u32;
        let code = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            return Ok(result);
        }
        if code != ERROR_SUCCESS {
            return Err(native::error(code));
        }
        result.push(
            String::from_utf16(&name[..length as usize])
                .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?,
        );
    }
    Err(PlatformError::new(ErrorKind::Unsupported))
}
/// Sole payload exception: fixed profile/known-folder path metadata. Never called
/// for session keys, arbitrary value names, credential blobs or hive file bytes.
fn path_value(key: &Key, name: &str) -> Result<Option<String>> {
    let mut buffer = [0u16; 32768];
    let mut bytes = (buffer.len() * 2) as u32;
    let mut kind = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            wide(name).as_ptr(),
            ptr::null(),
            &mut kind,
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if code == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if code != ERROR_SUCCESS {
        return Err(native::error(code));
    }
    if ![REG_SZ, REG_EXPAND_SZ].contains(&kind)
        || bytes < 2
        || !bytes.is_multiple_of(2)
        || bytes as usize > buffer.len() * 2
    {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let units = &buffer[..bytes as usize / 2];
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    Ok(Some(
        String::from_utf16(&units[..units.len() - 1])
            .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?,
    ))
}
fn state(key: &Key) -> Result<u32> {
    let mut value = 0u32;
    let mut bytes = 4;
    let mut kind = 0;
    let code = unsafe {
        RegQueryValueExW(
            key.0,
            wide("State").as_ptr(),
            ptr::null(),
            &mut kind,
            (&mut value as *mut u32).cast(),
            &mut bytes,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(native::error(code));
    }
    if kind != REG_DWORD || bytes != 4 {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    Ok(value)
}
struct Sid(PSID);
impl Drop for Sid {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn sid(value: &str) -> Result<Sid> {
    if !valid_user_sid(value) {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let mut out = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide(value).as_ptr(), &mut out) } == 0 {
        return Err(native::last_error());
    }
    Ok(Sid(out))
}
struct Policy(LSA_HANDLE);
impl Drop for Policy {
    fn drop(&mut self) {
        unsafe {
            LsaClose(self.0);
        }
    }
}
struct PolicyBuffer(*mut std::ffi::c_void);
impl Drop for PolicyBuffer {
    fn drop(&mut self) {
        unsafe {
            LsaFreeMemory(self.0);
        }
    }
}
struct NetBuffer(*mut u8);
impl Drop for NetBuffer {
    fn drop(&mut self) {
        unsafe {
            NetApiBufferFree(self.0.cast());
        }
    }
}
/// Query only local account-domain SID and level-20 SAM user identifiers.
/// No remote server, domain SID lookup, password field or credential API.
fn local_users() -> Result<HashSet<String>> {
    let attributes = LSA_OBJECT_ATTRIBUTES {
        Length: size_of::<LSA_OBJECT_ATTRIBUTES>() as u32,
        ..Default::default()
    };
    let mut policy: LSA_HANDLE = 0;
    let status = unsafe {
        LsaOpenPolicy(
            ptr::null(),
            &attributes,
            POLICY_VIEW_LOCAL_INFORMATION as u32,
            &mut policy,
        )
    };
    if status < 0 {
        return Err(native::error(unsafe { LsaNtStatusToWinError(status) }));
    }
    let policy = Policy(policy);
    let mut data = ptr::null_mut();
    let status =
        unsafe { LsaQueryInformationPolicy(policy.0, PolicyAccountDomainInformation, &mut data) };
    if status < 0 {
        return Err(native::error(unsafe { LsaNtStatusToWinError(status) }));
    }
    let _data = PolicyBuffer(data);
    if data.is_null() {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let domain = unsafe { &*data.cast::<POLICY_ACCOUNT_DOMAIN_INFO>() };
    if domain.DomainSid.is_null() || unsafe { IsValidSid(domain.DomainSid) } == 0 {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let mut raw = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(domain.DomainSid, &mut raw) } == 0 {
        return Err(native::last_error());
    }
    let _raw = Sid(raw.cast());
    let mut length = 0;
    while length < 256 && unsafe { *raw.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let prefix = String::from_utf16(unsafe { std::slice::from_raw_parts(raw, length) })
        .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?;
    let mut result = HashSet::new();
    let mut resume = 0;
    for _ in 0..4096 {
        let mut buffer = ptr::null_mut();
        let mut count = 0;
        let mut total = 0;
        let previous = resume;
        let code = unsafe {
            NetUserEnum(
                ptr::null(),
                20,
                FILTER_NORMAL_ACCOUNT,
                &mut buffer,
                65536,
                &mut count,
                &mut total,
                &mut resume,
            )
        };
        let _buffer = NetBuffer(buffer);
        if code != ERROR_SUCCESS && code != ERROR_MORE_DATA {
            return Err(native::error(code));
        }
        if count > 4096 || (count > 0 && buffer.is_null()) || result.len() + count as usize > 4096 {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        for index in 0..count as usize {
            let user = unsafe { &*buffer.cast::<USER_INFO_20>().add(index) };
            let value = format!("{prefix}-{}", user.usri20_user_id);
            if !valid_user_sid(&value) {
                return Err(PlatformError::new(ErrorKind::ScopeViolation));
            }
            result.insert(value);
        }
        if code == ERROR_SUCCESS {
            return Ok(result);
        }
        if count == 0 || resume == previous {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
    }
    Err(PlatformError::new(ErrorKind::Unsupported))
}
struct LsaBuffer(*mut std::ffi::c_void);
impl Drop for LsaBuffer {
    fn drop(&mut self) {
        unsafe {
            LsaFreeReturnBuffer(self.0);
        }
    }
}
fn logged_on(value: &str) -> Result<bool> {
    let owner = sid(value)?;
    let mut count = 0;
    let mut sessions = ptr::null_mut();
    let status = unsafe { LsaEnumerateLogonSessions(&mut count, &mut sessions) };
    if status < 0 {
        return Err(native::error(unsafe { LsaNtStatusToWinError(status) }));
    }
    let _sessions = LsaBuffer(sessions.cast());
    if count > 65536 {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    for index in 0..count as usize {
        let mut data = ptr::null_mut();
        let status = unsafe { LsaGetLogonSessionData(sessions.add(index), &mut data) };
        if status < 0 {
            return Err(native::error(unsafe { LsaNtStatusToWinError(status) }));
        }
        if data.is_null() {
            continue;
        }
        let _data = LsaBuffer(data.cast());
        let data = unsafe { &*data };
        if !data.Sid.is_null()
            && [2, 7, 10, 11, 12, 13].contains(&data.LogonType)
            && unsafe { EqualSid(data.Sid, owner.0) } != 0
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn mounted(value: &str) -> Result<bool> {
    match open(HKEY_USERS, value) {
        Ok(_) => Ok(true),
        Err(e) if native::absent(&e) => Ok(false),
        Err(e) => Err(e),
    }
}
pub struct NativeProfiles;
impl NativeProfiles {
    /// Fixed App Paths executable-location metadata exception, never session data.
    /// Unregistered/custom installations remain unsupported for process closing.
    pub fn installation_paths(&self, hive: &str, names: &[String]) -> Result<Vec<PathBuf>> {
        let user = open(HKEY_USERS, hive)?;
        self.paths_under(user.0, names)
    }
    /// Same fixed App Paths metadata allowlist for the invoking account.
    pub fn current_installation_paths(&self, names: &[String]) -> Result<Vec<PathBuf>> {
        self.paths_under(HKEY_CURRENT_USER, names)
    }
    fn paths_under(&self, user: HKEY, names: &[String]) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::new();
        for name in names {
            if crate::components(name)?.len() != 1 {
                return Err(PlatformError::new(ErrorKind::ScopeViolation));
            }
            let location =
                format!("Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\{name}");
            for parent in [user, HKEY_LOCAL_MACHINE] {
                let key = match open(parent, &location) {
                    Ok(key) => key,
                    Err(e) if native::absent(&e) => continue,
                    Err(e) => return Err(e),
                };
                if let Some(path) = path_value(&key, "")? {
                    if !local_path(&path)
                        || !PathBuf::from(&path)
                            .file_name()
                            .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(name))
                    {
                        return Err(PlatformError::new(ErrorKind::OwnershipConflict));
                    }
                    paths.push(PathBuf::from(path));
                }
            }
        }
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}
impl ProfileSource for NativeProfiles {
    fn records(&self) -> Result<Vec<ProfileRecord>> {
        let local = local_users()?;
        let root = open(
            HKEY_LOCAL_MACHINE,
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        )?;
        let mut result = Vec::new();
        for value in names(&root)? {
            let candidate = (|| -> Result<ProfileRecord> {
                if !valid_user_sid(&value) {
                    return Err(PlatformError::new(ErrorKind::Unsupported));
                }
                let key = open(root.0, &value)?;
                let path = path_value(&key, "ProfileImagePath")?
                    .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?;
                // Unknown nonzero profile state is excluded conservatively.
                Ok(ProfileRecord {
                    local_user: local.contains(&value),
                    special: false,
                    temporary: state(&key)? != 0,
                    logged_on: logged_on(&value)?,
                    hive_mounted: mounted(&value)?,
                    path: PathBuf::from(path),
                    sid: value.clone(),
                })
            })();
            result.push(candidate.unwrap_or_else(|_| ProfileRecord {
                sid: value.clone(),
                path: PathBuf::new(),
                local_user: false,
                special: !valid_user_sid(&value),
                temporary: false,
                logged_on: false,
                hive_mounted: false,
            }));
        }
        Ok(result)
    }
    fn folder(&self, hive: &str, folder: KnownFolder) -> Result<Option<String>> {
        if folder == KnownFolder::UserProfile {
            return Ok(None);
        }
        crate::components(hive)?;
        let parent = open(HKEY_USERS, hive)?;
        let key = match open(
            parent.0,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders",
        ) {
            Ok(key) => key,
            Err(e) if native::absent(&e) => return Ok(None),
            Err(e) => return Err(e),
        };
        path_value(
            &key,
            match folder {
                KnownFolder::LocalAppData => "Local AppData",
                KnownFolder::RoamingAppData => "AppData",
                KnownFolder::UserProfile => unreachable!(),
            },
        )
    }
}

/// Enable backup/restore ONLY around RegLoadKey/RegUnLoadKey; restore exact prior
/// token state. File cleanup never runs with these bypass privileges enabled.
struct Privilege {
    token: Handle,
    previous: TOKEN_PRIVILEGES,
}
impl Privilege {
    fn enable(name: &str) -> Result<Self> {
        let mut raw = ptr::null_mut();
        if unsafe {
            OpenThreadToken(
                GetCurrentThread(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                1,
                &mut raw,
            )
        } == 0
        {
            return Err(native::last_error());
        }
        let token = Handle(raw);
        let mut luid = LUID::default();
        if unsafe { LookupPrivilegeValueW(ptr::null(), wide(name).as_ptr(), &mut luid) } == 0 {
            return Err(native::last_error());
        }
        let request = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut bytes = 0;
        unsafe {
            SetLastError(ERROR_SUCCESS);
        }
        if unsafe {
            AdjustTokenPrivileges(
                token.0,
                0,
                &request,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut bytes,
            )
        } == 0
            || unsafe { GetLastError() } != ERROR_SUCCESS
        {
            return Err(native::last_error());
        }
        Ok(Self { token, previous })
    }
}
impl Drop for Privilege {
    fn drop(&mut self) {
        unsafe {
            AdjustTokenPrivileges(
                self.token.0,
                0,
                &self.previous,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    }
}
/// Privileged registry calls run on a short-lived impersonating worker. Even if
/// token restoration fails, ending that worker cannot leave bypass privileges on
/// the helper's ordinary file/process execution thread or process token.
fn privileged(call: impl FnOnce() -> u32 + Send + 'static) -> Result<()> {
    std::thread::spawn(move || {
        if unsafe { ImpersonateSelf(SecurityImpersonation) } == 0 {
            return Err(native::last_error());
        }
        struct Impersonation;
        impl Drop for Impersonation {
            fn drop(&mut self) {
                unsafe {
                    RevertToSelf();
                }
            }
        }
        let _impersonation = Impersonation;
        let _backup = Privilege::enable("SeBackupPrivilege")?;
        let _restore = Privilege::enable("SeRestorePrivilege")?;
        let code = call();
        if code == ERROR_SUCCESS {
            Ok(())
        } else {
            Err(native::error(code))
        }
    })
    .join()
    .unwrap_or_else(|_| Err(PlatformError::new(ErrorKind::Io)))
}
pub struct NativeHives;
impl HiveApi for NativeHives {
    fn mounted(&self, key: &str) -> Result<bool> {
        mounted(key)
    }
    fn logged_on(&self, value: &str) -> Result<bool> {
        logged_on(value)
    }
    fn load(&self, profile: &AccountProfile, key: &str) -> Result<()> {
        if !key.starts_with("EveryOut-") || crate::components(key)?.len() != 1 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        profile.revalidate(&NativeProfiles)?;
        let root = crate::AllowedRoot::absolute(profile.profile_path())?;
        let hive = root.path("NTUSER.DAT")?;
        let metadata = hive.probe_shallow()?;
        if !metadata.exists || metadata.is_directory {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let path = profile.profile_path().join("NTUSER.DAT");
        let path = path
            .to_str()
            .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?;
        // Pin this regular file against replacement while the path-based registry
        // API consumes it. Attribute-only access; never read NTUSER.DAT bytes.
        let raw = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(native::last_error());
        }
        let pinned = Handle(raw);
        if pinned.info()?.directory {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        if mounted(profile.sid())? || logged_on(profile.sid())? || mounted(key)? {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        let key = wide(key);
        let path = wide(path);
        privileged(move || unsafe { RegLoadKeyW(HKEY_USERS, key.as_ptr(), path.as_ptr()) })
    }
    fn unload(&self, key: &str) -> Result<()> {
        if !key.starts_with("EveryOut-") || crate::components(key)?.len() != 1 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let key = wide(key);
        privileged(move || unsafe { RegUnLoadKeyW(HKEY_USERS, key.as_ptr()) })
    }
    fn retry_delay(&self) {
        std::thread::sleep(Duration::from_millis(50));
    }
}
