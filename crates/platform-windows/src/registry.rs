use crate::{
    components,
    native::{self, wide},
    Mutation, PlatformError, Result,
};
use everyout_core_model::{ActionStatus, ErrorKind};
use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr, rc::Rc};
use windows_sys::{
    Wdk::System::Registry::NtDeleteKey,
    Win32::{Foundation::*, Storage::FileSystem::DELETE, System::Registry::*},
};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: exactly one successful registry open owned by this wrapper.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn check(code: u32) -> Result<()> {
    if code == ERROR_SUCCESS {
        Ok(())
    } else {
        Err(native::error(code))
    }
}
fn open(parent: &Key, component: &str, mutate: bool) -> Result<Key> {
    let name = wide(component);
    let mut handle = ptr::null_mut();
    let access = KEY_QUERY_VALUE
        | KEY_ENUMERATE_SUB_KEYS
        | KEY_WOW64_64KEY
        | if mutate { DELETE | KEY_SET_VALUE } else { 0 };
    // SAFETY: one grammar-checked component relative to a live checked key; OPEN_LINK
    // opens the link itself. Metadata inspection below rejects all REG_LINK values.
    check(unsafe {
        RegOpenKeyExW(
            parent.0,
            name.as_ptr(),
            REG_OPTION_OPEN_LINK,
            access,
            &mut handle,
        )
    })?;
    let key = Key(handle);
    values(&key)?;
    Ok(key)
}
fn values(key: &Key) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for index in 0..=10_000 {
        let mut name = vec![0u16; 16_384];
        let mut length = name.len() as u32;
        let mut kind = 0;
        // SAFETY: writable name/type buffers, but both value-data arguments are NULL.
        // This retrieves names and types only, never registry value payloads or sizes.
        let code = unsafe {
            RegEnumValueW(
                key.0,
                index,
                name.as_mut_ptr(),
                &mut length,
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if code == ERROR_NO_MORE_ITEMS {
            return Ok(result);
        }
        check(code)?;
        if kind == REG_LINK {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        result.push(
            String::from_utf16(&name[..length as usize])
                .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?,
        );
    }
    Err(PlatformError::new(ErrorKind::Unsupported))
}
fn children(key: &Key) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for index in 0..=10_000 {
        let mut name = [0u16; 256];
        let mut length = name.len() as u32;
        // SAFETY: bounded name buffer; class, last-write and other metadata omitted.
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
        check(code)?;
        let name = OsString::from_wide(&name[..length as usize])
            .into_string()
            .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?;
        components(&name)?;
        result.push(name);
    }
    Err(PlatformError::new(ErrorKind::Unsupported))
}

/// Exact current-user root plus exact reviewed key/value targets. Construction is
/// for trusted Rust manifest interpretation, never UI input. No alternate hive,
/// default value, recursive glob or root deletion is expressible.
#[derive(Clone)]
pub struct RegistryRoot {
    chain: Rc<Vec<Key>>,
    keys: Vec<Vec<String>>,
    values: Vec<Vec<String>>,
}
pub enum RegistryTarget {
    Key(String),
    Value(String),
}
impl RegistryRoot {
    pub fn from_manifest(root: &str, targets: &[RegistryTarget]) -> Result<Self> {
        Self::bind(root, targets, None)
    }
    /// Trusted helper only: reinterpret HKCU under a borrowed owner SID or this
    /// run's temporary HKU mount. Never use elevated administrator HKCU.
    pub fn for_account(root: &str, targets: &[RegistryTarget], hive: &str) -> Result<Self> {
        if components(hive)?.len() != 1
            || !(crate::accounts::valid_user_sid(hive) || hive.starts_with("EveryOut-"))
        {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        Self::bind(root, targets, Some(hive))
    }
    fn bind(root: &str, targets: &[RegistryTarget], hive: Option<&str>) -> Result<Self> {
        let parts = components(root)?;
        if parts.len() < 2 || !parts[0].eq_ignore_ascii_case("Software") {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let mut current = ptr::null_mut();
        // SAFETY: bind current process user's HKCU, not an arbitrary or other-user hive.
        check(if let Some(hive) = hive {
            unsafe {
                RegOpenKeyExW(
                    HKEY_USERS,
                    wide(hive).as_ptr(),
                    REG_OPTION_OPEN_LINK,
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
                    &mut current,
                )
            }
        } else {
            unsafe {
                RegOpenCurrentUser(
                    KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_WOW64_64KEY,
                    &mut current,
                )
            }
        })?;
        let mut chain = vec![Key(current)];
        for part in parts {
            chain.push(open(chain.last().expect("HKCU present"), &part, false)?);
        }
        let mut keys = Vec::new();
        let mut value_targets = Vec::new();
        for target in targets {
            match target {
                RegistryTarget::Key(path) => keys.push(components(path)?),
                RegistryTarget::Value(path) => value_targets.push(components(path)?),
            }
        }
        Ok(Self {
            chain: Rc::new(chain),
            keys,
            values: value_targets,
        })
    }
    fn allowed(&self, relative: &str, value: bool) -> Result<Vec<String>> {
        let parts = components(relative)?;
        let allowed = if value { &self.values } else { &self.keys };
        if !allowed.iter().any(|rule| {
            rule.len() == parts.len()
                && rule
                    .iter()
                    .zip(&parts)
                    .all(|(a, b)| a.eq_ignore_ascii_case(b))
        }) {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        Ok(parts)
    }
    fn descend(&self, parts: &[String], mutate: bool) -> Result<Vec<Key>> {
        let mut keys = Vec::new();
        let mut parent = self.chain.last().expect("root present");
        for part in parts {
            keys.push(open(parent, part, mutate)?);
            parent = keys.last().expect("just pushed");
        }
        Ok(keys)
    }
    pub fn key_exists(&self, relative: &str) -> Result<bool> {
        let parts = self.allowed(relative, false)?;
        match self.descend(&parts, false) {
            Ok(_) => Ok(true),
            Err(e) if native::absent(&e) => Ok(false),
            Err(e) => Err(e),
        }
    }
    pub fn value_exists(&self, relative: &str) -> Result<bool> {
        let parts = self.allowed(relative, true)?;
        let name = parts.last().expect("nonempty path");
        let chain = match self.descend(&parts[..parts.len() - 1], false) {
            Ok(chain) => chain,
            Err(e) if native::absent(&e) => return Ok(false),
            Err(e) => return Err(e),
        };
        let key = chain
            .last()
            .unwrap_or_else(|| self.chain.last().expect("root present"));
        Ok(values(key)?.iter().any(|v| v.eq_ignore_ascii_case(name)))
    }
    pub fn delete_value(&self, relative: &str, dry_run: bool) -> Result<Mutation> {
        let parts = self.allowed(relative, true)?;
        let name = parts.last().expect("nonempty path");
        // Open root itself relative to its bound parent, not its original full path.
        // An empty subkey duplicates a key handle with the requested rights.
        let mut chain = match self.descend(&parts[..parts.len() - 1], !dry_run) {
            Ok(chain) => chain,
            Err(e) if native::absent(&e) => {
                return Ok(Mutation {
                    status: ActionStatus::AlreadyAbsent,
                    objects: 0,
                })
            }
            Err(e) => return Err(e),
        };
        if chain.is_empty() {
            let parent = self.chain.last().expect("root present");
            chain.push(open(parent, "", !dry_run)?);
        }
        let key = chain.last().expect("key present");
        if !values(key)?.iter().any(|v| v.eq_ignore_ascii_case(name)) {
            return Ok(Mutation {
                status: ActionStatus::AlreadyAbsent,
                objects: 0,
            });
        }
        if dry_run {
            return Ok(Mutation {
                status: ActionStatus::WouldApply,
                objects: 1,
            });
        }
        let name = wide(name);
        // SAFETY: exact allow-listed value name on the held, non-link key; no data read.
        check(unsafe { RegDeleteValueW(key.0, name.as_ptr()) })?;
        Ok(Mutation {
            status: ActionStatus::Applied,
            objects: 1,
        })
    }
    pub fn delete_key_tree(&self, relative: &str, dry_run: bool) -> Result<Mutation> {
        let parts = self.allowed(relative, false)?;
        let mut chain = match self.descend(&parts, !dry_run) {
            Ok(chain) => chain,
            Err(e) if native::absent(&e) => {
                return Ok(Mutation {
                    status: ActionStatus::AlreadyAbsent,
                    objects: 0,
                })
            }
            Err(e) => return Err(e),
        };
        let leaf = chain.pop().expect("nonempty target");
        let mut objects = Vec::new();
        let mut count = 0;
        collect(leaf, !dry_run, 0, &mut objects, &mut count)?;
        if dry_run {
            return Ok(Mutation {
                status: ActionStatus::WouldApply,
                objects: count,
            });
        }
        let mut applied = 0;
        for (key, names) in objects.into_iter().rev() {
            let result = (|| {
                values(&key)?;
                for name in names {
                    let name = wide(name);
                    // SAFETY: the values of this allow-listed tree may be removed;
                    // only names were enumerated, never value data.
                    check(unsafe { RegDeleteValueW(key.0, name.as_ptr()) })?;
                    applied += 1;
                }
                // SAFETY: user-mode native deletion targets this checked key handle,
                // so a renamed/replaced pathname cannot redirect the operation.
                let status = unsafe { NtDeleteKey(key.0) };
                if status < 0 {
                    // SAFETY: pure error-code conversion.
                    return Err(native::error(unsafe { RtlNtStatusToDosError(status) }));
                }
                applied += 1;
                Ok(())
            })();
            result.map_err(|mut e: PlatformError| {
                e.applied = applied;
                e
            })?;
        }
        Ok(Mutation {
            status: ActionStatus::Applied,
            objects: applied,
        })
    }
}
fn collect(
    key: Key,
    mutate: bool,
    depth: usize,
    result: &mut Vec<(Key, Vec<String>)>,
    count: &mut usize,
) -> Result<()> {
    if depth >= 64 || *count >= 10_000 {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    let names = children(&key)?;
    let value_names = values(&key)?;
    *count += value_names.len() + 1;
    if *count > 10_000 {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    result.push((key, value_names));
    let index = result.len() - 1;
    for name in names {
        collect(
            open(&result[index].0, &name, mutate)?,
            mutate,
            depth + 1,
            result,
            count,
        )?;
    }
    Ok(())
}
