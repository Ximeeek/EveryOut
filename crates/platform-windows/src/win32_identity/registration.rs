//! Explicit nonsensitive registry allowlist and target-only local shell links.
use super::*;
use crate::native::wide;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, ptr};
use windows_sys::Win32::{Foundation::*, System::Registry::*};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn open(parent: HKEY, path: &str, view: u32) -> Result<Key> {
    let mut chain = Vec::<Key>::new();
    for component in crate::components(path)? {
        let mut raw = ptr::null_mut();
        let status = unsafe {
            RegOpenKeyExW(
                chain.last().map(|k| k.0).unwrap_or(parent),
                wide(component).as_ptr(),
                REG_OPTION_OPEN_LINK,
                KEY_READ | view,
                &mut raw,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(native::error(status));
        }
        let key = Key(raw);
        let mut kind = 0;
        let status = unsafe {
            RegQueryValueExW(
                raw,
                wide("SymbolicLinkValue").as_ptr(),
                ptr::null(),
                &mut kind,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status == ERROR_SUCCESS && kind == REG_LINK {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
            return Err(native::error(status));
        }
        chain.push(key);
    }
    Ok(chain.pop().expect("nonempty path"))
}
fn value(key: &Key, name: &str) -> Result<Option<String>> {
    // Private function; callers below are the complete fixed metadata allowlist.
    let mut buffer = [0u16; 4096];
    let mut bytes = (buffer.len() * 2) as u32;
    let mut kind = 0;
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            wide(name).as_ptr(),
            ptr::null(),
            &mut kind,
            buffer.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS {
        return Err(native::error(status));
    }
    if !matches!(kind, REG_SZ | REG_EXPAND_SZ)
        || bytes < 2
        || !bytes.is_multiple_of(2)
        || bytes as usize > buffer.len() * 2
    {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let value = String::from_utf16(&buffer[..bytes as usize / 2])
        .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?;
    let value = value.trim_end_matches('\0');
    if value.chars().any(char::is_control) {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    // No ambient environment expansion; unresolved expansions remain unusable hints.
    Ok((!value.is_empty()).then(|| value.to_owned()))
}
pub fn executable_path_hint(value: &str, display_icon: bool) -> Option<PathBuf> {
    let value = value.trim();
    let value = if display_icon {
        match value.rsplit_once(',') {
            Some((path, index)) if index.trim().parse::<i32>().is_ok() => path.trim(),
            _ => value,
        }
    } else {
        value
    };
    let value = if value.starts_with('"') && value.ends_with('"') && value.len() > 2 {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if value.contains(['"', '%']) || value.chars().any(char::is_control) {
        return None;
    }
    let path = PathBuf::from(value);
    (path.is_absolute()
        && path
            .extension()
            .is_some_and(|s| s.eq_ignore_ascii_case("exe")))
    .then_some(path)
}
pub(crate) fn registry_metadata(
    hive: HKEY,
    source: IdentitySource,
    name: &str,
    view: u32,
) -> Result<RegistrationMetadata> {
    if crate::components(name)?.len() != 1 {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let branch = if source == IdentitySource::AppPaths {
        "App Paths"
    } else {
        "Uninstall"
    };
    let key = open(
        hive,
        &format!("Software\\Microsoft\\Windows\\CurrentVersion\\{branch}\\{name}"),
        view,
    )?;
    let mut metadata = RegistrationMetadata {
        provenance: vec![EvidenceProvenance {
            source: source.code().into(),
            reason_code: format!(
                "{}-{}-allowlisted-installation-metadata",
                if hive == HKEY_CURRENT_USER {
                    "hkcu"
                } else if hive == HKEY_LOCAL_MACHINE {
                    "hklm"
                } else {
                    "account-hive"
                },
                if view == KEY_WOW64_32KEY { "32" } else { "64" }
            ),
        }],
        name: name.into(),
        source: Some(source),
        ..Default::default()
    };
    if source == IdentitySource::AppPaths {
        metadata.executable = value(&key, "")?
            .and_then(|s| executable_path_hint(&s, false))
            .filter(|p| p.file_name().is_some_and(|n| n.eq_ignore_ascii_case(name)));
    } else {
        metadata.display_name = value(&key, "DisplayName")?;
        metadata.publisher = value(&key, "Publisher")?;
        metadata.install_location = value(&key, "InstallLocation")?
            .map(PathBuf::from)
            .filter(|p| p.is_absolute());
        metadata.executable =
            value(&key, "DisplayIcon")?.and_then(|s| executable_path_hint(&s, true));
        metadata.display_version = value(&key, "DisplayVersion")?;
    }
    Ok(metadata)
}
/// Shared App Paths implementation for both account helpers and current-user process gates.
pub(crate) fn app_paths_under(user: HKEY, names: &[String]) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for name in names {
        if crate::components(name)?.len() != 1 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        for hive in [user, HKEY_LOCAL_MACHINE] {
            for view in [KEY_WOW64_32KEY, KEY_WOW64_64KEY] {
                match registry_metadata(hive, IdentitySource::AppPaths, name, view) {
                    Ok(r) => {
                        if let Some(path) = r.executable {
                            // Reparse rejection, existence, canonical and physical identity all share one binding.
                            let binding = ExecutableBinding::capture(&path)?;
                            binding.revalidate()?;
                            paths.push(binding.canonical_path.clone());
                        }
                    }
                    Err(e) if native::absent(&e) => (),
                    Err(e) => return Err(e),
                }
            }
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}
fn shortcut(path: &Path) -> Option<PathBuf> {
    use windows::{
        core::{Interface, PCWSTR},
        Win32::{
            System::Com::{CoCreateInstance, IPersistFile, CLSCTX_INPROC_SERVER, STGM_READ},
            UI::Shell::{IShellLinkW, ShellLink, SLGP_RAWPATH},
        },
    };
    let parent = AllowedRoot::absolute(path.parent()?).ok()?;
    let safe = parent.path(path.file_name()?.to_str()?).ok()?;
    let metadata = safe.probe_shallow().ok()?;
    if !metadata.exists || metadata.is_directory || metadata.size.is_some_and(|s| s > 1024 * 1024) {
        return None;
    }
    let _pin = safe.retain_shortcut_metadata().ok()?;
    let path = safe.canonical_metadata_path().ok()?;
    let link: IShellLinkW =
        unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.ok()?;
    let persist: IPersistFile = link.cast().ok()?;
    unsafe { persist.Load(PCWSTR(wide(&path).as_ptr()), STGM_READ) }.ok()?;
    let mut target = vec![0u16; 32768];
    // GetPath only. No Resolve, GetArguments, working-directory reads, or execution.
    unsafe { link.GetPath(&mut target, ptr::null_mut(), SLGP_RAWPATH.0 as u32) }.ok()?;
    safe.physical_chain().ok()??;
    let length = target.iter().position(|c| *c == 0)?;
    executable_path_hint(&String::from_utf16(&target[..length]).ok()?, false)
}
pub(crate) fn shortcuts() -> (Vec<RegistrationMetadata>, Vec<String>) {
    use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_CommonPrograms, FOLDERID_Programs, SHGetKnownFolderPath},
    };
    let initialized = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
    struct Apartment(bool);
    impl Drop for Apartment {
        fn drop(&mut self) {
            if self.0 {
                unsafe {
                    CoUninitialize();
                }
            }
        }
    }
    let _apartment = Apartment(initialized.is_ok());
    if initialized.is_err() && initialized.0 != 0x80010106u32 as i32 {
        return (vec![], vec!["shortcut-apartment-unavailable".into()]);
    }
    let mut records = Vec::new();
    let mut coverage = Vec::new();
    let mut visited = 0;
    for id in [&FOLDERID_Programs, &FOLDERID_CommonPrograms] {
        let mut raw = ptr::null_mut();
        if unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut raw) } < 0 || raw.is_null() {
            if !raw.is_null() {
                unsafe {
                    CoTaskMemFree(raw.cast());
                }
            }
            coverage.push("shortcut-folder-unavailable".into());
            continue;
        }
        let mut len = 0;
        while unsafe { *raw.add(len) } != 0 {
            len += 1;
        }
        let path = PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(raw, len)
        }));
        unsafe {
            CoTaskMemFree(raw.cast());
        }
        let mut stack = vec![(path, 0)];
        while let Some((path, depth)) = stack.pop() {
            let Ok(root) = AllowedRoot::absolute(&path) else {
                coverage.push("shortcut-root-unavailable".into());
                continue;
            };
            let Ok((children, omitted)) = root.discovery_children() else {
                coverage.push("shortcut-enumeration-incomplete".into());
                continue;
            };
            if omitted {
                coverage.push("shortcut-reparse-entries-omitted".into());
            }
            for (name, directory) in children {
                visited += 1;
                if visited > 2048 {
                    coverage.push("shortcut-entry-limit".into());
                    return (records, coverage);
                }
                if directory {
                    if depth < 6 {
                        stack.push((path.join(name), depth + 1));
                    } else {
                        coverage.push("shortcut-depth-limit".into());
                    }
                } else if name.to_ascii_lowercase().ends_with(".lnk") {
                    let executable = shortcut(&path.join(&name));
                    if executable.is_none() {
                        coverage.push("shortcut-target-unavailable".into());
                    }
                    records.push(RegistrationMetadata {
                        provenance: vec![EvidenceProvenance {
                            source: "start-menu-target".into(),
                            reason_code: "local-shortcut-target-only".into(),
                        }],
                        name,
                        executable,
                        source: Some(IdentitySource::Shortcut),
                        ..Default::default()
                    });
                }
            }
        }
    }
    (records, coverage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FixtureFolders;
    struct RegistryFixture {
        key: HKEY,
        path: String,
    }
    impl RegistryFixture {
        fn new() -> Self {
            let path = format!(
                "Software\\EveryOutWin32Test\\{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let mut key = ptr::null_mut();
            assert_eq!(
                unsafe {
                    RegCreateKeyExW(
                        HKEY_CURRENT_USER,
                        wide(&path).as_ptr(),
                        0,
                        ptr::null(),
                        REG_OPTION_VOLATILE,
                        KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                        ptr::null(),
                        &mut key,
                        ptr::null_mut(),
                    )
                },
                ERROR_SUCCESS
            );
            Self { key, path }
        }
        fn child(&self, path: &str) -> Key {
            let mut key = ptr::null_mut();
            assert_eq!(
                unsafe {
                    RegCreateKeyExW(
                        self.key,
                        wide(path).as_ptr(),
                        0,
                        ptr::null(),
                        REG_OPTION_VOLATILE,
                        KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                        ptr::null(),
                        &mut key,
                        ptr::null_mut(),
                    )
                },
                ERROR_SUCCESS
            );
            Key(key)
        }
    }
    impl Drop for RegistryFixture {
        fn drop(&mut self) {
            // Delete only the unique volatile fixture namespace owned by this test.
            unsafe {
                RegDeleteTreeW(self.key, ptr::null());
                RegCloseKey(self.key);
                RegDeleteKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&self.path).as_ptr(),
                    KEY_WOW64_64KEY,
                    0,
                );
            }
        }
    }
    fn set(key: &Key, name: &str, value: &str) {
        let value = wide(value);
        assert_eq!(
            unsafe {
                RegSetValueExW(
                    key.0,
                    wide(name).as_ptr(),
                    0,
                    REG_SZ,
                    value.as_ptr().cast(),
                    (value.len() * 2) as u32,
                )
            },
            ERROR_SUCCESS
        );
    }
    #[test]
    fn owned_registry_fixture_reads_only_the_installation_allowlist() {
        let registry = RegistryFixture::new();
        let fixture = FixtureFolders::create().unwrap();
        let exe = fixture.path().join("ObscureChat.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let app_paths = registry
            .child("Software\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ObscureChat.exe");
        set(&app_paths, "", &exe.to_string_lossy());
        let uninstall =
            registry.child("Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\fixture");
        for (name, value) in [
            ("DisplayName", "Obscure Chat"),
            ("Publisher", "Fixture Vendor"),
            ("DisplayVersion", "fixture-1"),
        ] {
            set(&uninstall, name, value);
        }
        set(
            &uninstall,
            "InstallLocation",
            &fixture.path().to_string_lossy(),
        );
        set(
            &uninstall,
            "DisplayIcon",
            &format!("\"{}\",0", exe.display()),
        );
        for name in [
            "UninstallString",
            "QuietUninstallString",
            "ModifyPath",
            "InstallSource",
            "arbitrary-value",
        ] {
            // A forbidden binary value would fail the string parser if it were queried.
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        uninstall.0,
                        wide(name).as_ptr(),
                        0,
                        REG_BINARY,
                        [0xffu8, 0x00].as_ptr(),
                        2,
                    )
                },
                ERROR_SUCCESS
            );
        }
        let a = registry_metadata(
            registry.key,
            IdentitySource::AppPaths,
            "ObscureChat.exe",
            KEY_WOW64_64KEY,
        )
        .unwrap();
        let u = registry_metadata(
            registry.key,
            IdentitySource::Uninstall,
            "fixture",
            KEY_WOW64_64KEY,
        )
        .unwrap();
        assert_eq!(a.executable.as_ref(), Some(&exe));
        assert_eq!(u.executable.as_ref(), Some(&exe));
        assert_eq!(u.display_name.as_deref(), Some("Obscure Chat"));
        assert_eq!(u.publisher.as_deref(), Some("Fixture Vendor"));
        assert_eq!(u.display_version.as_deref(), Some("fixture-1"));
        let snapshot = Win32Snapshot::from_registrations(vec![a, u]);
        assert_eq!(snapshot.applications.len(), 1);
        assert_eq!(
            snapshot.applications[0].identity().state,
            ApplicationIdentity::Corroborated
        );
    }
    #[test]
    fn local_shortcut_resolves_target_without_consuming_arguments() {
        use windows::{
            core::{Interface, PCWSTR},
            Win32::{
                System::Com::{
                    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile,
                    CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
                },
                UI::Shell::{IShellLinkW, ShellLink},
            },
        };
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .unwrap();
        struct Apartment;
        impl Drop for Apartment {
            fn drop(&mut self) {
                unsafe {
                    CoUninitialize();
                }
            }
        }
        let _apartment = Apartment;
        let fixture = FixtureFolders::create().unwrap();
        let exe = fixture.path().join("Portable.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        let link: IShellLinkW =
            unsafe { CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER) }.unwrap();
        unsafe {
            link.SetPath(PCWSTR(wide(&exe).as_ptr())).unwrap();
            link.SetArguments(PCWSTR(wide("--ignored-fixture-argument").as_ptr()))
                .unwrap();
        }
        let persist: IPersistFile = link.cast().unwrap();
        let path = fixture.path().join("Portable.lnk");
        unsafe { persist.Save(PCWSTR(wide(&path).as_ptr()), true) }.unwrap();
        let target = shortcut(&path).unwrap();
        assert_eq!(
            ExecutableBinding::capture(&target).unwrap().physical,
            ExecutableBinding::capture(&exe).unwrap().physical
        );
    }
}
