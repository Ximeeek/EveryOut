use everyout_heuristic_scan::{Candidate, candidate, excluded, installation_state, safe_path};
use serde::Serialize;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    ptr,
};
use windows::{Management::Deployment::PackageManager, core::HSTRING};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
    System::Registry::*,
};

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
#[derive(Serialize)]
pub struct Registration {
    id: String,
    sources: Vec<String>,
    state: &'static str,
}
#[derive(Serialize)]
pub struct Report {
    schema_version: u32,
    registrations: Vec<Registration>,
    candidates: Vec<Candidate>,
    coverage: Vec<String>,
}
fn registry() -> (Vec<Registration>, Vec<String>) {
    let mut found: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut coverage = Vec::new();
    for (hive, hive_label) in [(HKEY_CURRENT_USER, "hkcu"), (HKEY_LOCAL_MACHINE, "hklm")] {
        for (view, view_label) in [(KEY_WOW64_32KEY, "32"), (KEY_WOW64_64KEY, "64")] {
            for source in ["Uninstall", "App Paths"] {
                let path: Vec<u16> =
                    format!("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\{source}")
                        .encode_utf16()
                        .chain([0])
                        .collect();
                let mut raw = ptr::null_mut();
                // SAFETY: terminated constant key path, read/enumeration access only.
                let status = unsafe {
                    RegOpenKeyExW(
                        hive,
                        path.as_ptr(),
                        0,
                        KEY_ENUMERATE_SUB_KEYS | view,
                        &mut raw,
                    )
                };
                let label = format!("{hive_label}/{view_label}/{source}");
                if status != ERROR_SUCCESS {
                    coverage.push(format!(
                        "{label}:{}",
                        if status == ERROR_FILE_NOT_FOUND {
                            "absent"
                        } else {
                            "unknown"
                        }
                    ));
                    continue;
                }
                let key = Key(raw);
                let mut complete = false;
                for index in 0..10_000 {
                    let mut buffer = [0u16; 256];
                    let mut len = buffer.len() as u32;
                    // SAFETY: valid output buffer and size; only subkey names, never values.
                    let status = unsafe {
                        RegEnumKeyExW(
                            key.0,
                            index,
                            buffer.as_mut_ptr(),
                            &mut len,
                            ptr::null_mut(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                            ptr::null_mut(),
                        )
                    };
                    if status == ERROR_NO_MORE_ITEMS {
                        complete = true;
                        break;
                    }
                    if status != ERROR_SUCCESS {
                        break;
                    }
                    let Ok(name) = String::from_utf16(&buffer[..len as usize]) else {
                        break;
                    };
                    // Deduplicate aliases across views; separate sources/hives cannot prove same install.
                    found
                        .entry(format!("{hive_label}/{source}/{}", name.to_lowercase()))
                        .or_default()
                        .push(label.clone());
                }
                coverage.push(format!(
                    "{label}:{}",
                    if complete {
                        "complete_registration_names_only"
                    } else {
                        "incomplete"
                    }
                ));
            }
        }
    }
    (
        found
            .into_values()
            .enumerate()
            .map(|(i, sources)| Registration {
                id: format!("registry-{i:04}"),
                sources,
                state: "registration_only_installation_unknown",
            })
            .collect(),
        coverage,
    )
}
fn direct_children(root: &Path) -> Result<Vec<PathBuf>, &'static str> {
    safe_path(root).map_err(|_| "unsafe root")?;
    let mut children = Vec::new();
    for item in fs::read_dir(root).map_err(|_| "root enumeration unavailable")? {
        let path = item.map_err(|_| "entry unavailable")?.path();
        if children.len() >= 10_000 {
            return Err("enumeration limit");
        }
        children.push(path);
    }
    children.sort();
    Ok(children)
}
fn layouts(
    output: &mut Vec<Candidate>,
    id: &str,
    class: &'static str,
    root: &Path,
    install: Option<&Path>,
    package: bool,
) {
    // Fixed layouts, no recursive directory discovery and no per-origin/partition names.
    for (index, relative) in [
        "",
        "User Data/Default",
        "EBWebView/Default",
        "LocalCache",
        "LocalState",
        "RoamingState",
        "LocalCache/Roaming",
        "LocalCache/Local",
    ]
    .into_iter()
    .enumerate()
    {
        let path = root.join(relative);
        if safe_path(&path).is_err() {
            let mut c = candidate(
                format!("{id}-layout-{index}"),
                class,
                index,
                &path,
                None,
                false,
            );
            c.limitations.push("unsafe layout excluded");
            output.push(c);
            continue;
        }
        if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
            continue;
        }
        output.push(candidate(
            format!("{id}-layout-{index}"),
            class,
            index,
            &path,
            install,
            package,
        ));
    }
}
pub fn scan() -> Result<Report, &'static str> {
    use windows::Win32::System::WinRT::{RO_INIT_MULTITHREADED, RoInitialize, RoUninitialize};
    // SAFETY: this standalone CLI initializes its calling thread once, balanced by Drop.
    unsafe { RoInitialize(RO_INIT_MULTITHREADED) }.map_err(|_| "WinRT initialization failed")?;
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            unsafe {
                RoUninitialize();
            }
        }
    }
    let _apartment = Apartment;
    let roaming = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .ok_or("APPDATA unavailable")?;
    let local = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("LOCALAPPDATA unavailable")?;
    let (mut registrations, mut coverage) = registry();
    let mut candidates = Vec::new();
    for (root, class) in [(&roaming, "roaming"), (&local, "local")] {
        for (i, path) in direct_children(root)?.into_iter().enumerate() {
            let name = path
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or("unsupported name")?;
            if excluded(name) {
                continue;
            }
            layouts(
                &mut candidates,
                &format!("{class}-{i:04}"),
                class,
                &path,
                None,
                false,
            );
        }
    }
    let manager = PackageManager::new().map_err(|_| "package manager unavailable")?;
    // Empty SID explicitly means calling user, never all users or administrator fallback.
    let packages = manager
        .FindPackagesByUserSecurityId(&HSTRING::new())
        .map_err(|_| "package inventory unavailable")?;
    let mut mapped = BTreeMap::new();
    for (package_index, package) in packages.into_iter().enumerate() {
        if package_index >= 10_000 {
            return Err("package limit");
        }
        if package.IsFramework().map_err(|_| "package kind unknown")?
            || package
                .IsResourcePackage()
                .map_err(|_| "package kind unknown")?
        {
            continue;
        }
        let family = package
            .Id()
            .and_then(|id| id.FamilyName())
            .map_err(|_| "package identity unknown")?
            .to_string();
        // Validate a single path component before appending OS metadata to an allowlisted root.
        if family.is_empty() || family.contains(['/', '\\', ':']) || family == "." || family == ".."
        {
            return Err("invalid package identity");
        }
        if excluded(&family) {
            continue;
        }
        let install = package
            .InstalledLocation()
            .and_then(|folder| folder.Path())
            .ok()
            .map(|path| PathBuf::from(path.to_string()));
        mapped.entry(family).or_insert(install);
    }
    for (i, (family, install)) in mapped.into_iter().enumerate() {
        let id = format!("package-{i:04}");
        registrations.push(Registration {
            id: id.clone(),
            sources: vec!["current_user_package_api".into()],
            state: installation_state(install.as_deref()),
        });
        layouts(
            &mut candidates,
            &id,
            "package",
            &local.join("Packages").join(family),
            install.as_deref(),
            true,
        );
    }
    coverage.push("fixed layouts only; no registry values, CEF rules, custom roots, partitions or browser profile mappings".into());
    coverage
        .push("opaque IDs are run-local; label using separately reviewed OS/UI metadata".into());
    Ok(Report {
        schema_version: 1,
        registrations,
        candidates,
        coverage,
    })
}
