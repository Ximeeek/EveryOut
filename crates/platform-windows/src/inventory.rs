//! Current-user inventory with a fixed nonsensitive Win32 metadata allowlist.
use crate::{native, AllowedRoot};
use std::{collections::BTreeMap, path::PathBuf, ptr};
use windows::{core::HSTRING, Management::Deployment::PackageManager};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
    System::Registry::*,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventorySource {
    Uninstall,
    AppPaths,
    StartMenu,
    Package,
}
#[derive(Debug, Clone)]
pub struct Registration {
    /// Registry key name, shortcut filename or OS package name; not a display-name assertion.
    pub name: String,
    pub source: InventorySource,
    pub provenance: Vec<String>,
    /// Only package API metadata can supply these while the registry exception is open.
    pub publisher: Option<String>,
    pub package_family: Option<String>,
    pub installation_exists: Option<bool>,
    pub runtime_present: Option<bool>,
    /// Exact independently registered application container, not a guessed UDF mapping.
    pub exclusive_container: bool,
}
#[derive(Debug, Default, Clone)]
pub struct InstalledInventory {
    pub win32: std::rc::Rc<crate::win32_identity::Win32Snapshot>,
    pub registrations: Vec<Registration>,
    /// Stable codes only: failures are incomplete coverage, never an empty-machine claim.
    pub coverage: Vec<String>,
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: exactly one successfully opened read-only key.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
impl InstalledInventory {
    /// Production entry point. Tests must instead supply synthetic inventory records.
    pub fn collect_current_user() -> Self {
        let mut inventory = Self::default();
        inventory.registry();
        inventory.start_menu();
        inventory.packages();
        std::rc::Rc::get_mut(&mut inventory.win32)
            .expect("collecting snapshot")
            .finish();
        inventory.coverage.extend(inventory.win32.coverage.clone());
        inventory.coverage.extend(
            [
                "registry-command-and-arbitrary-values-blocked",
                "shortcut-arguments-and-working-directory-blocked",
                "browser-profile-configuration-and-custom-install-mappings-blocked",
            ]
            .map(str::to_owned),
        );
        inventory
    }
    fn registry(&mut self) {
        let mut found = BTreeMap::<(String, String, String), Registration>::new();
        for (hive, hive_label) in [(HKEY_CURRENT_USER, "hkcu"), (HKEY_LOCAL_MACHINE, "hklm")] {
            for (view, view_label) in [(KEY_WOW64_32KEY, "32"), (KEY_WOW64_64KEY, "64")] {
                for (source, kind) in [
                    ("Uninstall", InventorySource::Uninstall),
                    ("App Paths", InventorySource::AppPaths),
                ] {
                    let path = native::wide(format!(
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\{source}"
                    ));
                    let mut raw = ptr::null_mut();
                    // SAFETY: fixed inventory keys, enumeration rights only, no value queries.
                    let status = unsafe {
                        RegOpenKeyExW(
                            hive,
                            path.as_ptr(),
                            0,
                            KEY_ENUMERATE_SUB_KEYS | view,
                            &mut raw,
                        )
                    };
                    let label = format!("{hive_label}-{view_label}-{source}");
                    if status != ERROR_SUCCESS {
                        if status != ERROR_FILE_NOT_FOUND {
                            self.coverage.push(format!("{label}-unavailable"));
                        }
                        continue;
                    }
                    let key = Key(raw);
                    let mut complete = false;
                    for index in 0..10_000 {
                        let mut name = [0u16; 256];
                        let mut len = name.len() as u32;
                        // SAFETY: bounded writable name buffer; no values or data buffers requested.
                        let status = unsafe {
                            RegEnumKeyExW(
                                key.0,
                                index,
                                name.as_mut_ptr(),
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
                        let Ok(name) = String::from_utf16(&name[..len as usize]) else {
                            break;
                        };
                        let identity_source = if kind == InventorySource::AppPaths {
                            crate::win32_identity::IdentitySource::AppPaths
                        } else {
                            crate::win32_identity::IdentitySource::Uninstall
                        };
                        match crate::win32_identity::registry_metadata(
                            hive,
                            identity_source,
                            &name,
                            view,
                        ) {
                            Ok(record) => std::rc::Rc::get_mut(&mut self.win32)
                                .expect("collecting snapshot")
                                .registrations
                                .push(record),
                            Err(_) => self.coverage.push(format!("{label}-metadata-unavailable")),
                        }
                        let item = found
                            .entry((hive_label.into(), source.into(), name.to_lowercase()))
                            .or_insert(Registration {
                                name,
                                source: kind,
                                provenance: vec![],
                                publisher: None,
                                package_family: None,
                                installation_exists: None,
                                runtime_present: None,
                                exclusive_container: false,
                            });
                        item.provenance.push(label.clone());
                    }
                    if !complete {
                        self.coverage.push(format!("{label}-incomplete"));
                    }
                }
            }
        }
        self.registrations.extend(found.into_values());
    }
    fn start_menu(&mut self) {
        let (records, coverage) = crate::win32_identity::shortcuts();
        self.coverage.extend(coverage);
        for record in records {
            self.registrations.push(Registration {
                name: record.name.clone(),
                source: InventorySource::StartMenu,
                provenance: vec!["local-start-menu-target".into()],
                publisher: None,
                package_family: None,
                installation_exists: None,
                runtime_present: None,
                exclusive_container: false,
            });
            std::rc::Rc::get_mut(&mut self.win32)
                .expect("collecting snapshot")
                .registrations
                .push(record);
        }
    }
    fn packages(&mut self) {
        use windows::Win32::System::WinRT::{RoInitialize, RoUninitialize, RO_INIT_MULTITHREADED};
        // SAFETY: balance successful thread initialization; never change an existing apartment.
        let initialized = unsafe { RoInitialize(RO_INIT_MULTITHREADED) };
        struct Apartment(bool);
        impl Drop for Apartment {
            fn drop(&mut self) {
                if self.0 {
                    unsafe {
                        RoUninitialize();
                    }
                }
            }
        }
        let _apartment = Apartment(initialized.is_ok());
        // RPC_E_CHANGED_MODE means this thread is already initialized in a different apartment.
        if initialized
            .as_ref()
            .is_err_and(|e| e.code().0 != 0x80010106u32 as i32)
        {
            self.coverage.push("package-apartment-unavailable".into());
            return;
        }
        let packages =
            PackageManager::new().and_then(|m| m.FindPackagesByUserSecurityId(&HSTRING::new()));
        let Ok(packages) = packages else {
            self.coverage.push("package-inventory-unavailable".into());
            return;
        };
        let mut found = BTreeMap::new();
        let Ok(iterator) = packages.First() else {
            self.coverage.push("package-iterator-unavailable".into());
            return;
        };
        let mut index = 0;
        loop {
            match iterator.HasCurrent() {
                Ok(false) => break,
                Ok(true) => (),
                Err(_) => {
                    self.coverage.push("package-enumeration-incomplete".into());
                    break;
                }
            }
            if index >= 10_000 {
                self.coverage.push("package-limit".into());
                break;
            }
            index += 1;
            let Ok(package) = iterator.Current() else {
                self.coverage.push("package-enumeration-incomplete".into());
                break;
            };
            if iterator.MoveNext().is_err() {
                self.coverage.push("package-enumeration-incomplete".into());
                break;
            }
            match (package.IsFramework(), package.IsResourcePackage()) {
                (Ok(false), Ok(false)) => (),
                (Ok(_), Ok(_)) => continue,
                _ => {
                    self.coverage.push("package-kind-unknown".into());
                    continue;
                }
            }
            let Ok(id) = package.Id() else {
                self.coverage.push("package-identity-unknown".into());
                continue;
            };
            let Ok(family) = id.FamilyName() else {
                self.coverage.push("package-family-unknown".into());
                continue;
            };
            let family = family.to_string();
            if crate::components(&family).is_err() {
                self.coverage.push("package-family-invalid".into());
                continue;
            }
            let install = package.InstalledLocation().and_then(|folder| folder.Path());
            let root = install
                .ok()
                .map(|path| AllowedRoot::absolute(&PathBuf::from(path.to_string())));
            let (exists, runtime) = match root {
                Some(Ok(root)) => {
                    let mut runtime = Some(false);
                    for (path, directory) in
                        [("resources/app.asar", false), ("resources/app", true)]
                    {
                        match root.path(path).and_then(|path| path.probe_shallow()) {
                            Ok(m) if m.exists && m.is_directory == directory => {
                                runtime = Some(true);
                                break;
                            }
                            Ok(_) => (),
                            Err(_) => runtime = None,
                        }
                    }
                    (Some(true), runtime)
                }
                Some(Err(e)) if native::absent(&e) => (Some(false), None),
                _ => (None, None),
            };
            if exists.is_none() || runtime.is_none() {
                self.coverage
                    .push("package-install-metadata-incomplete".into());
            }
            let name = id
                .Name()
                .map(|s| s.to_string())
                .unwrap_or_else(|_| family.clone());
            let publisher = id.Publisher().ok().map(|s| s.to_string());
            if publisher.is_none() {
                self.coverage.push("package-publisher-unavailable".into());
            }
            found.insert(
                family.clone(),
                Registration {
                    name,
                    source: InventorySource::Package,
                    provenance: vec!["current-user-package-api".into()],
                    publisher,
                    package_family: Some(family),
                    installation_exists: exists,
                    runtime_present: runtime,
                    exclusive_container: true,
                },
            );
        }
        self.registrations.extend(found.into_values());
        self.coverage.sort();
        self.coverage.dedup();
    }
}
