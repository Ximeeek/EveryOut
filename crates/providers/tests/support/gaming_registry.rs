use everyout_platform_windows::{RegistryRoot, RegistryTarget};
use std::{
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{Foundation::ERROR_SUCCESS, System::Registry::*};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

/// A unique volatile fixture namespace; no vendor key can be supplied.
pub struct RegistryFixture {
    key: HKEY,
    path: String,
}
impl RegistryFixture {
    pub fn new(names: &[&str]) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!(
            "Software\\EveryOutTest\\gaming-{}-{stamp}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut key = ptr::null_mut();
        let mut disposition = 0;
        // SAFETY: uniquely generated volatile namespace, never an existing vendor root.
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
                    &mut disposition,
                )
            },
            ERROR_SUCCESS
        );
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        for name in names {
            let opaque = b"invented-fixture-bytes";
            // SAFETY: only synthetic values in the newly owned test key; no reads.
            assert_eq!(
                unsafe {
                    RegSetValueExW(
                        key,
                        wide(name).as_ptr(),
                        0,
                        REG_BINARY,
                        opaque.as_ptr(),
                        opaque.len() as u32,
                    )
                },
                ERROR_SUCCESS
            );
        }
        Self { key, path }
    }
    pub fn bind(&self, names: &[&str]) -> RegistryRoot {
        RegistryRoot::from_manifest(
            &self.path,
            &names
                .iter()
                .map(|s| RegistryTarget::Value((*s).into()))
                .collect::<Vec<_>>(),
        )
        .unwrap()
    }
}
impl Drop for RegistryFixture {
    fn drop(&mut self) {
        // SAFETY: remove only our generated namespace after releasing bound capabilities.
        unsafe {
            assert_eq!(RegDeleteTreeW(self.key, ptr::null()), ERROR_SUCCESS);
            RegCloseKey(self.key);
            assert_eq!(
                RegDeleteKeyExW(
                    HKEY_CURRENT_USER,
                    wide(&self.path).as_ptr(),
                    KEY_WOW64_64KEY,
                    0
                ),
                ERROR_SUCCESS
            );
        }
    }
}
