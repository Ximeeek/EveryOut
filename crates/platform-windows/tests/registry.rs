#![cfg(windows)]
use everyout_core_model::{ActionStatus, ErrorKind};
use everyout_platform_windows::{RegistryRoot, RegistryTarget};
use std::{
    ptr,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{Foundation::ERROR_SUCCESS, System::Registry::*};
use windows_sys::{
    Wdk::System::Registry::{KeyNameInformation, NtDeleteKey, NtQueryKey},
    Win32::Foundation::RtlNtStatusToDosError,
};

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
struct Fixture {
    path: String,
    key: HKEY,
}
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = format!(
            "Software\\SessionWipeTest\\everyout-{}-{unique}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        );
        let mut key = ptr::null_mut();
        // SAFETY: create only a unique synthetic namespace; never replace a test key.
        let status = unsafe {
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
        };
        assert_eq!(status, ERROR_SUCCESS);
        Self { path, key }
    }
    fn create(&self, relative: &str) -> HKEY {
        let mut key = ptr::null_mut();
        // SAFETY: fixed synthetic child relative to the owned test key.
        assert_eq!(
            unsafe {
                RegCreateKeyExW(
                    self.key,
                    wide(relative).as_ptr(),
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
        key
    }
    fn seed(&self, relative: &str, name: &str) {
        let key = self.create(relative);
        let payload = b"synthetic opaque value";
        // SAFETY: write only invented bytes to the test key; no value data is read.
        assert_eq!(
            unsafe {
                RegSetValueExW(
                    key,
                    wide(name).as_ptr(),
                    0,
                    REG_BINARY,
                    payload.as_ptr(),
                    payload.len() as u32,
                )
            },
            ERROR_SUCCESS
        );
        // SAFETY: release the harness-owned child handle.
        unsafe {
            RegCloseKey(key);
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // SAFETY: cleanup is confined to the uniquely created namespace, not the
        // shared SessionWipeTest parent or any preexisting user's keys.
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

#[test]
fn exact_allowlist_presence_dry_run_and_key_value_deletion() {
    let fixture = Fixture::new();
    fixture.seed("session\\nested", "token");
    fixture.seed("preserved", "canary");
    fixture.seed("", "direct");
    let root = RegistryRoot::from_manifest(
        &fixture.path,
        &[
            RegistryTarget::Key("session".into()),
            RegistryTarget::Key("missing".into()),
            RegistryTarget::Value("session\\nested\\token".into()),
            RegistryTarget::Value("direct".into()),
            RegistryTarget::Value("missing\\token".into()),
        ],
    )
    .unwrap();
    assert!(root.key_exists("session").unwrap());
    assert!(!root.key_exists("missing").unwrap());
    assert!(root.value_exists("session\\nested\\token").unwrap());
    assert!(!root.value_exists("missing\\token").unwrap());
    assert_eq!(
        root.key_exists("preserved").unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert!(root.delete_key_tree("session-other", false).is_err());
    assert!(root.delete_value("..\\direct", false).is_err());
    assert!(RegistryRoot::from_manifest("SYSTEM\\x", &[]).is_err());
    assert!(RegistryRoot::from_manifest("Software", &[]).is_err());
    assert_eq!(
        root.delete_value("session\\nested\\token", true)
            .unwrap()
            .status,
        ActionStatus::WouldApply
    );
    assert!(root.value_exists("session\\nested\\token").unwrap());
    assert_eq!(
        root.delete_key_tree("session", true).unwrap().status,
        ActionStatus::WouldApply
    );
    assert!(root.key_exists("session").unwrap());
    assert_eq!(
        root.delete_value("session\\nested\\token", false)
            .unwrap()
            .status,
        ActionStatus::Applied
    );
    assert!(!root.value_exists("session\\nested\\token").unwrap());
    assert_eq!(
        root.delete_value("session\\nested\\token", false)
            .unwrap()
            .status,
        ActionStatus::AlreadyAbsent
    );
    assert_eq!(
        root.delete_value("direct", false).unwrap().status,
        ActionStatus::Applied
    );
    assert_eq!(
        root.delete_key_tree("session", false).unwrap().status,
        ActionStatus::Applied
    );
    assert!(!root.key_exists("session").unwrap());
    assert_eq!(
        root.delete_key_tree("session", false).unwrap().status,
        ActionStatus::AlreadyAbsent
    );
    let preserved = RegistryRoot::from_manifest(
        &fixture.path,
        &[RegistryTarget::Value("preserved\\canary".into())],
    )
    .unwrap();
    assert!(preserved.value_exists("preserved\\canary").unwrap());
}

#[test]
fn link_typed_values_are_refused_without_reading_their_data() {
    let fixture = Fixture::new();
    let key = fixture.create("redirected");
    let payload: Vec<u16> = "\\Registry\\User\\nonexistent-synthetic-fixture"
        .encode_utf16()
        .collect();
    // SAFETY: this fixture-only REG_LINK payload is invented, not a user's registry
    // path. The adapter must reject its type without inspecting these bytes.
    assert_eq!(
        unsafe {
            RegSetValueExW(
                key,
                wide("SymbolicLinkValue").as_ptr(),
                0,
                REG_LINK,
                payload.as_ptr().cast(),
                (payload.len() * 2) as u32,
            )
        },
        ERROR_SUCCESS
    );
    unsafe {
        RegCloseKey(key);
    }
    let root =
        RegistryRoot::from_manifest(&fixture.path, &[RegistryTarget::Key("redirected".into())])
            .unwrap();
    assert_eq!(
        root.key_exists("redirected").unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        root.delete_key_tree("redirected", true).unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        root.delete_key_tree("redirected", false).unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
}

#[test]
fn actual_registry_link_never_reaches_the_preserved_test_key() {
    let fixture = Fixture::new();
    fixture.seed("preserved", "canary");
    // Read key-name metadata only to address the synthetic sibling key. No registry
    // value payload, SID buffer or user profile is read or retained in diagnostics.
    let mut name_buffer = vec![0u64; 1024];
    let mut used = 0;
    let status = unsafe {
        NtQueryKey(
            fixture.key,
            KeyNameInformation,
            name_buffer.as_mut_ptr().cast(),
            (name_buffer.len() * 8) as u32,
            &mut used,
        )
    };
    assert!(status >= 0, "key-name metadata query failed");
    let bytes =
        unsafe { std::slice::from_raw_parts(name_buffer.as_ptr().cast::<u8>(), used as usize) };
    let length = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
    assert!(length.is_multiple_of(2) && length + 4 <= bytes.len());
    let mut target: Vec<u16> = bytes[4..4 + length]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u16::from_ne_bytes(*b))
        .collect();
    target.extend("\\preserved".encode_utf16());
    let mut link = ptr::null_mut();
    assert_eq!(
        unsafe {
            RegCreateKeyExW(
                fixture.key,
                wide("redirected").as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_VOLATILE | REG_OPTION_CREATE_LINK,
                KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                ptr::null(),
                &mut link,
                ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
    struct Link(HKEY);
    impl Drop for Link {
        fn drop(&mut self) {
            // Remove the source link object before fixture teardown, never its target.
            let status = unsafe { NtDeleteKey(self.0) };
            unsafe {
                RegCloseKey(self.0);
            }
            assert!(status >= 0, "test link cleanup failed: {}", unsafe {
                RtlNtStatusToDosError(status)
            });
        }
    }
    let _link = Link(link);
    assert_eq!(
        unsafe {
            RegSetValueExW(
                link,
                wide("SymbolicLinkValue").as_ptr(),
                0,
                REG_LINK,
                target.as_ptr().cast(),
                (target.len() * 2) as u32,
            )
        },
        ERROR_SUCCESS
    );
    let root = RegistryRoot::from_manifest(
        &fixture.path,
        &[
            RegistryTarget::Key("redirected".into()),
            RegistryTarget::Key("redirected\\nested".into()),
            RegistryTarget::Value("preserved\\canary".into()),
        ],
    )
    .unwrap();
    assert_eq!(
        root.key_exists("redirected").unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        root.key_exists("redirected\\nested").unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        root.delete_key_tree("redirected", false).unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert!(root.value_exists("preserved\\canary").unwrap());
}
