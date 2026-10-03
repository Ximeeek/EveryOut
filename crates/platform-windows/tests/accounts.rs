//! Synthetic registry/profile records only. Never enumerate or mount host profiles.
use everyout_core_model::ErrorKind;
use everyout_platform_windows::{accounts::*, KnownFolder, PlatformError};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    path::PathBuf,
};
type Result<T> = std::result::Result<T, PlatformError>;
const SID: &str = "S-1-5-21-11-22-33-1001";
const OTHER: &str = "S-1-5-21-11-22-33-1002";
fn record(sid: &str, path: &str) -> ProfileRecord {
    ProfileRecord {
        sid: sid.into(),
        path: PathBuf::from(path),
        local_user: true,
        special: false,
        temporary: false,
        logged_on: false,
        hive_mounted: false,
    }
}
struct Source {
    records: Vec<ProfileRecord>,
    folders: BTreeMap<(String, u8), String>,
}
impl ProfileSource for Source {
    fn records(&self) -> Result<Vec<ProfileRecord>> {
        Ok(self.records.clone())
    }
    fn folder(&self, hive: &str, folder: KnownFolder) -> Result<Option<String>> {
        Ok(self.folders.get(&(hive.into(), folder as u8)).cloned())
    }
}
fn source() -> Source {
    Source {
        records: vec![
            record(SID, r"C:\Fixtures\alpha"),
            record(OTHER, r"D:\Fixtures\beta"),
        ],
        folders: BTreeMap::new(),
    }
}
#[test]
fn excludes_system_service_temporary_stale_nonlocal_and_redirected_profiles() {
    let mut source = source();
    for (sid, path) in [
        ("S-1-5-18", r"C:\Windows\systemprofile"),
        ("S-1-5-19", r"C:\Windows\LocalService"),
        ("S-1-5-20", r"C:\Windows\NetworkService"),
        ("S-1-5-21-11-22-33-1003.bak", r"C:\Fixtures\backup"),
        ("S-1-5-21-11-22-33-1004", r"C:\Users\TEMP.test"),
        ("S-1-5-21-11-22-33-1005", r"\\server\profile"),
    ] {
        source.records.push(record(sid, path));
    }
    let mut special = record("S-1-5-21-11-22-33-1006", r"C:\Fixtures\special");
    special.special = true;
    source.records.push(special);
    let mut temp = record("S-1-5-21-11-22-33-1007", r"C:\Fixtures\transient");
    temp.temporary = true;
    source.records.push(temp);
    let mut domain = record("S-1-5-21-11-22-33-1008", r"C:\Fixtures\domain");
    domain.local_user = false;
    source.records.push(domain);
    assert_eq!(enumerate(&source).unwrap().len(), 2);
    source.records[1].logged_on = true;
    source.records[1].hive_mounted = true;
    assert!(enumerate(&source).unwrap()[1].logged_on());
}
#[test]
fn resolves_each_sid_without_ambient_environment_and_refuses_escape() {
    let mut source = source();
    let profiles = enumerate(&source).unwrap();
    for p in &profiles {
        assert_eq!(
            resolve_path(&source, p, p.sid(), KnownFolder::UserProfile).unwrap(),
            p.profile_path()
        );
        let expected = format!("{}\\AppData\\Roaming", p.profile_path().display());
        assert_eq!(
            resolve_path(&source, p, p.sid(), KnownFolder::RoamingAppData).unwrap(),
            PathBuf::from(expected)
        );
    }
    source.folders.insert(
        (SID.into(), KnownFolder::LocalAppData as u8),
        r"%userprofile%\Custom\Local".into(),
    );
    assert_eq!(
        resolve_path(&source, &profiles[0], SID, KnownFolder::LocalAppData).unwrap(),
        PathBuf::from(r"C:\Fixtures\alpha\Custom\Local")
    );
    for invalid in [
        r"%TEMP%\cache",
        r"%USERPROFILE%\..\beta",
        r"D:\Fixtures\beta\AppData",
        r"\\server\cache",
    ] {
        source.folders.insert(
            (SID.into(), KnownFolder::LocalAppData as u8),
            invalid.into(),
        );
        assert!(resolve_path(&source, &profiles[0], SID, KnownFolder::LocalAppData).is_err());
    }
}
#[test]
fn ambiguous_profile_ownership_and_changed_state_invalidate_capabilities() {
    let mut source = source();
    let profile = enumerate(&source).unwrap().remove(0);
    source.records[0].logged_on = true;
    assert!(profile.revalidate(&source).is_err());
    source.records.push(source.records[0].clone());
    assert!(enumerate(&source).is_err());
}
struct Hives {
    mounted: Cell<bool>,
    logged: Cell<bool>,
    temp: RefCell<Option<String>>,
    loads: Cell<usize>,
    unloads: Cell<usize>,
    failures: Cell<usize>,
    load_failure: Cell<bool>,
    race: Cell<bool>,
}
impl Hives {
    fn new() -> Self {
        Self {
            mounted: Cell::new(false),
            logged: Cell::new(false),
            temp: RefCell::new(None),
            loads: Cell::new(0),
            unloads: Cell::new(0),
            failures: Cell::new(0),
            load_failure: Cell::new(false),
            race: Cell::new(false),
        }
    }
}
impl HiveApi for Hives {
    fn mounted(&self, key: &str) -> Result<bool> {
        Ok(if key == SID {
            self.mounted.get()
        } else {
            self.temp.borrow().as_deref() == Some(key)
        })
    }
    fn logged_on(&self, _sid: &str) -> Result<bool> {
        Ok(self.logged.get())
    }
    fn load(&self, _p: &AccountProfile, key: &str) -> Result<()> {
        if self.load_failure.get() {
            return Err(PlatformError {
                kind: ErrorKind::AccessDenied,
                os_code: Some(5),
                applied: 0,
            });
        }
        self.loads.set(self.loads.get() + 1);
        self.temp.replace(Some(key.into()));
        if self.race.get() {
            self.logged.set(true);
        }
        Ok(())
    }
    fn unload(&self, key: &str) -> Result<()> {
        assert!(key.starts_with("EveryOut-"));
        assert_ne!(key, SID);
        self.unloads.set(self.unloads.get() + 1);
        if self.failures.get() > 0 {
            self.failures.set(self.failures.get() - 1);
            return Err(PlatformError {
                kind: ErrorKind::Locked,
                os_code: Some(170),
                applied: 0,
            });
        }
        self.temp.take();
        Ok(())
    }
}
fn profile() -> AccountProfile {
    enumerate(&source()).unwrap().remove(0)
}
#[test]
fn successful_load_always_unloads_on_success_error_panic_and_logon_race() {
    for case in 0..4 {
        let api = Hives::new();
        if case == 3 {
            api.race.set(true);
        }
        let result = with_hive(&api, &profile(), &"a".repeat(64), |key| {
            assert!(key.starts_with("EveryOut-"));
            match case {
                1 => Err(PlatformError {
                    kind: ErrorKind::Io,
                    os_code: None,
                    applied: 0,
                }),
                2 => panic!("synthetic callback failure"),
                _ => Ok(()),
            }
        });
        assert_eq!(api.loads.get(), 1);
        assert_eq!(api.unloads.get(), 1);
        assert!(!result.cleanup.residual);
        assert!(api.temp.borrow().is_none());
        assert_eq!(result.operation.is_ok(), case == 0);
    }
}
#[test]
fn unload_retries_preserve_operation_error_and_report_residual_mount() {
    for failures in [2, 3] {
        let api = Hives::new();
        api.failures.set(failures);
        let result: HiveResult<()> = with_hive(&api, &profile(), &"b".repeat(64), |_| {
            Err(PlatformError {
                kind: ErrorKind::Io,
                os_code: Some(123),
                applied: 0,
            })
        });
        assert_eq!(result.operation.unwrap_err().os_code, Some(123));
        assert_eq!(result.cleanup.unload_attempts, 3);
        assert_eq!(result.cleanup.residual, failures == 3);
        assert_eq!(result.cleanup.error.is_some(), failures == 3);
        assert!(result
            .cleanup
            .temporary_key
            .unwrap()
            .starts_with("EveryOut-"));
    }
}
#[test]
fn live_hive_is_borrowed_and_never_loaded_or_unloaded() {
    let api = Hives::new();
    api.mounted.set(true);
    api.logged.set(true);
    let mut source = source();
    source.records[0].logged_on = true;
    source.records[0].hive_mounted = true;
    let result = with_hive(
        &api,
        &enumerate(&source).unwrap()[0],
        &"c".repeat(64),
        |key| {
            assert_eq!(key, SID);
            Ok(())
        },
    );
    assert!(result.operation.is_ok());
    assert_eq!(api.loads.get(), 0);
    assert_eq!(api.unloads.get(), 0);
}
#[test]
fn logged_on_unmounted_changed_state_and_load_failure_never_unload() {
    for case in 0..3 {
        let api = Hives::new();
        let mut source = source();
        if case == 0 {
            api.logged.set(true);
            source.records[0].logged_on = true;
        }
        if case == 1 {
            api.mounted.set(true);
        }
        if case == 2 {
            api.load_failure.set(true);
        }
        let result = with_hive(
            &api,
            &enumerate(&source).unwrap()[0],
            &"d".repeat(64),
            |_| -> Result<()> { panic!("work must not run") },
        );
        assert!(result.operation.is_err());
        assert_eq!(api.unloads.get(), 0);
    }
}
