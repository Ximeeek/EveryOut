use everyout_providers::load_manifest;
use serde_json::{json, Value};

const EXAMPLES: [&str; 3] = [
    include_str!("../../../catalog/apps/example-electron-cef.json"),
    include_str!("../../../catalog/apps/example-webview2.json"),
    include_str!("../../../catalog/apps/example-store.json"),
];

#[test]
fn application_boundaries_reject_keys_broad_containers_and_browser_aliases() {
    for example in EXAMPLES {
        load_manifest(example).unwrap();
        for path in [
            "Local State",
            "LocalState",
            "Settings",
            "Network",
            "EBWebView",
            "LocalState/Local State",
            "LocalState/Documents",
            "Login Data",
        ] {
            let mut m: Value = serde_json::from_str(example).unwrap();
            m["session_locations"][0]["relative"] = json!(path);
            assert!(load_manifest(&m.to_string()).is_err(), "{path}");
        }
        let mut m: Value = serde_json::from_str(example).unwrap();
        m["identity"]["browser_id"] = json!("chrome");
        assert!(load_manifest(&m.to_string()).is_err());
        m["identity"]["browser_id"] = Value::Null;
        m["roots"][0]["relative"] = json!("Google/Chrome/User Data");
        assert!(load_manifest(&m.to_string()).is_err());
    }
    let mut m: Value = serde_json::from_str(EXAMPLES[2]).unwrap();
    m["identity"]["package_id"] = json!("Other.Package_abcdefghijklm");
    assert!(load_manifest(&m.to_string()).is_err());
}

#[cfg(windows)]
mod windows {
    use super::*;
    use everyout_core_model::*;
    use everyout_engine::*;
    use everyout_platform_windows::FixtureFolders;
    use everyout_providers::{application::ApplicationProvider, executor::ProcessGate};
    use std::{cell::Cell, fs, fs::OpenOptions, os::windows::fs::OpenOptionsExt, path::PathBuf};

    #[derive(Default)]
    struct Gate(Cell<usize>);
    impl ProcessGate for Gate {
        fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
            Ok(vec![])
        }
        fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
        fn revalidate(&self) -> Result<(), ErrorKind> {
            Ok(())
        }
    }
    fn manifest(example: &str) -> Value {
        let mut m: Value = serde_json::from_str(example).unwrap();
        m["support"] = json!("validated");
        for artifact in m["session_locations"].as_array_mut().unwrap() {
            artifact["confidence"] = "verified".into();
        }
        m["compatibility"]["product_versions"] = json!("synthetic-v1");
        m["confidence"]["version_coverage"] = json!("synthetic-v1");
        m["confidence"]["status"] = json!("verified");
        m["open_spikes"] = json!([]);
        m["risks"] = json!({"flags": [], "affected_data": [], "permanent_data_loss": "none", "confirmations": [], "evidence": ["fixture-evidence"]});
        for method in m["cleaning_methods"].as_array_mut().unwrap() {
            method["blockers"] = json!([]);
        }
        m
    }
    fn seed(folders: &FixtureFolders, m: &Value) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let root = folders
            .path()
            .join(m["roots"][0]["relative"].as_str().unwrap());
        let profile = if m["application"] == "webview2" {
            root.join("Default")
        } else {
            root.clone()
        };
        fs::create_dir_all(&profile).unwrap();
        let mut targets = vec![];
        for a in m["session_locations"].as_array().unwrap() {
            let path = profile.join(a["relative"].as_str().unwrap());
            if a["kind"] == "directory" {
                fs::create_dir_all(&path).unwrap();
                fs::write(
                    path.join("protected-session-placeholder"),
                    b"opaque-dpapi-placeholder",
                )
                .unwrap();
                targets.push(path);
            } else {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    let p = PathBuf::from(format!("{}{suffix}", path.display()));
                    fs::write(&p, b"opaque-dpapi-placeholder").unwrap();
                    targets.push(p);
                }
            }
        }
        let mut preserved = vec![];
        for name in [
            "Local State",
            "Login Data",
            "Preferences",
            "Settings/settings.dat",
            "LocalState/Documents/draft",
        ] {
            let p = root.join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, b"preserved-placeholder").unwrap();
            preserved.push(p);
        }
        (targets, preserved)
    }
    fn prepare<'a>(
        engine: &Engine<'a>,
        provider: &'a ApplicationProvider<'a>,
        category: Category,
    ) -> PreparedRun<'a> {
        let inventory = engine.scan(&[provider], category, &mut |_| {}).unwrap();
        let ids = inventory.default_selection(category);
        engine
            .prepare(
                inventory,
                category,
                &ids,
                ProcessClosePolicy::Ask,
                &mut |_| {},
            )
            .unwrap()
    }
    #[test]
    fn electron_webview2_store_wipes_and_dry_runs_only_touch_reviewed_fixtures() {
        for example in EXAMPLES {
            let m = manifest(example);
            let folders = FixtureFolders::create().unwrap();
            let (targets, preserved) = seed(&folders, &m);
            let gate = Gate::default();
            let provider = ApplicationProvider::load(
                &m.to_string(),
                &folders,
                UserId("fixture-user".into()),
                InstallationId("fixture-install".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture-user".into()), &provider);
            let before = folders.snapshot().unwrap();
            let run = prepare(&engine, &provider, Category::Application);
            assert!(run.preview().sections[0].counts.would_apply > 0);
            assert_eq!(before, folders.snapshot().unwrap());
            assert_eq!(gate.0.get(), 0);
            let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
            assert_eq!(
                report.sections[0].aggregate,
                AggregateStatus::CompleteLocalScope
            );
            assert!(targets.iter().all(|p| !p.exists()));
            assert!(preserved.iter().all(|p| p.exists()));
            assert_eq!(gate.0.get(), 1);
            assert!(!serde_json::to_string(&report)
                .unwrap()
                .contains("opaque-dpapi"));
        }
    }
    #[test]
    fn locked_session_is_reported_without_reading_or_copying_its_payload() {
        let m = manifest(EXAMPLES[0]);
        let folders = FixtureFolders::create().unwrap();
        let (targets, _) = seed(&folders, &m);
        let gate = Gate::default();
        let provider = ApplicationProvider::load(
            &m.to_string(),
            &folders,
            UserId("fixture-user".into()),
            InstallationId("fixture-install".into()),
            &gate,
        )
        .unwrap();
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        // Deny both read sharing and deletion: metadata inventory must still work.
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&targets[0])
            .unwrap();
        let run = prepare(&engine, &provider, Category::Application);
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        assert!(targets[0].exists());
        assert!(report.sections[0].counts.locked > 0);
        assert_eq!(report.sections[0].aggregate, AggregateStatus::Partial);
        drop(lock);
    }
    #[test]
    fn candidate_examples_cannot_execute() {
        for example in EXAMPLES {
            let m: Value = serde_json::from_str(example).unwrap();
            let folders = FixtureFolders::create().unwrap();
            seed(&folders, &m);
            let gate = Gate::default();
            let provider = ApplicationProvider::load(
                example,
                &folders,
                UserId("fixture-user".into()),
                InstallationId("fixture-install".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture-user".into()), &provider);
            let inventory = engine
                .scan(&[&provider], Category::Application, &mut |_| {})
                .unwrap();
            assert!(inventory
                .default_selection(Category::Application)
                .is_empty());
            let selected = [InstanceId(format!(
                "{}-installation",
                m["id"].as_str().unwrap()
            ))];
            let run = engine
                .prepare(
                    inventory,
                    Category::Application,
                    &selected,
                    ProcessClosePolicy::Ask,
                    &mut |_| {},
                )
                .unwrap();
            let before = folders.snapshot().unwrap();
            let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
            assert_eq!(report.sections[0].aggregate, AggregateStatus::Blocked);
            assert_eq!(before, folders.snapshot().unwrap());
            assert_eq!(gate.0.get(), 0);
        }
    }

    #[test]
    fn opaque_protected_container_can_be_deleted_when_read_sharing_is_denied() {
        let m = manifest(EXAMPLES[0]);
        let folders = FixtureFolders::create().unwrap();
        let (targets, _) = seed(&folders, &m);
        let gate = Gate::default();
        let provider = ApplicationProvider::load(
            &m.to_string(),
            &folders,
            UserId("fixture-user".into()),
            InstallationId("fixture-install".into()),
            &gate,
        )
        .unwrap();
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(4)
            .open(&targets[0])
            .unwrap();
        assert!(fs::read(&targets[0]).is_err());
        let run = prepare(&engine, &provider, Category::Application);
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        // Windows retains a delete-pending file until the fixture handle closes.
        assert!(report.sections[0].counts.succeeded > 0);
        drop(lock);
        assert!(!targets[0].exists());
    }

    #[test]
    fn pwa_origin_storage_executes_and_reports_only_in_the_browser_profile() {
        let mut m = manifest(EXAMPLES[0]);
        m["application"] = Value::Null;
        m["category"] = json!("browser");
        m["identity"] =
            json!({"browser_id": "example-electron-cef", "process_names": ["fixture.exe"]});
        m["profiles"] = json!({"root": "user-data", "directory_patterns": ["Default"]});
        for a in m["session_locations"].as_array_mut().unwrap() {
            a["scope"] = json!("profile");
            a["ownership"] = json!("browser-profile");
        }
        let folders = FixtureFolders::create().unwrap();
        let root = folders.path().join("EveryOutFixtureElectron");
        fs::create_dir_all(root.join("Default/Local Storage")).unwrap();
        fs::write(
            root.join("Default/Local Storage/pwa-origin"),
            b"opaque-pwa-session",
        )
        .unwrap();
        let gate = Gate::default();
        let provider = ApplicationProvider::load(
            &m.to_string(),
            &folders,
            UserId("fixture-user".into()),
            InstallationId("fixture-browser".into()),
            &gate,
        )
        .unwrap();
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider, Category::Browser);
        assert!(run.preview().sections[0].items.is_empty());
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        assert!(report.sections[0].items.is_empty());
        assert_eq!(
            report.sections[1].aggregate,
            AggregateStatus::CompleteLocalScope
        );
        assert!(!root.join("Default/Local Storage").exists());
    }
}
