#![cfg(windows)]
use everyout_core_model::*;
use everyout_engine::*;
use everyout_platform_windows::FixtureFolders;
use everyout_providers::executor::{ManifestExecutor, ProcessGate};
use serde_json::{json, Value};
use std::{
    cell::Cell,
    fs,
    fs::OpenOptions,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};
const CATALOG: &str = include_str!("../../../catalog/browsers/firefox.json");
const PROFILES: [&str; 3] = [
    "Profiles/a.default",
    "Additional profile",
    "Profiles/żółć.extra",
];
const PROTECTED: [&str; 15] = [
    "logins.json",
    "key4.db",
    "key3.db",
    "places.sqlite",
    "places.sqlite-wal",
    "places.sqlite-shm",
    "formhistory.sqlite",
    "autofill-profiles.json",
    "Passkeys",
    "cert9.db",
    "signedInUser.json",
    "prefs.js",
    "user.js",
    "containers.json",
    "permissions.sqlite",
];
fn synthetic() -> Value {
    let mut m: Value = serde_json::from_str(CATALOG).unwrap();
    m["support"] = json!("validated");
    for artifact in m["session_locations"].as_array_mut().unwrap() {
        artifact["confidence"] = "verified".into();
    }
    m["compatibility"]["product_versions"] = json!("synthetic-only-v1");
    m["confidence"]["version_coverage"] = json!("synthetic-only-v1");
    m["confidence"]["status"] = json!("verified");
    m["open_spikes"] = json!([]);
    m["risks"] = json!({"flags": [], "affected_data": [], "permanent_data_loss": "none", "confirmations": [], "evidence": ["quota"]});
    for method in m["cleaning_methods"].as_array_mut().unwrap() {
        method["blockers"] = json!([]);
    }
    m
}
fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn ini(root: &Path) -> String {
    format!("[General]\nStartWithLastProfile=1\n[Profile0]\nName=ignored\nDefault=1\nIsRelative=1\nPath={}\n[Profile1]\nIsRelative=1\nPath={}\n[Profile2]\nIsRelative=0\nPath={}\n[InstallABC]\nDefault={}\n",
        PROFILES[0], PROFILES[1], root.join(PROFILES[2]).display(), PROFILES[0])
}
fn seed(folders: &FixtureFolders, m: &Value, extensions: bool) -> (Vec<PathBuf>, Vec<PathBuf>) {
    let root = folders.path().join("Mozilla/Firefox");
    write(&root.join("profiles.ini"), ini(&root).as_bytes());
    let mut targets = vec![];
    let mut preserved = vec![root.join("profiles.ini")];
    for profile in PROFILES {
        let profile = root.join(profile);
        for entry in m["session_locations"].as_array().unwrap() {
            let path = profile.join(entry["relative"].as_str().unwrap());
            if entry["kind"] == "file" {
                let method = m["cleaning_methods"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|method| method["id"] == entry["method"])
                    .unwrap();
                for suffix in std::iter::once("").chain(
                    method["companions"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap()),
                ) {
                    let path = PathBuf::from(format!("{}{suffix}", path.display()));
                    write(&path, b"synthetic-session-canary");
                    targets.push(path);
                }
            } else {
                write(&path.join("canary"), b"synthetic-session-canary");
                targets.push(path);
            }
        }
        for store in [
            "storage/default/https+++site.test^userContextId=2/idb/data",
            "storage/default/https+++site.test^partitionKey=site.test/ls/data",
            "storage/temporary/https+++site.test/cache/data",
            "storage/permanent/https+++site.test/idb/data",
            "storage/ls-archive.sqlite",
            "sessionstore-backups/upgrade.jsonlz4-fixture",
        ] {
            write(&profile.join(store), b"synthetic-partition-canary");
        }
        for name in PROTECTED.into_iter().chain(["parent.lock"]) {
            let path = profile.join(name);
            write(&path, b"synthetic-preservation-canary");
            preserved.push(path);
        }
        if extensions {
            for risk in m["extensions"]["known"].as_array().unwrap() {
                let store = profile
                    .join("browser-extension-data")
                    .join(risk["id"].as_str().unwrap());
                write(&store.join("storage.js"), b"synthetic-extension-canary");
                targets.push(store);
            }
        }
    }
    write(
        &root.join("Profiles/unlisted/cookies.sqlite"),
        b"synthetic-unlisted-profile",
    );
    preserved.push(root.join("Profiles/unlisted/cookies.sqlite"));
    (targets, preserved)
}
#[derive(Default)]
struct Gate {
    closed: Cell<bool>,
    calls: Cell<usize>,
    fail: Cell<Option<ErrorKind>>,
}
impl ProcessGate for Gate {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
        Ok(vec![ProcessPreview {
            identity: "fixture-browser".into(),
            label: "synthetic-process".into(),
            unsaved_work_loss: true,
        }])
    }
    fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
        self.calls.set(self.calls.get() + 1);
        if let Some(kind) = self.fail.get() {
            return Err(kind);
        }
        self.closed.set(true);
        Ok(())
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        if self.closed.get() {
            Ok(())
        } else {
            Err(ErrorKind::Locked)
        }
    }
}
fn provider<'a>(json: &Value, folders: &'a FixtureFolders, gate: &'a Gate) -> ManifestExecutor<'a> {
    ManifestExecutor::load(
        &json.to_string(),
        folders,
        UserId("fixture-user".into()),
        InstallationId("fixture-install".into()),
        gate,
    )
    .unwrap()
}
fn prepare<'a>(engine: &Engine<'a>, provider: &'a ManifestExecutor<'a>) -> PreparedRun<'a> {
    let inventory = engine
        .scan(&[provider], Category::Browser, &mut |_| {})
        .unwrap();
    let ids = inventory.default_selection(Category::Browser);
    assert_eq!(ids.len(), 1);
    engine
        .prepare(
            inventory,
            Category::Browser,
            &ids,
            ProcessClosePolicy::Ask,
            &mut |_| {},
        )
        .unwrap()
}
fn approve(run: &PreparedRun<'_>) -> Approval {
    let mut approval = Approval::default();
    for item in &run.preview().sections[1].items {
        let plan = item.plan.as_ref().unwrap();
        approval
            .confirmed_risks
            .push(run.confirm_risks(&item.instance, &plan.risks.flags));
        approval
            .confirmations
            .extend(plan.risks.confirmations.clone());
    }
    approval
}

#[test]
fn multi_profile_wipe_dry_run_and_preserved_payloads() {
    let m = synthetic();
    let folders = FixtureFolders::create().unwrap();
    let (targets, preserved) = seed(&folders, &m, false);
    let before: Vec<_> = preserved.iter().map(|p| fs::read(p).unwrap()).collect();
    let snapshot = folders.snapshot().unwrap();
    // Deny content reads on secret/mixed files. Metadata discovery must work.
    let held: Vec<_> = preserved
        .iter()
        .filter(|p| p.file_name().unwrap() != "profiles.ini")
        .map(|p| OpenOptions::new().read(true).share_mode(2).open(p).unwrap())
        .collect();
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    assert_eq!(
        run.preview().sections[1].items[0]
            .plan
            .as_ref()
            .unwrap()
            .actions
            .iter()
            .filter_map(|a| a.profile_id.as_ref())
            .collect::<std::collections::HashSet<_>>()
            .len(),
        3
    );
    assert_eq!(folders.snapshot().unwrap(), snapshot);
    assert_eq!(gate.calls.get(), 0);
    let approval = approve(&run);
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(
        report.sections[1].aggregate,
        AggregateStatus::CompleteLocalScope
    );
    assert_eq!(gate.calls.get(), 1);
    for target in targets {
        assert!(!target.exists(), "{}", target.display());
    }
    drop(held);
    for (path, bytes) in preserved.iter().zip(before) {
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
#[test]
fn locked_cookie_companion_is_reported_without_bypass() {
    let m = synthetic();
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    let path = folders
        .path()
        .join("Mozilla/Firefox")
        .join(PROFILES[0])
        .join("cookies.sqlite-wal");
    let held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)
        .unwrap();
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert!(path.exists());
    assert!(report.sections[1].counts.locked > 0);
    assert!(report.sections[1].counts.succeeded > 0);
    assert_eq!(report.sections[1].aggregate, AggregateStatus::Partial);
    drop(held);
}
#[test]
fn known_extension_flags_and_both_confirmation_gates() {
    for approval_mode in [0, 1, 2] {
        let m = synthetic();
        let folders = FixtureFolders::create().unwrap();
        let (targets, _) = seed(&folders, &m, true);
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider);
        let risks = &run.preview().sections[1].items[0]
            .plan
            .as_ref()
            .unwrap()
            .risks;
        assert!(risks.flags.contains(&RiskFlag::WalletOrKeyMaterial));
        assert!(risks.flags.contains(&RiskFlag::VaultOr2faRecovery));
        let mut approval = approve(&run);
        if approval_mode == 0 {
            approval.confirmed_risks.clear();
        }
        if approval_mode == 1 {
            approval.confirmations.clear();
        }
        let before = folders.snapshot().unwrap();
        let report = engine.apply(run, approval, &|| false, &mut |_| {});
        if approval_mode == 2 {
            assert_eq!(
                report.sections[1].aggregate,
                AggregateStatus::CompleteLocalScope
            );
            for path in targets {
                assert!(!path.exists());
            }
        } else {
            assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
            assert_eq!(folders.snapshot().unwrap(), before);
        }
    }
}
#[test]
fn unknown_legacy_uuid_and_sync_extension_stores_block_the_scope() {
    for store in [
        "browser-extension-data/unknown@fixture.test/storage.js",
        "storage/default/moz-extension+++fixture-uuid/idb/data",
        "storage/temporary/moz-extension+++fixture-uuid^userContextId=2/idb/data",
        "storage-sync-v2.sqlite",
        "storage-sync.sqlite-wal",
    ] {
        let m = synthetic();
        let folders = FixtureFolders::create().unwrap();
        seed(&folders, &m, false);
        write(
            &folders
                .path()
                .join("Mozilla/Firefox")
                .join(PROFILES[0])
                .join(store),
            b"synthetic-opaque-canary",
        );
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider);
        let approval = approve(&run);
        let before = folders.snapshot().unwrap();
        let report = engine.apply(run, approval, &|| false, &mut |_| {});
        assert_eq!(
            report.sections[1].aggregate,
            AggregateStatus::Blocked,
            "{store}"
        );
        assert_eq!(folders.snapshot().unwrap(), before);
        assert_eq!(gate.calls.get(), 0);
    }
}
#[test]
fn changed_ini_new_extension_and_process_relaunch_invalidate_review() {
    for change in ["profile", "legacy", "uuid", "sync", "process"] {
        let m = synthetic();
        let folders = FixtureFolders::create().unwrap();
        seed(&folders, &m, false);
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider);
        let approval = approve(&run);
        let root = folders.path().join("Mozilla/Firefox");
        match change {
            "profile" => write(
                &root.join("profiles.ini"),
                format!(
                    "{}[Profile3]\nPath=Profiles/unlisted\nIsRelative=1\n",
                    ini(&root)
                )
                .as_bytes(),
            ),
            "legacy" => write(
                &root
                    .join(PROFILES[0])
                    .join("browser-extension-data/unknown@fixture/storage.js"),
                b"synthetic-new-extension",
            ),
            "uuid" => write(
                &root
                    .join(PROFILES[0])
                    .join("storage/default/moz-extension+++new/idb/data"),
                b"synthetic-new-extension",
            ),
            "sync" => write(
                &root.join(PROFILES[0]).join("storage-sync.sqlite"),
                b"synthetic-new-extension",
            ),
            _ => gate.fail.set(Some(ErrorKind::Locked)),
        }
        let before = folders.snapshot().unwrap();
        let report = engine.apply(run, approval, &|| false, &mut |_| {});
        assert_eq!(
            report.sections[1].aggregate,
            AggregateStatus::Blocked,
            "{change}"
        );
        assert_eq!(folders.snapshot().unwrap(), before);
    }
}
#[test]
fn unsafe_ini_paths_missing_roots_and_hardlinks_never_grant_authority() {
    for path in [
        "../outside",
        "Profiles/../a.default",
        "Profiles/a.default:stream",
        "Profiles/missing",
        "Profiles/a.default/../",
        "Profiles/a.default/cookies.sqlite",
        "//server/share/profile",
        "C:/outside/profile",
    ] {
        let m = synthetic();
        let folders = FixtureFolders::create().unwrap();
        seed(&folders, &m, false);
        let root = folders.path().join("Mozilla/Firefox");
        let relative = if path.contains(':') || path.starts_with('/') {
            0
        } else {
            1
        };
        write(
            &root.join("profiles.ini"),
            format!("[Profile0]\nPath={path}\nIsRelative={relative}\n").as_bytes(),
        );
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let before = folders.snapshot().unwrap();
        let inventory = provider.detect(&DetectionContext {
            snapshot_id: SnapshotId("fixture".into()),
            account_mode: AccountMode::Current,
            metadata: &provider,
        });
        assert!(inventory.instances.is_empty(), "{path}");
        assert!(!inventory.issues.is_empty());
        assert_eq!(folders.snapshot().unwrap(), before);
    }
    let m = synthetic();
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let root = folders.path().join("Mozilla/Firefox");
    fs::hard_link(root.join("profiles.ini"), root.join("linked.ini")).unwrap();
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let inventory = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("fixture".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    assert!(inventory.instances.is_empty());
    assert_eq!(inventory.issues[0].kind, ErrorKind::ScopeViolation);
}
#[test]
fn candidate_and_mislabeled_preservation_targets_cannot_execute() {
    for protected in std::iter::once(None).chain(PROTECTED.into_iter().map(Some)) {
        let mut m = if protected.is_none() {
            serde_json::from_str(CATALOG).unwrap()
        } else {
            synthetic()
        };
        if let Some(path) = protected {
            m["session_locations"][0]["relative"] = json!(path);
        }
        let folders = FixtureFolders::create().unwrap();
        seed(&folders, &m, false);
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider);
        let approval = approve(&run);
        let before = folders.snapshot().unwrap();
        let report = engine.apply(run, approval, &|| false, &mut |_| {});
        assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
        assert_eq!(folders.snapshot().unwrap(), before);
        assert_eq!(gate.calls.get(), 0);
    }
}

#[test]
fn physical_profile_aliases_deduplicate_and_overlapping_roots_block() {
    let m = synthetic();
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let root = folders.path().join("Mozilla/Firefox");
    write(
        &root.join("profiles.ini"),
        format!(
            "{}[Profile3]\nPath=profiles/A.DEFAULT\nIsRelative=1\n",
            ini(&root)
        )
        .as_bytes(),
    );
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let inventory = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("aliases".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    assert_eq!(inventory.instances[0].profiles.len(), 3);
    write(
        &root.join("profiles.ini"),
        format!(
            "{}[Profile3]\nPath={}/storage\nIsRelative=1\n",
            ini(&root),
            PROFILES[0]
        )
        .as_bytes(),
    );
    let inventory = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("overlap".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    assert!(inventory.instances.is_empty());
    assert_eq!(inventory.issues[0].kind, ErrorKind::OwnershipConflict);
}
#[test]
fn absent_or_locked_ini_never_falls_back_to_directory_patterns() {
    let m = synthetic();
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let path = folders.path().join("Mozilla/Firefox/profiles.ini");
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let held = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let inventory = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("locked-ini".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    assert!(inventory.instances.is_empty());
    assert_eq!(inventory.issues[0].kind, ErrorKind::Locked);
    drop(held);
    fs::remove_file(&path).unwrap();
    let before = folders.snapshot().unwrap();
    let inventory = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("missing-ini".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    assert!(inventory.instances.is_empty());
    assert_eq!(folders.snapshot().unwrap(), before);
}
