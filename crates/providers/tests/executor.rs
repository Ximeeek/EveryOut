#![cfg(windows)]
use everyout_core_model::*;
use everyout_engine::*;
use everyout_platform_windows::FixtureFolders;
use everyout_providers::{
    executor::{ManifestExecutor, ProcessGate},
    load_manifest,
};
use serde_json::{json, Value};
use std::{cell::Cell, fs, fs::OpenOptions, os::windows::fs::OpenOptionsExt, path::Path};

const CATALOGS: [&str; 5] = [
    include_str!("../../../catalog/browsers/chrome.json"),
    include_str!("../../../catalog/browsers/edge.json"),
    include_str!("../../../catalog/browsers/brave.json"),
    include_str!("../../../catalog/browsers/opera.json"),
    include_str!("../../../catalog/browsers/vivaldi.json"),
];
const PROTECTED: [&str; 11] = [
    "Login Data",
    "Login Data For Account",
    "Web Data",
    "Account Web Data",
    "History",
    "Archived History",
    "Visited Links",
    "Preferences",
    "Secure Preferences",
    "AccountPreferences",
    "Passkeys",
];
const WALLET: &str = "nkbihfbeogaeaoehlefnkodbefgpgknn";
const VAULT: &str = "nngceckbapebfimnlniiiahkandclblb";

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
fn synthetic(catalog: &str) -> Value {
    let mut m: Value = serde_json::from_str(catalog).unwrap();
    m["support"] = json!("validated");
    m["compatibility"]["product_versions"] = json!("synthetic-only-v1");
    m["confidence"]["version_coverage"] = json!("synthetic-only-v1");
    m["confidence"]["status"] = json!("verified");
    m["open_spikes"] = json!([]);
    m["risks"] = json!({"flags": [], "affected_data": [], "permanent_data_loss": "none", "confirmations": [], "evidence": ["storage"]});
    for method in m["cleaning_methods"].as_array_mut().unwrap() {
        method["blockers"] = json!([]);
    }
    m
}
fn write(path: &Path, bytes: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}
fn seed(
    folders: &FixtureFolders,
    m: &Value,
    extensions: bool,
) -> (Vec<std::path::PathBuf>, Vec<std::path::PathBuf>) {
    let root = folders
        .path()
        .join(m["roots"][0]["relative"].as_str().unwrap());
    let mut profiles = vec![root.join("Default"), root.join("Profile 2")];
    if m["profiles"]["root_profile"] == true {
        profiles.push(root.clone());
    }
    let mut targets = vec![];
    let mut preserved = vec![];
    for profile in profiles {
        for entry in m["session_locations"].as_array().unwrap() {
            let path = profile.join(entry["relative"].as_str().unwrap());
            if entry["kind"] == "file" {
                for suffix in ["", "-wal", "-shm", "-journal"] {
                    let path = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
                    write(&path, b"synthetic-session-canary");
                    targets.push(path);
                }
            } else {
                write(&path.join("canary"), b"synthetic-origin-canary");
                targets.push(path);
            }
        }
        for name in PROTECTED {
            let path = profile.join(name);
            write(&path, b"synthetic-preservation-canary");
            preserved.push(path);
        }
        if extensions {
            for id in [WALLET, VAULT] {
                let path = profile.join("Local Extension Settings").join(id);
                write(&path.join("canary"), b"synthetic-extension-canary");
                targets.push(path);
            }
        }
    }
    let local_state = root.join("Local State");
    write(&local_state, b"synthetic-key-metadata");
    preserved.push(local_state);
    let ignored = root.join("Profile unexpected/Network/Cookies");
    write(&ignored, b"synthetic-preserved-unrecognized-profile");
    preserved.push(ignored);
    (targets, preserved)
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
fn five_layouts_multi_profile_dry_run_and_byte_identical_preservation() {
    for catalog in CATALOGS {
        let m = synthetic(catalog);
        let folders = FixtureFolders::create().unwrap();
        let (targets, preserved) = seed(&folders, &m, false);
        let before: Vec<_> = preserved.iter().map(|p| fs::read(p).unwrap()).collect();
        let snapshot = folders.snapshot().unwrap();
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider);
        assert_eq!(folders.snapshot().unwrap(), snapshot);
        assert_eq!(gate.calls.get(), 0);
        assert!(run.preview().sections[1].counts.would_apply > 0);
        let approval = approve(&run);
        let report = engine.apply(run, approval, &|| false, &mut |_| {});
        assert_eq!(gate.calls.get(), 1);
        assert_eq!(
            report.sections[1].aggregate,
            AggregateStatus::CompleteLocalScope
        );
        for path in targets {
            assert!(!path.exists(), "{}", path.display());
        }
        for (path, bytes) in preserved.iter().zip(before) {
            assert_eq!(fs::read(path).unwrap(), bytes);
        }
    }
}
#[test]
fn locked_sqlite_companion_is_distinct_and_retains_partial_progress() {
    let m = synthetic(CATALOGS[0]);
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    let file = folders
        .path()
        .join("Google/Chrome/User Data/Default/Network/Cookies-wal");
    let locked = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&file)
        .unwrap();
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert!(file.exists());
    assert!(report.sections[1].counts.locked > 0);
    assert!(report.sections[1].counts.succeeded > 0);
    assert_eq!(report.sections[1].aggregate, AggregateStatus::Partial);
    drop(locked);
}
#[test]
fn known_extension_loss_requires_separate_engine_confirmation() {
    let m = synthetic(CATALOGS[0]);
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, true);
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    let flags = &run.preview().sections[1].items[0]
        .plan
        .as_ref()
        .unwrap()
        .risks
        .flags;
    assert!(flags.contains(&RiskFlag::WalletOrKeyMaterial));
    assert!(flags.contains(&RiskFlag::VaultOr2faRecovery));
    let mut approval = approve(&run);
    approval.confirmed_risks.clear();
    let before = folders.snapshot().unwrap();
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
    assert_eq!(folders.snapshot().unwrap(), before);
    assert_eq!(gate.calls.get(), 0);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(
        report.sections[1].aggregate,
        AggregateStatus::CompleteLocalScope
    );
}
#[test]
fn unknown_extension_and_candidate_catalog_never_mutate() {
    for candidate in [false, true] {
        let m = if candidate {
            serde_json::from_str(CATALOGS[0]).unwrap()
        } else {
            synthetic(CATALOGS[0])
        };
        let folders = FixtureFolders::create().unwrap();
        seed(&folders, &m, false);
        if !candidate {
            write(
                &folders.path().join(
                    "Google/Chrome/User Data/Default/Local Extension Settings/unknown/canary",
                ),
                b"synthetic-unknown-extension",
            );
        }
        let gate = Gate::default();
        let provider = provider(&m, &folders, &gate);
        let engine = Engine::new(UserId("fixture-user".into()), &provider);
        let run = prepare(&engine, &provider);
        let approval = approve(&run);
        let before = folders.snapshot().unwrap();
        let report = engine.apply(run, approval, &|| false, &mut |_| {});
        assert_eq!(folders.snapshot().unwrap(), before);
        assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
        assert_eq!(gate.calls.get(), 0);
    }
}
#[test]
fn process_failure_and_stale_snapshot_block_before_deletion() {
    let m = synthetic(CATALOGS[0]);
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    let before = folders.snapshot().unwrap();
    gate.fail.set(Some(ErrorKind::Locked));
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
    assert_eq!(folders.snapshot().unwrap(), before);
    gate.fail.set(None);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    engine
        .scan(&[&provider], Category::Browser, &mut |_| {})
        .unwrap();
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(folders.snapshot().unwrap(), before);
    assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
}
#[test]
fn extension_added_after_preview_invalidates_the_review() {
    let m = synthetic(CATALOGS[0]);
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, true);
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    write(
        &folders
            .path()
            .join("Google/Chrome/User Data/Default/Local Extension Settings/new-extension/canary"),
        b"synthetic-added-extension",
    );
    let before = folders.snapshot().unwrap();
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(report.sections[1].aggregate, AggregateStatus::Blocked);
    assert_eq!(folders.snapshot().unwrap(), before);
}
#[test]
fn selected_profile_contract_verifies_and_reports_without_touching_siblings() {
    let m = synthetic(CATALOGS[0]);
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let inventory = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("selected-profile".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    let instance = &inventory.instances[0];
    let selection = Selection {
        snapshot_id: inventory.snapshot_id.clone(),
        account_mode: AccountMode::Current,
        instances: vec![instance.instance_id.clone()],
        profiles: vec![instance.profiles[0].profile_id.clone()],
    };
    let PlanResult::Ready(plan) = provider.plan(
        &PlanContext {
            inventory: &inventory,
        },
        &selection,
    ) else {
        panic!("fixture plan");
    };
    assert!(plan
        .limitations
        .iter()
        .any(|l| l.contains("identity-sync-metadata: chrome-profile-0")));
    assert!(!plan
        .limitations
        .iter()
        .any(|l| l.contains("identity-sync-metadata: chrome-profile-1")));
    let valid = ValidatedPlan::review(*plan, &[]).unwrap();
    assert_eq!(provider.identity_sync(&valid), Err(ErrorKind::Locked));
    provider.process_preview(valid.plan()).unwrap();
    provider.close(&valid, ProcessClosePolicy::Ask).unwrap();
    let result = provider.execute(
        &OperationContext {
            operations: &provider,
            cancelled: &|| false,
        },
        &valid,
        ExecutionMode::Apply,
    );
    let verification = provider.verify(
        &VerificationContext {
            plan: &valid,
            metadata: &provider,
        },
        &result,
    );
    assert!(verification
        .artifacts
        .iter()
        .all(|a| a.status == VerificationStatus::TargetAbsent));
    assert!(!folders
        .path()
        .join("Google/Chrome/User Data/Default/Network/Cookies")
        .exists());
    assert!(folders
        .path()
        .join("Google/Chrome/User Data/Profile 2/Network/Cookies")
        .exists());
    let report = provider.report(&ProviderResult {
        description: provider.describe(instance),
        execution: result,
        verification,
        aggregate: AggregateStatus::CompleteLocalScope,
    });
    assert_eq!(report.browsers[0].authentication, Uncertainty::Unknown);
    assert_eq!(
        report.browsers[0].remote_revocation,
        Uncertainty::Unsupported
    );
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("synthetic-session-canary"));
}
#[test]
fn preservation_conflict_cannot_be_authorized_by_confirmation() {
    let mut m = synthetic(CATALOGS[0]);
    m["session_locations"][0]["relative"] = json!("Login Data");
    // Deliberately mislabeled family: the executor's browser path boundary wins.
    let folders = FixtureFolders::create().unwrap();
    seed(&folders, &m, false);
    load_manifest(&m.to_string()).unwrap();
    let gate = Gate::default();
    let provider = provider(&m, &folders, &gate);
    let engine = Engine::new(UserId("fixture-user".into()), &provider);
    let run = prepare(&engine, &provider);
    let approval = approve(&run);
    let before = folders.snapshot().unwrap();
    engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(folders.snapshot().unwrap(), before);
    assert_eq!(gate.calls.get(), 0);
}
