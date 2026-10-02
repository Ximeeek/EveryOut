use everyout_core_model::*;
use everyout_providers::{load_manifest, Manifest};
use serde_json::{json, Value};

const CATALOG: [&str; 7] = [
    include_str!("../../../catalog/apps/gaming/steam.json"),
    include_str!("../../../catalog/apps/gaming/epic-games-launcher.json"),
    include_str!("../../../catalog/apps/gaming/battle-net.json"),
    include_str!("../../../catalog/apps/gaming/riot-client.json"),
    include_str!("../../../catalog/apps/gaming/ea-app.json"),
    include_str!("../../../catalog/apps/gaming/ubisoft-connect.json"),
    include_str!("../../../catalog/apps/gaming/gog-galaxy.json"),
];
fn synthetic(input: &str) -> Value {
    let mut m: Value = serde_json::from_str(input).unwrap();
    m["support"] = json!("validated");
    m["compatibility"]["product_versions"] = json!("synthetic-only-v1");
    m["confidence"]["version_coverage"] = json!("synthetic-only-v1");
    m["confidence"]["status"] = json!("verified");
    m["open_spikes"] = json!([]);
    m["risks"]["flags"] = json!(["settings-or-profiles", "shared-store"]);
    m["risks"]["permanent_data_loss"] = json!("known");
    for method in m["cleaning_methods"].as_array_mut().unwrap() {
        method["blockers"] = json!([]);
    }
    m
}
#[test]
fn every_entry_has_sources_risks_and_unverified_coverage() {
    for input in CATALOG {
        let m = load_manifest(input).unwrap();
        assert_eq!(m.support, Support::Candidate);
        assert_eq!(m.confidence.status.as_deref(), Some("unverified"));
        assert!(m.risks.flags.contains(&RiskFlag::SettingsOrProfiles));
        assert!(m.risks.flags.contains(&RiskFlag::Unknown));
        assert!(!m.risks.confirmations.is_empty());
        assert!(!m.sources.unwrap().is_empty());
        assert!(m
            .session_locations
            .iter()
            .all(|a| a.confidence.as_deref() == Some("unverified")));
        let mut promoted: Value = serde_json::from_str(input).unwrap();
        promoted["support"] = json!("validated");
        assert!(load_manifest(&promoted.to_string()).is_err());
        for target in [
            "../outside",
            "Local State",
            "steamapps",
            "Data",
            "savegames",
            "Settings",
            "ssfn*",
        ] {
            let mut bad: Value = serde_json::from_str(input).unwrap();
            bad["session_locations"][0]["relative"] = json!(target);
            assert!(
                load_manifest(&bad.to_string()).is_err(),
                "{}: {target}",
                m.id
            );
        }
        let mut bad: Value = serde_json::from_str(input).unwrap();
        bad["roots"][0]["relative"] = json!("OtherOwner");
        assert!(load_manifest(&bad.to_string()).is_err());
        let mut bad: Value = serde_json::from_str(input).unwrap();
        bad["session_locations"][0]["name_prefix"] = json!("anything");
        assert!(load_manifest(&bad.to_string()).is_err());
    }
    assert!(load_manifest(&synthetic(CATALOG[0]).to_string()).is_err());
}

#[cfg(windows)]
#[path = "support/gaming_registry.rs"]
mod gaming_registry;

#[cfg(windows)]
mod windows {
    use super::*;
    use everyout_engine::*;
    use everyout_platform_windows::{AllowedRoot, FixtureFolders, KnownFolder};
    use everyout_providers::{
        executor::{ManifestExecutor, ProcessGate},
        platform::PlatformManifest,
        steam::SteamCleanup,
        Root,
    };
    use std::{cell::Cell, fs, fs::OpenOptions, os::windows::fs::OpenOptionsExt, path::PathBuf};

    #[derive(Default)]
    struct Gate {
        calls: Cell<usize>,
        fail: Cell<Option<ErrorKind>>,
    }
    impl ProcessGate for Gate {
        fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
            Ok(vec![])
        }
        fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
            self.calls.set(self.calls.get() + 1);
            self.revalidate()
        }
        fn revalidate(&self) -> Result<(), ErrorKind> {
            self.fail.get().map_or(Ok(()), Err)
        }
    }
    fn seed(folders: &FixtureFolders, m: &Manifest) -> (Vec<PathBuf>, Vec<PathBuf>) {
        let root = folders.path().join(m.roots[0].relative());
        fs::create_dir_all(&root).unwrap();
        let mut targets = vec![];
        for a in &m.session_locations {
            if a.kind == ArtifactKind::RegistryValue {
                continue;
            }
            let path = root.join(if a.name_prefix.is_some() {
                "ssfn123"
            } else {
                &a.relative
            });
            if a.kind == ArtifactKind::Directory {
                fs::create_dir_all(&path).unwrap();
                fs::write(path.join("opaque"), b"invented bytes").unwrap();
            } else {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(&path, b"invented bytes").unwrap();
            }
            targets.push(path);
        }
        if m.id == "steam" {
            let path = root.join("SSFN789");
            fs::write(&path, b"invented bytes").unwrap();
            targets.push(path);
        }
        let mut preserved = vec![];
        for path in [
            "Local State",
            "settings.yaml",
            "steamapps/game",
            "userdata/save",
            "savegames/save",
            "Config/settings",
            "ssfn-directory/keep",
            "nested/ssfn456",
        ] {
            let path = root.join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, b"preserved").unwrap();
            preserved.push(path);
        }
        (targets, preserved)
    }
    fn prepare<'a>(engine: &Engine<'a>, provider: &'a ManifestExecutor<'a>) -> PreparedRun<'a> {
        let inventory = engine
            .scan(&[provider], Category::Application, &mut |_| {})
            .unwrap();
        let selection = inventory.default_selection(Category::Application);
        engine
            .prepare(
                inventory,
                Category::Application,
                &selection,
                ProcessClosePolicy::Ask,
                &mut |_| {},
            )
            .unwrap()
    }
    #[test]
    fn single_root_launchers_preview_gate_risks_and_wipe_only_synthetic_targets() {
        for input in &CATALOG[1..6] {
            let folders = FixtureFolders::create().unwrap();
            let original = load_manifest(input).unwrap();
            let (targets, preserved) = seed(&folders, &original);
            let gate = Gate::default();
            let candidate = ManifestExecutor::load(
                input,
                &folders,
                UserId("fixture".into()),
                InstallationId("fixture".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture".into()), &candidate);
            let before = folders.snapshot().unwrap();
            let run = prepare(&engine, &candidate);
            assert_eq!(before, folders.snapshot().unwrap());
            let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
            assert_eq!(report.sections[0].aggregate, AggregateStatus::Blocked);
            assert_eq!(before, folders.snapshot().unwrap());
            assert_eq!(gate.calls.get(), 0);
            drop(engine);
            drop(candidate);

            let m = synthetic(input);
            let provider = ManifestExecutor::load(
                &m.to_string(),
                &folders,
                UserId("fixture".into()),
                InstallationId("fixture".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture".into()), &provider);
            let run = prepare(&engine, &provider);
            assert!(run.preview().sections[0].counts.would_apply > 0);
            assert_eq!(before, folders.snapshot().unwrap());
            let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
            assert_eq!(report.sections[0].aggregate, AggregateStatus::Blocked);
            assert_eq!(before, folders.snapshot().unwrap());
            assert_eq!(gate.calls.get(), 0);
            let run = prepare(&engine, &provider);
            let mut approval = Approval::default();
            for item in &run.preview().sections[0].items {
                if let Some(plan) = &item.plan {
                    approval
                        .confirmed_risks
                        .push(run.confirm_risks(&item.instance, &plan.risks.flags));
                    approval
                        .confirmations
                        .extend(plan.risks.confirmations.clone());
                }
            }
            let report = engine.apply(run, approval, &|| false, &mut |_| {});
            assert_eq!(
                report.sections[0].aggregate,
                AggregateStatus::CompleteLocalScope,
                "{}",
                original.id
            );
            assert!(targets.iter().all(|p| !p.exists()));
            assert!(preserved.iter().all(|p| p.exists()));
            assert_eq!(gate.calls.get(), 1);
        }
    }
    #[test]
    fn gog_file_and_registry_fixtures_keep_unrelated_values() {
        let folders = FixtureFolders::create().unwrap();
        let m = load_manifest(CATALOG[6]).unwrap();
        let (targets, preserved) = seed(&folders, &m);
        let candidate = PlatformManifest::load(CATALOG[6]).unwrap();
        let file = candidate.file("client-config", None, &folders).unwrap();
        assert_eq!(file.delete(true).unwrap().status, ActionStatus::WouldApply);
        assert_eq!(file.delete(false).unwrap_err().kind, ErrorKind::Unsupported);
        let fixture = gaming_registry::RegistryFixture::new(&["refreshToken", "unrelated"]);
        let registry = fixture.bind(&["refreshToken", "unrelated"]);
        registry.delete_value("refreshToken", true).unwrap();
        assert!(registry.value_exists("refreshToken").unwrap());
        // Rebind the candidate's exact target name only to our generated namespace.
        let target = &m
            .session_locations
            .iter()
            .find(|a| a.kind == ArtifactKind::RegistryValue)
            .unwrap()
            .relative;
        registry.delete_value(target, false).unwrap();
        assert!(!registry.value_exists("refreshToken").unwrap());
        assert!(registry.value_exists("unrelated").unwrap());
        let validated = PlatformManifest::load(&synthetic(CATALOG[6]).to_string()).unwrap();
        validated
            .file("client-config", None, &folders)
            .unwrap()
            .delete(false)
            .unwrap();
        assert!(targets.iter().all(|p| !p.exists()));
        assert!(preserved.iter().all(|p| p.exists()));
    }
    #[test]
    fn steam_exact_names_dry_run_candidates_confirmation_and_partial_failure() {
        let folders = FixtureFolders::create().unwrap();
        let m = load_manifest(CATALOG[0]).unwrap();
        let (targets, preserved) = seed(&folders, &m);
        let root =
            AllowedRoot::from_manifest(&folders, KnownFolder::LocalAppData, "Steam").unwrap();
        let fixture = gaming_registry::RegistryFixture::new(&[
            "AutoLoginUser",
            "RememberPassword",
            "SteamPath",
            "unrelated",
        ]);
        let registry = fixture.bind(&["AutoLoginUser", "RememberPassword"]);
        let canaries = fixture.bind(&["SteamPath", "unrelated"]);
        let gate = Gate::default();
        let candidate =
            SteamCleanup::discover(&root, &registry, Support::Candidate, &gate).unwrap();
        let before = folders.snapshot().unwrap();
        assert!(candidate
            .dry_run()
            .iter()
            .all(|o| o.result.as_ref().unwrap().status == ActionStatus::WouldApply));
        assert_eq!(before, folders.snapshot().unwrap());
        assert!(registry.value_exists("AutoLoginUser").unwrap());
        assert_eq!(
            candidate.apply(true, ProcessClosePolicy::Ask).err(),
            Some(ErrorKind::Unsupported)
        );
        assert_eq!(gate.calls.get(), 0);
        let plan = SteamCleanup::discover(&root, &registry, Support::Validated, &gate).unwrap();
        assert_eq!(
            plan.apply(false, ProcessClosePolicy::Ask).err(),
            Some(ErrorKind::ScopeViolation)
        );
        assert_eq!(
            plan.apply(true, ProcessClosePolicy::HardKillAfter2s).err(),
            Some(ErrorKind::Unsupported)
        );
        assert_eq!(gate.calls.get(), 0);
        gate.fail.set(Some(ErrorKind::Locked));
        assert_eq!(
            plan.apply(true, ProcessClosePolicy::Ask).err(),
            Some(ErrorKind::Locked)
        );
        assert_eq!(before, folders.snapshot().unwrap());
        gate.fail.set(None);
        // The adapter may observe metadata, but never open this opaque fixture for reading.
        let lock = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(&targets[0])
            .unwrap();
        let outcomes = plan.apply(true, ProcessClosePolicy::Ask).unwrap();
        assert!(outcomes.iter().any(|o| o
            .result
            .as_ref()
            .is_err_and(|e| e.kind == ErrorKind::Locked)));
        assert!(targets[0].exists());
        assert!(targets[1..].iter().all(|p| !p.exists()));
        assert!(preserved.iter().all(|p| p.exists()));
        assert!(!registry.value_exists("AutoLoginUser").unwrap());
        assert!(!registry.value_exists("RememberPassword").unwrap());
        assert!(canaries.value_exists("SteamPath").unwrap());
        assert!(canaries.value_exists("unrelated").unwrap());
        drop(lock);
        let retry = SteamCleanup::discover(&root, &registry, Support::Validated, &gate).unwrap();
        assert!(retry
            .apply(true, ProcessClosePolicy::Ask)
            .unwrap()
            .iter()
            .all(|o| o.result.is_ok()));
        assert!(targets.iter().all(|p| !p.exists()));
        assert!(preserved.iter().all(|p| p.exists()));
    }
    #[test]
    fn steam_new_guard_file_invalidates_review_without_closing_processes() {
        let folders = FixtureFolders::create().unwrap();
        seed(&folders, &load_manifest(CATALOG[0]).unwrap());
        let root =
            AllowedRoot::from_manifest(&folders, KnownFolder::LocalAppData, "Steam").unwrap();
        let fixture = gaming_registry::RegistryFixture::new(&["AutoLoginUser", "RememberPassword"]);
        let registry = fixture.bind(&["AutoLoginUser", "RememberPassword"]);
        let gate = Gate::default();
        let plan = SteamCleanup::discover(&root, &registry, Support::Validated, &gate).unwrap();
        fs::write(folders.path().join("Steam/ssfn-new"), b"synthetic").unwrap();
        let before = folders.snapshot().unwrap();
        assert_eq!(
            plan.apply(true, ProcessClosePolicy::Ask).err(),
            Some(ErrorKind::StalePlan)
        );
        assert_eq!(before, folders.snapshot().unwrap());
        assert_eq!(gate.calls.get(), 0);
    }
    #[test]
    fn steam_installation_slot_and_gog_multi_root_do_not_enter_generic_executor() {
        let folders = FixtureFolders::create().unwrap();
        let gate = Gate::default();
        for input in [CATALOG[0], CATALOG[6]] {
            assert_eq!(
                ManifestExecutor::load(
                    input,
                    &folders,
                    UserId("fixture".into()),
                    InstallationId("fixture".into()),
                    &gate
                )
                .err(),
                Some(ErrorKind::Unsupported)
            );
        }
        assert!(matches!(
            load_manifest(CATALOG[0]).unwrap().roots[0],
            Root::ReviewedInstallation { .. }
        ));
    }
}
