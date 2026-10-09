#![cfg(windows)]
use everyout_core_model::*;
use everyout_engine::ProcessPreview;
use everyout_lib::{application::CurrentSession, bridge::Bridge, dto::*, settings::SettingsStore};
use everyout_platform_windows::FixtureFolders;
use everyout_providers::executor::{ManifestExecutor, ProcessGate};
use serde_json::{json, Value};
use std::{
    fs,
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

struct Gate;
struct CategoryFixture<'a>(&'a ManifestExecutor<'a>);
impl Provider for CategoryFixture<'_> {
    fn detect(&self, cx: &DetectionContext<'_>) -> DetectionResult {
        self.0.detect(cx)
    }
    fn describe(&self, instance: &ProviderInstance) -> ProviderDescription {
        let mut description = self.0.describe(instance);
        description.descriptor.category = Category::WindowsMicrosoftAndDevTools;
        description
    }
    fn plan(&self, cx: &PlanContext<'_>, selection: &Selection) -> PlanResult {
        self.0.plan(cx, selection)
    }
    fn execute(
        &self,
        cx: &OperationContext<'_>,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult {
        self.0.execute(cx, plan, mode)
    }
    fn verify(&self, cx: &VerificationContext<'_>, result: &ExecutionResult) -> VerificationResult {
        self.0.verify(cx, result)
    }
    fn report(&self, result: &ProviderResult) -> SanitizedReport {
        self.0.report(result)
    }
}
impl everyout_engine::EngineProvider for CategoryFixture<'_> {
    fn process_preview(&self, plan: &ProposedPlan) -> Result<Vec<ProcessPreview>, ErrorKind> {
        self.0.process_preview(plan)
    }
    fn close(&self, plan: &ValidatedPlan, policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        self.0.close(plan, policy)
    }
    fn revalidate(&self, plan: &ValidatedPlan) -> Result<(), ErrorKind> {
        self.0.revalidate(plan)
    }
    fn target_label(&self, action: &PlannedAction) -> String {
        self.0.target_label(action)
    }
}
impl ProcessGate for Gate {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
        Ok(vec![])
    }
    fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
        Ok(())
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        Ok(())
    }
}
fn fixture(folders: &FixtureFolders, risks: bool) -> String {
    let mut m: Value =
        serde_json::from_str(include_str!("../../catalog/browsers/chrome.json")).unwrap();
    m["support"] = json!("validated");
    for artifact in m["session_locations"].as_array_mut().unwrap() {
        artifact["confidence"] = "verified".into();
    }
    m["compatibility"]["product_versions"] = json!("synthetic-only-v1");
    m["confidence"]["version_coverage"] = json!("synthetic-only-v1");
    m["confidence"]["status"] = json!("verified");
    m["open_spikes"] = json!([]);
    m["risks"] = if risks {
        json!({"flags":["settings-or-profiles"],"affected_data":["synthetic-data"],"permanent_data_loss":"known","reason":"fixture-only review","confirmations":["fixture-review"],"evidence":["storage"]})
    } else {
        json!({"flags":[],"affected_data":[],"permanent_data_loss":"none","confirmations":[],"evidence":["storage"]})
    };
    for method in m["cleaning_methods"].as_array_mut().unwrap() {
        method["blockers"] = json!([]);
    }
    let profile = folders.path().join("Google/Chrome/User Data/Default");
    for entry in m["session_locations"].as_array().unwrap() {
        let path = profile.join(entry["relative"].as_str().unwrap());
        if entry["kind"] == "file" {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"synthetic-session").unwrap();
        } else {
            fs::create_dir_all(&path).unwrap();
            fs::write(path.join("canary"), b"synthetic-session").unwrap();
        }
    }
    fs::write(profile.join("Login Data"), b"synthetic-preserved").unwrap();
    m.to_string()
}
fn select(scan: ScanDto) -> SelectionRequest {
    SelectionRequest {
        skipped: None,
        profiles: vec![],
        inventory_id: scan.inventory_id,
        items: scan
            .groups
            .iter()
            .flat_map(|g| &g.items)
            .filter(|i| i.selectable)
            .map(|i| i.id.clone())
            .collect(),
    }
}

#[test]
fn storage_discovery_reaches_ui_but_cannot_be_submitted_as_a_cleanup_target() {
    let config = everyout_test_support::FixtureTree::empty().unwrap();
    let (bridge, worker) = Bridge::channel(SettingsStore::new(config.path().into()), None).unwrap();
    let thread = std::thread::spawn(move || {
        let folders = FixtureFolders::create().unwrap();
        let json = fixture(&folders, false);
        fs::create_dir_all(folders.path().join("NicheApp/Nested/Cache")).unwrap();
        let gate = Gate;
        let provider = ManifestExecutor::load(
            &json,
            &folders,
            UserId("current-account".into()),
            InstallationId("chrome".into()),
            &gate,
        )
        .unwrap();
        worker.serve(
            CurrentSession::new(&provider, vec![(Category::Browser, &provider)]),
            || {
                everyout_detection::scanner::scan(
                    &folders,
                    &everyout_platform_windows::inventory::InstalledInventory::default(),
                    &[],
                    &|| false,
                )
            },
            vec![],
        );
    });
    let scan = bridge.scan().unwrap();
    let item = scan
        .groups
        .iter()
        .flat_map(|g| &g.items)
        .find(|item| item.name == "NicheApp")
        .unwrap();
    assert!(!item.selectable && !item.default_selected && item.provider.is_none());
    assert!(item.signals.contains(&"cache-directory-name".into()));
    let request = SelectionRequest {
        inventory_id: scan.inventory_id.clone(),
        items: vec![item.id.clone()],
        skipped: None,
        profiles: vec![],
    };
    assert_eq!(
        bridge.build_plan(request).unwrap_err(),
        CommandError::InvalidSelection
    );
    drop(bridge);
    thread.join().unwrap();
}

#[test]
fn previews_can_be_rebuilt_without_a_scan_and_old_approvals_become_stale() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, false);
    let gate = Gate;
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
    let selection = select(session.scan().unwrap());
    let before = folders.snapshot().unwrap();
    let first = session
        .build_plan(selection.clone(), ProcessClosePolicy::Ask)
        .unwrap();
    let second = session
        .build_plan(selection.clone(), ProcessClosePolicy::Ask)
        .unwrap();
    assert_ne!(first.plan_id, second.plan_id);
    assert_eq!(
        session.dry_run(&first.plan_id).unwrap_err(),
        CommandError::StalePlan
    );
    assert!(session.dry_run(&second.plan_id).is_ok());
    assert_eq!(folders.snapshot().unwrap(), before);
    session
        .execute(approve(&second), &|| false, &mut |_| {})
        .unwrap();
    assert_eq!(
        session
            .build_plan(selection, ProcessClosePolicy::Ask)
            .unwrap_err(),
        CommandError::StalePlan
    );
}

#[test]
fn desktop_candidates_expose_real_blockers_and_allow_read_only_replanning() {
    for json in [
        include_str!("../../catalog/apps/communication/spotify.json"),
        include_str!("../../catalog/apps/communication/discord.json"),
        include_str!("../../catalog/apps/gaming/ea-app.json"),
        include_str!("../../catalog/apps/gaming/epic-games-launcher.json"),
        include_str!("../../catalog/apps/gaming/riot-client.json"),
    ] {
        let folders = FixtureFolders::create().unwrap();
        let manifest: Value = serde_json::from_str(json).unwrap();
        let root = folders
            .path()
            .join(manifest["roots"][0]["relative"].as_str().unwrap());
        fs::create_dir_all(&root).unwrap();
        for artifact in manifest["session_locations"].as_array().unwrap() {
            let path = root.join(artifact["relative"].as_str().unwrap());
            if artifact["kind"] == "directory" {
                fs::create_dir_all(path).unwrap();
            } else {
                fs::create_dir_all(path.parent().unwrap()).unwrap();
                fs::write(path, b"synthetic candidate data").unwrap();
            }
        }
        let gate = Gate;
        let provider = ManifestExecutor::load(
            json,
            &folders,
            UserId("current-account".into()),
            InstallationId(manifest["id"].as_str().unwrap().into()),
            &gate,
        )
        .unwrap();
        let mut session = CurrentSession::new(&provider, vec![(Category::Application, &provider)]);
        let selection = select(session.scan().unwrap());
        let before = folders.snapshot().unwrap();
        let plan = session
            .build_plan(selection.clone(), ProcessClosePolicy::Ask)
            .unwrap();
        let item = &plan.report.accounts[0].sections[0].items[0];
        assert!(item
            .actions
            .iter()
            .all(|action| action.outcome == ActionStatus::Blocked));
        for method in manifest["cleaning_methods"].as_array().unwrap() {
            for blocker in method["blockers"].as_array().unwrap() {
                assert!(item
                    .limitations
                    .iter()
                    .any(|reason| reason == blocker.as_str().unwrap()));
            }
        }
        assert!(item
            .limitations
            .contains(&"automatic-cleanup-unverified".into()));
        assert!(session
            .build_plan(selection, ProcessClosePolicy::Ask)
            .is_ok());
        assert_eq!(folders.snapshot().unwrap(), before);
    }
}

#[test]
fn current_and_account_discovery_share_evidence_and_unverified_status() {
    use everyout_detection::scanner::{scan, ReviewedManifest};
    use everyout_platform_windows::inventory::InstalledInventory;
    for input in [
        include_str!("../../catalog/apps/communication/discord.json"),
        include_str!("../../catalog/apps/communication/spotify.json"),
    ] {
        let folders = FixtureFolders::create().unwrap();
        let manifest = everyout_providers::load_manifest(input).unwrap();
        let root = folders.path().join(manifest.roots[0].relative());
        fs::create_dir_all(&root).unwrap();
        if manifest.id == "spotify" {
            fs::write(root.join("prefs"), b"synthetic preferences").unwrap();
            fs::write(root.join("Spotify.exe"), b"unreviewed synthetic executable").unwrap();
        } else {
            fs::create_dir_all(root.join("Local Storage")).unwrap();
        }
        let gate = Gate;
        let provider = ManifestExecutor::load(
            input,
            &folders,
            UserId("current-account".into()),
            InstallationId(manifest.id.clone()),
            &gate,
        )
        .unwrap();
        let mut session = CurrentSession::new(&provider, vec![(Category::Application, &provider)]);
        let current = session.scan().unwrap();
        let current_item = current.groups.iter().flat_map(|g| &g.items).next().unwrap();
        let account_scan = scan(
            &folders,
            &InstalledInventory::default(),
            &[ReviewedManifest::load(input).unwrap()],
            &|| false,
        );
        let detected = account_scan
            .known
            .iter()
            .find(|d| d.id.starts_with(&manifest.id))
            .unwrap();
        assert_eq!(current_item.decision, detected.decision);
        let mut account_dto = current.clone();
        account_dto.mode = AccountMode::AllAccounts;
        account_dto.groups.clear();
        let mut account_item = current_item.clone();
        account_item.decision = detected.decision.clone();
        account_item.unverified = false;
        account_dto.push(detected.category, detected.confidence, account_item);
        assert_eq!(
            current_item.unverified,
            account_dto.groups[0].items[0].unverified
        );
        assert!(current_item.unverified);
        assert!(!current_item.decision.action_allowed);
        if manifest.id == "discord" {
            for code in [
                "unvalidated-product-version",
                "unknown-authentication-closure",
                "unreviewed-preservation",
            ] {
                assert!(current_item.decision.blocked_by.contains(&code.into()));
            }
            assert_eq!(
                current_item.decision.evidence.authentication_scope.state,
                AuthenticationScope::FrameworkHint
            );
        } else {
            assert_eq!(
                current_item.decision.evidence.version_applicability.state,
                VersionApplicability::Stale
            );
            assert!(current_item
                .decision
                .blocked_by
                .contains(&"spotify-build-not-reviewed".into()));
        }
    }
}

#[test]
fn scan_projects_confidence_profiles_and_engine_risks_without_secret_reads() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, true);
    let before = folders.snapshot().unwrap();
    let gate = Gate;
    for confidence in ["high", "medium", "low"] {
        let mut manifest: Value = serde_json::from_str(&json).unwrap();
        manifest["confidence"]["level"] = json!(confidence);
        let provider = ManifestExecutor::load(
            &manifest.to_string(),
            &folders,
            UserId("current-account".into()),
            InstallationId("chrome".into()),
            &gate,
        )
        .unwrap();
        let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
        let scan = session.scan().unwrap();
        let item = &scan.groups[0].items[0];
        assert_eq!(item.default_selected, confidence == "high");
        assert!(!item.profiles.is_empty());
        assert_eq!(item.risks, vec![RiskFlag::SettingsOrProfiles]);
        assert_eq!(item.loss, LossAssessment::Known);
        assert!(item.sync_warning);
        assert!(!serde_json::to_string(&scan)
            .unwrap()
            .contains(folders.path().to_str().unwrap()));
    }
    assert_eq!(folders.snapshot().unwrap(), before);
}

#[test]
fn selected_profile_subset_is_bound_to_preview_and_invalid_scopes_are_rejected() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, false);
    let manifest: Value = serde_json::from_str(&json).unwrap();
    let second = folders.path().join("Google/Chrome/User Data/Profile 1");
    for entry in manifest["session_locations"].as_array().unwrap() {
        let path = second.join(entry["relative"].as_str().unwrap());
        if entry["kind"] == "file" {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"synthetic-session").unwrap();
        } else {
            fs::create_dir_all(path).unwrap();
        }
    }
    let before = folders.snapshot().unwrap();
    let gate = Gate;
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
    let scan = session.scan().unwrap();
    let item = &scan.groups[0].items[0];
    assert_eq!(item.profiles.len(), 2);
    let selected_profile = item.profiles[0].clone();
    let base = select(scan.clone());
    for profiles in [
        vec![],
        vec!["foreign-profile".into()],
        vec![selected_profile.clone(), selected_profile.clone()],
    ] {
        let mut request = base.clone();
        request.profiles.push(ProfileSelection {
            item: item.id.clone(),
            profiles,
        });
        assert_eq!(
            session
                .build_plan(request, ProcessClosePolicy::Ask)
                .unwrap_err(),
            CommandError::InvalidSelection
        );
    }
    let mut foreign = base.clone();
    foreign.profiles.push(ProfileSelection {
        item: "unselected-instance".into(),
        profiles: vec![selected_profile.clone()],
    });
    assert_eq!(
        session
            .build_plan(foreign, ProcessClosePolicy::Ask)
            .unwrap_err(),
        CommandError::InvalidSelection
    );
    let mut duplicate = base.clone();
    let scope = ProfileSelection {
        item: item.id.clone(),
        profiles: vec![selected_profile.clone()],
    };
    duplicate.profiles = vec![scope.clone(), scope.clone()];
    assert_eq!(
        session
            .build_plan(duplicate, ProcessClosePolicy::Ask)
            .unwrap_err(),
        CommandError::InvalidSelection
    );
    let mut request = base;
    request.profiles = vec![scope];
    let plan = session
        .build_plan(request, ProcessClosePolicy::Ask)
        .unwrap();
    assert_eq!(
        plan.report.accounts[0].sections[1].items[0].profiles,
        vec![selected_profile]
    );
    assert_eq!(folders.snapshot().unwrap(), before);
}
fn approve(plan: &PlanDto) -> ExecuteRequest {
    ExecuteRequest {
        plan_id: plan.plan_id.clone(),
        category_tokens: plan
            .category_tokens
            .iter()
            .map(|t| t.token.clone())
            .collect(),
        force_close_accounts: plan
            .report
            .accounts
            .iter()
            .map(|a| a.account.clone())
            .collect(),
        confirmed_risks: plan
            .report
            .accounts
            .iter()
            .flat_map(|a| {
                a.sections.iter().flat_map(|s| {
                    s.items.iter().map(|i| RiskAcceptance {
                        account: a.account.clone(),
                        instance: i.instance.clone(),
                        flags: i.risks.clone(),
                        confirmations: i.confirmations.clone(),
                    })
                })
            })
            .collect(),
    }
}
#[test]
fn full_fixture_flow_streams_results_preserves_data_and_consumes_plan() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, false);
    let gate = Gate;
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
    let before = folders.snapshot().unwrap();
    let selection = select(session.scan().unwrap());
    let plan = session
        .build_plan(selection, ProcessClosePolicy::Ask)
        .unwrap();
    assert!(plan.report.accounts[0].sections[1].would_apply > 0);
    assert_eq!(
        session.dry_run(&plan.plan_id).unwrap().plan_id,
        plan.plan_id
    );
    assert_eq!(folders.snapshot().unwrap(), before);
    let mut events = Vec::new();
    let report = session
        .execute(approve(&plan), &|| false, &mut |e| events.push(e))
        .unwrap();
    assert!(report.accounts[0].sections[1].succeeded > 0);
    assert!(events.iter().any(|e| matches!(
        e,
        WipeEvent::Progress {
            stage: everyout_engine::Stage::Cleaning,
            ..
        }
    )));
    assert!(events.iter().any(|e| matches!(e, WipeEvent::Item { .. })));
    assert_eq!(
        fs::read(
            folders
                .path()
                .join("Google/Chrome/User Data/Default/Login Data")
        )
        .unwrap(),
        b"synthetic-preserved"
    );
    assert_eq!(
        session.dry_run(&plan.plan_id).unwrap_err(),
        CommandError::StalePlan
    );
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains(folders.path().to_str().unwrap()));
}
#[test]
fn missing_risks_confirmation_and_force_close_refuse_before_mutation() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, true);
    let gate = Gate;
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
    let before = folders.snapshot().unwrap();
    let scan = session.scan().unwrap();
    let plan = session
        .build_plan(select(scan), ProcessClosePolicy::HardKillAfter2s)
        .unwrap();
    let mut request = approve(&plan);
    request.confirmed_risks.clear();
    assert_eq!(
        session
            .execute(request, &|| false, &mut |_| {})
            .unwrap_err(),
        CommandError::ConfirmationRequired
    );
    let mut request = approve(&plan);
    request.force_close_accounts.clear();
    assert_eq!(
        session
            .execute(request, &|| false, &mut |_| {})
            .unwrap_err(),
        CommandError::ConfirmationRequired
    );
    assert_eq!(folders.snapshot().unwrap(), before);
    session
        .execute(approve(&plan), &|| false, &mut |_| {})
        .unwrap();
}
#[test]
fn unknown_duplicate_and_stale_selections_fail_and_rescan_invalidates_review() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, false);
    let gate = Gate;
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
    let scan = session.scan().unwrap();
    let mut selection = select(scan);
    selection.items.push("path:C:/Users".into());
    assert_eq!(
        session
            .build_plan(selection, ProcessClosePolicy::Ask)
            .unwrap_err(),
        CommandError::InvalidSelection
    );
    let scan = session.scan().unwrap();
    let selection = select(scan);
    let plan = session
        .build_plan(selection, ProcessClosePolicy::Ask)
        .unwrap();
    session.scan().unwrap();
    assert_eq!(
        session
            .execute(approve(&plan), &|| false, &mut |_| {})
            .unwrap_err(),
        CommandError::StalePlan
    );
}
#[test]
fn settings_defaults_atomic_replacement_and_invalid_json() {
    let fixture = everyout_test_support::FixtureTree::empty().unwrap();
    let store = SettingsStore::new(fixture.path().join("config"));
    assert_eq!(store.load().unwrap(), Settings::default());
    let settings = Settings {
        process_close_policy: ProcessClosePolicy::HardKillAfter2s,
        account_mode: AccountMode::AllAccounts,
        first_run_completed: true,
    };
    store.save(&settings).unwrap();
    assert_eq!(store.load().unwrap(), settings);
    store.save(&Settings::default()).unwrap();
    assert_eq!(store.load().unwrap(), Settings::default());
    fs::write(fixture.path().join("config/settings.json"), b"{}").unwrap();
    assert_eq!(store.load().unwrap_err(), CommandError::SettingsIo);
}

#[test]
fn category_tokens_bind_the_review_and_stale_metadata_refuses_dry_run() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, false);
    let gate = Gate;
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let classified = CategoryFixture(&provider);
    let mut session = CurrentSession::new(
        &provider,
        vec![(Category::WindowsMicrosoftAndDevTools, &classified)],
    );
    let selection = select(session.scan().unwrap());
    let plan = session
        .build_plan(selection, ProcessClosePolicy::Ask)
        .unwrap();
    let mut request = approve(&plan);
    request.category_tokens.clear();
    let before = folders.snapshot().unwrap();
    assert_eq!(
        session
            .execute(request, &|| false, &mut |_| {})
            .unwrap_err(),
        CommandError::ConfirmationRequired
    );
    let mut request = approve(&plan);
    request.category_tokens[0] = "another-plan-category".into();
    assert_eq!(
        session
            .execute(request, &|| false, &mut |_| {})
            .unwrap_err(),
        CommandError::InvalidSelection
    );
    assert_eq!(folders.snapshot().unwrap(), before);
    fs::write(
        folders
            .path()
            .join("Google/Chrome/User Data/Default/Network/Cookies"),
        b"changed synthetic metadata with a different size",
    )
    .unwrap();
    assert_eq!(
        session.dry_run(&plan.plan_id).unwrap_err(),
        CommandError::StalePlan
    );
}
#[test]
fn bridge_blocks_concurrent_wipes_cancel_stops_mutations_and_stores_last_report() {
    let config = everyout_test_support::FixtureTree::empty().unwrap();
    let (bridge, worker) = Bridge::channel(SettingsStore::new(config.path().into()), None).unwrap();
    let worker_thread = std::thread::spawn(move || {
        let folders = FixtureFolders::create().unwrap();
        let json = fixture(&folders, false);
        let gate = Gate;
        let provider = ManifestExecutor::load(
            &json,
            &folders,
            UserId("current-account".into()),
            InstallationId("chrome".into()),
            &gate,
        )
        .unwrap();
        let session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
        worker.serve(session, everyout_detection::ScanReport::default, vec![]);
    });
    let scan = bridge.scan().unwrap();
    // An unavailable update service must not consume a usable inventory.
    assert_eq!(
        bridge.check_catalog_updates().unwrap().error.as_deref(),
        Some("catalog-unconfigured")
    );
    let plan = bridge.build_plan(select(scan)).unwrap();
    assert_eq!(
        bridge.check_catalog_updates().unwrap_err(),
        CommandError::Busy
    );
    assert!(bridge.dry_run(plan.plan_id.clone()).is_ok());
    let (entered, wait) = mpsc::channel();
    let (release, paused) = mpsc::channel();
    let (done, finished) = mpsc::channel();
    let paused = Arc::new(Mutex::new(paused));
    let mut blocked = false;
    bridge
        .execute(
            approve(&plan),
            Box::new(move |event| {
                if !blocked
                    && matches!(
                        event,
                        WipeEvent::Progress {
                            stage: everyout_engine::Stage::Closing,
                            ..
                        }
                    )
                {
                    blocked = true;
                    entered.send(()).unwrap();
                    paused
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(10))
                        .unwrap();
                }
                if matches!(event, WipeEvent::Finished { .. }) {
                    done.send(()).unwrap();
                }
            }),
        )
        .unwrap();
    wait.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(
        bridge
            .execute(approve(&plan), Box::new(|_| {}))
            .unwrap_err(),
        CommandError::Busy
    );
    assert_eq!(bridge.scan().unwrap_err(), CommandError::Busy);
    assert_eq!(
        bridge.cancel("forged-id").unwrap_err(),
        CommandError::StalePlan
    );
    bridge.cancel(&plan.plan_id).unwrap();
    release.send(()).unwrap();
    finished.recv_timeout(Duration::from_secs(10)).unwrap();
    let report = bridge.get_last_report().unwrap().unwrap();
    assert_eq!(report.accounts[0].sections[1].succeeded, 0);
    for format in [ExportFormat::Json, ExportFormat::Text] {
        let relative = bridge.export_report(format).unwrap();
        let content = fs::read_to_string(config.path().join(relative)).unwrap();
        assert!(!content.contains("synthetic-session"));
        assert!(!content.contains(config.path().to_str().unwrap()));
        assert!(content.contains("current-account"));
    }
    drop(bridge);
    worker_thread.join().unwrap();
}
#[test]
fn no_pin_fallback_discards_review_and_persists_current_without_uac() {
    let config = everyout_test_support::FixtureTree::empty().unwrap();
    let (bridge, worker) = Bridge::channel(SettingsStore::new(config.path().into()), None).unwrap();
    let thread = std::thread::spawn(move || {
        let folders = FixtureFolders::create().unwrap();
        let json = fixture(&folders, false);
        let gate = Gate;
        let provider = ManifestExecutor::load(
            &json,
            &folders,
            UserId("current-account".into()),
            InstallationId("chrome".into()),
            &gate,
        )
        .unwrap();
        worker.serve(
            CurrentSession::new(&provider, vec![(Category::Browser, &provider)]),
            everyout_detection::ScanReport::default,
            vec![],
        );
    });
    let plan = bridge.build_plan(select(bridge.scan().unwrap())).unwrap();
    let mode = bridge.enable_all_accounts_mode().unwrap();
    assert_eq!(mode.effective_mode, AccountMode::Current);
    assert!(mode.requires_fresh_review);
    assert_eq!(
        bridge.dry_run(plan.plan_id).unwrap_err(),
        CommandError::StalePlan
    );
    assert_eq!(
        bridge.get_settings().unwrap().account_mode,
        AccountMode::Current
    );
    drop(bridge);
    thread.join().unwrap();
}
struct AskGate {
    open: std::cell::Cell<bool>,
    survives: std::cell::Cell<bool>,
    identity: std::cell::Cell<u32>,
    closes: std::cell::Cell<usize>,
}
impl ProcessGate for AskGate {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
        Ok(if self.open.get() {
            vec![ProcessPreview {
                identity: format!("fixture-process-{}", self.identity.get()),
                label: "synthetic program".into(),
                unsaved_work_loss: true,
            }]
        } else {
            vec![]
        })
    }
    fn close(&self, policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        assert_eq!(policy, ProcessClosePolicy::Ask);
        self.closes.set(self.closes.get() + 1);
        if self.survives.get() {
            Err(ErrorKind::Locked)
        } else {
            self.open.set(false);
            Ok(())
        }
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        if self.open.get() {
            Err(ErrorKind::Locked)
        } else {
            Ok(())
        }
    }
}
#[test]
fn ask_close_is_reviewed_consumes_plan_and_never_deletes_targets() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, true);
    let gate = AskGate {
        open: true.into(),
        survives: true.into(),
        identity: 1.into(),
        closes: 0.into(),
    };
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &gate,
    )
    .unwrap();
    let classified = CategoryFixture(&provider);
    let mut session = CurrentSession::new(
        &provider,
        vec![(Category::WindowsMicrosoftAndDevTools, &classified)],
    );
    let before = folders.snapshot().unwrap();
    let scan = session.scan().unwrap();
    let plan = session
        .build_plan(select(scan), ProcessClosePolicy::Ask)
        .unwrap();
    let item = &plan.report.accounts[0].sections[2].items[0];
    assert!(!item.processes.is_empty());
    assert!(item
        .actions
        .iter()
        .any(|a| a.bytes.is_some_and(|n| n > 0.0)));
    for risk in [true, false] {
        let mut approval = approve(&plan);
        if risk {
            approval.confirmed_risks.clear();
        } else {
            approval.category_tokens.clear();
        }
        assert_eq!(
            session.close_reviewed(approval).unwrap_err(),
            CommandError::ConfirmationRequired
        );
    }
    assert_eq!(gate.closes.get(), 0);
    gate.identity.set(2);
    assert_eq!(
        session.close_reviewed(approve(&plan)).unwrap_err(),
        CommandError::StalePlan
    );
    gate.identity.set(1);
    let locked = session.close_reviewed(approve(&plan)).unwrap();
    assert!(locked.accounts[0].sections[2].items[0].locked);
    assert_eq!(folders.snapshot().unwrap(), before);
    assert_eq!(
        session.dry_run(&plan.plan_id).unwrap_err(),
        CommandError::StalePlan
    );
    gate.survives.set(false);
    let scan = session.scan().unwrap();
    let plan = session
        .build_plan(select(scan), ProcessClosePolicy::Ask)
        .unwrap();
    session.close_reviewed(approve(&plan)).unwrap();
    assert!(!gate.open.get());
    assert_eq!(folders.snapshot().unwrap(), before);
    let scan = session.scan().unwrap();
    let plan = session
        .build_plan(select(scan), ProcessClosePolicy::Ask)
        .unwrap();
    assert!(plan.report.accounts[0].sections[2].items[0]
        .processes
        .is_empty());
    let report = session
        .execute(approve(&plan), &|| false, &mut |_| {})
        .unwrap();
    assert!(report.accounts[0].sections[2].succeeded > 0);
}
#[test]
fn skipped_only_plan_reports_choice_without_confirmations_or_mutation() {
    let folders = FixtureFolders::create().unwrap();
    let json = fixture(&folders, true);
    let provider = ManifestExecutor::load(
        &json,
        &folders,
        UserId("current-account".into()),
        InstallationId("chrome".into()),
        &Gate,
    )
    .unwrap();
    let mut session = CurrentSession::new(&provider, vec![(Category::Browser, &provider)]);
    let scan = session.scan().unwrap();
    let mut selection = select(scan);
    for ids in [
        vec!["foreign-item".into()],
        vec![selection.items[0].clone(), selection.items[0].clone()],
    ] {
        let mut invalid = selection.clone();
        invalid.items.clear();
        invalid.skipped = Some(ids);
        assert_eq!(
            session
                .build_plan(invalid, ProcessClosePolicy::Ask)
                .unwrap_err(),
            CommandError::InvalidSelection
        );
    }
    let before = folders.snapshot().unwrap();
    selection.skipped = Some(std::mem::take(&mut selection.items));
    let plan = session
        .build_plan(selection, ProcessClosePolicy::Ask)
        .unwrap();
    assert_eq!(plan.report.skipped.len(), 1);
    assert!(plan.report.accounts[0]
        .sections
        .iter()
        .all(|s| s.status == AggregateStatus::NotRequested));
    assert!(plan.category_tokens.is_empty());
    let report = session
        .execute(approve(&plan), &|| false, &mut |_| {})
        .unwrap();
    assert_eq!(report.skipped[0].provider, "chrome");
    assert_eq!(folders.snapshot().unwrap(), before);
    let export =
        everyout_lib::reports::export(folders.path(), &report, ExportFormat::Text).unwrap();
    let content = fs::read_to_string(
        folders
            .path()
            .join(export.strip_prefix("reports/").unwrap()),
    )
    .unwrap();
    assert!(content.contains("Skipped by choice"));
    assert!(!content.contains("synthetic-session"));
}
