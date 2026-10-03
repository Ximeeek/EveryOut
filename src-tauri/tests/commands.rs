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
    let plan = bridge.build_plan(select(scan)).unwrap();
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
