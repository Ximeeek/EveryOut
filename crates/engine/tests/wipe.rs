#![cfg(windows)]

use everyout_core_model::*;
use everyout_engine::*;
use everyout_platform_windows::{AllowedRoot, FixtureFolders, KnownFolder, RootResolver};
use std::{
    cell::{Cell, RefCell},
    fs::OpenOptions,
    os::windows::fs::OpenOptionsExt,
};

const BASE: &str = "Chromium/User Data/Default/Network";
const FILES: [&str; 3] = ["Cookies", "Cookies-wal", "Cookies-shm"];
fn owner() -> OwnerIdentity {
    OwnerIdentity {
        user_id: UserId("fixture-user".into()),
        installation_id: InstallationId("fixture-install".into()),
        root_id: RootId("fixture-root".into()),
    }
}
fn risk(flags: Vec<RiskFlag>) -> RiskAssessment {
    RiskAssessment {
        permanent_data_loss: if flags.is_empty() {
            LossAssessment::None
        } else {
            LossAssessment::Known
        },
        flags,
        affected_data: vec![],
        reason: None,
        confirmations: vec![],
        evidence: vec![],
    }
}
struct Operations {
    root: AllowedRoot,
    mutations: Cell<usize>,
    deny_verify: Cell<bool>,
}
impl MetadataAccess for Operations {
    fn observe(
        &self,
        requested: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind> {
        if requested != &owner() || !FILES.contains(&artifact.0.as_str()) {
            return Err(ErrorKind::ScopeViolation);
        }
        if self.deny_verify.get() && self.mutations.get() > 0 {
            return Err(ErrorKind::AccessDenied);
        }
        let metadata = self
            .root
            .path(&format!("{BASE}/{}", artifact.0))
            .map_err(|e| e.kind)?
            .probe()
            .map_err(|e| e.kind)?;
        Ok(MetadataObservation {
            artifact_id: artifact.clone(),
            kind: ArtifactKind::File,
            exists: metadata.exists,
            size: Some(metadata.size),
        })
    }
}
impl LocalOperations for Operations {
    fn apply(&self, plan: &ValidatedPlan, id: &ActionId) -> ActionOutcome {
        self.mutations.set(self.mutations.get() + 1);
        let action = plan
            .plan()
            .actions
            .iter()
            .find(|a| &a.action_id == id)
            .unwrap();
        match self
            .root
            .path(&format!("{BASE}/{}", action.artifact_id.0))
            .and_then(|path| path.delete_file(false))
        {
            Ok(result) => ActionOutcome {
                action_id: id.clone(),
                status: result.status,
                issues: vec![],
            },
            Err(error) => ActionOutcome {
                action_id: id.clone(),
                status: ActionStatus::Failed,
                issues: vec![ProviderIssue {
                    phase: Phase::Execute,
                    provider_id: plan.plan().provider_id.clone(),
                    instance_id: Some(InstanceId("fixture-instance".into())),
                    action_id: Some(id.clone()),
                    kind: error.kind,
                    os_code: error.os_code,
                    explanation_code: "fixture-error".into(),
                    blocked: true,
                }],
            },
        }
    }
}
struct LabProvider {
    instance: &'static str,
    files: Vec<&'static str>,
    category: Category,
    flags: Vec<RiskFlag>,
    confidence: Confidence,
    detection_origin: DetectionOrigin,
    support: Support,
    resolved_owner: bool,
    revision: Cell<u64>,
    close_error: Cell<Option<ErrorKind>>,
    close_calls: Cell<usize>,
    identity_calls: Cell<usize>,
    relaunch_after: Cell<Option<usize>>,
    validations: Cell<usize>,
    cancel_after: Cell<Option<usize>>,
    cancelled: Cell<bool>,
    counterfeit: Cell<bool>,
    reckless_preview: Cell<bool>,
    process_revision: Cell<u64>,
}
impl LabProvider {
    fn new(category: Category) -> Self {
        Self {
            instance: "fixture-instance",
            files: FILES.to_vec(),
            category,
            flags: vec![],
            confidence: Confidence::High,
            detection_origin: DetectionOrigin::KnownProvider,
            support: Support::Validated,
            resolved_owner: true,
            revision: Cell::new(1),
            close_error: Cell::new(None),
            close_calls: Cell::new(0),
            identity_calls: Cell::new(0),
            relaunch_after: Cell::new(None),
            validations: Cell::new(0),
            cancel_after: Cell::new(None),
            cancelled: Cell::new(false),
            counterfeit: Cell::new(false),
            reckless_preview: Cell::new(false),
            process_revision: Cell::new(1),
        }
    }
}
impl Provider for LabProvider {
    fn detect(&self, cx: &DetectionContext<'_>) -> DetectionResult {
        assert_eq!(cx.account_mode, AccountMode::Current);
        DetectionResult {
            snapshot_id: cx.snapshot_id.clone(),
            instances: vec![ProviderInstance {
                provider_id: ProviderId("test-only".into()),
                instance_id: InstanceId(self.instance.into()),
                owner: if self.resolved_owner {
                    owner()
                } else {
                    OwnerIdentity {
                        root_id: RootId(String::new()),
                        ..owner()
                    }
                },
                profiles: vec![],
                confidence: self.confidence,
                detection_origin: self.detection_origin,
                evidence: vec![],
                issues: vec![],
            }],
            observations: FILES
                .iter()
                .filter_map(|name| {
                    cx.metadata
                        .observe(&owner(), &ArtifactId((*name).into()))
                        .ok()
                })
                .collect(),
            issues: vec![],
        }
    }
    fn describe(&self, instance: &ProviderInstance) -> ProviderDescription {
        ProviderDescription {
            descriptor: ProviderDescriptor {
                provider_id: instance.provider_id.clone(),
                name: "Synthetic fixture".into(),
                category: self.category,
                revision: self.revision.get(),
                support: self.support,
                evidence: vec![],
                limitations: vec!["dbsc-key-reference-coverage-unknown".into()],
            },
            instance_id: instance.instance_id.clone(),
            profiles: vec![],
            risks: risk(self.flags.clone()),
            expected_effects: vec!["remove-synthetic-cookie-family".into()],
        }
    }
    fn plan(&self, _cx: &PlanContext<'_>, selected: &Selection) -> PlanResult {
        PlanResult::Ready(Box::new(ProposedPlan {
            plan_id: PlanId("fixture-plan".into()),
            provider_id: ProviderId("test-only".into()),
            manifest_revision: self.revision.get(),
            support: self.support,
            selection: selected.clone(),
            actions: self
                .files
                .iter()
                .map(|name| PlannedAction {
                    action_id: ActionId((*name).into()),
                    artifact_id: ArtifactId((*name).into()),
                    root_id: owner().root_id.clone(),
                    profile_id: None,
                    method_id: "delete-fixture-file".into(),
                    method: MethodKind::DeleteFileFamily,
                    owner: owner(),
                    shared_owners: vec![],
                    artifact_families: vec!["synthetic-cookie-family".into()],
                    effects: vec!["delete-file".into()],
                    blockers: vec![],
                    confirmations: vec![],
                })
                .collect(),
            risks: risk(self.flags.clone()),
            blockers: vec![],
            confirmations: vec![],
            limitations: vec!["dbsc-key-reference-coverage-unknown".into()],
        }))
    }
    fn execute(
        &self,
        cx: &OperationContext<'_>,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult {
        let mut outcomes = Vec::new();
        for (index, action) in plan.plan().actions.iter().enumerate() {
            if (cx.cancelled)() {
                break;
            }
            let outcome = if mode == ExecutionMode::DryRun && self.reckless_preview.get() {
                cx.operations.apply(plan, &action.action_id)
            } else if mode == ExecutionMode::DryRun {
                ActionOutcome {
                    action_id: action.action_id.clone(),
                    status: ActionStatus::WouldApply,
                    issues: vec![],
                }
            } else if self.counterfeit.get() {
                ActionOutcome {
                    action_id: action.action_id.clone(),
                    status: ActionStatus::Applied,
                    issues: vec![],
                }
            } else {
                cx.operations.apply(plan, &action.action_id)
            };
            outcomes.push(outcome);
            if mode == ExecutionMode::Apply && self.cancel_after.get() == Some(index + 1) {
                self.cancelled.set(true);
            }
        }
        ExecutionResult {
            plan_id: plan.plan().plan_id.clone(),
            mode,
            outcomes,
            issues: vec![],
        }
    }
    fn verify(
        &self,
        cx: &VerificationContext<'_>,
        _result: &ExecutionResult,
    ) -> VerificationResult {
        VerificationResult {
            plan_id: cx.plan.plan().plan_id.clone(),
            artifacts: vec![],
            issues: vec![],
        }
    }
    fn report(&self, _result: &ProviderResult) -> SanitizedReport {
        SanitizedReport {
            applications: vec![],
            browsers: vec![],
            windows_microsoft_and_dev_tools: vec![],
        }
    }
}
impl EngineProvider for LabProvider {
    fn process_preview(&self, _plan: &ProposedPlan) -> Result<Vec<ProcessPreview>, ErrorKind> {
        if self.process_revision.get() == 1 {
            Ok(vec![])
        } else {
            Ok(vec![ProcessPreview {
                identity: "new-process".into(),
                label: "Synthetic process".into(),
                unsaved_work_loss: true,
            }])
        }
    }
    fn close(&self, _plan: &ValidatedPlan, _policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        self.close_calls.set(self.close_calls.get() + 1);
        self.close_error.get().map_or(Ok(()), Err)
    }
    fn revalidate(&self, _plan: &ValidatedPlan) -> Result<(), ErrorKind> {
        self.validations.set(self.validations.get() + 1);
        if self
            .relaunch_after
            .get()
            .is_some_and(|count| self.validations.get() >= count)
        {
            Err(ErrorKind::Locked)
        } else {
            Ok(())
        }
    }
    fn identity_sync(&self, _plan: &ValidatedPlan) -> Result<Option<IdentitySync>, ErrorKind> {
        self.identity_calls.set(self.identity_calls.get() + 1);
        Ok(None)
    }
    fn target_label(&self, action: &PlannedAction) -> String {
        format!("fixture-root/{BASE}/{}", action.artifact_id.0)
    }
}
fn setup() -> (FixtureFolders, Operations) {
    let fixture = FixtureFolders::profiles(18).unwrap();
    let ops = Operations {
        root: fixture.resolve(KnownFolder::LocalAppData).unwrap(),
        mutations: Cell::new(0),
        deny_verify: Cell::new(false),
    };
    (fixture, ops)
}
fn prepare<'a>(
    engine: &Engine<'a>,
    provider: &'a LabProvider,
    events: &mut dyn FnMut(Progress),
) -> PreparedRun<'a> {
    let inventory = engine.scan(&[provider], provider.category, events).unwrap();
    let selection = inventory.default_selection(provider.category);
    engine
        .prepare(
            inventory,
            provider.category,
            &selection,
            ProcessClosePolicy::Ask,
            events,
        )
        .unwrap()
}
fn item(report: &RunReport) -> &ItemReport {
    report
        .sections
        .iter()
        .find_map(|s| s.items.first())
        .unwrap()
}

#[test]
fn full_run_verifies_family_preserves_canaries_and_reports_no_contents() {
    let (fixture, ops) = setup();
    let provider = LabProvider::new(Category::Browser);
    let engine = Engine::new(owner().user_id, &ops);
    let sentinel = "synthetic-content-must-never-appear";
    std::fs::write(
        fixture.path().join(format!("LocalAppData/{BASE}/Cookies")),
        sentinel,
    )
    .unwrap();
    let before = fixture.snapshot().unwrap();
    let events = RefCell::new(Vec::new());
    let run = prepare(&engine, &provider, &mut |e| events.borrow_mut().push(e));
    let report = engine.apply(run, Approval::default(), &|| false, &mut |e| {
        events.borrow_mut().push(e)
    });
    let result = item(&report);
    assert_eq!(result.aggregate, AggregateStatus::CompleteLocalScope);
    assert!(result
        .actions
        .iter()
        .all(|a| a.outcome.status == ActionStatus::Applied
            && a.verification.status == VerificationStatus::TargetAbsent));
    assert_eq!(result.identity_sync.identity, Uncertainty::Unknown);
    assert_eq!(result.remote_revocation, Uncertainty::Unsupported);
    assert_eq!(provider.close_calls.get(), 1);
    assert_eq!(provider.identity_calls.get(), 1);
    before.assert_nothing_else_changed(
        &fixture.snapshot().unwrap(),
        &FILES
            .map(|name| format!("LocalAppData/{BASE}/{name}"))
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>(),
    );
    let json = report.json().unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["sections"].as_array().unwrap().len(), 3);
    assert!(report
        .sections
        .iter()
        .filter(|s| s.category != Category::Browser)
        .all(|s| s.aggregate == AggregateStatus::NotRequested));
    assert!(json.contains("dbsc-key-reference-coverage-unknown"));
    assert!(report.text().contains("Cookies"));
    // A synthetic content sentinel never enters the metadata/report pipeline.
    assert!(!json.contains(sentinel));
    assert!(!report.text().contains(sentinel));
    let stages: Vec<_> = events.borrow().iter().map(|e| e.stage).collect();
    for stage in [
        Stage::Scan,
        Stage::Selection,
        Stage::DryRun,
        Stage::Review,
        Stage::Closing,
        Stage::Cleaning,
        Stage::IdentitySync,
        Stage::Verification,
        Stage::Report,
    ] {
        assert!(stages.contains(&stage));
    }
}

#[test]
fn dry_run_has_no_filesystem_or_process_effects() {
    let (fixture, ops) = setup();
    let provider = LabProvider::new(Category::Application);
    let before = fixture.snapshot().unwrap();
    let engine = Engine::new(owner().user_id, &ops);
    let run = prepare(&engine, &provider, &mut |_| {});
    assert_eq!(run.preview().mode, ExecutionMode::DryRun);
    assert!(item(run.preview())
        .actions
        .iter()
        .all(|a| a.outcome.status == ActionStatus::WouldApply
            && a.verification.status == VerificationStatus::NotPerformed));
    before.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
    assert_eq!(ops.mutations.get(), 0);
    assert_eq!(provider.close_calls.get(), 0);
    assert_eq!(provider.identity_calls.get(), 0);
}

#[test]
fn second_run_is_already_absent_and_changes_nothing() {
    let (fixture, ops) = setup();
    let provider = LabProvider::new(Category::Application);
    let engine = Engine::new(owner().user_id, &ops);
    let run = prepare(&engine, &provider, &mut |_| {});
    engine.apply(run, Approval::default(), &|| false, &mut |_| {});
    let before = fixture.snapshot().unwrap();
    let run = prepare(&engine, &provider, &mut |_| {});
    let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
    assert_eq!(item(&report).aggregate, AggregateStatus::CompleteLocalScope);
    assert!(item(&report)
        .actions
        .iter()
        .all(|a| a.outcome.status == ActionStatus::AlreadyAbsent));
    before.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
}

#[test]
fn locked_companion_is_partial_and_identity_hook_still_runs() {
    let (fixture, ops) = setup();
    let provider = LabProvider::new(Category::Browser);
    let engine = Engine::new(owner().user_id, &ops);
    let lock = OpenOptions::new()
        .read(true)
        .share_mode(1 | 2)
        .open(
            fixture
                .path()
                .join(format!("LocalAppData/{BASE}/Cookies-wal")),
        )
        .unwrap();
    let run = prepare(&engine, &provider, &mut |_| {});
    let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
    assert_eq!(item(&report).aggregate, AggregateStatus::Partial);
    assert_eq!(
        item(&report).actions[0].outcome.status,
        ActionStatus::Applied
    );
    assert_eq!(
        item(&report).actions[1].outcome.status,
        ActionStatus::Failed
    );
    assert_eq!(
        item(&report).actions[1].outcome.issues[0].kind,
        ErrorKind::Locked
    );
    assert_eq!(
        item(&report).actions[1].verification.status,
        VerificationStatus::TargetPresent
    );
    assert_eq!(
        item(&report).actions[2].outcome.status,
        ActionStatus::Applied
    );
    assert_eq!(provider.identity_calls.get(), 1);
    drop(lock);
}

#[test]
fn both_risk_and_special_category_gates_are_required_and_plan_bound() {
    for category_ok in [false, true] {
        for risk_ok in [false, true] {
            let (fixture, ops) = setup();
            let mut provider = LabProvider::new(Category::WindowsMicrosoftAndDevTools);
            provider.flags = vec![
                RiskFlag::DraftsOrOfflineMessages,
                RiskFlag::LocalOnlyDocuments,
            ];
            let engine = Engine::new(owner().user_id, &ops);
            let before = fixture.snapshot().unwrap();
            let run = prepare(&engine, &provider, &mut |_| {});
            assert!(run.preview().text().contains(WINDOWS_DEV_SSO_WARNING));
            assert!(item(run.preview())
                .plan
                .as_ref()
                .unwrap()
                .limitations
                .iter()
                .any(|s| s == WINDOWS_DEV_SSO_WARNING));
            let approval = Approval {
                category_confirmation: category_ok.then(|| run.confirm_category()),
                confirmed_risks: if risk_ok {
                    vec![run.confirm_risks(&InstanceId("fixture-instance".into()), &provider.flags)]
                } else {
                    vec![]
                },
                ..Default::default()
            };
            let report = engine.apply(run, approval, &|| false, &mut |_| {});
            assert!(report.text().contains(WINDOWS_DEV_SSO_WARNING));
            assert!(report.json().unwrap().contains("Windows SSO"));
            if category_ok && risk_ok {
                assert_eq!(item(&report).aggregate, AggregateStatus::CompleteLocalScope);
            } else {
                assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
                assert_eq!(ops.mutations.get(), 0);
                before.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
            }
        }
    }
    let (_fixture, ops) = setup();
    let provider = LabProvider::new(Category::WindowsMicrosoftAndDevTools);
    let engine = Engine::new(owner().user_id, &ops);
    let old = prepare(&engine, &provider, &mut |_| {});
    let token = old.confirm_category();
    let new = prepare(&engine, &provider, &mut |_| {});
    let report = engine.apply(
        new,
        Approval {
            category_confirmation: Some(token),
            ..Default::default()
        },
        &|| false,
        &mut |_| {},
    );
    assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
    assert_eq!(ops.mutations.get(), 0);
}

#[test]
fn special_category_warning_survives_an_empty_selection() {
    let (_fixture, ops) = setup();
    let engine = Engine::new(owner().user_id, &ops);
    let category = Category::WindowsMicrosoftAndDevTools;
    let inventory = engine.scan(&[], category, &mut |_| {}).unwrap();
    let run = engine
        .prepare(
            inventory,
            category,
            &[],
            ProcessClosePolicy::Ask,
            &mut |_| {},
        )
        .unwrap();
    assert!(run.preview().text().contains(WINDOWS_DEV_SSO_WARNING));
    assert!(run
        .preview()
        .sections
        .iter()
        .filter(|s| s.category != category)
        .all(|s| s.warnings.is_empty()));
    let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
    assert!(report.text().contains(WINDOWS_DEV_SSO_WARNING));
    assert!(report.json().unwrap().contains("Windows SSO"));
    assert_eq!(ops.mutations.get(), 0);
}

#[test]
fn stale_revision_and_changed_metadata_require_new_review() {
    for revision_changed in [true, false] {
        let (fixture, ops) = setup();
        let provider = LabProvider::new(Category::Application);
        let engine = Engine::new(owner().user_id, &ops);
        let run = prepare(&engine, &provider, &mut |_| {});
        if revision_changed {
            provider.revision.set(2);
        } else {
            std::fs::write(
                fixture.path().join(format!("LocalAppData/{BASE}/Cookies")),
                b"different-synthetic-size",
            )
            .unwrap();
        }
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
        assert_eq!(
            item(&report).issues.last().unwrap().kind,
            ErrorKind::StalePlan
        );
        assert_eq!(ops.mutations.get(), 0);
        assert_eq!(provider.close_calls.get(), 0);
    }
}

#[test]
fn cancellation_retains_completed_action_and_verifies_remaining_targets() {
    let (_fixture, ops) = setup();
    let provider = LabProvider::new(Category::Application);
    provider.cancel_after.set(Some(1));
    let engine = Engine::new(owner().user_id, &ops);
    let run = prepare(&engine, &provider, &mut |_| {});
    let report = engine.apply(
        run,
        Approval::default(),
        &|| provider.cancelled.get(),
        &mut |_| {},
    );
    assert_eq!(item(&report).aggregate, AggregateStatus::Cancelled);
    assert_eq!(
        item(&report).actions[0].outcome.status,
        ActionStatus::Applied
    );
    assert_eq!(
        item(&report).actions[1].outcome.status,
        ActionStatus::Skipped
    );
    assert_eq!(
        item(&report).actions[1].verification.status,
        VerificationStatus::TargetPresent
    );
    assert_eq!(ops.mutations.get(), 1);
    assert_eq!(provider.identity_calls.get(), 0);
}

#[test]
fn surviving_or_relaunched_processes_block_dependent_actions() {
    for relaunched in [false, true] {
        let (_fixture, ops) = setup();
        let provider = LabProvider::new(Category::Browser);
        if relaunched {
            provider.relaunch_after.set(Some(2));
        } else {
            provider.close_error.set(Some(ErrorKind::Locked));
        }
        let engine = Engine::new(owner().user_id, &ops);
        let run = prepare(&engine, &provider, &mut |_| {});
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        assert_eq!(ops.mutations.get(), if relaunched { 1 } else { 0 });
        assert_eq!(
            item(&report).aggregate,
            if relaunched {
                AggregateStatus::Partial
            } else {
                AggregateStatus::Blocked
            }
        );
        assert!(item(&report).actions.iter().all(|a| a.verification.status
            == if relaunched {
                VerificationStatus::Unknown
            } else {
                VerificationStatus::TargetPresent
            }));
    }
}

#[test]
fn inaccessible_verification_and_counterfeit_success_never_claim_completion() {
    for counterfeit in [false, true] {
        let (_fixture, ops) = setup();
        let provider = LabProvider::new(Category::Application);
        provider.counterfeit.set(counterfeit);
        ops.deny_verify.set(!counterfeit);
        let engine = Engine::new(owner().user_id, &ops);
        let run = prepare(&engine, &provider, &mut |_| {});
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        assert_eq!(
            item(&report).aggregate,
            if counterfeit {
                AggregateStatus::Blocked
            } else {
                AggregateStatus::Partial
            }
        );
        assert!(item(&report).actions.iter().all(|a| a.verification.status
            == if counterfeit {
                VerificationStatus::TargetPresent
            } else {
                VerificationStatus::Inaccessible
            }));
    }
}

#[test]
fn provenance_and_low_confidence_candidate_policy_control_selection() {
    let (_fixture, ops) = setup();
    let engine = Engine::new(owner().user_id, &ops);
    for category in [
        Category::Application,
        Category::Browser,
        Category::WindowsMicrosoftAndDevTools,
    ] {
        for confidence in [Confidence::High, Confidence::Medium, Confidence::Low] {
            for support in [Support::Validated, Support::Candidate] {
                for origin in [DetectionOrigin::KnownProvider, DetectionOrigin::Heuristic] {
                    let mut provider = LabProvider::new(category);
                    provider.confidence = confidence;
                    provider.support = support;
                    provider.detection_origin = origin;
                    let inventory = engine.scan(&[&provider], category, &mut |_| {}).unwrap();
                    assert_eq!(
                        inventory.default_selection(category).len(),
                        usize::from(
                            origin == DetectionOrigin::KnownProvider
                                && !(category == Category::Application
                                    && support == Support::Candidate
                                    && confidence == Confidence::Low)
                        )
                    );
                }
            }
        }
    }
    assert_eq!(ops.mutations.get(), 0);
}

#[test]
fn unresolved_owner_cannot_enter_the_executable_inventory() {
    let (_fixture, ops) = setup();
    let engine = Engine::new(owner().user_id, &ops);
    let mut provider = LabProvider::new(Category::Application);
    provider.resolved_owner = false;
    assert!(matches!(
        engine.scan(&[&provider], Category::Application, &mut |_| {}),
        Err(ErrorKind::OwnershipConflict)
    ));
    assert_eq!(ops.mutations.get(), 0);
}

#[test]
fn medium_confidence_is_unchecked_and_preservation_risk_cannot_be_confirmed_away() {
    let (_fixture, ops) = setup();
    let mut provider = LabProvider::new(Category::Application);
    provider.confidence = Confidence::Medium;
    provider.detection_origin = DetectionOrigin::Heuristic;
    let engine = Engine::new(owner().user_id, &ops);
    let inventory = engine
        .scan(&[&provider], Category::Application, &mut |_| {})
        .unwrap();
    assert!(inventory
        .default_selection(Category::Application)
        .is_empty());
    provider.confidence = Confidence::High;
    provider.detection_origin = DetectionOrigin::KnownProvider;
    provider.flags = vec![RiskFlag::SavedPasswordsPasskeysAutofillHistory];
    let run = prepare(&engine, &provider, &mut |_| {});
    let approval = Approval {
        confirmed_risks: vec![
            run.confirm_risks(&InstanceId("fixture-instance".into()), &provider.flags)
        ],
        ..Default::default()
    };
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
    assert_eq!(ops.mutations.get(), 0);
}

#[test]
fn one_blocked_instance_does_not_abort_an_independent_instance() {
    let (_fixture, ops) = setup();
    let mut blocked = LabProvider::new(Category::Application);
    blocked.files = vec!["Cookies"];
    blocked.close_error.set(Some(ErrorKind::Locked));
    let mut eligible = LabProvider::new(Category::Application);
    eligible.instance = "independent-instance";
    eligible.files = vec!["Cookies-wal", "Cookies-shm"];
    let engine = Engine::new(owner().user_id, &ops);
    let inventory = engine
        .scan(&[&blocked, &eligible], Category::Application, &mut |_| {})
        .unwrap();
    let selected = inventory.default_selection(Category::Application);
    let run = engine
        .prepare(
            inventory,
            Category::Application,
            &selected,
            ProcessClosePolicy::Ask,
            &mut |_| {},
        )
        .unwrap();
    let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
    let section = &report.sections[0];
    assert_eq!(section.aggregate, AggregateStatus::Partial);
    assert_eq!(section.items[0].aggregate, AggregateStatus::Blocked);
    assert_eq!(
        section.items[1].aggregate,
        AggregateStatus::CompleteLocalScope
    );
    assert_eq!(section.counts.succeeded, 2);
    assert_eq!(section.counts.locked, 1);
    assert_eq!(ops.mutations.get(), 2);
}

#[test]
fn preview_denies_a_provider_mutation_attempt_and_new_processes_invalidate_review() {
    for reckless in [true, false] {
        let (fixture, ops) = setup();
        let provider = LabProvider::new(Category::Application);
        provider.reckless_preview.set(reckless);
        let engine = Engine::new(owner().user_id, &ops);
        let before = fixture.snapshot().unwrap();
        let run = prepare(&engine, &provider, &mut |_| {});
        if !reckless {
            provider.process_revision.set(2);
        }
        let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
        assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
        assert_eq!(ops.mutations.get(), 0);
        assert_eq!(provider.close_calls.get(), 0);
        before.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
    }
}

#[test]
fn wrong_engine_unknown_selection_and_force_close_without_acknowledgment_are_refused() {
    let (_fixture, ops) = setup();
    let provider = LabProvider::new(Category::Application);
    let engine = Engine::new(owner().user_id, &ops);
    let other = Engine::new(owner().user_id, &ops);
    let run = prepare(&engine, &provider, &mut |_| {});
    let report = other.apply(run, Approval::default(), &|| false, &mut |_| {});
    assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
    let inventory = engine
        .scan(&[&provider], Category::Application, &mut |_| {})
        .unwrap();
    assert!(matches!(
        engine.prepare(
            inventory,
            Category::Application,
            &[InstanceId("unknown".into())],
            ProcessClosePolicy::Ask,
            &mut |_| {}
        ),
        Err(ErrorKind::ScopeViolation)
    ));
    let inventory = engine
        .scan(&[&provider], Category::Application, &mut |_| {})
        .unwrap();
    let selected = inventory.default_selection(Category::Application);
    let run = engine
        .prepare(
            inventory,
            Category::Application,
            &selected,
            ProcessClosePolicy::HardKillAfter2s,
            &mut |_| {},
        )
        .unwrap();
    assert_eq!(
        run.preview().process_close_policy,
        ProcessClosePolicy::HardKillAfter2s
    );
    let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
    assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
    assert_eq!(ops.mutations.get(), 0);
    assert_eq!(provider.close_calls.get(), 0);
}

#[test]
fn a_subset_of_risks_does_not_confirm_the_other_flags() {
    let (_fixture, ops) = setup();
    let mut provider = LabProvider::new(Category::Application);
    provider.flags = vec![
        RiskFlag::LocalOnlyDocuments,
        RiskFlag::DraftsOrOfflineMessages,
    ];
    let engine = Engine::new(owner().user_id, &ops);
    let run = prepare(&engine, &provider, &mut |_| {});
    let approval = Approval {
        confirmed_risks: vec![run.confirm_risks(
            &InstanceId("fixture-instance".into()),
            &[RiskFlag::LocalOnlyDocuments],
        )],
        ..Default::default()
    };
    let report = engine.apply(run, approval, &|| false, &mut |_| {});
    assert_eq!(item(&report).aggregate, AggregateStatus::Blocked);
    assert_eq!(ops.mutations.get(), 0);
}
