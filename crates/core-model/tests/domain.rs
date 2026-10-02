use everyout_core_model::*;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

fn round_trip<T: Serialize + DeserializeOwned + PartialEq + Debug>(value: &T) {
    assert_eq!(
        *value,
        serde_json::from_str::<T>(&serde_json::to_string(value).unwrap()).unwrap()
    );
}
fn issue() -> ProviderIssue {
    ProviderIssue {
        phase: Phase::Execute,
        provider_id: ProviderId("fixture".into()),
        instance_id: Some(InstanceId("instance-1".into())),
        action_id: Some(ActionId("action-1".into())),
        kind: ErrorKind::Locked,
        os_code: Some(32),
        explanation_code: "artifact-locked".into(),
        blocked: true,
    }
}
fn owner() -> OwnerIdentity {
    OwnerIdentity {
        user_id: UserId("user-1".into()),
        installation_id: InstallationId("install-1".into()),
        root_id: RootId("root-1".into()),
    }
}
fn risks() -> RiskAssessment {
    RiskAssessment {
        flags: vec![RiskFlag::DraftsOrOfflineMessages],
        affected_data: vec!["drafts".into()],
        permanent_data_loss: LossAssessment::Known,
        reason: Some("drafts-in-session-family".into()),
        confirmations: vec![ConfirmationId("confirm-drafts".into())],
        evidence: vec![EvidenceRef("fixture".into())],
    }
}
fn description() -> ProviderDescription {
    ProviderDescription {
        descriptor: ProviderDescriptor {
            provider_id: ProviderId("fixture".into()),
            name: "Fixture".into(),
            category: Category::Application,
            revision: 1,
            support: Support::Validated,
            evidence: vec![EvidenceRef("fixture".into())],
            limitations: vec!["no-authentication-proof".into()],
        },
        instance_id: InstanceId("instance-1".into()),
        profiles: vec![ProfileScope {
            profile_id: ProfileId("profile-1".into()),
            root_id: RootId("root-1".into()),
        }],
        risks: risks(),
        expected_effects: vec!["remove-fixture".into()],
    }
}
fn proposed() -> ProposedPlan {
    ProposedPlan {
        plan_id: PlanId("plan-1".into()),
        provider_id: ProviderId("fixture".into()),
        manifest_revision: 1,
        support: Support::Validated,
        selection: Selection {
            snapshot_id: SnapshotId("snapshot-1".into()),
            account_mode: AccountMode::Current,
            instances: vec![InstanceId("instance-1".into())],
            profiles: vec![ProfileId("profile-1".into())],
        },
        actions: vec![PlannedAction {
            action_id: ActionId("action-1".into()),
            artifact_id: ArtifactId("artifact-1".into()),
            root_id: RootId("root-1".into()),
            profile_id: Some(ProfileId("profile-1".into())),
            method_id: "remove-fixture".into(),
            method: MethodKind::DeleteFileFamily,
            owner: owner(),
            shared_owners: vec![],
            artifact_families: vec!["fixture-session".into()],
            effects: vec!["remove-fixture".into()],
            blockers: vec![],
            confirmations: vec![ConfirmationId("confirm-action".into())],
        }],
        risks: risks(),
        blockers: vec![],
        confirmations: vec![ConfirmationId("confirm-plan".into())],
        limitations: vec!["no-authentication-proof".into()],
    }
}
fn result() -> ProviderResult {
    ProviderResult {
        description: description(),
        execution: ExecutionResult {
            plan_id: PlanId("plan-1".into()),
            mode: ExecutionMode::Apply,
            outcomes: vec![
                ActionOutcome {
                    action_id: ActionId("action-1".into()),
                    status: ActionStatus::Applied,
                    issues: vec![],
                },
                ActionOutcome {
                    action_id: ActionId("action-2".into()),
                    status: ActionStatus::Failed,
                    issues: vec![issue()],
                },
            ],
            issues: vec![issue()],
        },
        verification: VerificationResult {
            plan_id: PlanId("plan-1".into()),
            artifacts: vec![ArtifactVerification {
                artifact_id: ArtifactId("artifact-1".into()),
                status: VerificationStatus::TargetAbsent,
                observation: Some(MetadataObservation {
                    artifact_id: ArtifactId("artifact-1".into()),
                    kind: ArtifactKind::File,
                    exists: false,
                    size: None,
                }),
                issues: vec![],
            }],
            issues: vec![],
        },
        aggregate: AggregateStatus::Partial,
    }
}
#[test]
fn domain_serialization_retains_partial_results_and_scope() {
    round_trip(&proposed());
    round_trip(&result());
    round_trip(&owner());
    let instance = ProviderInstance {
        provider_id: ProviderId("fixture".into()),
        instance_id: InstanceId("instance-1".into()),
        owner: owner(),
        profiles: description().profiles,
        confidence: Confidence::Medium,
        detection_origin: DetectionOrigin::KnownProvider,
        evidence: vec![EvidenceRef("fixture".into())],
        issues: vec![issue()],
    };
    let mut old_json = serde_json::to_value(&instance).unwrap();
    old_json.as_object_mut().unwrap().remove("detection_origin");
    let legacy: ProviderInstance = serde_json::from_value(old_json).unwrap();
    assert_eq!(legacy.detection_origin, DetectionOrigin::Heuristic);
    round_trip(&DetectionResult {
        snapshot_id: SnapshotId("snapshot-1".into()),
        instances: vec![instance],
        observations: vec![MetadataObservation {
            artifact_id: ArtifactId("artifact-1".into()),
            kind: ArtifactKind::File,
            exists: true,
            size: Some(4096),
        }],
        issues: vec![],
    });
    let result = result();
    let report = SanitizedReport {
        applications: vec![ReportItem {
            provider_id: ProviderId("fixture".into()),
            instance_id: InstanceId("instance-1".into()),
            user_id: UserId("user-1".into()),
            profiles: vec![ProfileId("profile-1".into())],
            shared_effects: vec![],
            aggregate: AggregateStatus::Partial,
            outcomes: result.execution.outcomes,
            verification: result.verification.artifacts,
            issues: vec![issue()],
            risk_flags: risks().flags,
            limitations: vec!["no-authentication-proof".into()],
            authentication: Uncertainty::Unknown,
            browser_identity: Uncertainty::NotRequested,
            sync: Uncertainty::NotRequested,
            silent_sso: Uncertainty::Unknown,
            remote_revocation: Uncertainty::Unsupported,
        }],
        browsers: vec![],
        windows_microsoft_and_dev_tools: vec![],
    };
    round_trip(&report);
    let serialized = serde_json::to_value(report).unwrap();
    let item = &serialized["applications"][0];
    assert!(item.get("owner").is_none());
    assert!(item.get("root_id").is_none());
    assert_eq!(item["aggregate"], "partial");
    assert_eq!(item["remote_revocation"], "unsupported");
}
#[test]
fn exact_architecture_vocabulary_round_trips() {
    for category in [
        Category::Application,
        Category::Browser,
        Category::WindowsMicrosoftAndDevTools,
    ] {
        round_trip(&category);
    }
    for confidence in [Confidence::High, Confidence::Medium, Confidence::Low] {
        round_trip(&confidence);
    }
    for status in [
        ActionStatus::WouldApply,
        ActionStatus::Applied,
        ActionStatus::AlreadyAbsent,
        ActionStatus::Skipped,
        ActionStatus::Blocked,
        ActionStatus::Failed,
    ] {
        round_trip(&status);
    }
    for status in [
        VerificationStatus::TargetAbsent,
        VerificationStatus::TargetPresent,
        VerificationStatus::Inaccessible,
        VerificationStatus::Unknown,
        VerificationStatus::NotPerformed,
    ] {
        round_trip(&status);
    }
    for kind in [
        ErrorKind::AccessDenied,
        ErrorKind::Locked,
        ErrorKind::OwnershipConflict,
        ErrorKind::StalePlan,
        ErrorKind::Unsupported,
        ErrorKind::InvalidManifest,
        ErrorKind::ScopeViolation,
        ErrorKind::SecurityProductBlocked,
        ErrorKind::Cancelled,
        ErrorKind::Io,
    ] {
        round_trip(&kind);
    }
    for flag in [
        RiskFlag::LocalOnlyDocuments,
        RiskFlag::DraftsOrOfflineMessages,
        RiskFlag::SettingsOrProfiles,
        RiskFlag::WalletOrKeyMaterial,
        RiskFlag::VaultOr2faRecovery,
        RiskFlag::SavedPasswordsPasskeysAutofillHistory,
        RiskFlag::SharedStore,
        RiskFlag::Unknown,
    ] {
        round_trip(&flag);
    }
    assert_eq!(
        serde_json::to_string(&RiskFlag::VaultOr2faRecovery).unwrap(),
        "\"vault-or-2fa-recovery\""
    );
    assert_eq!(
        serde_json::to_string(&Category::WindowsMicrosoftAndDevTools).unwrap(),
        "\"windows-microsoft-and-dev-tools\""
    );
}
#[test]
fn review_never_promotes_candidates_or_waives_preservation() {
    let accepted = [
        ConfirmationId("confirm-plan".into()),
        ConfirmationId("confirm-action".into()),
        ConfirmationId("confirm-drafts".into()),
    ];
    let reviewed = ValidatedPlan::review(proposed(), &accepted).unwrap();
    assert_eq!(reviewed.plan(), &proposed());
    assert_eq!(
        ValidatedPlan::review(proposed(), &[]),
        Err(ErrorKind::ScopeViolation)
    );
    let mut plan = proposed();
    plan.support = Support::Candidate;
    assert_eq!(
        ValidatedPlan::review(plan, &accepted),
        Err(ErrorKind::Unsupported)
    );
    let mut plan = proposed();
    plan.actions[0].blockers.push("ownership-conflict".into());
    assert_eq!(
        ValidatedPlan::review(plan, &accepted),
        Err(ErrorKind::Unsupported)
    );
    let mut plan = proposed();
    plan.risks.permanent_data_loss = LossAssessment::Unknown;
    assert_eq!(
        ValidatedPlan::review(plan, &accepted),
        Err(ErrorKind::Unsupported)
    );
    let mut plan = proposed();
    plan.risks
        .flags
        .push(RiskFlag::SavedPasswordsPasskeysAutofillHistory);
    assert_eq!(
        ValidatedPlan::review(plan, &accepted),
        Err(ErrorKind::Unsupported)
    );
    // No Deserialize implementation exists for ValidatedPlan; review is not an IPC endpoint.
}
struct FixtureProvider;
impl Provider for FixtureProvider {
    fn detect(&self, cx: &DetectionContext<'_>) -> DetectionResult {
        DetectionResult {
            snapshot_id: cx.snapshot_id.clone(),
            instances: vec![],
            observations: vec![],
            issues: vec![],
        }
    }
    fn describe(&self, _: &ProviderInstance) -> ProviderDescription {
        description()
    }
    fn plan(&self, _: &PlanContext<'_>, _: &Selection) -> PlanResult {
        PlanResult::Ready(Box::new(proposed()))
    }
    fn execute(
        &self,
        _: &OperationContext<'_>,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult {
        ExecutionResult {
            plan_id: plan.plan().plan_id.clone(),
            mode,
            outcomes: vec![ActionOutcome {
                action_id: plan.plan().actions[0].action_id.clone(),
                status: if mode == ExecutionMode::DryRun {
                    ActionStatus::WouldApply
                } else {
                    ActionStatus::Applied
                },
                issues: vec![],
            }],
            issues: vec![],
        }
    }
    fn verify(&self, _: &VerificationContext<'_>, result: &ExecutionResult) -> VerificationResult {
        VerificationResult {
            plan_id: result.plan_id.clone(),
            artifacts: vec![ArtifactVerification {
                artifact_id: ArtifactId("artifact-1".into()),
                status: if result.mode == ExecutionMode::DryRun {
                    VerificationStatus::NotPerformed
                } else {
                    VerificationStatus::Unknown
                },
                observation: None,
                issues: vec![],
            }],
            issues: vec![],
        }
    }
    fn report(&self, _: &ProviderResult) -> SanitizedReport {
        SanitizedReport {
            applications: vec![],
            browsers: vec![],
            windows_microsoft_and_dev_tools: vec![],
        }
    }
}
#[test]
fn provider_contract_is_object_safe_and_revoke_is_reserved() {
    let provider: &dyn Provider = &FixtureProvider;
    assert_eq!(
        provider.revoke().unwrap_err().to_string(),
        "not supported in V1"
    );
}
