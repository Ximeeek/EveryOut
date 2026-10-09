use everyout_core_model::*;

fn plan(evidence: ScopeEvidence) -> ProposedPlan {
    ProposedPlan {
        scope_evidence: evidence,
        plan_id: PlanId("fixture-plan".into()),
        provider_id: ProviderId("fixture".into()),
        manifest_revision: 1,
        support: Support::Validated,
        selection: Selection {
            snapshot_id: SnapshotId("fixture".into()),
            account_mode: AccountMode::Current,
            instances: vec![InstanceId("fixture".into())],
            profiles: vec![],
        },
        actions: vec![PlannedAction {
            action_id: ActionId("fixture".into()),
            artifact_id: ArtifactId("fixture".into()),
            root_id: RootId("fixture".into()),
            profile_id: None,
            method_id: "fixture".into(),
            method: MethodKind::DeleteFileFamily,
            owner: OwnerIdentity {
                user_id: UserId("fixture".into()),
                installation_id: InstallationId("fixture".into()),
                root_id: RootId("fixture".into()),
            },
            shared_owners: vec![],
            artifact_families: vec!["fixture".into()],
            effects: vec![],
            blockers: vec![],
            confirmations: vec![],
        }],
        risks: RiskAssessment {
            flags: vec![],
            affected_data: vec![],
            permanent_data_loss: LossAssessment::None,
            reason: None,
            confirmations: vec![],
            evidence: vec![],
        },
        blockers: vec![],
        confirmations: vec![],
        limitations: vec![],
    }
}
#[test]
fn closure_and_framework_hints_cannot_be_confirmed_into_permission() {
    for state in [
        AuthenticationScope::Unknown,
        AuthenticationScope::Observed,
        AuthenticationScope::FrameworkHint,
    ] {
        let mut evidence = ScopeEvidence::reviewed_catalog(LossAssessment::None);
        evidence.authentication_scope =
            EvidenceState::new(state, "framework-inference", "fixture-observation");
        let mut proposed = plan(evidence);
        proposed
            .confirmations
            .push(ConfirmationId("review-candidate-provider-fixture".into()));
        let trace = proposed.decision_trace();
        assert!(!trace.action_allowed);
        assert!(trace
            .blocked_by
            .contains(&"unknown-authentication-closure".into()));
        assert_eq!(
            ValidatedPlan::review(proposed.clone(), &proposed.confirmations),
            Err(ErrorKind::Unsupported)
        );
        assert_eq!(proposed.decision_trace(), trace);
    }
}
#[test]
fn known_losses_need_confirmation_but_unknown_preservation_is_a_hard_blocker() {
    let mut proposed = plan(ScopeEvidence::reviewed_catalog(LossAssessment::Known));
    proposed.risks.permanent_data_loss = LossAssessment::Known;
    proposed.risks.flags.push(RiskFlag::SettingsOrProfiles);
    proposed
        .risks
        .confirmations
        .push(ConfirmationId("review-known-loss".into()));
    assert!(proposed.decision_trace().action_allowed);
    assert_eq!(
        ValidatedPlan::review(proposed.clone(), &[]),
        Err(ErrorKind::ScopeViolation)
    );
    let accepted = proposed.risks.confirmations.clone();
    assert!(ValidatedPlan::review(proposed.clone(), &accepted).is_ok());
    proposed.scope_evidence.preservation.state = PreservationState::Unknown;
    assert_eq!(
        ValidatedPlan::review(proposed, &accepted),
        Err(ErrorKind::Unsupported)
    );
}
#[test]
fn missing_evidence_in_legacy_json_fails_closed() {
    let mut value =
        serde_json::to_value(plan(ScopeEvidence::reviewed_catalog(LossAssessment::None))).unwrap();
    value.as_object_mut().unwrap().remove("scope_evidence");
    let legacy: ProposedPlan = serde_json::from_value(value).unwrap();
    assert!(!legacy.decision_trace().action_allowed);
    assert_eq!(
        ValidatedPlan::review(legacy, &[]),
        Err(ErrorKind::Unsupported)
    );
}

#[test]
fn changing_a_state_without_provenance_does_not_create_evidence() {
    let mut evidence = ScopeEvidence::reviewed_catalog(LossAssessment::None);
    evidence.authentication_scope = EvidenceState::new(
        AuthenticationScope::Validated,
        "missing-evidence",
        "evidence-not-available",
    );
    let trace = plan(evidence).decision_trace();
    assert!(!trace.action_allowed);
    assert!(trace
        .blocked_by
        .contains(&"evidence-provenance-missing".into()));
    let example = ProductValidationRecord::parse(include_str!(
        "../../../docs/testing/product-validation-record.example.json"
    ))
    .unwrap();
    assert_eq!(example.status, ValidationStatus::Incomplete);
    assert!(
        !plan(example.bind(None).unwrap())
            .decision_trace()
            .action_allowed
    );
}
#[test]
fn adapter_authority_is_bounded_to_spotify_and_cannot_be_reused_for_generic_deletion() {
    let mut proposed = plan(ScopeEvidence::reviewed_catalog(LossAssessment::None));
    proposed.support = Support::Candidate;
    proposed.scope_evidence.authority = OperationAuthority::SpotifySavedLogin;
    proposed
        .confirmations
        .push(ConfirmationId("review-candidate-provider-spotify".into()));
    assert!(!proposed.decision_trace().action_allowed);
    proposed.provider_id = ProviderId("spotify".into());
    assert!(!proposed.decision_trace().action_allowed);
    proposed.actions[0].method = MethodKind::ExceptionAdapter;
    assert!(proposed.decision_trace().action_allowed);
    assert!(ValidatedPlan::review(proposed.clone(), &proposed.confirmations).is_ok());
    proposed.scope_evidence.version_applicability.state = VersionApplicability::Stale;
    assert_eq!(
        ValidatedPlan::review(proposed.clone(), &proposed.confirmations),
        Err(ErrorKind::Unsupported)
    );
}

fn record() -> ProductValidationRecord {
    ProductValidationRecord {
        format_version: 1,
        application_id: "fixture-app".into(),
        channel: "stable".into(),
        product_identity: ProductIdentity {
            executable_name: "Fixture.exe".into(),
            product_name: "Fixture".into(),
            sha256: Some("a".repeat(64)),
            publisher: Some("Fixture Publisher".into()),
            signature_identity: Some("fixture-signature".into()),
        },
        tested_version: "1.0.0".into(),
        storage_layout: "fixture-layout-v1".into(),
        artifact_families: vec!["local-storage".into()],
        storage_ownership: StorageOwnership::Exclusive,
        authentication_closure: ClosureResult::SignedOut,
        preservation: PreservationState::Validated,
        known_losses: vec![],
        repetitions: 2,
        test_date: "2026-10-09".into(),
        validation_method: ValidationMethod::DisposableVm,
        status: ValidationStatus::Validated,
    }
}
fn observed(record: &ProductValidationRecord) -> ObservedProduct {
    ObservedProduct {
        application_id: record.application_id.clone(),
        channel: record.channel.clone(),
        product_identity: record.product_identity.clone(),
        version: record.tested_version.clone(),
        storage_layout: record.storage_layout.clone(),
        artifact_families: record.artifact_families.clone(),
    }
}
#[test]
fn product_record_requires_real_closure_repetitions_preservation_and_a_vm_method() {
    let original = record();
    let encoded = serde_json::to_string(&original).unwrap();
    assert_eq!(ProductValidationRecord::parse(&encoded).unwrap(), original);
    for key in [
        "repetitions",
        "authentication_closure",
        "validation_method",
        "test_date",
        "preservation",
    ] {
        let mut value = serde_json::to_value(&original).unwrap();
        value[key] = match key {
            "repetitions" => serde_json::json!(1),
            "authentication_closure" => serde_json::json!("still-signed-in"),
            "validation_method" => serde_json::json!("synthetic-safety"),
            "test_date" => serde_json::json!("2026-02-30"),
            _ => serde_json::json!("unknown"),
        };
        assert!(
            ProductValidationRecord::parse(&value.to_string()).is_err(),
            "{key}"
        );
    }
    let mut value = serde_json::to_value(&original).unwrap();
    value["credential_blob"] = serde_json::json!("forbidden fixture property");
    assert!(ProductValidationRecord::parse(&value.to_string()).is_err());
}
#[test]
fn version_channel_identity_and_layout_changes_require_revalidation() {
    let record = record();
    let original = observed(&record);
    assert!(
        plan(record.bind(Some(&original)).unwrap())
            .decision_trace()
            .action_allowed
    );
    assert!(
        !plan(record.bind(None).unwrap())
            .decision_trace()
            .action_allowed
    );
    for change in ["version", "channel", "hash", "layout", "scope"] {
        let mut actual = original.clone();
        match change {
            "version" => actual.version = "2.0.0".into(),
            "channel" => actual.channel = "canary".into(),
            "hash" => actual.product_identity.sha256 = Some("b".repeat(64)),
            "layout" => actual.storage_layout = "fixture-layout-v2".into(),
            _ => actual.artifact_families.push("network".into()),
        }
        let evidence = record.bind(Some(&actual)).unwrap();
        assert_eq!(
            evidence.version_applicability.state,
            VersionApplicability::Stale
        );
        let trace = plan(evidence).decision_trace();
        assert!(!trace.action_allowed);
        assert!(trace
            .blocked_by
            .contains(&"product-version-revalidation-required".into()));
    }
}
#[test]
fn observed_and_synthetic_records_never_become_product_validation() {
    let mut record = record();
    record.status = ValidationStatus::Observed;
    record.validation_method = ValidationMethod::ExistingLocalAdapter;
    record.repetitions = 20;
    let evidence = record.bind(Some(&observed(&record))).unwrap();
    assert_eq!(
        evidence.authentication_scope.state,
        AuthenticationScope::Observed
    );
    assert!(!plan(evidence).decision_trace().action_allowed);
    record.validation_method = ValidationMethod::SyntheticSafety;
    assert_eq!(
        record.validate(),
        Err("synthetic-authentication-proof-not-allowed")
    );
    record.authentication_closure = ClosureResult::Inconclusive;
    let evidence = record.bind(Some(&observed(&record))).unwrap();
    assert_eq!(
        evidence.authentication_scope.state,
        AuthenticationScope::Unknown
    );
}
