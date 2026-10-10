use everyout_core_model::{local_validation::*, observation::*, *};
use std::collections::BTreeMap;

fn trial() -> TrialEvidence {
    TrialEvidence {
        scope: vec![FamilyScope {
            root: "C:/synthetic/unknown".into(),
            family: "local storage".into(),
        }],
        purpose: TrialPurpose::FinalRepeat,
        a1: AppOutcome::SignedIn,
        b: AppOutcome::SignedOut,
        a2: AppOutcome::SignedIn,
        rollback_verified: true,
        complete_metadata: true,
        collateral_families: vec![],
        result: CausalResult::Inconclusive,
    }
}
#[test]
fn signed_out_intervention_requires_reversal_and_complete_metadata() {
    let mut evidence = trial();
    evidence.classify();
    assert_eq!(evidence.result, CausalResult::Sufficient);
    for outcome in [AppOutcome::SignedOut, AppOutcome::Unclear] {
        let mut evidence = trial();
        evidence.a2 = outcome;
        evidence.classify();
        assert_eq!(
            evidence.result,
            CausalResult::FailedRestoreOrExternalStateChange
        );
    }
    let mut evidence = trial();
    evidence.b = AppOutcome::SignedIn;
    evidence.classify();
    assert_eq!(evidence.result, CausalResult::Insufficient);
    let mut evidence = trial();
    evidence.complete_metadata = false;
    evidence.classify();
    assert_eq!(evidence.result, CausalResult::Inconclusive);
    let mut evidence = trial();
    evidence.rollback_verified = false;
    evidence.classify();
    assert_eq!(
        evidence.result,
        CausalResult::FailedRestoreOrExternalStateChange
    );
}
#[test]
fn incomplete_or_contradictory_p2_family_cannot_become_validation_candidate() {
    let mut family = FamilyObservation {
        family: "local storage".into(),
        class: ArtifactClass::CorrelatedAuthCandidate,
        verdict: ObservationVerdict::StronglyObserved,
        cycles: vec![
            CycleDifferential {
                complete: true,
                changed: [false; 6],
                persisted: true,
                login_logout: true
            };
            2
        ],
    };
    assert!(approved_family(&family));
    family.cycles[1].complete = false;
    assert!(!approved_family(&family));
    family.cycles[1].complete = true;
    family.cycles[1].login_logout = false;
    assert!(!approved_family(&family));
    family.cycles[1].login_logout = true;
    family.verdict = ObservationVerdict::Noise;
    assert!(!approved_family(&family));
}
#[test]
fn bounded_search_checks_all_smaller_subsets_without_monotonicity() {
    let families: Vec<_> = (0..6)
        .map(|i| FamilyScope {
            root: "synthetic".into(),
            family: format!("family-{i}"),
        })
        .collect();
    let scopes = search_scopes(&families);
    assert_eq!(scopes.len(), MAX_SEARCH_TRIALS);
    assert!(scopes[..6].iter().all(|s| s.len() == 1));
    assert!(scopes[6..21].iter().all(|s| s.len() == 2));
    assert!(scopes.windows(2).all(|w| w[0].len() <= w[1].len()));
}
#[test]
fn local_authority_projection_requires_exact_identity_and_causal_evidence() {
    let mut evidence = ScopeEvidence::reviewed_catalog(LossAssessment::Known);
    evidence.authority = OperationAuthority::LocalBounded;
    evidence.authentication_scope.state = AuthenticationScope::LocallyValidated;
    evidence.preservation.state = PreservationState::BoundedKnownLosses;
    let decision = |e: &ScopeEvidence| {
        e.decide(
            Support::Candidate,
            &[],
            LossAssessment::Known,
            &[RiskFlag::SettingsOrProfiles],
            &[ConfirmationId("local-bounded-losses".into())],
        )
    };
    assert!(!decision(&evidence).action_allowed);
    evidence.application_identity.state = ApplicationIdentity::Exact;
    assert!(decision(&evidence).action_allowed);
    evidence.storage_ownership.state = StorageOwnership::SharedConflict;
    assert!(!decision(&evidence).action_allowed);
    evidence.storage_ownership.state = StorageOwnership::Corroborated;
    evidence.authentication_scope.state = AuthenticationScope::Observed;
    assert!(!decision(&evidence).action_allowed);
    evidence.authentication_scope.state = AuthenticationScope::LocallyValidated;
    evidence.version_applicability.state = VersionApplicability::Stale;
    assert!(!decision(&evidence).action_allowed);
}
#[test]
fn collateral_analysis_preserves_unknown_for_missing_root_or_incomplete_snapshot() {
    // No real paths or payloads are opened by this domain test.
    let binding: ApplicationBinding = serde_json::from_value(serde_json::json!({
        "identity": {"state":"exact", "provenance":[]}, "executable_path":"synthetic.exe", "executable":{"volume":1,"index":"1"},
        "executable_size":"1", "executable_write_ticks":"1", "publisher":null,"signature":null,"signature_status":"unsigned",
        "version":null,"channel":null,"framework":[],"framework_fingerprint":[],"selected_process":null
    })).unwrap();
    let learned = LearnedObservation {
        session_id: "synthetic".into(),
        binding,
        roots: vec![RootObservation {
            root: "synthetic-root".into(),
            physical: FileIdentity {
                volume: 1,
                index: 2,
            },
            layout: vec![],
            families: vec![],
            ownership: EvidenceState::default(),
        }],
        status: LearnedStatus::Observed,
        completeness: Completeness::Complete,
        cycles: 2,
        recorded_at_ms: 0,
        provenance: vec![],
    };
    assert!(collateral(&[], &[], &[], &[], &[], &learned).is_none());
    let snapshot = MetadataSnapshot {
        root: "synthetic-root".into(),
        root_identity: learned.roots[0].physical,
        entries: BTreeMap::new(),
        completeness: Completeness::Incomplete,
        captured_at_ms: 0,
        provenance: vec![],
    };
    let snapshots = vec![snapshot];
    assert!(collateral(
        &snapshots,
        &snapshots,
        &snapshots,
        &snapshots,
        &[],
        &learned
    )
    .is_none());
}

#[test]
fn documented_local_rule_and_journal_are_typed_metadata_without_global_authority() {
    let mut rule: LocalValidatedRule = serde_json::from_str(include_str!(
        "../../../docs/architecture/examples/local-validated-rule.json"
    ))
    .unwrap();
    assert!(rule.qualified());
    assert_eq!(
        rule.decision().evidence.authority,
        OperationAuthority::LocalBounded
    );
    assert_eq!(rule.decision().support, Support::Candidate);
    assert_eq!(rule.repetitions, 2);
    assert_ne!(rule.preservation, PreservationState::Validated);
    rule.trials[1].b = AppOutcome::SignedIn;
    assert!(!rule.qualified());
    rule.trials[1].b = AppOutcome::SignedOut;
    rule.trials.retain(|t| t.purpose != TrialPurpose::Search);
    assert!(!rule.qualified());
    let journal: ValidationJournal = serde_json::from_str(include_str!(
        "../../../docs/architecture/examples/p3-validation-journal.json"
    ))
    .unwrap();
    assert_eq!(journal.stage, JournalStage::Completed);
    assert!(journal
        .slots
        .iter()
        .all(|s| s.stage == SlotStage::Cleaned && s.original != s.generated));
    let before: DecisionTrace = serde_json::from_str(include_str!(
        "../../../docs/architecture/examples/p3-decision-before.json"
    ))
    .unwrap();
    let after: DecisionTrace = serde_json::from_str(include_str!(
        "../../../docs/architecture/examples/p3-decision-after.json"
    ))
    .unwrap();
    assert!(!before.action_allowed);
    assert!(after.action_allowed);
}

#[test]
fn validation_effects_have_no_payload_read_copy_or_generic_credential_primitive() {
    let validation = include_str!("../../platform-windows/src/validation.rs");
    let journal = include_str!("../../platform-windows/src/validation/journal.rs");
    for source in [validation, journal] {
        for forbidden in [
            "fs::copy(",
            "CopyFile",
            "MOVEFILE_COPY_ALLOWED",
            "MoveFileTransacted",
            "CreateTransaction",
            "CredDelete",
            "RegDelete",
            "ReadFile(",
        ] {
            assert!(
                !source.contains(forbidden),
                "unexpected primitive {forbidden}"
            );
        }
    }
    assert!(!validation.contains("read_to_end"));
    assert!(!validation.contains("FILE_READ_DATA"));
    assert!(journal.contains("T: serde::de::DeserializeOwned"));
    assert!(journal.contains("self.load(\"journal\")"));
    assert!(journal.contains("self.load(\"rule\")"));
}
