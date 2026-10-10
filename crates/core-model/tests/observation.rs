use everyout_core_model::{observation::*, *};
use std::collections::{BTreeMap, BTreeSet};

fn binding() -> ApplicationBinding {
    ApplicationBinding {
        identity: EvidenceState::new(
            ApplicationIdentity::Exact,
            "physical-identity",
            "selected-physical-executable",
        ),
        executable_path: "C:/fixture/TotallyUnknownApp-7193.exe".into(),
        executable: FileIdentity {
            volume: 1,
            index: 10,
        },
        executable_size: 90,
        executable_write_ticks: 10,
        publisher: None,
        signature: None,
        signature_status: "unsigned".into(),
        version: Some("1".into()),
        channel: None,
        framework: vec![],
        framework_fingerprint: vec![],
        selected_process: None,
    }
}
fn metadata(tick: u64) -> EntryMetadata {
    EntryMetadata {
        directory: false,
        size: tick,
        created_ticks: 1,
        write_ticks: tick,
        change_ticks: tick,
        attributes: 0,
        identity: FileIdentity {
            volume: 1,
            index: 20,
        },
        parent: Some(FileIdentity {
            volume: 1,
            index: 30,
        }),
    }
}
fn cycle(valid: bool) -> TeachCycle {
    let order = [
        TeachPhase::ClosedBaseline,
        TeachPhase::LaunchLoggedOut,
        TeachPhase::Login,
        TeachPhase::SettledLoggedIn,
        TeachPhase::RestartPersistence,
        TeachPhase::VendorLogout,
        TeachPhase::ClosedLoggedOut,
    ];
    TeachCycle {
        phases: order
            .into_iter()
            .enumerate()
            .map(|(i, phase)| {
                let mut entries = BTreeMap::new();
                entries.insert("Cache/rotating-entry".into(), metadata(i as u64));
                entries.insert("Logs/activity.log".into(), metadata(i as u64));
                entries.insert("Persistent/settings.bin".into(), metadata(3));
                if valid && (2..=4).contains(&i) {
                    entries.insert("Local Storage/leveldb/000123.ldb".into(), metadata(8));
                }
                PhaseObservation {
                    phase,
                    started_at_ms: i as u64,
                    ended_at_ms: i as u64 + 1,
                    snapshots: vec![MetadataSnapshot {
                        root: "C:/Local/SomeVendor/RandomProfile82".into(),
                        root_identity: FileIdentity {
                            volume: 1,
                            index: 30,
                        },
                        entries,
                        completeness: Completeness::Complete,
                        captured_at_ms: i as u64,
                        provenance: vec![provenance(
                            "metadata-snapshot",
                            "bounded-handle-enumeration",
                        )],
                    }],
                    changed_families: BTreeMap::new(),
                    completeness: Completeness::Complete,
                    signed_in: Some((2..=4).contains(&i)),
                    processes: vec![],
                    provenance: vec![provenance("teach-phase", "user-labelled-session-state")],
                }
            })
            .collect(),
    }
}
fn session(cycles: Vec<TeachCycle>) -> TeachSession {
    let mut session = TeachSession::new("fixture".into(), binding(), 1).unwrap();
    session.roots = vec!["C:/Local/SomeVendor/RandomProfile82".into()];
    session.cycles = cycles;
    session
}
fn auth(record: &LearnedObservation) -> &FamilyObservation {
    record.roots[0]
        .families
        .iter()
        .find(|f| f.family == "local storage")
        .unwrap()
}

#[test]
fn unknown_app_two_complete_cycles_are_observed_and_always_blocked() {
    let record = analyze(
        &session(vec![cycle(true), cycle(true)]),
        &BTreeSet::new(),
        90,
    );
    assert_eq!(record.status, LearnedStatus::Observed);
    assert_eq!(auth(&record).verdict, ObservationVerdict::StronglyObserved);
    let evidence = record.evidence(&record.roots[0], auth(&record));
    assert_eq!(
        evidence.application_identity.state,
        ApplicationIdentity::Exact
    );
    assert_eq!(
        evidence.storage_ownership.state,
        StorageOwnership::Corroborated
    );
    assert_eq!(
        evidence.authentication_scope.state,
        AuthenticationScope::Observed
    );
    assert_eq!(evidence.preservation.state, PreservationState::Unknown);
    assert_eq!(evidence.authority, OperationAuthority::Unreviewed);
    assert!(
        !evidence
            .decide(Support::Validated, &[], LossAssessment::None, &[], &[])
            .action_allowed
    );
    assert!(evidence
        .authentication_scope
        .provenance
        .iter()
        .all(|p| p.source == "teach-observation"));
    for family in record.roots[0]
        .families
        .iter()
        .filter(|f| f.family == "cache" || f.family == "logs")
    {
        assert_eq!(family.class, ArtifactClass::BackgroundNoise);
        assert_eq!(family.verdict, ObservationVerdict::Noise);
    }
}
#[test]
fn one_cycle_and_user_labels_cannot_promote_authentication() {
    let record = analyze(&session(vec![cycle(true)]), &BTreeSet::new(), 90);
    assert_eq!(record.status, LearnedStatus::Candidate);
    assert_eq!(
        record
            .evidence(&record.roots[0], auth(&record))
            .authentication_scope
            .state,
        AuthenticationScope::Unknown
    );
    let record = analyze(
        &session(vec![cycle(false), cycle(false)]),
        &BTreeSet::new(),
        90,
    );
    assert_eq!(record.status, LearnedStatus::Candidate);
    assert!(record.roots[0].families.iter().all(|f| record
        .evidence(&record.roots[0], f)
        .authentication_scope
        .state
        != AuthenticationScope::Validated));
}
#[test]
fn contradictory_cycles_remain_inconclusive_even_with_two_positive_cycles() {
    let record = analyze(
        &session(vec![cycle(true), cycle(false), cycle(true)]),
        &BTreeSet::new(),
        90,
    );
    assert_eq!(auth(&record).verdict, ObservationVerdict::Inconclusive);
    assert_eq!(record.status, LearnedStatus::Candidate);
}
#[test]
fn recovered_endpoint_never_supplies_missing_negative_history() {
    let mut overflowed = cycle(true);
    overflowed.phases[1].completeness = Completeness::RecoveredByRescan;
    overflowed.phases[1].snapshots[0].completeness = Completeness::RecoveredByRescan;
    let record = analyze(
        &session(vec![overflowed, cycle(true)]),
        &BTreeSet::new(),
        90,
    );
    assert_eq!(record.status, LearnedStatus::Candidate);
    assert!(!auth(&record).cycles[0].complete);
}
#[test]
fn missing_phase_or_failed_restart_is_not_a_complete_login_logout_cycle() {
    let mut partial = cycle(true);
    partial.phases.remove(4);
    let mut signed_out_restart = cycle(true);
    signed_out_restart.phases[4].signed_in = Some(false);
    for failed in [partial, signed_out_restart] {
        assert_eq!(
            analyze(&session(vec![failed, cycle(true)]), &BTreeSet::new(), 90).status,
            LearnedStatus::Candidate
        );
    }
}
#[test]
fn rotating_database_and_cache_members_normalize_to_bounded_families() {
    for path in [
        "Local Storage/leveldb/000123.log",
        "Local Storage/leveldb/000124.ldb",
        "Local Storage/leveldb/MANIFEST-000122",
    ] {
        assert_eq!(artifact_family(path), "local storage");
    }
    for path in [
        "Profile/auth.db",
        "Profile/auth.db-wal",
        "Profile/auth.db-shm",
        "Profile/auth.db-journal",
    ] {
        assert_eq!(artifact_family(path), "profile/auth.db");
    }
    for path in [
        "Profile/IndexedDB/a.leveldb/123.log",
        "Profile/IndexedDB/b.leveldb/456.ldb",
    ] {
        assert_eq!(artifact_family(path), "profile/indexeddb");
    }
    assert_eq!(
        artifact_family("Profile/Session Storage/rotating-file"),
        "profile/session storage"
    );
}
#[test]
fn executable_version_channel_framework_and_layout_invalidate_without_erasing_history() {
    let original = session(vec![cycle(true), cycle(true)]);
    for field in 0..4 {
        let mut changed = binding();
        match field {
            0 => changed.executable.index += 1,
            1 => changed.version = Some("2".into()),
            2 => changed.channel = Some("beta".into()),
            _ => changed.framework = vec!["cef".into()],
        }
        let mut active = original.clone();
        assert!(!active.revalidate(&changed));
        assert_eq!(
            analyze(&active, &BTreeSet::new(), 90).status,
            LearnedStatus::Stale
        );
        assert_eq!(active.cycles.len(), 2);
        let mut record = analyze(&original, &BTreeSet::new(), 90);
        record.invalidate(&changed, &[]);
        assert_eq!(record.status, LearnedStatus::Stale);
        assert_eq!(record.cycles, 2);
    }
    let mut record = analyze(&original, &BTreeSet::new(), 90);
    record.invalidate(&binding(), &[]);
    assert_eq!(record.status, LearnedStatus::NeedsReobservation);
    assert_eq!(
        record
            .evidence(&record.roots[0], auth(&record))
            .authentication_scope
            .state,
        AuthenticationScope::Unknown
    );
}
#[test]
fn shared_root_and_restart_manager_never_grant_exclusivity_or_authentication() {
    let mut session = session(vec![cycle(true), cycle(true)]);
    session.provenance.push(provenance(
        "restart-manager",
        "bounded-active-resource-corroboration",
    ));
    let shared = session.roots.iter().cloned().collect();
    let record = analyze(&session, &shared, 90);
    assert_eq!(
        record.roots[0].ownership.state,
        StorageOwnership::SharedConflict
    );
    assert!(
        !record
            .evidence(&record.roots[0], auth(&record))
            .decide(Support::Candidate, &[], LossAssessment::None, &[], &[])
            .action_allowed
    );
    session.cycles.clear();
    let record = analyze(&session, &BTreeSet::new(), 90);
    assert_eq!(record.status, LearnedStatus::Candidate);
}

#[test]
fn unnamed_continuous_activity_is_noise_without_cache_name_rules() {
    let mut cycles = vec![cycle(true), cycle(true)];
    for phase in cycles.iter_mut().flat_map(|c| &mut c.phases) {
        let entry = phase.snapshots[0]
            .entries
            .remove("Cache/rotating-entry")
            .unwrap();
        phase.snapshots[0]
            .entries
            .insert("OpaqueStore/random-data".into(), entry);
    }
    let record = analyze(&session(cycles), &BTreeSet::new(), 90);
    let noise = record.roots[0]
        .families
        .iter()
        .find(|f| f.family == "opaquestore")
        .unwrap();
    assert_eq!(noise.class, ArtifactClass::BackgroundNoise);
}

#[test]
fn physical_root_change_between_cycles_prevents_evidence_promotion() {
    let mut changed = cycle(true);
    for phase in &mut changed.phases {
        phase.snapshots[0].root_identity.index += 1;
    }
    let record = analyze(&session(vec![cycle(true), changed]), &BTreeSet::new(), 90);
    assert_eq!(record.status, LearnedStatus::Candidate);
    assert_eq!(auth(&record).verdict, ObservationVerdict::Inconclusive);
}

#[test]
fn published_example_is_typed_observation_and_cannot_accept_validation_or_authority() {
    let example = include_str!("../../../docs/architecture/examples/learned-observation.json");
    let record: LearnedObservation = serde_json::from_str(example).unwrap();
    let root = &record.roots[0];
    assert_eq!(
        record
            .evidence(root, &root.families[0])
            .authentication_scope
            .state,
        AuthenticationScope::Observed
    );
    assert_eq!(
        record.evidence(root, &root.families[0]).authority,
        OperationAuthority::Unreviewed
    );
    let mut edited: serde_json::Value = serde_json::from_str(example).unwrap();
    edited["status"] = serde_json::json!("validated");
    assert!(serde_json::from_value::<LearnedObservation>(edited).is_err());
    let mut edited: serde_json::Value = serde_json::from_str(example).unwrap();
    edited["authority"] = serde_json::json!("reviewed-catalog");
    assert!(serde_json::from_value::<LearnedObservation>(edited).is_err());
}

#[test]
fn ipc_file_identity_preserves_all_bits_without_javascript_number_rounding() {
    let identity = FileIdentity {
        volume: u32::MAX,
        index: u64::MAX,
    };
    let serialized = serde_json::to_value(identity).unwrap();
    assert_eq!(serialized["index"], "18446744073709551615");
    assert_eq!(
        serde_json::from_value::<FileIdentity>(serialized).unwrap(),
        identity
    );
}
