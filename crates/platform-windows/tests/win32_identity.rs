#![cfg(windows)]
use everyout_core_model::*;
use everyout_platform_windows::{win32_identity::*, FixtureFolders};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn executable(fixture: &FixtureFolders, name: &str) -> PathBuf {
    let path = fixture.path().join("installation").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    // Own compiled test image; no installed product is required or executed.
    fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    path
}
fn selected(path: &Path) -> Win32Snapshot {
    let mut snapshot = Win32Snapshot::default();
    snapshot
        .observe_executable(path, IdentitySource::Selected, None)
        .unwrap();
    snapshot
}
#[test]
fn process_source_requires_pid_and_creation_time() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "Portable.exe");
    for process in [
        None,
        Some(ProcessIdentity {
            pid: 100,
            creation_ticks: 0,
        }),
        Some(ProcessIdentity {
            pid: 0,
            creation_ticks: 10,
        }),
    ] {
        let mut snapshot = Win32Snapshot::default();
        assert!(snapshot
            .observe_executable(&path, IdentitySource::Process, process)
            .is_err());
        assert!(snapshot.applications.is_empty());
    }
}
#[test]
fn discovery_allows_image_updates_but_stale_physical_bindings_fail_closed() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "Portable.exe");
    let snapshot = selected(&path);
    assert_eq!(
        snapshot.applications[0].identity().state,
        ApplicationIdentity::Exact
    );
    fs::rename(&path, path.with_extension("old")).unwrap();
    fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    assert_eq!(
        snapshot.applications[0].identity().state,
        ApplicationIdentity::Unknown
    );
}
#[test]
fn in_place_image_changes_invalidate_cached_metadata() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "Portable.exe");
    let snapshot = selected(&path);
    fs::write(&path, b"changed image bytes").unwrap();
    assert_eq!(
        snapshot.applications[0].identity().state,
        ApplicationIdentity::Unknown
    );
}
#[test]
fn app_paths_and_shortcut_converge_on_one_physical_executable() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "ObscureChat.exe");
    let mut snapshot = Win32Snapshot::from_registrations(vec![
        RegistrationMetadata {
            name: "ObscureChat.exe".into(),
            executable: Some(path.clone()),
            source: Some(IdentitySource::AppPaths),
            ..Default::default()
        },
        RegistrationMetadata {
            name: "ObscureChat.lnk".into(),
            executable: Some(path.clone()),
            source: Some(IdentitySource::Shortcut),
            ..Default::default()
        },
    ]);
    snapshot
        .observe_executable(&path, IdentitySource::Selected, None)
        .unwrap();
    assert_eq!(snapshot.applications.len(), 1);
    let app = &snapshot.applications[0];
    assert_eq!(app.identity().state, ApplicationIdentity::Exact);
    assert!(app
        .identity()
        .provenance
        .iter()
        .any(|p| p.source == "app-paths"));
    assert!(app
        .identity()
        .provenance
        .iter()
        .any(|p| p.source == "start-menu-target"));
    assert_eq!(
        app.executable.physical,
        ExecutableBinding::capture(&path).unwrap().physical
    );
}
#[test]
fn display_name_or_publisher_alone_cannot_resolve_an_executable() {
    for registration in [
        RegistrationMetadata {
            display_name: Some("ObscureChat".into()),
            ..Default::default()
        },
        RegistrationMetadata {
            publisher: Some("Shared Vendor".into()),
            ..Default::default()
        },
    ] {
        let snapshot = Win32Snapshot::from_registrations(vec![registration]);
        assert!(snapshot.applications.is_empty());
        assert!(snapshot.matching(&["ObscureChat.exe".into()]).is_none());
    }
}
#[test]
fn names_frameworks_and_runtime_usage_never_grant_authentication_or_exclusive_storage() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "ObscureChat.exe");
    let mut snapshot = selected(&path);
    let process = ProcessIdentity {
        pid: 100,
        creation_ticks: 55,
    };
    snapshot
        .observe_executable(&path, IdentitySource::Process, Some(process))
        .unwrap();
    let app = &snapshot.applications[0];
    assert_eq!(
        app.storage_evidence(true, true, &RuntimeUsage::default())
            .state,
        StorageOwnership::Unknown
    );
    let usage = RuntimeUsage {
        processes: vec![process],
        ..Default::default()
    };
    let ownership = app.storage_evidence(true, true, &usage);
    assert_eq!(ownership.state, StorageOwnership::Corroborated);
    let evidence = ScopeEvidence {
        application_identity: app.identity(),
        storage_ownership: ownership,
        ..Default::default()
    };
    assert_eq!(
        evidence.authentication_scope.state,
        AuthenticationScope::Unknown
    );
    assert!(
        !evidence
            .decide(Support::Candidate, &[], LossAssessment::Unknown, &[], &[])
            .action_allowed
    );
    assert_eq!(
        app.storage_evidence(true, false, &usage).state,
        StorageOwnership::Unknown
    );
    let shared = RuntimeUsage {
        processes: vec![
            process,
            ProcessIdentity {
                pid: 200,
                creation_ticks: 66,
            },
        ],
        ..Default::default()
    };
    assert_eq!(
        app.storage_evidence(true, true, &shared).state,
        StorageOwnership::SharedConflict
    );
}
#[test]
fn reused_pid_does_not_bind_the_new_process_to_old_observations() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "Portable.exe");
    let mut snapshot = selected(&path);
    snapshot
        .observe_executable(
            &path,
            IdentitySource::Process,
            Some(ProcessIdentity {
                pid: 100,
                creation_ticks: 10,
            }),
        )
        .unwrap();
    let reused = RuntimeUsage {
        processes: vec![ProcessIdentity {
            pid: 100,
            creation_ticks: 20,
        }],
        ..Default::default()
    };
    assert_eq!(
        snapshot.applications[0]
            .storage_evidence(true, true, &reused)
            .state,
        StorageOwnership::Unknown
    );
}
#[test]
fn portable_has_exact_identity_without_installation_or_authentication_proof() {
    let fixture = FixtureFolders::create().unwrap();
    let snapshot = selected(&executable(&fixture, "Portable.exe"));
    let app = &snapshot.applications[0];
    assert!(app.registrations.is_empty());
    assert!(app.pe.executable_header);
    assert_eq!(app.identity().state, ApplicationIdentity::Exact);
    assert_eq!(
        app.storage_evidence(false, false, &RuntimeUsage::default())
            .state,
        StorageOwnership::Unknown
    );
}
#[test]
fn pinned_executable_cannot_be_replaced_and_symlinks_are_rejected() {
    let fixture = FixtureFolders::create().unwrap();
    let path = executable(&fixture, "Portable.exe");
    let binding = ExecutableBinding::capture(&path).unwrap();
    assert!(fs::rename(&path, path.with_extension("old")).is_err());
    binding.revalidate().unwrap();
    let alias = fixture.path().join("Alias.exe");
    std::os::windows::fs::symlink_file(&path, &alias).unwrap();
    assert!(ExecutableBinding::capture(&alias).is_err());
}
#[test]
fn command_like_app_paths_and_display_icons_are_only_path_hints() {
    assert_eq!(
        executable_path_hint(r#""C:\Program Files\App\App.exe",0"#, true),
        Some(PathBuf::from(r"C:\Program Files\App\App.exe"))
    );
    for hint in [
        r"C:\App.exe --delete",
        r"cmd.exe /c anything",
        r"%LOCALAPPDATA%\App.exe",
        r#""C:\App.exe" --run"#,
    ] {
        assert!(executable_path_hint(hint, false).is_none(), "{hint}");
    }
}
#[test]
fn renamed_data_files_do_not_become_portable_applications() {
    let fixture = FixtureFolders::create().unwrap();
    let path = fixture.path().join("data.exe");
    fs::write(&path, b"not a PE executable").unwrap();
    assert!(Win32Snapshot::default()
        .observe_executable(&path, IdentitySource::Selected, None)
        .is_err());
}
fn record(app: &Win32Application) -> ProductValidationRecord {
    ProductValidationRecord {
        format_version: 1,
        application_id: "obscure-chat".into(),
        channel: "stable".into(),
        product_identity: ProductIdentity {
            executable_name: "ObscureChat.exe".into(),
            product_name: "Obscure Chat".into(),
            sha256: Some(app.executable.sha256().unwrap()),
            publisher: None,
            signature_identity: None,
        },
        tested_version: "1.0.0".into(),
        storage_layout: "electron-fixture-v1".into(),
        artifact_families: vec!["electron-state".into()],
        storage_ownership: StorageOwnership::Corroborated,
        authentication_closure: ClosureResult::SignedOut,
        preservation: PreservationState::Validated,
        known_losses: vec![],
        repetitions: 2,
        test_date: "2026-10-09".into(),
        validation_method: ValidationMethod::DisposableVm,
        status: ValidationStatus::Validated,
    }
}
#[test]
fn formal_record_binds_observed_hash_version_channel_signature_and_layout() {
    let fixture = FixtureFolders::create().unwrap();
    let mut snapshot = selected(&executable(&fixture, "ObscureChat.exe"));
    let app = &mut snapshot.applications[0];
    // Synthetic metadata projection tests binding only, never actual product closure.
    app.pe.product_name = Some("Obscure Chat".into());
    app.pe.product_version = Some("1.0.0".into());
    let good = record(app);
    let bound = app
        .bind_validation(
            &good,
            "obscure-chat",
            "stable",
            "electron-fixture-v1",
            &["electron-state".into()],
        )
        .unwrap();
    assert_eq!(
        bound.version_applicability.state,
        VersionApplicability::Current
    );
    for change in [
        "version",
        "hash",
        "publisher",
        "signature",
        "channel",
        "layout",
        "families",
        "id",
    ] {
        let mut mismatched = good.clone();
        match change {
            "version" => mismatched.tested_version = "2.0.0".into(),
            "hash" => mismatched.product_identity.sha256 = Some("0".repeat(64)),
            "publisher" => mismatched.product_identity.publisher = Some("Other Vendor".into()),
            "signature" => {
                mismatched.product_identity.signature_identity =
                    Some("different-certificate".into())
            }
            "channel" => mismatched.channel = "beta".into(),
            "layout" => mismatched.storage_layout = "different-layout".into(),
            "families" => mismatched.artifact_families = vec!["different-family".into()],
            "id" => mismatched.application_id = "different-app".into(),
            _ => unreachable!(),
        }
        let bound = app
            .bind_validation(
                &mismatched,
                "obscure-chat",
                "stable",
                "electron-fixture-v1",
                &["electron-state".into()],
            )
            .unwrap();
        assert_eq!(
            bound.version_applicability.state,
            VersionApplicability::Stale,
            "{change}"
        );
        let trace = bound.decide(Support::Validated, &[], LossAssessment::None, &[], &[]);
        assert!(!trace.action_allowed, "{change}");
        assert!(trace
            .blocked_by
            .iter()
            .any(|b| b == "product-version-revalidation-required"));
    }
    app.pe.product_version = None;
    let bound = app
        .bind_validation(
            &good,
            "obscure-chat",
            "stable",
            "electron-fixture-v1",
            &["electron-state".into()],
        )
        .unwrap();
    assert_eq!(
        bound.version_applicability.state,
        VersionApplicability::Stale
    );
}
