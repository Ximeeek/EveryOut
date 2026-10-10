#![cfg(windows)]
use everyout_core_model::*;
use everyout_detection::scanner::{scan_with_runtime, ReviewedManifest};
use everyout_platform_windows::{
    inventory::InstalledInventory, win32_identity::*, FixtureFolders, IdentityFolders, SafePath,
};
use std::{cell::RefCell, fs, rc::Rc};

struct FixtureUsage(Vec<ProcessIdentity>);
impl RuntimeObserver for FixtureUsage {
    fn observe(&mut self, _: &SafePath, _: &Win32Snapshot) -> RuntimeUsage {
        RuntimeUsage {
            processes: self.0.clone(),
            ..Default::default()
        }
    }
}
fn app(fixture: &FixtureFolders, name: &str, pid: u32) -> Win32Snapshot {
    let path = fixture.path().join("install").join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    let mut snapshot = Win32Snapshot::from_registrations(vec![
        RegistrationMetadata {
            name: name.into(),
            executable: Some(path.clone()),
            source: Some(IdentitySource::AppPaths),
            ..Default::default()
        },
        RegistrationMetadata {
            name: format!("{name}.lnk"),
            executable: Some(path.clone()),
            source: Some(IdentitySource::Shortcut),
            ..Default::default()
        },
    ]);
    snapshot
        .observe_executable(
            &path,
            IdentitySource::Process,
            Some(ProcessIdentity {
                pid,
                creation_ticks: 10,
            }),
        )
        .unwrap();
    snapshot
}
fn chromium(fixture: &FixtureFolders, name: &str) {
    let root = fixture.path().join(name);
    fs::create_dir_all(root.join("Local Storage/leveldb")).unwrap();
    fs::create_dir_all(root.join("IndexedDB")).unwrap();
    fs::create_dir_all(root.join("Network")).unwrap();
    fs::write(root.join("Network/Cookies"), b"synthetic state").unwrap();
    fs::write(root.join("Local Storage/leveldb/LOCK"), b"").unwrap();
}
#[test]
fn discord_trace_improves_identity_and_ownership_but_keeps_p0_authentication_gates() {
    let fixture = FixtureFolders::create().unwrap();
    chromium(&fixture, "discord");
    let input = include_str!("../../../catalog/apps/communication/discord.json");
    let manifest = everyout_providers::load_manifest(input).unwrap();
    let before = everyout_providers::evidence::assess(&manifest, &fixture);
    let inventory = InstalledInventory {
        win32: Rc::new(app(&fixture, "Discord.exe", 100)),
        ..Default::default()
    };
    let identity = RefCell::new(inventory.win32.clone());
    let resolver = IdentityFolders {
        folders: &fixture,
        identity: &identity,
    };
    let report = scan_with_runtime(
        &resolver,
        &inventory,
        &[ReviewedManifest::load(input).unwrap()],
        &[],
        &|| false,
        &mut FixtureUsage(vec![ProcessIdentity {
            pid: 100,
            creation_ticks: 10,
        }]),
    );
    let after = &report
        .known
        .iter()
        .find(|d| d.id.starts_with("discord-instance-"))
        .unwrap()
        .decision;
    assert_eq!(
        before.evidence.application_identity.state,
        ApplicationIdentity::Weak
    );
    assert_eq!(
        before.evidence.storage_ownership.state,
        StorageOwnership::Unknown
    );
    assert_eq!(
        after.evidence.application_identity.state,
        ApplicationIdentity::Exact
    );
    assert_eq!(
        after.evidence.storage_ownership.state,
        StorageOwnership::Corroborated
    );
    assert_eq!(
        after.evidence.authentication_scope.state,
        AuthenticationScope::FrameworkHint
    );
    assert_eq!(
        after.evidence.preservation.state,
        PreservationState::Unknown
    );
    assert_eq!(
        after.evidence.version_applicability.state,
        before.evidence.version_applicability.state
    );
    assert_eq!(after.support, before.support);
    assert!(!after.action_allowed);
    for code in [
        "unknown-authentication-closure",
        "unreviewed-preservation",
        "unvalidated-product-version",
        "automatic-cleanup-unverified",
    ] {
        assert!(after.blocked_by.iter().any(|b| b == code));
    }
    // The provider/plan projection consumes exactly the same cached physical observations.
    assert_eq!(
        everyout_providers::evidence::assess(&manifest, &resolver),
        *after
    );
    assert_eq!(manifest.session_locations.len(), 1);
    assert_eq!(manifest.session_locations[0].relative, "Local Storage");
    assert!(report.candidates.iter().all(|d| !d.executable));
}
#[test]
fn same_named_appdata_without_runtime_usage_remains_unknown() {
    let fixture = FixtureFolders::create().unwrap();
    chromium(&fixture, "ObscureChat");
    let inventory = InstalledInventory {
        win32: Rc::new(app(&fixture, "ObscureChat.exe", 100)),
        ..Default::default()
    };
    let report = scan_with_runtime(
        &fixture,
        &inventory,
        &[],
        &[],
        &|| false,
        &mut FixtureUsage(vec![]),
    );
    let row = report
        .candidates
        .iter()
        .find(|d| d.application_label.as_deref() == Some("ObscureChat.exe"))
        .unwrap();
    assert_eq!(
        row.decision.evidence.application_identity.state,
        ApplicationIdentity::Exact
    );
    assert_eq!(
        row.decision.evidence.storage_ownership.state,
        StorageOwnership::Unknown
    );
    assert_eq!(
        row.decision.evidence.authentication_scope.state,
        AuthenticationScope::Unknown
    );
    assert!(!row.decision.action_allowed);
}
#[test]
fn provider_projection_cannot_transfer_root_proof_or_overwrite_a_conflict() {
    use everyout_platform_windows::{KnownFolder, RootResolver};
    for first in [
        StorageOwnership::Corroborated,
        StorageOwnership::SharedConflict,
    ] {
        let fixture = FixtureFolders::create().unwrap();
        chromium(&fixture, "discord");
        chromium(&fixture, "second");
        let snapshot = Rc::new(app(&fixture, "Discord.exe", 100));
        let mut manifest = everyout_providers::load_manifest(include_str!(
            "../../../catalog/apps/communication/discord.json"
        ))
        .unwrap();
        manifest
            .roots
            .push(everyout_providers::Root::RoamingAppData {
                id: "second".into(),
                relative: "second".into(),
                scope: Scope::OsUser,
                owner: "discord".into(),
            });
        let root = fixture.resolve(KnownFolder::RoamingAppData).unwrap();
        snapshot.remember_storage(
            &snapshot.applications[0],
            &root.path("discord").unwrap(),
            EvidenceState::new(first, "fixture", "first-root-proof"),
        );
        if first == StorageOwnership::SharedConflict {
            snapshot.remember_storage(
                &snapshot.applications[0],
                &root.path("second").unwrap(),
                EvidenceState::new(
                    StorageOwnership::Corroborated,
                    "fixture",
                    "second-root-proof",
                ),
            );
        }
        let identity = RefCell::new(snapshot);
        let resolver = IdentityFolders {
            folders: &fixture,
            identity: &identity,
        };
        let trace = everyout_providers::evidence::assess(&manifest, &resolver);
        assert_eq!(
            trace.evidence.storage_ownership.state,
            if first == StorageOwnership::SharedConflict {
                StorageOwnership::SharedConflict
            } else {
                StorageOwnership::Unknown
            }
        );
        assert!(!trace.action_allowed);
    }
}
#[test]
fn generic_electron_application_has_a_recognized_row_without_a_destructive_provider() {
    for name in ["ObscureChat", "Slack"] {
        let fixture = FixtureFolders::create().unwrap();
        chromium(&fixture, name);
        let inventory = InstalledInventory {
            win32: Rc::new(app(&fixture, &format!("{name}.exe"), 100)),
            ..Default::default()
        };
        let report = scan_with_runtime(
            &fixture,
            &inventory,
            &[],
            &[],
            &|| false,
            &mut FixtureUsage(vec![ProcessIdentity {
                pid: 100,
                creation_ticks: 10,
            }]),
        );
        let row = report
            .candidates
            .iter()
            .find(|d| d.decision.evidence.application_identity.state == ApplicationIdentity::Exact)
            .unwrap();
        assert!(row.owner.as_deref().unwrap().contains(name));
        assert_eq!(row.category, Some(Category::Application));
        assert_eq!(
            row.decision.evidence.storage_ownership.state,
            StorageOwnership::Corroborated
        );
        assert_eq!(
            row.decision.evidence.authentication_scope.state,
            AuthenticationScope::Unknown
        );
        assert!(!row.executable && !row.selected && !row.decision.action_allowed);
        assert!(row
            .decision
            .blocked_by
            .iter()
            .any(|b| b == "discovery-only-no-provider"));
    }
}
#[test]
fn portable_and_webview2_keep_unknown_authentication_even_with_runtime_storage_usage() {
    let fixture = FixtureFolders::create().unwrap();
    let mut snapshot = app(&fixture, "Portable.exe", 100);
    snapshot.applications[0].sources = vec![IdentitySource::Selected];
    snapshot.applications[0].registrations.clear();
    let udf = fixture
        .path()
        .join("install/Portable.exe.WebView2/EBWebView/Default/Network");
    fs::create_dir_all(&udf).unwrap();
    fs::write(udf.join("Cookies"), b"synthetic state").unwrap();
    let inventory = InstalledInventory {
        win32: Rc::new(snapshot),
        ..Default::default()
    };
    let report = scan_with_runtime(
        &fixture,
        &inventory,
        &[],
        &[],
        &|| false,
        &mut FixtureUsage(vec![ProcessIdentity {
            pid: 100,
            creation_ticks: 10,
        }]),
    );
    let row = report
        .candidates
        .iter()
        .find(|d| d.id.starts_with("win32-application-"))
        .unwrap();
    assert_eq!(
        row.decision.evidence.application_identity.state,
        ApplicationIdentity::Exact
    );
    assert_eq!(
        row.decision.evidence.storage_ownership.state,
        StorageOwnership::Corroborated
    );
    assert_eq!(
        row.decision.evidence.authentication_scope.state,
        AuthenticationScope::Unknown
    );
    assert!(!row.decision.action_allowed);
}
#[test]
fn steam_uses_catalog_installation_candidates_without_interpreting_login_artifacts() {
    let fixture = FixtureFolders::create().unwrap();
    let mut snapshot = app(&fixture, "steam.exe", 100);
    snapshot.applications[0].pe.product_name = Some("Steam".into());
    snapshot.applications[0].pe.company_name = Some("Valve".into());
    snapshot.applications[0].pe.product_version = Some("fixture-1".into());
    let config = fixture.path().join("install/config");
    fs::create_dir_all(&config).unwrap();
    for name in ["loginusers.vdf", "config.vdf"] {
        fs::write(config.join(name), b"uninterpreted synthetic content").unwrap();
    }
    let input = include_str!("../../../catalog/apps/gaming/steam.json");
    let inventory = InstalledInventory {
        win32: Rc::new(snapshot),
        ..Default::default()
    };
    let before = fixture.snapshot().unwrap();
    let report = scan_with_runtime(
        &fixture,
        &inventory,
        &[ReviewedManifest::load(input).unwrap()],
        &[],
        &|| false,
        &mut FixtureUsage(vec![ProcessIdentity {
            pid: 100,
            creation_ticks: 10,
        }]),
    );
    let row = report
        .candidates
        .iter()
        .find(|d| d.owner.as_deref() == Some("Steam"))
        .unwrap();
    assert_eq!(
        row.decision.evidence.application_identity.state,
        ApplicationIdentity::Exact
    );
    assert_eq!(
        row.decision.evidence.storage_ownership.state,
        StorageOwnership::Corroborated
    );
    assert_eq!(
        row.decision.evidence.authentication_scope.state,
        AuthenticationScope::Unknown
    );
    assert!(!row.executable && !row.decision.action_allowed);
    assert_eq!(row.observations.len(), 2);
    assert_eq!(before, fixture.snapshot().unwrap());
}
#[test]
fn unrelated_executables_with_a_shared_root_are_never_exclusive() {
    let fixture = FixtureFolders::create().unwrap();
    chromium(&fixture, "Shared");
    let mut snapshot = app(&fixture, "First.exe", 100);
    snapshot.applications[0].pe.product_name = Some("Shared".into());
    let mut other = app(&fixture, "Second.exe", 200);
    other.applications[0].pe.product_name = Some("Shared".into());
    snapshot.applications.extend(other.applications);
    let inventory = InstalledInventory {
        win32: Rc::new(snapshot),
        ..Default::default()
    };
    let report = scan_with_runtime(
        &fixture,
        &inventory,
        &[],
        &[],
        &|| false,
        &mut FixtureUsage(vec![
            ProcessIdentity {
                pid: 100,
                creation_ticks: 10,
            },
            ProcessIdentity {
                pid: 200,
                creation_ticks: 10,
            },
        ]),
    );
    let rows: Vec<_> = report
        .candidates
        .iter()
        .filter(|d| d.id.starts_with("win32-application-"))
        .collect();
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(
            row.decision.evidence.storage_ownership.state,
            StorageOwnership::SharedConflict
        );
        assert!(!row.decision.action_allowed);
    }
}
