#![cfg(windows)]
use everyout_core_model::{ActionStatus, ErrorKind};
use everyout_platform_windows::FixtureFolders;
use everyout_providers::platform::PlatformManifest;

#[test]
fn manifest_process_names_match_metadata_and_paths_narrow_candidates() {
    let image = std::env::current_exe().unwrap();
    let mut json: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/provider.json")).unwrap();
    json["identity"]["process_names"] =
        serde_json::json!([image.file_name().unwrap().to_str().unwrap()]);
    let manifest = PlatformManifest::load(&json.to_string()).unwrap();
    let inventory = everyout_platform_windows::process::enumerate_current_user().unwrap();
    let matches = manifest.match_processes(&inventory, std::slice::from_ref(&image));
    assert!(matches.iter().any(|p| p.pid() == std::process::id()));
    assert!(manifest
        .match_processes(&inventory, &[image.with_file_name("wrong.exe")])
        .is_empty());
    json["identity"]["process_names"] = serde_json::json!([]);
    let no_names = PlatformManifest::load(&json.to_string()).unwrap();
    assert!(no_names.match_processes(&inventory, &[image]).is_empty());
}

#[test]
fn immutable_loaded_manifest_binds_only_declared_artifacts_and_profiles() {
    let fixture = FixtureFolders::create().unwrap();
    let base = fixture
        .path()
        .join("EveryOutFixtures/Browser/Default/Storage");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(base.join("Session"), b"opaque fixture").unwrap();
    let manifest = PlatformManifest::load(include_str!("fixtures/provider.json")).unwrap();
    assert!(manifest
        .file("undeclared", Some("Default"), &fixture)
        .is_err());
    assert!(manifest
        .file("session-store", Some("../Default"), &fixture)
        .is_err());
    assert!(manifest
        .file("session-store", Some("Unreviewed"), &fixture)
        .is_err());
    assert!(manifest.file("session-store", None, &fixture).is_err());
    let artifact = manifest
        .file("session-store", Some("Default"), &fixture)
        .unwrap();
    assert_eq!(artifact.probe().unwrap().size, 14);
    assert_eq!(
        artifact.delete(true).unwrap().status,
        ActionStatus::WouldApply
    );
    assert_eq!(
        artifact.delete(false).unwrap_err().kind,
        ErrorKind::Unsupported
    );
    assert!(base.join("Session").exists());
}
