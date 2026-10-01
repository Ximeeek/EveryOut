#![cfg(windows)]
use everyout_core_model::{ActionStatus, ErrorKind};
use everyout_platform_windows::FixtureFolders;
use everyout_providers::platform::PlatformManifest;

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
