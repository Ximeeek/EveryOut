// Fixture writes/removal occur only here, never in the probe executable.
use everyout_identity_probe::directory_summary;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "everyout-identity-fixture-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn sums_only_metadata_and_omits_payload_paths() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("żółć")).unwrap();
    fs::write(
        fixture.0.join("żółć/dummy"),
        b"SYNTHETIC_PAYLOAD_DO_NOT_EXPORT",
    )
    .unwrap();
    let summary = directory_summary("fixture", &fixture.0);
    assert_eq!(summary.state, "present");
    assert_eq!(summary.bytes, Some(31));
    assert_eq!(summary.files, Some(1));
    let json = serde_json::to_string(&summary).unwrap();
    assert!(!json.contains("dummy"));
    assert!(!json.contains("żółć"));
    assert!(!json.contains("SYNTHETIC_PAYLOAD"));
}
#[test]
fn empty_directory_has_known_zero_size() {
    let fixture = Fixture::new();
    let summary = directory_summary("fixture", &fixture.0);
    assert_eq!(summary.state, "present");
    assert_eq!(summary.bytes, Some(0));
    assert_eq!(summary.files, Some(0));
}
#[cfg(windows)]
#[test]
fn does_not_open_even_a_sharing_denied_payload() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let path = fixture.0.join("locked");
    fs::write(&path, b"dummy").unwrap();
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    assert!(fs::File::open(&path).is_err());
    let summary = directory_summary("fixture", &fixture.0);
    assert_eq!(summary.state, "present");
    assert_eq!(summary.bytes, Some(5));
    drop(held);
}
#[cfg(windows)]
#[test]
fn rejects_junctions_without_partial_sums() {
    use std::os::windows::process::CommandExt;
    let fixture = Fixture::new();
    let target = Fixture::new();
    let junction = fixture.0.join("junction");
    let status = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target.0)
        .creation_flags(0x08000000)
        .output()
        .unwrap()
        .status;
    assert!(status.success());
    let summary = directory_summary("fixture", &fixture.0);
    assert_eq!(summary.state, "unsafe_or_incomplete");
    assert!(summary.bytes.is_none());
    fs::remove_dir(junction).unwrap();
}

#[test]
fn missing_directory_never_reports_zero_size() {
    let fixture = Fixture::new();
    let summary = directory_summary("fixture", &fixture.0.join("missing"));
    assert_ne!(summary.state, "present");
    assert!(summary.bytes.is_none());
}
