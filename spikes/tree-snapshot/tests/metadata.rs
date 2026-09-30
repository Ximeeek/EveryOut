use everyout_tree_snapshot::{Entry, Snapshot, capture, compare, validate};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "everyout-metadata-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        Self(root)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        // Only the uniquely created synthetic fixture is removed.
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn captures_nested_unicode_metadata_without_payload_or_absolute_root() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("żółć space")).unwrap();
    fs::write(
        fixture.0.join("żółć space/opaque"),
        b"SYNTHETIC_PAYLOAD_CANARY",
    )
    .unwrap();
    let snapshot = capture(&fixture.0).unwrap();
    assert_eq!(snapshot.entries.len(), 2);
    assert_eq!(snapshot.entries[1].path, "żółć space/opaque");
    assert_eq!(snapshot.entries[1].size, 24);
    let json = serde_json::to_string(&snapshot).unwrap();
    assert!(!json.contains("SYNTHETIC_PAYLOAD_CANARY"));
    assert!(!json.contains(fixture.0.to_str().unwrap()));
    assert_eq!(snapshot, serde_json::from_str::<Snapshot>(&json).unwrap());
}

#[cfg(windows)]
#[test]
fn capture_succeeds_when_windows_denies_file_content_open() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let path = fixture.0.join("opaque");
    fs::write(&path, b"SYNTHETIC_SECRET").unwrap();
    let guard = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    // This is a synthetic test oracle, never used by the capture implementation.
    assert!(fs::File::open(&path).is_err());
    let snapshot = capture(&fixture.0).unwrap();
    assert_eq!(snapshot.entries[0].size, 16);
    drop(guard);
}

#[test]
fn capture_module_has_no_content_or_network_io_api() {
    let source = include_str!("../src/lib.rs");
    for prohibited in [
        "File::open",
        "OpenOptions",
        "fs::read(",
        "read_to_end",
        "read_to_string",
        "TcpStream",
        "UdpSocket",
        "Command::",
    ] {
        assert!(
            !source.contains(prohibited),
            "capture module includes {prohibited}"
        );
    }
}

fn entry(path: &str, size: u64) -> Entry {
    Entry {
        path: path.into(),
        size,
        modified_ns: Some("1".into()),
        created_ns: None,
    }
}

#[test]
fn diff_detects_added_removed_size_and_timestamp_changes_in_sorted_order() {
    let before = Snapshot {
        version: 1,
        entries: vec![
            entry("removed", 1),
            entry("size", 1),
            entry("time", 1),
            entry("same", 1),
        ],
    };
    let mut time = entry("time", 1);
    time.modified_ns = Some("2".into());
    let after = Snapshot {
        version: 1,
        entries: vec![entry("added", 1), entry("size", 2), time, entry("same", 1)],
    };
    let diff = compare(&before, &after).unwrap();
    assert_eq!(diff.added[0].path, "added");
    assert_eq!(diff.removed[0].path, "removed");
    assert_eq!(diff.changed.len(), 2);
    assert_eq!(diff.changed[0].after.path, "size");
    assert_eq!(diff.changed[1].after.path, "time");
    assert!(compare(&after, &after).unwrap().changed.is_empty());
}

#[test]
fn empty_tree_and_missing_root() {
    let fixture = Fixture::new();
    assert!(capture(&fixture.0).unwrap().entries.is_empty());
    assert!(capture(&fixture.0.join("missing")).is_err());
    assert!(capture(&fixture.0.join("..")).is_err());
}

#[test]
fn malformed_and_ambiguous_snapshots_are_rejected() {
    for path in [
        "",
        "../escape",
        "/absolute",
        "C:/profile",
        "a//b",
        "a/./b",
        "a\\b",
    ] {
        assert!(
            validate(&Snapshot {
                version: 1,
                entries: vec![entry(path, 1)]
            })
            .is_err()
        );
    }
    assert!(
        validate(&Snapshot {
            version: 2,
            entries: vec![]
        })
        .is_err()
    );
    assert!(
        validate(&Snapshot {
            version: 1,
            entries: vec![entry("same", 1), entry("same", 2)]
        })
        .is_err()
    );
    assert!(
        serde_json::from_str::<Snapshot>(r#"{"version":1,"entries":[],"payload":"forbidden"}"#)
            .is_err()
    );
}

#[cfg(windows)]
#[test]
fn junction_entries_and_redirected_ancestors_fail_without_partial_output() {
    let fixture = Fixture::new();
    let outside = Fixture::new();
    fs::create_dir(outside.0.join("nested")).unwrap();
    fs::write(outside.0.join("opaque"), b"OUTSIDE_SYNTHETIC_CANARY").unwrap();
    let junction = fixture.0.join("redirect");
    let result = std::process::Command::new("cmd.exe")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&outside.0)
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(capture(&fixture.0).is_err());
    assert!(capture(&junction.join("nested")).is_err());
    // Remove the junction itself, not its target tree.
    fs::remove_dir(&junction).unwrap();
    assert!(outside.0.join("opaque").exists());
}

#[test]
fn cli_capture_diff_and_failures_have_complete_json_or_empty_stdout() {
    let tree = Fixture::new();
    let evidence = Fixture::new();
    fs::write(tree.0.join("opaque"), b"FIRST_SYNTHETIC_VALUE").unwrap();
    let executable = env!("CARGO_BIN_EXE_everyout-tree-snapshot");
    let before = std::process::Command::new(executable)
        .arg("capture")
        .arg(&tree.0)
        .output()
        .unwrap();
    assert!(before.status.success());
    fs::write(evidence.0.join("before.json"), &before.stdout).unwrap();
    fs::write(tree.0.join("opaque"), b"SECOND_SYNTHETIC_VALUE_LONGER").unwrap();
    let after = std::process::Command::new(executable)
        .arg("capture")
        .arg(&tree.0)
        .output()
        .unwrap();
    assert!(after.status.success());
    fs::write(evidence.0.join("after.json"), &after.stdout).unwrap();
    let diff = std::process::Command::new(executable)
        .arg("diff")
        .arg(evidence.0.join("before.json"))
        .arg(evidence.0.join("after.json"))
        .output()
        .unwrap();
    assert!(diff.status.success());
    let json: serde_json::Value = serde_json::from_slice(&diff.stdout).unwrap();
    assert_eq!(json["changed"].as_array().unwrap().len(), 1);
    let failed = std::process::Command::new(executable)
        .arg("capture")
        .arg(tree.0.join("PRIVATE_MISSING_PATH"))
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(failed.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&failed.stderr).contains("PRIVATE_MISSING_PATH"));
    fs::write(evidence.0.join("bad.json"), b"not a snapshot").unwrap();
    let invalid = std::process::Command::new(executable)
        .arg("diff")
        .arg(evidence.0.join("bad.json"))
        .arg(evidence.0.join("after.json"))
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(invalid.stdout.is_empty());
}
