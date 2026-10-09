#![cfg(windows)]
use everyout_detection::{scanner::scan, storage::discover};
use everyout_platform_windows::{inventory::InstalledInventory, FixtureFolders};
use std::{fs, os::windows::fs::OpenOptionsExt};

fn directory(fixture: &FixtureFolders, path: &str) {
    fs::create_dir_all(fixture.path().join(path)).unwrap();
}

#[test]
fn nested_unknown_app_and_partitions_are_found_without_owner_or_payload_reads() {
    let fixture = FixtureFolders::create().unwrap();
    for profile in ["Default", "Partitions/opaque"] {
        let base = format!("NicheVendor/NicheApp/User Data/{profile}");
        for leaf in ["Network", "Local Storage", "Session Storage", "Cache"] {
            directory(&fixture, &format!("{base}/{leaf}"));
        }
        fs::write(
            fixture.path().join(format!("{base}/Network/Cookies")),
            b"private fixture",
        )
        .unwrap();
    }
    let locked = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(
            fixture
                .path()
                .join("NicheVendor/NicheApp/User Data/Default/Network/Cookies"),
        )
        .unwrap();
    let before = fixture.snapshot().unwrap();
    let report = scan(&fixture, &InstalledInventory::default(), &[], &|| false);
    // FixtureFolders::create maps both known folders to the same synthetic root.
    assert_eq!(report.storage.len(), 2);
    assert!(report.storage.iter().all(|s| s.locations == 2
        && s.signals.contains(&"chromium-storage-cluster".into())
        && s.signals.contains(&"cache-directory-name".into())
        && s.label == "NicheVendor"));
    assert!(report.known.is_empty() && report.candidates.is_empty());
    assert!(!serde_json::to_string(&report)
        .unwrap()
        .contains("private fixture"));
    assert_eq!(before, fixture.snapshot().unwrap());
    drop(locked);
}

#[test]
fn caches_are_candidates_and_payload_trees_are_not_explored() {
    let fixture = FixtureFolders::create().unwrap();
    for path in [
        "NativeApp/Cache/Unknown/More",
        "NativeApp/Downloads/Fake/Cache",
        "EveryOut/Cache",
        "io.github.ximeeek.session-wipe/Cache",
        "Microsoft/Other/Cache",
        "Coincidence/Network",
        "Coincidence/Local Storage",
        "Coincidence/Session Storage",
    ] {
        directory(&fixture, path);
    }
    let (storage, _) = discover(&fixture, &InstalledInventory::default(), &|| false);
    assert_eq!(storage.len(), 2);
    assert!(storage.iter().all(|s| s.label == "NativeApp"
        && s.locations == 1
        && s.signals == ["cache-directory-name"]));
}

#[test]
fn depth_and_cancellation_produce_explicit_incomplete_coverage() {
    let fixture = FixtureFolders::create().unwrap();
    directory(&fixture, "Vendor/a/b/c/d/e/f/g/Cache");
    let (storage, coverage) = discover(&fixture, &InstalledInventory::default(), &|| false);
    assert!(storage.is_empty());
    assert!(coverage.contains(&"storage-depth-budget-exhausted".into()));
    let (storage, coverage) = discover(&fixture, &InstalledInventory::default(), &|| true);
    assert!(storage.is_empty());
    assert!(coverage.contains(&"cancelled".into()));
}

#[test]
fn nested_junction_is_omitted_instead_of_scanned() {
    use std::os::windows::process::CommandExt;
    let fixture = FixtureFolders::create().unwrap();
    directory(&fixture, "NativeApp");
    let outside = FixtureFolders::create().unwrap();
    directory(&outside, "Cache");
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c"])
        .raw_arg(format!(
            "mklink /J \"{}\" \"{}\"",
            fixture.path().join("NativeApp/Redirected").display(),
            outside.path().display()
        ))
        .output()
        .unwrap();
    assert!(output.status.success());
    let (storage, coverage) = discover(&fixture, &InstalledInventory::default(), &|| false);
    assert!(storage.is_empty());
    assert!(coverage.contains(&"storage-entries-omitted".into()));
}
