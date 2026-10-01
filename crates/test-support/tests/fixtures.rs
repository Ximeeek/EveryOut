use everyout_test_support::{profile_layout, FixtureTree, Snapshot};
use std::{collections::BTreeMap, fs, path::Path};

#[test]
fn all_five_layouts_have_exact_relative_metadata() {
    let fixture = FixtureTree::profiles(17).unwrap();
    let mut expected = BTreeMap::new();
    for (path, size) in profile_layout() {
        expected.insert(path.clone(), size);
        let mut parent = Path::new(path.trim_end_matches('/')).parent();
        while let Some(directory) = parent.filter(|p| !p.as_os_str().is_empty()) {
            expected.insert(
                format!("{}/", directory.to_str().unwrap().replace('\\', "/")),
                0,
            );
            parent = directory.parent();
        }
    }
    let before = fixture.snapshot().unwrap();
    assert_eq!(before, Snapshot(expected));
    for (path, size) in [
        (
            "LocalAppData/Chromium/User Data/Default/Network/Cookies",
            64,
        ),
        (
            "LocalAppData/Chromium/User Data/Profile 1/Network/Cookies",
            64,
        ),
        (
            "RoamingAppData/Firefox/Profiles/lab.default/cookies.sqlite",
            64,
        ),
        ("RoamingAppData/Electron Lab/Network/Cookies", 64),
        ("LocalAppData/Steam/config/loginusers.vdf", 32),
        ("LocalAppData/Steam/ssfn0000000001", 24),
        (
            "LocalAppData/Packages/EveryOutLab_synthetic/LocalState/session",
            32,
        ),
    ] {
        assert_eq!(before.0.get(path), Some(&size));
    }
    let other = FixtureTree::profiles(17).unwrap();
    assert_ne!(fixture.path(), other.path());
    assert_eq!(before, other.snapshot().unwrap());
}

#[test]
fn assertions_detect_removal_resize_additions_and_non_idempotence() {
    let fixture = FixtureTree::profiles(17).unwrap();
    let before = fixture.snapshot().unwrap();
    let removed = "LocalAppData/Steam/ssfn0000000001";
    fs::remove_file(fixture.path().join(removed)).unwrap();
    let after = fixture.snapshot().unwrap();
    before.assert_removed(&after, &[removed]);
    before.assert_nothing_else_changed(&after, &[removed]);
    after.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
    assert!(std::panic::catch_unwind(|| before.assert_removed(&before, &[removed])).is_err());
    fs::write(fixture.path().join("outside-allowed/canary"), b"resized").unwrap();
    let resized = fixture.snapshot().unwrap();
    assert!(
        std::panic::catch_unwind(|| before.assert_nothing_else_changed(&resized, &[removed]))
            .is_err()
    );
    assert!(
        std::panic::catch_unwind(|| after.assert_second_run_changes_nothing(&resized)).is_err()
    );
    fs::write(fixture.path().join("new"), b"invented").unwrap();
    assert!(std::panic::catch_unwind(
        || before.assert_nothing_else_changed(&fixture.snapshot().unwrap(), &[removed])
    )
    .is_err());
}

#[test]
fn snapshots_refuse_redirected_descendants() {
    let fixture = FixtureTree::empty().unwrap();
    let outside = FixtureTree::empty().unwrap();
    fs::write(outside.path().join("canary"), b"synthetic").unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_dir(outside.path(), fixture.path().join("redirected")).unwrap();
    #[cfg(not(windows))]
    std::os::unix::fs::symlink(outside.path(), fixture.path().join("redirected")).unwrap();
    assert!(fixture.snapshot().is_err());
    #[cfg(windows)]
    fs::remove_dir(fixture.path().join("redirected")).unwrap();
    #[cfg(not(windows))]
    fs::remove_file(fixture.path().join("redirected")).unwrap();
    assert_eq!(
        fs::metadata(outside.path().join("canary")).unwrap().len(),
        9
    );
}
