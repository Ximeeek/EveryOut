#![cfg(windows)]
use everyout_core_model::{ActionStatus, ErrorKind};
use everyout_platform_windows::{AllowedRoot, FixtureFolders, KnownFolder, RootResolver};
use std::{fs, os::windows::fs::OpenOptionsExt, path::Path};

fn setup() -> (FixtureFolders, AllowedRoot) {
    let fixture = FixtureFolders::create().unwrap();
    let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
    (fixture, root)
}

#[test]
fn metadata_and_dry_run_then_real_deletion() {
    let (fixture, root) = setup();
    fs::create_dir_all(fixture.path().join("żółć space/nested")).unwrap();
    fs::write(fixture.path().join("żółć space/a"), b"opaque").unwrap();
    fs::write(fixture.path().join("żółć space/nested/b"), b"fake").unwrap();
    let before = fixture.snapshot().unwrap();
    let file = root.path("żółć space/a").unwrap();
    assert!(file.exists().unwrap());
    assert!(!file.is_directory().unwrap());
    assert_eq!(file.size().unwrap(), 6);
    assert!(file.modified().unwrap().is_some());
    assert_eq!(
        file.delete_file(true).unwrap().status,
        ActionStatus::WouldApply
    );
    assert!(file.exists().unwrap());
    let tree = root.path("żółć space").unwrap();
    assert!(tree.is_directory().unwrap());
    assert_eq!(tree.size().unwrap(), 10);
    assert_eq!(tree.delete_tree(true).unwrap().objects, 4);
    before.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
    assert_eq!(tree.delete_tree(false).unwrap().objects, 4);
    assert!(!tree.exists().unwrap());
    let after = fixture.snapshot().unwrap();
    before.assert_nothing_else_changed(
        &after,
        &[
            "żółć space/",
            "żółć space/a",
            "żółć space/nested/",
            "żółć space/nested/b",
        ],
    );
    assert_eq!(
        tree.delete_tree(false).unwrap().status,
        ActionStatus::AlreadyAbsent
    );
    after.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
    assert!(!root.path("missing/child").unwrap().exists().unwrap());
}

#[test]
fn generated_profiles_resolve_distinct_folders_and_delete_only_selected_files() {
    let fixture = FixtureFolders::profiles(35).unwrap();
    let before = fixture.snapshot().unwrap();
    let mut removed = Vec::new();
    for (folder, base, path) in [
        (
            KnownFolder::LocalAppData,
            "LocalAppData",
            "Chromium/User Data/Profile 1/Network/Cookies",
        ),
        (
            KnownFolder::RoamingAppData,
            "RoamingAppData",
            "Firefox/Profiles/lab.default/cookies.sqlite",
        ),
        (
            KnownFolder::RoamingAppData,
            "RoamingAppData",
            "Electron Lab/Network/Cookies",
        ),
        (
            KnownFolder::LocalAppData,
            "LocalAppData",
            "Steam/ssfn0000000001",
        ),
        (
            KnownFolder::LocalAppData,
            "LocalAppData",
            "Packages/EveryOutLab_synthetic/LocalState/session",
        ),
    ] {
        let root = fixture.resolve(folder).unwrap();
        let target = root.path(path).unwrap();
        assert_eq!(
            target.delete_file(false).unwrap().status,
            ActionStatus::Applied
        );
        assert_eq!(
            target.delete_file(false).unwrap().status,
            ActionStatus::AlreadyAbsent
        );
        removed.push(format!("{base}/{path}"));
    }
    before.assert_nothing_else_changed(
        &fixture.snapshot().unwrap(),
        &removed.iter().map(String::as_str).collect::<Vec<_>>(),
    );
}

#[test]
fn fixture_guard_refuses_external_roots_and_sibling_prefix_without_effects() {
    let fixture = FixtureFolders::profiles(17).unwrap();
    let outside = everyout_test_support::FixtureTree::empty().unwrap();
    fs::write(outside.path().join("canary"), b"untouched").unwrap();
    let before = fixture.snapshot().unwrap();
    let outside_before = outside.snapshot().unwrap();
    let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
    for escape in [
        outside.path().join("canary").to_str().unwrap(),
        "../outside-allowed/canary",
        "../LocalAppData-other/canary",
    ] {
        assert_eq!(
            root.path(escape).err().unwrap().kind,
            ErrorKind::ScopeViolation
        );
        assert!(AllowedRoot::from_manifest(&fixture, KnownFolder::LocalAppData, escape).is_err());
    }
    fs::create_dir_all(fixture.path().join("LocalAppData/allowed-other")).unwrap();
    fs::write(
        fixture.path().join("LocalAppData/allowed-other/canary"),
        b"synthetic",
    )
    .unwrap();
    fs::create_dir(fixture.path().join("LocalAppData/allowed")).unwrap();
    let allowed =
        AllowedRoot::from_manifest(&fixture, KnownFolder::LocalAppData, "allowed").unwrap();
    assert!(allowed.path("../allowed-other/canary").is_err());
    drop(allowed);
    let with_sibling = fixture.snapshot().unwrap();
    // Exercise the actual recursive deletion boundary with a redirected descendant.
    junction(
        &fixture.path().join("LocalAppData/allowed/redirected"),
        outside.path(),
    );
    let refusal = root
        .path("allowed")
        .unwrap()
        .delete_tree(false)
        .unwrap_err()
        .kind;
    assert!(
        matches!(refusal, ErrorKind::ScopeViolation | ErrorKind::AccessDenied),
        "redirected descendant must be refused, got {refusal:?}"
    );
    outside_before.assert_second_run_changes_nothing(&outside.snapshot().unwrap());
    fs::remove_dir(fixture.path().join("LocalAppData/allowed/redirected")).unwrap();
    with_sibling.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
    fs::remove_dir(fixture.path().join("LocalAppData/allowed")).unwrap();
    fs::remove_file(fixture.path().join("LocalAppData/allowed-other/canary")).unwrap();
    fs::remove_dir(fixture.path().join("LocalAppData/allowed-other")).unwrap();
    before.assert_second_run_changes_nothing(&fixture.snapshot().unwrap());
}

#[test]
fn metadata_does_not_need_content_read_access_and_lock_is_distinct() {
    let (fixture, root) = setup();
    let path = fixture.path().join("opaque");
    fs::write(&path, b"synthetic only").unwrap();
    let file = root.path("opaque").unwrap();
    let locked = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    // Synthetic harness oracle: a content-read open is denied by the OS. No bytes
    // are read, and this API does not occur anywhere in production adapter source.
    assert!(fs::OpenOptions::new().read(true).open(&path).is_err());
    assert_eq!(file.size().unwrap(), 14);
    assert_eq!(file.delete_file(false).unwrap_err().kind, ErrorKind::Locked);
    assert_eq!(
        file.delete_file(true).unwrap().status,
        ActionStatus::WouldApply
    );
    assert!(path.exists());
    drop(locked);
    assert_eq!(
        file.delete_file(false).unwrap().status,
        ActionStatus::Applied
    );
}

#[test]
fn traversal_absolute_sibling_prefix_and_hard_links_are_refused() {
    let (fixture, root) = setup();
    for path in [
        "../outside",
        "..\\outside",
        "C:\\outside",
        "\\\\server\\x",
        ".",
        "a:stream",
        "a/../../b",
        "a/./b",
        "a\\",
        "CON",
        "a.",
    ] {
        assert!(root.path(path).is_err(), "{path}");
    }
    fs::write(fixture.path().join("outside"), b"sentinel").unwrap();
    fs::create_dir(fixture.path().join("allowed")).unwrap();
    fs::hard_link(
        fixture.path().join("outside"),
        fixture.path().join("allowed/alias"),
    )
    .unwrap();
    let allowed =
        AllowedRoot::from_manifest(&fixture, KnownFolder::LocalAppData, "allowed").unwrap();
    assert_eq!(
        allowed.path("../outside").err().unwrap().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        allowed.path("alias").err().unwrap().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        fs::metadata(fixture.path().join("outside")).unwrap().len(),
        8
    );
}

fn junction(link: &Path, target: &Path) {
    // Both paths come from this freshly owned synthetic fixture, never from input.
    use std::os::windows::process::CommandExt;
    let link = link.to_str().unwrap().replace('/', "\\");
    let target = target.to_str().unwrap().replace('/', "\\");
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c"])
        .raw_arg(format!("mklink /J \"{link}\" \"{target}\""))
        .output()
        .unwrap();
    assert!(
        status.status.success(),
        "junction creation failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

#[test]
fn junctions_at_root_parent_leaf_and_recursive_child_never_redirect() {
    let (fixture, root) = setup();
    fs::create_dir_all(fixture.path().join("outside")).unwrap();
    fs::write(fixture.path().join("outside/canary"), b"untouched").unwrap();
    junction(
        &fixture.path().join("redirected"),
        &fixture.path().join("outside"),
    );
    assert!(AllowedRoot::from_manifest(&fixture, KnownFolder::LocalAppData, "redirected").is_err());
    assert!(root.path("redirected").is_err());
    assert!(root.path("redirected/canary").is_err());
    fs::create_dir(fixture.path().join("tree")).unwrap();
    fs::write(fixture.path().join("tree/first"), b"preserve on refusal").unwrap();
    junction(
        &fixture.path().join("tree/redirected"),
        &fixture.path().join("outside"),
    );
    let tree = root.path("tree").unwrap();
    assert_eq!(
        tree.delete_tree(false).unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert_eq!(
        tree.delete_tree(true).unwrap_err().kind,
        ErrorKind::ScopeViolation
    );
    assert!(tree.size().is_err());
    assert!(fixture.path().join("tree/first").exists());
    assert!(fixture.path().join("outside/canary").exists());
    fs::remove_dir(fixture.path().join("tree/redirected")).unwrap();
    fs::remove_dir(fixture.path().join("redirected")).unwrap();
}

#[test]
fn symlink_leaf_is_refused_or_creation_is_explicitly_unsupported() {
    let (fixture, root) = setup();
    fs::write(fixture.path().join("canary"), b"untouched").unwrap();
    match std::os::windows::fs::symlink_file(
        fixture.path().join("canary"),
        fixture.path().join("link"),
    ) {
        Ok(()) => {
            assert_eq!(
                root.path("link").err().unwrap().kind,
                ErrorKind::ScopeViolation
            );
            fs::remove_file(fixture.path().join("link")).unwrap();
            assert!(fixture.path().join("canary").exists());
        }
        Err(e) => panic!("symlink fixture requires Developer Mode or symlink privilege: {e}"),
    }
}

#[test]
fn target_and_ancestor_substitution_after_dry_run_are_refused() {
    let (fixture, root) = setup();
    fs::create_dir(fixture.path().join("parent")).unwrap();
    fs::write(fixture.path().join("parent/file"), b"original").unwrap();
    let path = root.path("parent/file").unwrap();
    path.delete_file(true).unwrap();
    fs::rename(
        fixture.path().join("parent/file"),
        fixture.path().join("parent/old"),
    )
    .unwrap();
    fs::write(fixture.path().join("parent/file"), b"replacement").unwrap();
    assert_eq!(
        path.delete_file(false).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    let path = root.path("parent/file").unwrap();
    fs::rename(
        fixture.path().join("parent"),
        fixture.path().join("old-parent"),
    )
    .unwrap();
    fs::create_dir(fixture.path().join("parent")).unwrap();
    fs::write(fixture.path().join("parent/file"), b"different parent").unwrap();
    assert_eq!(
        path.delete_file(false).unwrap_err().kind,
        ErrorKind::StalePlan
    );
    assert!(fixture.path().join("old-parent/file").exists());
    let absent = root.path("later").unwrap();
    fs::write(fixture.path().join("later"), b"new").unwrap();
    assert_eq!(
        absent.delete_file(false).unwrap_err().kind,
        ErrorKind::StalePlan
    );
}

#[test]
fn root_cannot_be_replaced_during_capability_lifetime() {
    let (fixture, _root) = setup();
    fs::create_dir(fixture.path().join("owned")).unwrap();
    let _owned = AllowedRoot::from_manifest(&fixture, KnownFolder::LocalAppData, "owned").unwrap();
    assert!(fs::rename(fixture.path().join("owned"), fixture.path().join("renamed")).is_err());
}

#[test]
fn production_modules_contain_no_payload_or_network_api() {
    for source in [
        include_str!("../src/lib.rs"),
        include_str!("../src/filesystem.rs"),
        include_str!("../src/native.rs"),
        include_str!("../src/registry.rs"),
        include_str!("../src/resolver.rs"),
    ] {
        for forbidden in [
            "File::open",
            "ReadFile(",
            "read_to_string",
            "read_to_end",
            "fs::read(",
            "RegQueryValueEx",
            "RegGetValue",
            "TcpStream",
            "UdpSocket",
            "WinHttp",
            "reqwest",
            "Command::",
        ] {
            assert!(
                !source.contains(forbidden),
                "production source contains {forbidden}"
            );
        }
    }
}
