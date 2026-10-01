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
    assert!(fixture.path().join("żółć space/nested/b").exists());
    assert_eq!(tree.delete_tree(false).unwrap().objects, 4);
    assert!(!tree.exists().unwrap());
    assert_eq!(
        tree.delete_tree(false).unwrap().status,
        ActionStatus::AlreadyAbsent
    );
    assert!(!root.path("missing/child").unwrap().exists().unwrap());
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
