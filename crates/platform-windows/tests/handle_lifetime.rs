#![cfg(windows)]
use everyout_platform_windows::{FixtureFolders, KnownFolder, RootResolver};
use std::fs;
#[test]
fn released_probes_allow_parent_rename() {
    let fixture = FixtureFolders::create().unwrap();
    let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
    fs::create_dir(fixture.path().join("parent")).unwrap();
    fs::write(fixture.path().join("parent/file"), b"synthetic").unwrap();
    fs::rename(fixture.path().join("parent"), fixture.path().join("before"))
        .expect("before binding");
    fs::rename(fixture.path().join("before"), fixture.path().join("parent")).unwrap();
    let file = root.path("parent/file").unwrap();
    fs::rename(fixture.path().join("parent"), fixture.path().join("one"))
        .expect("after path binding");
    fs::rename(fixture.path().join("one"), fixture.path().join("parent")).unwrap();
    file.exists().unwrap();
    fs::rename(fixture.path().join("parent"), fixture.path().join("two")).expect("after probe");
    fs::rename(fixture.path().join("two"), fixture.path().join("parent")).unwrap();
    file.delete_file(true).unwrap();
    fs::rename(fixture.path().join("parent"), fixture.path().join("three")).expect("after dry run");
}
