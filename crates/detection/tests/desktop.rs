#![cfg(windows)]
use everyout_core_model::ArtifactKind;
use everyout_detection::scanner::{scan, ReviewedManifest};
use everyout_platform_windows::{inventory::InstalledInventory, FixtureFolders};
use everyout_providers::{load_manifest, Root};
use std::{fs, path::Path};

#[test]
fn unknown_roots_are_not_probed_and_discovery_never_authorizes_execution() {
    let catalog = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/apps");
    let mut checked = 0;
    for category in [
        "communication",
        "messengers",
        "mail",
        "vpn",
        "authenticators",
        "wallets",
        "password-managers",
    ] {
        for entry in fs::read_dir(catalog.join(category)).unwrap() {
            let input = fs::read_to_string(entry.unwrap().path()).unwrap();
            let m = load_manifest(&input).unwrap();
            let fixture = FixtureFolders::create().unwrap();
            if matches!(m.roots[0], Root::Unresolved { .. }) {
                // A lookalike cannot turn a research marker into an AppData target.
                fs::create_dir_all(fixture.path().join("unresolved/unresolved")).unwrap();
            } else {
                let root = fixture.path().join(m.roots[0].relative());
                fs::create_dir_all(&root).unwrap();
                for a in &m.session_locations {
                    let p = root.join(&a.relative);
                    if a.kind == ArtifactKind::Directory {
                        fs::create_dir_all(&p).unwrap();
                    } else {
                        fs::create_dir_all(p.parent().unwrap()).unwrap();
                        fs::write(p, b"invented fixture bytes").unwrap();
                    }
                }
            }
            let before = fixture.snapshot().unwrap();
            let manifests = [ReviewedManifest::load(&input).unwrap()];
            let report = scan(
                &fixture,
                &InstalledInventory::default(),
                &manifests,
                &|| false,
            );
            assert_eq!(before, fixture.snapshot().unwrap());
            assert!(report.known.iter().all(|d| !d.executable), "{}", m.id);
            // The reviewed Spotify manifest has high static confidence, but
            // runtime build/format gates remain the executor's responsibility.
            assert!(report
                .known
                .iter()
                .all(|d| d.selected == (m.id == "spotify")));
            if matches!(m.roots[0], Root::Unresolved { .. }) {
                assert!(report.known.is_empty());
                assert!(report
                    .coverage
                    .iter()
                    .any(|c| c == &format!("{}-session-location-unresolved", m.id)));
            } else {
                assert_eq!(report.known.len(), 1, "{}", m.id);
            }
            checked += 1;
        }
    }
    assert_eq!(checked, 17);
}
