use everyout_heuristic_scan::{Evidence, candidate, excluded, safe_path, score, storage};
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
            "everyout-scan-{}-{}",
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
fn scores_independent_families_and_requires_high_gates() {
    let all = Evidence {
        identity: true,
        runtime: true,
        storage: true,
        ownership: true,
        plausible_owner: true,
        ..Default::default()
    };
    assert_eq!(score(all).points, 11);
    assert_eq!(score(all).confidence, "high");
    assert!(!score(all).actionable);
    assert_eq!(
        score(Evidence {
            ownership: false,
            ..all
        })
        .confidence,
        "medium"
    );
    assert_eq!(
        score(Evidence {
            identity: false,
            ..all
        })
        .confidence,
        "medium"
    );
    assert_eq!(
        score(Evidence {
            plausible_owner: false,
            ownership: false,
            ..all
        })
        .confidence,
        "low"
    );
    assert_eq!(
        score(Evidence {
            runtime: true,
            storage: true,
            ..Default::default()
        })
        .confidence,
        "low"
    );
    for e in [
        Evidence {
            conflict: true,
            ..all
        },
        Evidence {
            excluded: true,
            ..all
        },
        Evidence {
            storage: true,
            ..Default::default()
        },
    ] {
        assert_eq!(score(e).confidence, "suppressed");
    }
}
#[test]
fn fixture_observes_sizes_but_never_reads_locked_payloads() {
    let fixture = Fixture::new();
    fs::write(fixture.0.join("Cookies"), b"SYNTHETIC_SECRET").unwrap();
    fs::create_dir(fixture.0.join("Local Storage")).unwrap();
    fs::create_dir(fixture.0.join("Session Storage")).unwrap();
    #[cfg(windows)]
    let guard = {
        use std::os::windows::fs::OpenOptionsExt;
        let guard = fs::OpenOptions::new()
            .read(true)
            .share_mode(0)
            .open(fixture.0.join("Cookies"))
            .unwrap();
        assert!(fs::File::open(fixture.0.join("Cookies")).is_err());
        guard
    };
    let (fired, observations) = storage(&fixture.0);
    assert!(fired);
    assert_eq!(observations[0].bytes, Some(16));
    let c = candidate("opaque".into(), "fixture", 0, &fixture.0, None, false);
    assert_eq!(c.score.confidence, "suppressed");
    let json = serde_json::to_string(&c).unwrap();
    assert!(!json.contains("SYNTHETIC_SECRET"));
    assert!(!json.contains(fixture.0.to_str().unwrap()));
    #[cfg(windows)]
    drop(guard);
}
#[test]
fn cookie_aliases_do_not_manufacture_a_storage_cluster() {
    let fixture = Fixture::new();
    fs::create_dir(fixture.0.join("Network")).unwrap();
    for path in ["Cookies", "Network/Cookies", "Local State"] {
        fs::write(fixture.0.join(path), b"fixture").unwrap();
    }
    assert!(!storage(&fixture.0).0);
}
#[test]
fn registered_package_fixture_can_be_high_but_missing_install_cannot() {
    let data = Fixture::new();
    let install = Fixture::new();
    for name in ["IndexedDB", "Local Storage", "Session Storage"] {
        fs::create_dir(data.0.join(name)).unwrap();
    }
    fs::create_dir_all(install.0.join("resources/app")).unwrap();
    let missing_data = candidate(
        "missing".into(),
        "fixture",
        0,
        &data.0.join("absent"),
        Some(&install.0),
        true,
    );
    assert_eq!(missing_data.score.confidence, "suppressed");
    let residue = candidate(
        "residue".into(),
        "fixture",
        0,
        &data.0,
        Some(&install.0.join("absent")),
        true,
    );
    assert_eq!(residue.installation_state, "residue");
    assert_eq!(
        candidate(
            "package".into(),
            "fixture",
            0,
            &data.0,
            Some(&install.0),
            true
        )
        .score
        .confidence,
        "high"
    );
    assert_eq!(
        candidate(
            "package".into(),
            "fixture",
            0,
            &data.0,
            Some(&install.0.join("absent")),
            true
        )
        .score
        .confidence,
        "suppressed"
    );
    assert_eq!(
        candidate(
            "unmapped".into(),
            "fixture",
            0,
            &data.0,
            Some(&install.0),
            false
        )
        .score
        .confidence,
        "suppressed"
    );
}
#[test]
fn exclusions_missing_and_relative_roots() {
    assert!(excluded("EveryOut"));
    assert!(excluded("Microsoft.AAD.BrokerPlugin_fixture"));
    assert!(safe_path(std::path::Path::new("relative")).is_err());
    let fixture = Fixture::new();
    assert!(safe_path(&fixture.0.join("..")).is_err());
    let observations = storage(&fixture.0.join("absent")).1;
    assert!(
        observations
            .iter()
            .all(|o| o.state == "absent" && o.bytes.is_none())
    );
}
#[cfg(windows)]
#[test]
fn junctions_and_redirected_ancestors_are_unknown_without_traversal() {
    use std::os::windows::process::CommandExt;
    let fixture = Fixture::new();
    let outside = Fixture::new();
    fs::write(outside.0.join("Cookies"), b"outside").unwrap();
    let junction = fixture.0.join("redirect");
    assert!(
        std::process::Command::new("cmd.exe")
            .args(["/c", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside.0)
            .creation_flags(0x08000000)
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(safe_path(&junction.join("Cookies")).is_err());
    assert!(storage(&junction).1.iter().all(|o| o.state == "unknown"));
    fs::remove_dir(junction).unwrap();
    assert!(outside.0.join("Cookies").exists());
}
#[test]
fn source_audit_excludes_payload_network_and_mutation_operations() {
    for source in [
        include_str!("../src/lib.rs"),
        include_str!("../src/windows.rs"),
        include_str!("../src/main.rs"),
    ] {
        for api in [
            "File::open",
            "OpenOptions",
            "fs::read(",
            "read_to_end",
            "read_to_string",
            "RegQueryValue",
            "RegSetValue",
            "Command::",
            "TcpStream",
            "UdpSocket",
            "fs::write",
            "remove_file",
        ] {
            assert!(!source.contains(api), "prohibited API {api}");
        }
    }
}
