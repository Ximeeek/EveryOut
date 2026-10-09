#![cfg(windows)]
use everyout_core_model::*;
use everyout_engine::*;
use everyout_platform_windows::FixtureFolders;
use everyout_providers::executor::{ManifestExecutor, ProcessGate};
use serde_json::{json, Value};
use std::{cell::Cell, fs};

const CATALOGS: [&str; 6] = [
    include_str!("../../../catalog/browsers/chrome.json"),
    include_str!("../../../catalog/browsers/edge.json"),
    include_str!("../../../catalog/browsers/brave.json"),
    include_str!("../../../catalog/browsers/opera.json"),
    include_str!("../../../catalog/browsers/vivaldi.json"),
    include_str!("../../../catalog/browsers/firefox.json"),
];
const WARNING: &str = "Sync or automatic sign-in can recreate data or access after this wipe.";
#[derive(Default)]
struct Gate {
    closed: Cell<bool>,
    refuse: bool,
}
impl ProcessGate for Gate {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
        Ok(vec![])
    }
    fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
        if self.refuse {
            return Err(ErrorKind::Locked);
        }
        self.closed.set(true);
        Ok(())
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        if self.closed.get() {
            Ok(())
        } else {
            Err(ErrorKind::Locked)
        }
    }
}
#[test]
fn six_browsers_warn_without_reading_or_mutating_identity_payloads() {
    for catalog in CATALOGS {
        for (present, refuse) in [(false, false), (true, false), (true, true)] {
            let mut m: Value = serde_json::from_str(catalog).unwrap();
            m["support"] = json!("validated");
            for artifact in m["session_locations"].as_array_mut().unwrap() {
                artifact["confidence"] = "verified".into();
            }
            m["compatibility"]["product_versions"] = json!("synthetic-only-v1");
            m["confidence"]["version_coverage"] = json!("synthetic-only-v1");
            m["confidence"]["status"] = json!("verified");
            m["open_spikes"] = json!([]);
            m["risks"] = json!({"flags": [], "affected_data": [], "permanent_data_loss": "none", "confirmations": [], "evidence": ["layout"]});
            for method in m["cleaning_methods"].as_array_mut().unwrap() {
                method["blockers"] = json!([]);
            }
            let folders = FixtureFolders::create().unwrap();
            let root = folders
                .path()
                .join(m["roots"][0]["relative"].as_str().unwrap());
            let firefox = m["id"] == "firefox";
            let profile = root.join(if firefox { "Profiles/test" } else { "Default" });
            fs::create_dir_all(&profile).unwrap();
            if firefox {
                fs::write(
                    root.join("profiles.ini"),
                    b"[Profile0]\nIsRelative=1\nPath=Profiles/test\n",
                )
                .unwrap();
            }
            let identity = profile.join(if firefox {
                "signedInUser.json"
            } else {
                "Account Web Data"
            });
            let sync = profile.join(if firefox { "weave" } else { "Sync Data" });
            let opaque = b"\xff\xfe synthetic-email@example.invalid synthetic-token-canary";
            if present {
                fs::write(&identity, opaque).unwrap();
                fs::create_dir(&sync).unwrap();
                fs::write(sync.join("opaque"), opaque).unwrap();
            }
            let config = profile.join(if firefox { "prefs.js" } else { "Preferences" });
            fs::write(&config, opaque).unwrap();
            let cookie = profile.join(if firefox {
                "cookies.sqlite"
            } else {
                "Network/Cookies"
            });
            fs::create_dir_all(cookie.parent().unwrap()).unwrap();
            fs::write(&cookie, b"fixture-session").unwrap();
            let before = folders.snapshot().unwrap();
            let gate = Gate {
                refuse,
                ..Gate::default()
            };
            let provider = ManifestExecutor::load(
                &m.to_string(),
                &folders,
                UserId("fixture".into()),
                InstallationId("fixture".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture".into()), &provider);
            let inventory = engine
                .scan(&[&provider], Category::Browser, &mut |_| {})
                .unwrap();
            let ids = inventory.default_selection(Category::Browser);
            let run = engine
                .prepare(
                    inventory,
                    Category::Browser,
                    &ids,
                    ProcessClosePolicy::Ask,
                    &mut |_| {},
                )
                .unwrap();
            assert_eq!(before, folders.snapshot().unwrap());
            assert!(!gate.closed.get());
            let preview = run.preview().text();
            assert!(preview.contains(WARNING));
            assert!(preview.contains(if present {
                "=present; unverified"
            } else {
                "=absent; unverified"
            }));
            assert!(preview.contains("sync-active=unknown"));
            assert!(!preview.contains("synthetic-token"));
            assert!(!preview.contains("synthetic-email"));
            let mut approval = Approval::default();
            for item in &run.preview().sections[1].items {
                approval.confirmed_risks.push(
                    run.confirm_risks(&item.instance, &item.plan.as_ref().unwrap().risks.flags),
                );
            }
            let report = engine.apply(run, approval, &|| false, &mut |_| {});
            assert!(report.text().contains(WARNING));
            assert!(report.json().unwrap().contains("unverified"));
            assert_eq!(
                report.sections[1].items[0].identity_sync.identity,
                if refuse {
                    Uncertainty::Unknown
                } else {
                    Uncertainty::Unsupported
                }
            );
            assert_eq!(
                report.sections[1].items[0].identity_sync.sync,
                if refuse {
                    Uncertainty::Unknown
                } else {
                    Uncertainty::Unsupported
                }
            );
            assert_eq!(cookie.exists(), refuse);
            if refuse {
                assert_eq!(before, folders.snapshot().unwrap());
            }
            assert_eq!(fs::read(config).unwrap(), opaque);
            if present {
                assert_eq!(fs::read(identity).unwrap(), opaque);
                assert_eq!(fs::read(sync.join("opaque")).unwrap(), opaque);
            }
        }
    }
}

#[test]
fn exclusive_payload_lock_allows_metadata_without_content_access() {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    let folders = FixtureFolders::create().unwrap();
    let root_path = folders.path().join("Google/Chrome/User Data");
    fs::create_dir_all(root_path.join("Default")).unwrap();
    let path = root_path.join("Default/Account Web Data");
    fs::write(&path, b"opaque-fixture").unwrap();
    let locked = OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    let gate = Gate::default();
    let provider = ManifestExecutor::load(
        CATALOGS[0],
        &folders,
        UserId("fixture".into()),
        InstallationId("fixture".into()),
        &gate,
    )
    .unwrap();
    let detection = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("fixture".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    let description = provider.describe(&detection.instances[0]);
    assert!(description
        .descriptor
        .limitations
        .iter()
        .any(|l| l.contains("Account Web Data=present")));
    assert!(description
        .descriptor
        .limitations
        .iter()
        .any(|l| l.contains(WARNING)));
    drop(locked);
    assert_eq!(fs::read(path).unwrap(), b"opaque-fixture");
}

#[test]
fn redirected_sync_metadata_is_unknown_and_never_traversed() {
    use std::os::windows::process::CommandExt;
    let folders = FixtureFolders::create().unwrap();
    let profile = folders.path().join("Google/Chrome/User Data/Default");
    let outside = folders.path().join("unselected-fixture");
    fs::create_dir_all(&profile).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("canary"), b"preserved-fixture").unwrap();
    let link = profile.join("Sync Data");
    let output = std::process::Command::new("cmd.exe")
        .args(["/d", "/c"])
        .raw_arg(format!(
            "mklink /J \"{}\" \"{}\"",
            link.display(),
            outside.display()
        ))
        .output()
        .unwrap();
    assert!(output.status.success());
    let gate = Gate::default();
    let provider = ManifestExecutor::load(
        CATALOGS[0],
        &folders,
        UserId("fixture".into()),
        InstallationId("fixture".into()),
        &gate,
    )
    .unwrap();
    let detection = provider.detect(&DetectionContext {
        snapshot_id: SnapshotId("fixture".into()),
        account_mode: AccountMode::Current,
        metadata: &provider,
    });
    let description = provider.describe(&detection.instances[0]);
    assert!(description
        .descriptor
        .limitations
        .iter()
        .any(|l| l.contains("Sync Data=unknown")));
    assert_eq!(
        fs::read(outside.join("canary")).unwrap(),
        b"preserved-fixture"
    );
    fs::remove_dir(link).unwrap();
}
