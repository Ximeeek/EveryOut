#![cfg(windows)]
use everyout_core_model::{Category, Confidence};
use everyout_detection::scanner::{
    scan, scan_with_aliases, ReviewedBrowserAlias, ReviewedManifest,
};
use everyout_platform_windows::{
    inventory::{InstalledInventory, InventorySource, Registration},
    FixtureFolders, KnownFolder, RootResolver,
};
use serde_json::{json, Value};
use std::{fs, os::windows::fs::OpenOptionsExt};

fn config(id: &str, relative: &str, category: &str, artifact: &str) -> Value {
    let mut value: Value =
        serde_json::from_str(include_str!("../../providers/tests/fixtures/provider.json")).unwrap();
    value["id"] = json!(id);
    value["category"] = json!(category);
    value["roots"][0]["relative"] = json!(relative);
    value["roots"][0]["owner"] = json!(id);
    value["session_locations"][0]["relative"] = json!(artifact);
    value["confidence"]["level"] = json!("high");
    if category == "browser" {
        value["identity"]["browser_id"] = json!(id);
        value["profiles"]["directory_patterns"] = json!(["Default", "Profile *"]);
    } else {
        value["identity"] = json!({"installation_id":id, "process_names":[]});
        value["profiles"] = Value::Null;
        value["session_locations"][0]["scope"] = json!("os-user");
        value["session_locations"][0]["ownership"] = json!(if category == "application" {
            "application"
        } else {
            "shared-identity"
        });
    }
    value
}
fn reviewed(value: Value) -> ReviewedManifest {
    ReviewedManifest::load(&value.to_string()).unwrap()
}
fn package(family: &str, existing: Option<bool>, runtime: Option<bool>) -> Registration {
    Registration {
        name: "synthetic-store".into(),
        source: InventorySource::Package,
        provenance: vec!["fixture".into()],
        publisher: None,
        package_family: Some(family.into()),
        installation_exists: existing,
        runtime_present: runtime,
        exclusive_container: true,
    }
}
fn seed(root: &std::path::Path, relative: &str, bytes: usize) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, vec![17; bytes]).unwrap();
}
#[test]
fn phase_seventeen_known_fixtures_are_detected_and_selected_without_payload_reads() {
    let fixture = FixtureFolders::profiles(19).unwrap();
    let before = fixture.snapshot().unwrap();
    let mut firefox = config(
        "fixture-firefox",
        "Firefox/Profiles/lab.default",
        "application",
        "cookies.sqlite",
    );
    firefox["roots"][0]["base"] = json!("roaming-app-data");
    let mut electron = config(
        "fixture-electron",
        "Electron Lab",
        "application",
        "Network/Cookies",
    );
    electron["roots"][0]["base"] = json!("roaming-app-data");
    let manifests = [
        reviewed(config(
            "fixture-browser",
            "Chromium/User Data",
            "browser",
            "Network/Cookies",
        )),
        reviewed(firefox),
        reviewed(electron),
        reviewed(config(
            "fixture-steam",
            "Steam",
            "application",
            "config/loginusers.vdf",
        )),
        reviewed(config(
            "fixture-store",
            "Packages/EveryOutLab_synthetic/LocalState",
            "application",
            "session",
        )),
    ];
    // Sharing-denied payload still permits attributes-only detection.
    let locked = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(
            fixture
                .path()
                .join("LocalAppData/Chromium/User Data/Default/Network/Cookies"),
        )
        .unwrap();
    assert!(fs::File::open(
        fixture
            .path()
            .join("LocalAppData/Chromium/User Data/Default/Network/Cookies")
    )
    .is_err());
    let report = scan(
        &fixture,
        &InstalledInventory::default(),
        &manifests,
        &|| false,
    );
    assert_eq!(report.known.len(), 6);
    assert!(report.known.iter().all(|d| d.selected
        && !d.executable
        && d.confidence == Confidence::High
        && d.category.is_some()));
    assert!(report
        .known
        .iter()
        .flat_map(|d| &d.observations)
        .any(|o| o.size == Some(64)));
    assert!(report.candidates.is_empty());
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(&fixture.path().display().to_string()));
    drop(locked);
    assert_eq!(before, fixture.snapshot().unwrap());
}
#[test]
fn registered_package_highs_and_mediums_stay_in_unselected_candidate_group() {
    let fixture = FixtureFolders::profiles(20).unwrap();
    for family in [
        "SyntheticHigh_fixture",
        "SyntheticMedium_fixture",
        "SyntheticResidue_fixture",
        "SyntheticUnknown_fixture",
    ] {
        for (path, size) in [
            ("Network/Cookies", 64),
            ("Local Storage/opaque", 8),
            ("Session Storage/opaque", 8),
        ] {
            seed(
                fixture.path(),
                &format!("LocalAppData/Packages/{family}/LocalState/{path}"),
                size,
            );
        }
    }
    let mut medium = package("SyntheticMedium_fixture", Some(true), Some(false));
    medium.exclusive_container = false;
    let inventory = InstalledInventory {
        registrations: vec![
            package("SyntheticHigh_fixture", Some(true), Some(false)),
            medium,
            package("SyntheticResidue_fixture", Some(false), None),
            package("SyntheticUnknown_fixture", None, None),
        ],
        coverage: vec![],
    };
    let report = scan(&fixture, &inventory, &[], &|| false);
    assert_eq!(report.candidates.len(), 2);
    assert!(report
        .candidates
        .iter()
        .all(|d| !d.selected && !d.executable));
    assert!(report
        .candidates
        .iter()
        .any(|d| d.confidence == Confidence::High
            && d.points == Some(9)
            && d.category == Some(Category::Application)));
    assert!(report
        .candidates
        .iter()
        .any(|d| d.confidence == Confidence::Medium
            && d.points == Some(6)
            && d.category.is_none()
            && d.owner.is_none()));
    assert!(report.known.is_empty());
    assert!(report
        .coverage
        .iter()
        .any(|c| c == "package-registration-residue"));
    assert!(report
        .coverage
        .iter()
        .any(|c| c == "package-installation-unknown"));
    assert!(report.candidates.iter().all(|d| d.signals.len() >= 2));
}

#[test]
fn junctions_are_omitted_and_shallow_observation_does_not_enumerate_descendants() {
    use std::os::windows::process::CommandExt;
    let fixture = FixtureFolders::profiles(26).unwrap();
    let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
    for link in [
        "LocalAppData/redirected",
        "LocalAppData/Chromium/User Data/Default/redirected",
    ] {
        let link = fixture.path().join(link);
        let target = fixture.path().join("outside-allowed");
        let output = std::process::Command::new("cmd.exe")
            .args(["/d", "/c"])
            .raw_arg(format!(
                "mklink /J \"{}\" \"{}\"",
                link.display(),
                target.display()
            ))
            .output()
            .unwrap();
        assert!(output.status.success());
    }
    let shallow = root
        .path("Chromium/User Data/Default")
        .unwrap()
        .probe_shallow()
        .unwrap();
    assert!(shallow.exists && shallow.is_directory && shallow.size.is_none());
    assert!(root
        .path("Chromium/User Data/Default/redirected/canary")
        .is_err());
    let report = scan(&fixture, &InstalledInventory::default(), &[], &|| false);
    assert!(report
        .coverage
        .iter()
        .any(|c| c == "local-redirected-or-invalid-entries-omitted"));
    assert!(report.known.is_empty() && report.candidates.is_empty());
    let known = [reviewed(config(
        "fixture-browser",
        "Chromium/User Data",
        "browser",
        "Network/Cookies",
    ))];
    let report = scan(&fixture, &InstalledInventory::default(), &known, &|| false);
    assert_eq!(report.known.len(), 2);
}

#[test]
fn registry_key_presence_corroborates_manifests_without_value_or_target_reads() {
    let fixture = FixtureFolders::profiles(27).unwrap();
    let mut value = config(
        "registry-host",
        "Steam",
        "application",
        "config/loginusers.vdf",
    );
    value["roots"].as_array_mut().unwrap().push(json!({
        "id":"registration", "base":"registry", "hive":"current-user",
        "key":"Software/Microsoft/Windows/CurrentVersion/Uninstall/registry-host",
        "scope":"installation", "owner":"registry-host"
    }));
    value["detection"]["signals"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"registered", "root":"registration", "family":"installation", "observe":"exists"
        }));
    let manifests = [reviewed(value)];
    let inventory = InstalledInventory {
        registrations: vec![Registration {
            name: "registry-host".into(),
            source: InventorySource::Uninstall,
            provenance: vec!["hkcu-32-Uninstall".into(), "hkcu-64-Uninstall".into()],
            publisher: None,
            package_family: None,
            installation_exists: None,
            runtime_present: None,
            exclusive_container: false,
        }],
        coverage: vec![],
    };
    let report = scan(&fixture, &inventory, &manifests, &|| false);
    assert_eq!(report.known.len(), 1);
    assert!(report.known[0].signals.iter().any(|s| s == "registered"));
    let mut hklm = inventory.clone();
    hklm.registrations[0].provenance = vec!["hklm-64-Uninstall".into()];
    assert!(scan(&fixture, &hklm, &manifests, &|| false)
        .known
        .is_empty());
}
#[test]
fn false_positive_corpus_is_suppressed_even_with_coincidental_storage_names() {
    let fixture = FixtureFolders::profiles(21).unwrap();
    for (name, paths) in [
        ("random unrelated folder", vec!["notes", "photo"]),
        (
            "ordinary program",
            vec!["program.exe", "resources/app.asar"],
        ),
        (
            "cache only",
            vec!["Cache/opaque", "GPUCache/opaque", "Code Cache/opaque"],
        ),
        ("cookie name only", vec!["Cookies", "Network/Cookies"]),
        (
            "coincidental storage",
            vec![
                "Network/Cookies",
                "Local Storage/opaque",
                "Session Storage/opaque",
                "resources/app.asar",
            ],
        ),
        (
            "EveryOut",
            vec![
                "Network/Cookies",
                "Local Storage/opaque",
                "Session Storage/opaque",
            ],
        ),
    ] {
        for path in paths {
            seed(fixture.path(), &format!("LocalAppData/{name}/{path}"), 8);
        }
    }
    let inventory = InstalledInventory {
        registrations: vec![Registration {
            name: "coincidental storage".into(),
            source: InventorySource::Uninstall,
            provenance: vec!["hkcu-32".into(), "hkcu-64".into()],
            publisher: None,
            package_family: None,
            installation_exists: None,
            runtime_present: None,
            exclusive_container: false,
        }],
        coverage: vec![],
    };
    let before = fixture.snapshot().unwrap();
    let report = scan(&fixture, &inventory, &[], &|| false);
    assert!(report.known.is_empty());
    assert!(report
        .candidates
        .iter()
        .all(|d| d.confidence == Confidence::Low && !d.selected));
    assert!(report.candidates.is_empty()); // folder names do not establish another family
    assert_eq!(before, fixture.snapshot().unwrap());
}
#[test]
fn reviewed_pwa_alias_merges_with_browser_and_unreviewed_wrapper_conflicts() {
    let fixture = FixtureFolders::profiles(22).unwrap();
    let manifests = [
        reviewed(config(
            "fixture-browser",
            "Chromium/User Data",
            "browser",
            "Network/Cookies",
        )),
        reviewed(config(
            "fixture-pwa",
            "Chromium/User Data/Default",
            "application",
            "Network/Cookies",
        )),
    ];
    let unreviewed = scan(
        &fixture,
        &InstalledInventory::default(),
        &manifests,
        &|| false,
    );
    assert_eq!(unreviewed.candidates.len(), 2);
    assert!(unreviewed
        .candidates
        .iter()
        .all(|d| d.category.is_none() && d.owner.is_none() && !d.selected && !d.executable));
    let report = scan_with_aliases(
        &fixture,
        &InstalledInventory::default(),
        &manifests,
        &[ReviewedBrowserAlias {
            provider_id: "fixture-pwa".into(),
            browser_owner: "fixture-browser".into(),
        }],
        &|| false,
    );
    assert_eq!(report.known.len(), 2); // two browser profiles, one PWA alias
    assert!(report.candidates.is_empty());
    assert!(report
        .known
        .iter()
        .all(|d| d.category == Some(Category::Browser)));
    assert_eq!(
        report.known.iter().map(|d| d.aliases.len()).sum::<usize>(),
        1
    );
}
#[test]
fn independent_webview2_and_store_classify_as_apps_and_shared_udf_is_unclassified() {
    let fixture = FixtureFolders::profiles(23).unwrap();
    let manifests = [
        reviewed(config(
            "webview-host",
            "Chromium/User Data/Default",
            "application",
            "Network/Cookies",
        )),
        reviewed(config(
            "store-host",
            "Packages/EveryOutLab_synthetic/LocalState",
            "application",
            "session",
        )),
        reviewed(config(
            "reviewed-sso",
            "Steam",
            "windows-microsoft-and-dev-tools",
            "config/loginusers.vdf",
        )),
    ];
    let report = scan(
        &fixture,
        &InstalledInventory::default(),
        &manifests,
        &|| false,
    );
    assert_eq!(report.known.len(), 3);
    assert!(report
        .known
        .iter()
        .take(2)
        .all(|d| d.category == Some(Category::Application)));
    assert_eq!(
        report.known[2].category,
        Some(Category::WindowsMicrosoftAndDevTools)
    );
    let shared = [
        reviewed(config(
            "host-a",
            "Chromium/User Data/Default",
            "application",
            "Network/Cookies",
        )),
        reviewed(config(
            "host-b",
            "Chromium/User Data/Default",
            "application",
            "Network/Cookies",
        )),
    ];
    let report = scan(&fixture, &InstalledInventory::default(), &shared, &|| false);
    assert!(report.known.is_empty());
    assert_eq!(report.candidates.len(), 2);
    assert!(report
        .candidates
        .iter()
        .all(|d| d.category.is_none() && !d.selected && !d.executable));
}
#[test]
fn ancestor_overlap_is_blocked_and_metadata_probe_never_walks_nested_directories() {
    let fixture = FixtureFolders::profiles(24).unwrap();
    let root = fixture.resolve(KnownFolder::LocalAppData).unwrap();
    let shallow = root
        .path("Chromium/User Data")
        .unwrap()
        .probe_shallow()
        .unwrap();
    assert!(shallow.exists && shallow.is_directory);
    assert_eq!(shallow.size, None);
    let mut broad = config("broad-host", "Chromium/User Data", "application", "Default");
    broad["session_locations"][0]["kind"] = json!("directory");
    broad["session_locations"][0]["observe"] = json!("exists");
    broad["detection"]["signals"][1]["observe"] = json!("exists");
    broad["cleaning_methods"][0] = json!({"id":"remove-store", "kind":"delete-directory-family", "blockers":["candidate-support"], "effects":["fixture-only"], "exclusions":[]});
    let manifests = [
        reviewed(broad),
        reviewed(config(
            "narrow-host",
            "Chromium/User Data/Default",
            "application",
            "Network/Cookies",
        )),
    ];
    let report = scan(
        &fixture,
        &InstalledInventory::default(),
        &manifests,
        &|| false,
    );
    assert!(report.known.is_empty());
    assert_eq!(report.candidates.len(), 2);
    assert!(report
        .candidates
        .iter()
        .all(|d| d.category.is_none() && !d.executable));
}
#[test]
fn cancellation_and_missing_metadata_are_incomplete_coverage() {
    let fixture = FixtureFolders::profiles(25).unwrap();
    let report = scan(&fixture, &InstalledInventory::default(), &[], &|| true);
    assert!(report.known.is_empty() && report.candidates.is_empty());
    assert!(report.coverage.iter().any(|c| c == "cancelled"));
    let manifests = [reviewed(config(
        "missing-host",
        "Missing",
        "application",
        "Network/Cookies",
    ))];
    let report = scan(
        &fixture,
        &InstalledInventory::default(),
        &manifests,
        &|| false,
    );
    assert!(report.known.is_empty());
    assert!(report
        .coverage
        .iter()
        .any(|c| c == "registry-install-mapping-and-profile-configuration-blocked"));
}
