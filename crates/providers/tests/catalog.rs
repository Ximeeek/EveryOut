use everyout_providers::load_manifest;
use std::{fs, path::Path};

#[test]
fn every_catalog_manifest_validates_and_browser_entries_have_evidence() {
    fn visit(path: &Path, count: &mut usize) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path.file_name().unwrap() != "schema" {
                    visit(&path, count);
                }
            } else if path.extension().is_some_and(|e| e == "json") {
                let m = load_manifest(&fs::read_to_string(&path).unwrap()).unwrap();
                *count += 1;
                assert_eq!(m.confidence.status.as_deref(), Some("unverified"));
                for entry in m.session_locations {
                    assert_eq!(entry.confidence.as_deref(), Some("unverified"));
                    assert!(!entry.evidence.unwrap().is_empty());
                }
                for risk in m.extensions.unwrap().known {
                    assert!(risk.source.contains(&risk.id));
                    assert!(matches!(
                        risk.confidence.as_str(),
                        "verified" | "unverified"
                    ));
                }
            }
        }
    }
    let mut count = 0;
    visit(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../catalog")
            .as_path(),
        &mut count,
    );
    assert_eq!(count, 5);
}

#[test]
fn extension_policy_rejects_escapes_unknown_waivers_and_invalid_ids() {
    let initial: serde_json::Value =
        serde_json::from_str(include_str!("../../../catalog/browsers/chrome.json")).unwrap();
    for (pointer, replacement) in [
        ("/extensions/stores/0", serde_json::json!("Login Data")),
        ("/extensions/unknown", serde_json::json!("delete")),
        ("/extensions/known/0/id", serde_json::json!("../outside")),
        (
            "/extensions/known/0/source",
            serde_json::json!("https://example.com/unrelated"),
        ),
        (
            "/extensions/known/0/confidence",
            serde_json::json!("certain"),
        ),
        (
            "/extensions/known/0/flag",
            serde_json::json!("shared-store"),
        ),
        ("/confidence/status", serde_json::json!("certain")),
        (
            "/session_locations/0/evidence",
            serde_json::json!(["nonexistent-source"]),
        ),
    ] {
        let mut m = initial.clone();
        *m.pointer_mut(pointer).unwrap() = replacement;
        assert!(load_manifest(&m.to_string()).is_err(), "{pointer}");
    }
}
