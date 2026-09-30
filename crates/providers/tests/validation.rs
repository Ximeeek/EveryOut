use everyout_providers::{
    load_manifest, manifest::manifest_schema, validation::MANIFEST_SCHEMA, ManifestErrorKind,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/provider.json")).unwrap()
}
fn load(value: &Value) -> Result<everyout_providers::Manifest, everyout_providers::ManifestError> {
    load_manifest(&value.to_string())
}
fn reject(mut value: Value, pointer: &str, replacement: Value, code: &str) {
    *value.pointer_mut(pointer).unwrap() = replacement;
    let error = load(&value).unwrap_err();
    assert_eq!(error.code, code, "{pointer}");
}
#[test]
fn valid_candidate_and_serialization_round_trip() {
    let manifest = load(&fixture()).unwrap();
    let serialized = serde_json::to_string(&manifest).unwrap();
    assert_eq!(manifest, load_manifest(&serialized).unwrap());
}
#[test]
fn bundled_schema_matches_the_serde_model() {
    assert_eq!(
        serde_json::from_str::<Value>(MANIFEST_SCHEMA).unwrap(),
        manifest_schema()
    );
}
#[test]
fn json_and_schema_rejections() {
    assert_eq!(
        load_manifest("{").unwrap_err().kind,
        ManifestErrorKind::Json
    );
    for field in [
        "format_version",
        "id",
        "revision",
        "name",
        "category",
        "support",
        "compatibility",
        "identity",
        "detection",
        "roots",
        "session_locations",
        "cleaning_methods",
        "preserve",
        "true_logout",
        "risks",
        "confidence",
        "evidence",
        "limitations",
        "open_spikes",
    ] {
        let mut value = fixture();
        value.as_object_mut().unwrap().remove(field);
        assert_eq!(
            load(&value).unwrap_err().kind,
            ManifestErrorKind::Schema,
            "{field}"
        );
    }
    for (pointer, replacement) in [
        ("/format_version", json!(2)),
        ("/revision", json!(0)),
        ("/id", json!("Bad_ID")),
        ("/category", json!("other")),
        ("/confidence/level", json!("certain")),
        ("/roots/0/base", json!("user-override")),
        ("/roots/0/base", json!("program-data")),
        ("/cleaning_methods/0/kind", json!("shell-command")),
        ("/compatibility/os/0", json!("linux")),
        ("/roots", json!([])),
        ("/evidence", json!([])),
        ("/session_locations", json!([])),
        ("/cleaning_methods", json!([])),
        ("/risks/permanent_data_loss", json!("safe")),
    ] {
        reject(fixture(), pointer, replacement, "invalid-schema");
    }
    let mut value = fixture();
    value["identity"]["read_cookies"] = json!(true);
    assert_eq!(load(&value).unwrap_err().kind, ManifestErrorKind::Schema);
    value = fixture();
    value["session_locations"][0]["command"] = json!("anything");
    assert_eq!(load(&value).unwrap_err().kind, ManifestErrorKind::Schema);
}
#[test]
fn windows_paths_are_checked_without_touching_any_profile() {
    let bad = [
        "..",
        "a/../b",
        "a\\..\\b",
        ".",
        "a/./b",
        "C:\\Outside",
        "C:relative",
        "\\\\server\\share",
        "\\\\?\\C:\\outside",
        "/root",
        "\\root",
        "a//b",
        "a\\\\b",
        "a/",
        "file:stream",
        "%APPDATA%\\other",
        "a*",
        "a?",
        "NUL",
        "con.txt",
        "COM1",
        "LPT9.txt",
        "COM¹.txt",
        "trailing.",
        "trailing ",
        ".. ",
        "a\u{0000}b",
        "a|b",
        "<a>",
        "\"a\"",
    ];
    for path in bad {
        reject(
            fixture(),
            "/roots/0/relative",
            json!(path),
            "invalid-root-scope-or-path",
        );
        reject(
            fixture(),
            "/session_locations/0/relative",
            json!(path),
            "invalid-artifact-reference-or-path",
        );
    }
    for path in ["a b\\c", "目录\\Storage", "COM10", "file.json"] {
        let mut value = fixture();
        value["roots"][0]["relative"] = json!(path);
        assert!(load(&value).is_ok(), "{path}");
    }
}
#[test]
fn category_specific_fields_and_owner_scope_are_required() {
    reject(
        fixture(),
        "/identity/browser_id",
        Value::Null,
        "browser-requires-identity-and-profiles",
    );
    reject(
        fixture(),
        "/profiles",
        Value::Null,
        "browser-requires-identity-and-profiles",
    );
    for category in ["application", "windows-microsoft-and-dev-tools"] {
        reject(
            fixture(),
            "/category",
            json!(category),
            "category-requires-installation-or-package",
        );
    }
    reject(
        fixture(),
        "/roots/0/owner",
        json!("other"),
        "invalid-root-scope-or-path",
    );
    reject(
        fixture(),
        "/roots/0/scope",
        json!("profile"),
        "invalid-root-scope-or-path",
    );
    reject(
        fixture(),
        "/session_locations/0/ownership",
        json!("application"),
        "category-ownership-conflict",
    );
    reject(
        fixture(),
        "/detection/require_exclusive_owner",
        json!(false),
        "missing-coverage-or-ownership",
    );
}
#[test]
fn references_and_profile_patterns_are_bounded() {
    for (pointer, replacement, code) in [
        ("/roots/0/id", json!("Bad"), "invalid-or-duplicate-id"),
        (
            "/session_locations/0/root",
            json!("missing"),
            "invalid-artifact-reference-or-path",
        ),
        (
            "/session_locations/0/method",
            json!("missing"),
            "invalid-artifact-reference-or-path",
        ),
        (
            "/profiles/root",
            json!("missing"),
            "invalid-profile-discovery",
        ),
        (
            "/profiles/directory_patterns",
            json!([]),
            "invalid-profile-discovery",
        ),
        (
            "/detection/signals/0/root",
            json!("missing"),
            "invalid-detection-reference",
        ),
        (
            "/detection/signals/1/artifact",
            json!("missing"),
            "invalid-detection-reference",
        ),
        (
            "/risks/evidence",
            json!(["missing"]),
            "missing-evidence-reference",
        ),
        (
            "/true_logout/evidence",
            json!([]),
            "missing-evidence-reference",
        ),
    ] {
        reject(fixture(), pointer, replacement, code);
    }
    for pattern in [
        "../*",
        "**",
        "a/b",
        "a\\b",
        "C:*",
        "Profile * *",
        ".",
        "NUL",
    ] {
        reject(
            fixture(),
            "/profiles/directory_patterns/0",
            json!(pattern),
            "invalid-profile-discovery",
        );
    }
    let mut value = fixture();
    value["profiles"]["metadata_adapter"] = json!("parse-preferences");
    assert_eq!(load(&value).unwrap_err().code, "invalid-profile-discovery");
    value = fixture();
    value["detection"]["signals"][0]["artifact"] = json!("session-store");
    assert_eq!(
        load(&value).unwrap_err().code,
        "invalid-detection-reference"
    );
    for field in ["roots", "session_locations", "cleaning_methods", "evidence"] {
        value = fixture();
        let duplicate = value[field][0].clone();
        value[field].as_array_mut().unwrap().push(duplicate);
        assert_eq!(load(&value).unwrap_err().code, "invalid-or-duplicate-id");
    }
}
fn validated() -> Value {
    let mut value = fixture();
    value["support"] = json!("validated");
    value["compatibility"]["product_versions"] = json!("fixture-1");
    value["confidence"]["version_coverage"] = json!("fixture-1");
    value["open_spikes"] = json!([]);
    value["risks"]["flags"] = json!([]);
    value["risks"]["permanent_data_loss"] = json!("none");
    value["cleaning_methods"][0]["blockers"] = json!([]);
    value["cleaning_methods"][0]["effects"] = json!(["remove-fixture-session"]);
    value
}
#[test]
fn validated_support_cannot_hide_unknown_coverage_or_loss() {
    assert!(load(&validated()).is_ok());
    for (pointer, replacement) in [
        ("/compatibility/product_versions", json!("unvalidated")),
        ("/confidence/version_coverage", Value::Null),
        ("/open_spikes", json!(["closure"])),
        ("/risks/permanent_data_loss", json!("unknown")),
        ("/cleaning_methods/0/blockers", json!(["unresolved"])),
        ("/cleaning_methods/0/effects", json!([])),
    ] {
        reject(
            validated(),
            pointer,
            replacement,
            "validated-support-has-unresolved-coverage",
        );
    }
    reject(
        validated(),
        "/risks/flags",
        json!(["saved-passwords-passkeys-autofill-history"]),
        "loss-flags-conflict-with-no-loss",
    );
    let mut protected = validated();
    protected["risks"]["flags"] = json!(["saved-passwords-passkeys-autofill-history"]);
    protected["risks"]["permanent_data_loss"] = json!("known");
    protected["risks"]["reason"] = json!("protected-fixture-family");
    assert_eq!(
        load(&protected).unwrap_err().code,
        "validated-support-has-unresolved-coverage"
    );
    reject(
        validated(),
        "/session_locations/0/artifact_family",
        json!("history"),
        "preservation-conflict",
    );
    reject(
        validated(),
        "/risks/flags",
        json!(["unknown"]),
        "unknown-risk-treated-as-known",
    );
    reject(
        fixture(),
        "/risks/permanent_data_loss",
        json!("known"),
        "incomplete-known-loss-assessment",
    );
    reject(
        fixture(),
        "/preserve/artifact_families",
        json!([]),
        "missing-browser-preservation",
    );
}
#[test]
fn methods_evidence_and_observations_have_no_broad_fallback() {
    reject(
        fixture(),
        "/cleaning_methods/0/companions",
        json!(["../../other"]),
        "invalid-companion",
    );
    reject(
        fixture(),
        "/cleaning_methods/0/companions",
        json!(["-wal", "-wal"]),
        "invalid-companion",
    );
    reject(
        fixture(),
        "/session_locations/0/kind",
        json!("directory"),
        "incompatible-artifact-method",
    );
    reject(
        fixture(),
        "/identity/process_names/0",
        json!("../app.exe"),
        "invalid-process-name",
    );
    reject(
        fixture(),
        "/evidence/0/dossier",
        json!("no-anchor"),
        "incomplete-evidence",
    );
    let mut value = fixture();
    value["evidence"][0]["source"] = json!("https://example.invalid/source");
    assert_eq!(load(&value).unwrap_err().code, "incomplete-evidence");
    for kind in ["local-api-operation", "exception-adapter"] {
        value = validated();
        value["cleaning_methods"][0] = if kind == "local-api-operation" {
            json!({"id":"remove-store", "kind":kind, "operation_id":"review-pending", "blockers":[], "effects":["fixture"]})
        } else {
            json!({"id":"remove-store", "kind":kind, "adapter_id":"review-pending", "blockers":[], "effects":["fixture"]})
        };
        assert_eq!(
            load(&value).unwrap_err().code,
            if kind == "local-api-operation" {
                "unreviewed-local-api"
            } else {
                "unreviewed-exception-adapter"
            }
        );
    }
}
#[test]
fn exact_registry_scope_and_directory_exclusions() {
    let mut value = fixture();
    value["category"] = json!("windows-microsoft-and-dev-tools");
    value["identity"] = json!({"installation_id":"fixture", "process_names":[]});
    value["profiles"] = Value::Null;
    value["roots"][0] = json!({"id":"user-data", "base":"registry", "hive":"current-user", "key":"Software\\EveryOutFixtures", "scope":"os-user", "owner":"fixture-browser"});
    value["session_locations"][0]["scope"] = json!("os-user");
    value["session_locations"][0]["kind"] = json!("registry-value");
    value["session_locations"][0]["observe"] = json!("exists");
    value["session_locations"][0]["ownership"] = json!("developer-tool");
    value["detection"]["signals"][1]["observe"] = json!("exists");
    value["cleaning_methods"][0] = json!({"id":"remove-store", "kind":"delete-registry-target", "blockers":["candidate-support"], "effects":["fixture"]});
    assert!(load(&value).is_ok());
    reject(
        value.clone(),
        "/roots/0/hive",
        json!("local-machine"),
        "invalid-schema",
    );
    reject(
        value.clone(),
        "/roots/0/key",
        json!("System\\Identity"),
        "registry-root-outside-software",
    );
    reject(
        value,
        "/session_locations/0/observe",
        json!("exists-and-size"),
        "incompatible-artifact-method",
    );
    let mut value = fixture();
    value["session_locations"][0]["kind"] = json!("directory");
    value["session_locations"][0]["observe"] = json!("exists");
    value["cleaning_methods"][0] = json!({"id":"remove-store", "kind":"delete-directory-family", "blockers":["candidate-support"], "effects":["fixture"], "exclusions":["Preserved\\Store"]});
    assert!(load(&value).is_ok());
    reject(
        value,
        "/cleaning_methods/0/exclusions/0",
        json!("../outside"),
        "invalid-exclusion",
    );
}

#[test]
fn remaining_semantic_rejections_are_explicit() {
    for (pointer, replacement) in [
        ("/name", json!(" ")),
        ("/compatibility/os", json!([])),
        ("/compatibility/channel", json!("")),
        ("/compatibility/product_versions", json!("")),
        ("/confidence/rationale", json!("")),
        ("/true_logout/mechanism", json!("")),
        ("/detection/signals", json!([])),
    ] {
        reject(
            fixture(),
            pointer,
            replacement,
            "missing-coverage-or-ownership",
        );
    }
    let mut value = fixture();
    value["category"] = json!("application");
    value["identity"]["installation_id"] = json!("fixture-install");
    assert_eq!(
        load(&value).unwrap_err().code,
        "conflicting-category-identity"
    );
    value["identity"]["browser_id"] = Value::Null;
    value["session_locations"][0]["ownership"] = json!("application");
    value["profiles"] = Value::Null;
    assert_eq!(load(&value).unwrap_err().code, "missing-profile-scope");
    value = fixture();
    value["roots"][0] = json!({"id":"user-data", "base":"registry", "hive":"current-user", "key":"Software\\Fixture", "scope":"os-user", "owner":"fixture-browser"});
    assert_eq!(
        load(&value).unwrap_err().code,
        "browser-registry-root-unsupported"
    );
    value = validated();
    value["category"] = json!("windows-microsoft-and-dev-tools");
    value["identity"] = json!({"installation_id":"fixture-install", "process_names":[]});
    value["session_locations"][0]["ownership"] = json!("developer-tool");
    value["risks"]["confirmations"] = json!([]);
    assert_eq!(
        load(&value).unwrap_err().code,
        "special-category-requires-confirmation"
    );
    reject(
        validated(),
        "/risks/flags",
        json!(["wallet-or-key-material"]),
        "loss-flags-conflict-with-no-loss",
    );
    for version in [" UNKNOWN ", "Unvalidated", ""] {
        let code = if version.is_empty() {
            "missing-coverage-or-ownership"
        } else {
            "validated-support-has-unresolved-coverage"
        };
        reject(
            validated(),
            "/compatibility/product_versions",
            json!(version),
            code,
        );
        reject(
            validated(),
            "/confidence/version_coverage",
            json!(version),
            "validated-support-has-unresolved-coverage",
        );
    }
    reject(
        validated(),
        "/cleaning_methods/0/effects",
        json!([""]),
        "validated-support-has-unresolved-coverage",
    );
    reject(
        fixture(),
        "/profiles/directory_patterns/0",
        json!("*"),
        "invalid-profile-discovery",
    );
}
