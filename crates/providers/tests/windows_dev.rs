use everyout_core_model::*;
use everyout_providers::{load_manifest, windows_dev, Root};
use serde_json::json;

const CATALOG: [&str; 12] = [
    include_str!("../../../catalog/windows-dev/microsoft-credentials.json"),
    include_str!("../../../catalog/windows-dev/tokenbroker.json"),
    include_str!("../../../catalog/windows-dev/identitycache.json"),
    include_str!("../../../catalog/windows-dev/oneauth.json"),
    include_str!("../../../catalog/windows-dev/git-credentials.json"),
    include_str!("../../../catalog/windows-dev/github-cli.json"),
    include_str!("../../../catalog/windows-dev/npm.json"),
    include_str!("../../../catalog/windows-dev/docker.json"),
    include_str!("../../../catalog/windows-dev/azure-cli.json"),
    include_str!("../../../catalog/windows-dev/aws-cli.json"),
    include_str!("../../../catalog/windows-dev/gcloud.json"),
    include_str!("../../../catalog/windows-dev/kubectl.json"),
];
fn selection() -> Selection {
    Selection {
        snapshot_id: SnapshotId("research-only".into()),
        account_mode: AccountMode::Current,
        instances: vec![],
        profiles: vec![],
    }
}

#[test]
fn all_research_plans_are_blocked_with_sources_losses_and_sso_warning() {
    let docs = include_str!("../../../docs/catalog/windows-dev.md");
    for (id, input) in windows_dev::IDS.iter().zip(CATALOG) {
        let m = load_manifest(input).unwrap();
        assert_eq!(&m.id, id);
        assert!(matches!(m.roots[0], Root::Unresolved { .. }));
        assert!(docs.contains(&format!("id=\"{id}\"")));
        assert!(!m.risks.affected_data.is_empty());
        assert!(!m.sources.as_ref().unwrap().is_empty());
        let plan = windows_dev::research_plan(&m, selection()).unwrap();
        assert!(plan.actions.is_empty());
        assert!(plan
            .limitations
            .iter()
            .any(|s| s == windows_dev::refusal_reason(id).unwrap()));
        assert!(plan
            .blockers
            .iter()
            .any(|s| s == windows_dev::blocker(id).unwrap()));
        assert!(plan
            .limitations
            .iter()
            .any(|s| s == everyout_engine::WINDOWS_DEV_SSO_WARNING));
        let approvals = plan.confirmations.clone();
        assert_eq!(
            ValidatedPlan::review(plan, &approvals).unwrap_err(),
            ErrorKind::Unsupported
        );
        let mut all_users = selection();
        all_users.account_mode = AccountMode::AllAccounts;
        assert_eq!(
            windows_dev::research_plan(&m, all_users).unwrap_err(),
            ErrorKind::Unsupported
        );
    }
}

#[test]
fn no_manifest_edit_can_turn_unreviewed_targets_into_capabilities() {
    for input in CATALOG {
        for (pointer, replacement) in [
            ("/support", json!("validated")),
            (
                "/roots/0",
                json!({"id":"data","base":"local-app-data",
                "relative":"Microsoft/TokenBroker","scope":"os-user","owner":"tokenbroker"}),
            ),
            ("/cleaning_methods/0/blockers", json!([])),
            ("/cleaning_methods/0/adapter_id", json!("arbitrary-cli")),
            (
                "/cleaning_methods/0",
                json!({"id":"blocked-windows-dev",
                "kind":"delete-directory-family","blockers":[],"effects":["erase"],"exclusions":[]}),
            ),
            ("/risks/confirmations", json!([])),
            ("/preserve/artifact_families", json!([])),
            ("/sources", json!([])),
            ("/identity/process_names", json!(["cmd.exe"])),
            ("/id", json!("windows-sign-in")),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(input).unwrap();
            *value.pointer_mut(pointer).unwrap() = replacement;
            assert!(load_manifest(&value.to_string()).is_err(), "{pointer}");
        }
    }
}

#[test]
fn fabricated_validation_cannot_enable_a_generic_windows_cleanup() {
    let mut value: serde_json::Value = serde_json::from_str(CATALOG[0]).unwrap();
    value["id"] = json!("fabricated-reviewed-identity");
    value["identity"]["installation_id"] = json!("fabricated-reviewed-identity");
    value["support"] = json!("validated");
    value["compatibility"]["product_versions"] = json!("fixture-1");
    value["confidence"]["status"] = json!("verified");
    value["confidence"]["version_coverage"] = json!("fixture-1");
    value["open_spikes"] = json!([]);
    value["roots"][0] = json!({"id":"data","base":"local-app-data",
        "relative":"Microsoft/TokenBroker","scope":"os-user",
        "owner":"fabricated-reviewed-identity"});
    value["cleaning_methods"][0] = json!({"id":"blocked-windows-dev",
        "kind":"delete-directory-family","blockers":[],
        "effects":["remove-local-state"],"exclusions":[]});
    value["risks"]["flags"] = json!([]);
    value["risks"]["permanent_data_loss"] = json!("none");
    assert_eq!(
        load_manifest(&value.to_string()).unwrap_err().code,
        "unreviewed-windows-dev-scope"
    );
}

#[cfg(windows)]
#[test]
fn blocked_scopes_never_bind_files_registry_processes_or_credentials() {
    use everyout_engine::ProcessPreview;
    use everyout_platform_windows::FixtureFolders;
    use everyout_providers::{
        executor::{ManifestExecutor, ProcessGate},
        platform::PlatformManifest,
    };
    struct NoProcesses;
    impl ProcessGate for NoProcesses {
        fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
            panic!("unexpected process discovery")
        }
        fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
            panic!("unexpected process close")
        }
        fn revalidate(&self) -> Result<(), ErrorKind> {
            panic!("unexpected process revalidation")
        }
    }
    let fixture = FixtureFolders::create().unwrap();
    // Synthetic canaries only: a matching Microsoft name grants no ownership or deletion.
    for name in [
        "TokenBroker",
        "IdentityCache",
        "OneAuth",
        "windows-sign-in",
        "git-test-target",
    ] {
        std::fs::write(fixture.path().join(name), b"non-secret fixture").unwrap();
    }
    let before = fixture.snapshot().unwrap();
    for input in CATALOG {
        let manifest = PlatformManifest::load(input).unwrap();
        assert!(manifest.file("unresolved-session", None, &fixture).is_err());
        assert!(manifest.registry("unresolved-session").is_err());
        assert_eq!(
            ManifestExecutor::load(
                input,
                &fixture,
                UserId("test-user".into()),
                InstallationId("test-tool".into()),
                &NoProcesses
            )
            .err(),
            Some(ErrorKind::Unsupported)
        );
    }
    assert_eq!(before, fixture.snapshot().unwrap());
}
