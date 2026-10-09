use crate::{application::CurrentSession, bridge::Bridge, dto::*, settings::SettingsStore};
use ed25519_dalek::{Signer, SigningKey};
use everyout_catalog_update::{self as catalog, store::Store};
use everyout_core_model::*;
use rand_core::RngCore;

struct NoOperations;
impl MetadataAccess for NoOperations {
    fn observe(&self, _: &OwnerIdentity, _: &ArtifactId) -> Result<MetadataObservation, ErrorKind> {
        panic!("catalog tests must never inspect session data")
    }
}
impl LocalOperations for NoOperations {
    fn apply(&self, _: &ValidatedPlan, _: &ActionId) -> ActionOutcome {
        panic!("catalog tests must never mutate session data")
    }
}
struct Fake(Vec<u8>);
impl catalog::transport::Source for Fake {
    fn download(&self, _: usize) -> catalog::Result<Vec<u8>> {
        Ok(self.0.clone())
    }
}
#[test]
fn acceptance_defers_review_rebuilds_session_and_refuses_stale_inventory_and_helper() {
    let dir = tempfile::tempdir().unwrap();
    let (bridge, mut worker) =
        Bridge::channel(SettingsStore::new(dir.path().into()), None).unwrap();
    let base = catalog::bundled(
        catalog::entries([
            include_str!("../../crates/providers/tests/fixtures/provider.json").to_owned(),
        ])
        .unwrap(),
    )
    .unwrap();
    let mut seed = [0; 32];
    rand_core::OsRng.fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    let trust = catalog::Trust::new(Some(key.verifying_key().to_bytes()), &base).unwrap();
    let mut m: serde_json::Value = serde_json::from_str(&base.entries[0].manifest).unwrap();
    m["revision"] = serde_json::json!(2);
    let payload = serde_json::to_string(&catalog::envelope(
        catalog::entries([m.to_string()]).unwrap(),
        catalog::BUNDLED_VERSION + 1,
        "Changed provider".into(),
    ))
    .unwrap();
    let bytes = serde_json::to_vec(&catalog::SignedBundle {
        signature: hex::encode(key.sign(&catalog::signing_bytes(&payload)).to_bytes()),
        payload,
    })
    .unwrap();
    let mut store = Store::open(&dir.path().join("catalog"), base, trust).unwrap();
    let digest = store.check(&Fake(bytes)).unwrap().digest.clone();
    worker.catalog = Some(Ok(store));
    let thread = std::thread::spawn(move || loop {
        let session = CurrentSession::new(&NoOperations, vec![]);
        match worker.serve(session, everyout_detection::ScanReport::default, vec![]) {
            Some(next) => worker = next,
            None => break,
        }
    });
    let old = bridge.scan().unwrap();
    assert!(matches!(
        bridge.activate_catalog_update(digest.clone()),
        Err(CommandError::Busy)
    ));
    bridge.set_settings(Settings::default()).unwrap();
    let accepted = bridge.activate_catalog_update(digest).unwrap();
    assert_eq!(
        accepted.installed_version,
        (catalog::BUNDLED_VERSION + 1).to_string()
    );
    assert!(!accepted.helper_compatible);
    assert!(accepted.error.is_none());
    assert!(matches!(
        bridge.enable_all_accounts_mode(),
        Err(CommandError::HelperUnavailable)
    ));
    assert!(matches!(
        bridge.build_plan(SelectionRequest {
            inventory_id: old.inventory_id,
            items: vec![],
            profiles: vec![],
            skipped: None
        }),
        Err(CommandError::StalePlan)
    ));
    assert!(bridge.scan().is_ok());
    drop(bridge);
    thread.join().unwrap();
}
#[test]
fn failed_catalog_state_blocks_scan_but_status_remains_available() {
    let dir = tempfile::tempdir().unwrap();
    let (bridge, mut worker) =
        Bridge::channel(SettingsStore::new(dir.path().into()), None).unwrap();
    worker.catalog = Some(Err(catalog::Error::Storage));
    let thread = std::thread::spawn(move || {
        worker.serve(
            CurrentSession::new(&NoOperations, vec![]),
            everyout_detection::ScanReport::default,
            vec![],
        );
    });
    assert!(matches!(
        bridge.scan(),
        Err(CommandError::WorkerUnavailable)
    ));
    let status = bridge.check_catalog_updates().unwrap();
    assert_eq!(status.error.as_deref(), Some("catalog-storage"));
    assert_eq!(status.installed_version, "unavailable");
    drop(bridge);
    thread.join().unwrap();
}
