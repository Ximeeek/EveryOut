//! A single immediate-durability transaction couples snapshot, floor and tombstones.
use crate::*;
use redb::{Database, Durability, TableDefinition};
use std::{fs, path::Path};

const STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("catalog-state-v1");
fn linked(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct Revision {
    revision: u64,
    digest: String,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct State {
    lineage: String,
    floor: u64,
    digest: String,
    signed: Option<Vec<u8>>,
    history: BTreeMap<String, Revision>,
}
impl State {
    fn initial(snapshot: &Snapshot) -> Self {
        Self {
            lineage: "EveryOut/stable-v1".into(),
            floor: snapshot.version,
            digest: snapshot.digest.clone(),
            signed: None,
            history: snapshot
                .entries
                .iter()
                .map(|e| {
                    (
                        e.id.clone(),
                        Revision {
                            revision: e.revision,
                            digest: e.sha256.clone(),
                        },
                    )
                })
                .collect(),
        }
    }
    fn accept(&self, snapshot: &Snapshot) -> Result<()> {
        if snapshot.version < self.floor
            || (snapshot.version == self.floor && snapshot.digest != self.digest)
        {
            return Err(Error::Rollback);
        }
        for entry in &snapshot.entries {
            if self.history.get(&entry.id).is_some_and(|old| {
                entry.revision < old.revision
                    || (entry.revision == old.revision && entry.sha256 != old.digest)
            }) {
                return Err(Error::Revision);
            }
        }
        Ok(())
    }
}
pub struct Store {
    db: Database,
    trust: Trust,
    bundled: Snapshot,
    active: Snapshot,
    state: State,
    pending: Option<(Vec<u8>, Snapshot)>,
    blocked: bool,
}
impl Store {
    /// The dedicated directory is the initialization marker. Missing DB in an existing
    /// marker is an error, never permission to reset a previously accepted floor.
    pub fn open(path: &Path, bundled: Snapshot, trust: Trust) -> Result<Self> {
        let fresh = match fs::create_dir(path) {
            Ok(()) => true,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
            Err(_) => return Err(Error::Storage),
        };
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::Storage)?;
        if !metadata.is_dir() || linked(&metadata) {
            return Err(Error::Storage);
        }
        let file = path.join("accepted.redb");
        if !fresh {
            let metadata = fs::symlink_metadata(&file).map_err(|_| Error::Storage)?;
            if !metadata.is_file() || linked(&metadata) {
                return Err(Error::Storage);
            }
        }
        let db = if fresh {
            Database::create(&file)
        } else {
            Database::open(&file)
        }
        .map_err(|_| Error::Storage)?;
        if fresh {
            let mut txn = db.begin_write().map_err(|_| Error::Storage)?;
            txn.set_durability(Durability::Immediate);
            {
                let bytes =
                    serde_json::to_vec(&State::initial(&bundled)).map_err(|_| Error::Storage)?;
                txn.open_table(STATE)
                    .map_err(|_| Error::Storage)?
                    .insert("accepted", bytes.as_slice())
                    .map_err(|_| Error::Storage)?;
            }
            txn.commit().map_err(|_| Error::Storage)?;
        }
        let mut state: State = {
            let txn = db.begin_read().map_err(|_| Error::Storage)?;
            let table = txn.open_table(STATE).map_err(|_| Error::Storage)?;
            let record = table
                .get("accepted")
                .map_err(|_| Error::Storage)?
                .ok_or(Error::Storage)?;
            if record.value().len() > MAX_BUNDLE * 6 {
                return Err(Error::Storage);
            }
            strict_json(record.value()).map_err(|_| Error::Storage)?
        };
        if state.lineage != "EveryOut/stable-v1" {
            return Err(Error::Storage);
        }
        // A newer catalog compiled into an installed application is a trusted
        // release upgrade. Preserve the accepted floor and revision tombstones;
        // never reset or silently replace equal-version divergent content.
        if bundled.version > state.floor {
            if let Some(bytes) = &state.signed {
                let previous = trust.verify(bytes).map_err(|_| Error::Storage)?;
                if previous.version != state.floor || previous.digest != state.digest {
                    return Err(Error::Storage);
                }
                state.accept(&previous).map_err(|_| Error::Storage)?;
                if previous.entries.iter().any(|entry| {
                    state.history.get(&entry.id).is_none_or(|old| {
                        old.revision != entry.revision || old.digest != entry.sha256
                    })
                }) {
                    return Err(Error::Storage);
                }
            }
            state.accept(&bundled).map_err(|_| Error::Storage)?;
            let mut next = state.clone();
            next.floor = bundled.version;
            next.digest = bundled.digest.clone();
            next.signed = None;
            for entry in &bundled.entries {
                next.history.insert(
                    entry.id.clone(),
                    Revision {
                        revision: entry.revision,
                        digest: entry.sha256.clone(),
                    },
                );
            }
            let encoded = serde_json::to_vec(&next).map_err(|_| Error::Storage)?;
            let mut txn = db.begin_write().map_err(|_| Error::Storage)?;
            txn.set_durability(Durability::Immediate);
            txn.open_table(STATE)
                .map_err(|_| Error::Storage)?
                .insert("accepted", encoded.as_slice())
                .map_err(|_| Error::Storage)?;
            txn.commit().map_err(|_| Error::Storage)?;
            state = next;
        }
        let active = match &state.signed {
            Some(bytes) => trust.verify(bytes).map_err(|_| Error::Storage)?,
            None if state.floor == bundled.version && state.digest == bundled.digest => {
                bundled.clone()
            }
            None => return Err(Error::Storage),
        };
        if active.version != state.floor || active.digest != state.digest {
            return Err(Error::Storage);
        }
        state.accept(&active).map_err(|_| Error::Storage)?;
        // Current membership must have history too; tombstones for removed IDs stay retained.
        if active.entries.iter().any(|e| {
            state
                .history
                .get(&e.id)
                .is_none_or(|old| old.revision != e.revision || old.digest != e.sha256)
        }) {
            return Err(Error::Storage);
        }
        Ok(Self {
            db,
            trust,
            bundled,
            active,
            state,
            pending: None,
            blocked: false,
        })
    }
    pub fn snapshot(&self) -> Result<&Snapshot> {
        if self.blocked {
            Err(Error::Storage)
        } else {
            Ok(&self.active)
        }
    }
    pub fn helper_compatible(&self) -> bool {
        self.active.entries.len() == self.bundled.entries.len()
            && self
                .active
                .entries
                .iter()
                .zip(&self.bundled.entries)
                .all(|(a, b)| a.id == b.id && a.sha256 == b.sha256)
    }
    pub fn configured(&self) -> bool {
        self.trust.configured()
    }
    pub fn proposed(&self) -> Option<&Snapshot> {
        self.pending.as_ref().map(|(_, snapshot)| snapshot)
    }
    pub fn discard_proposal(&mut self) {
        self.pending = None;
    }
    pub fn check(&mut self, source: &dyn transport::Source) -> Result<&Snapshot> {
        self.pending = None;
        if self.blocked {
            return Err(Error::Storage);
        }
        if !self.configured() {
            return Err(Error::Unconfigured);
        }
        let bytes = source.download(MAX_BUNDLE)?;
        let snapshot = self.trust.verify(&bytes)?;
        self.state.accept(&snapshot)?;
        self.pending = Some((bytes, snapshot));
        Ok(&self.pending.as_ref().unwrap().1)
    }
    /// Runs only after explicit acceptance. No session capabilities are involved.
    pub fn activate(&mut self, expected_digest: &str) -> Result<()> {
        self.activate_before_commit(expected_digest, || Ok(()))
    }
    fn activate_before_commit(
        &mut self,
        expected_digest: &str,
        fault: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        if self.blocked {
            return Err(Error::Storage);
        }
        let (bytes, snapshot) = self.pending.as_ref().ok_or(Error::NoProposal)?;
        if snapshot.digest != expected_digest {
            return Err(Error::NoProposal);
        }
        // Reverify rather than trusting the UI's digest or a previously parsed cache.
        let snapshot = self.trust.verify(bytes)?;
        self.state.accept(&snapshot)?;
        let mut next = self.state.clone();
        next.floor = snapshot.version;
        next.digest = snapshot.digest.clone();
        next.signed = Some(bytes.clone());
        for entry in &snapshot.entries {
            next.history.insert(
                entry.id.clone(),
                Revision {
                    revision: entry.revision,
                    digest: entry.sha256.clone(),
                },
            );
        }
        let encoded = serde_json::to_vec(&next).map_err(|_| Error::Storage)?;
        if encoded.len() > MAX_BUNDLE * 6 {
            return Err(Error::Bounds);
        }
        let mut txn = self.db.begin_write().map_err(|_| Error::Storage)?;
        txn.set_durability(Durability::Immediate);
        {
            txn.open_table(STATE)
                .map_err(|_| Error::Storage)?
                .insert("accepted", encoded.as_slice())
                .map_err(|_| Error::Storage)?;
        }
        fault()?; // Fault tests abort a fully written, uncommitted transaction.
        if txn.commit().is_err() {
            // Commit I/O failure may have an uncertain outcome. Never execute an inferred floor.
            self.blocked = true;
            return Err(Error::Storage);
        }
        self.state = next;
        self.active = snapshot;
        self.pending = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn setup() -> (Snapshot, Trust, SigningKey) {
        use rand_core::RngCore;
        let mut seed = [0; 32];
        rand_core::OsRng.fill_bytes(&mut seed);
        let key = SigningKey::from_bytes(&seed);
        let mut snapshot = bundled(
            entries([include_str!("../../providers/tests/fixtures/provider.json").to_owned()])
                .unwrap(),
        )
        .unwrap();
        snapshot.version = 1; // Explicit initial version for the upgrade fixtures.
        let trust = Trust::new(Some(key.verifying_key().to_bytes()), &snapshot).unwrap();
        (snapshot, trust, key)
    }
    fn signed(key: &SigningKey, entries: Vec<Entry>, version: u64) -> Vec<u8> {
        let payload =
            serde_json::to_string(&envelope(entries, version, "Reviewed changes".into())).unwrap();
        serde_json::to_vec(&SignedBundle {
            signature: hex::encode(key.sign(&signing_bytes(&payload)).to_bytes()),
            payload,
        })
        .unwrap()
    }
    #[test]
    fn application_catalog_upgrade_preserves_floor_and_provider_history() {
        let (base, trust, key) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog");
        drop(Store::open(&path, base.clone(), trust.clone()).unwrap());
        let mut manifest: serde_json::Value =
            serde_json::from_str(&base.entries[0].manifest).unwrap();
        manifest["revision"] = serde_json::json!(2);
        let upgraded = bundled(entries([manifest.to_string()]).unwrap()).unwrap();
        assert_eq!(upgraded.version, 2);
        let mut store = Store::open(&path, upgraded.clone(), trust.clone()).unwrap();
        assert_eq!(store.snapshot().unwrap().digest, upgraded.digest);
        assert!(matches!(
            store.check(&Fake(signed(&key, base.entries.clone(), 3))),
            Err(Error::Revision)
        ));
        drop(store);
        assert!(Store::open(&path, base, trust.clone()).is_err());
        let reloaded = Store::open(&path, upgraded.clone(), trust.clone()).unwrap();
        assert_eq!(reloaded.snapshot().unwrap().version, 2);
        drop(reloaded);
        let mut divergent = upgraded;
        divergent.digest = "different".into();
        assert!(Store::open(&path, divergent, trust).is_err());
    }
    struct Fake(Vec<u8>);
    impl transport::Source for Fake {
        fn download(&self, _: usize) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
    }
    #[test]
    fn rollback_equal_content_revision_tombstones_and_reload() {
        let (base, trust, key) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog");
        let mut store = Store::open(&path, base.clone(), trust.clone()).unwrap();
        let original = base.entries.clone();
        let mut changed = serde_json::from_str::<serde_json::Value>(&original[0].manifest).unwrap();
        changed["revision"] = serde_json::json!(2);
        let newer = entries([changed.to_string()]).unwrap();
        let bytes = signed(&key, newer.clone(), 2);
        let proposal = store.check(&Fake(bytes.clone())).unwrap().digest.clone();
        assert_eq!(store.activate("wrong"), Err(Error::NoProposal));
        store.activate(&proposal).unwrap();
        drop(store);
        let mut store = Store::open(&path, base, trust).unwrap();
        assert_eq!(store.snapshot().unwrap().version, 2);
        assert!(store.check(&Fake(bytes)).is_ok());
        assert!(matches!(
            store.check(&Fake(signed(&key, original.clone(), 1))),
            Err(Error::Rollback)
        ));
        assert!(matches!(
            store.check(&Fake(signed(&key, original.clone(), 2))),
            Err(Error::Rollback)
        ));
        assert!(matches!(
            store.check(&Fake(signed(&key, original, 3))),
            Err(Error::Revision)
        ));
        // Remove original ID in favor of another provider, then attempt its old revision.
        changed["id"] = serde_json::json!("other-app");
        changed["roots"][0]["owner"] = serde_json::json!("other-app");
        changed["identity"]["browser_id"] = serde_json::json!("other-app");
        let other = entries([changed.to_string()]).unwrap();
        let digest = store
            .check(&Fake(signed(&key, other, 3)))
            .unwrap()
            .digest
            .clone();
        store.activate(&digest).unwrap();
        let mut old = newer;
        let value = serde_json::from_str::<serde_json::Value>(&old[0].manifest).unwrap();
        let mut value = value;
        value["revision"] = serde_json::json!(1);
        old = entries([value.to_string()]).unwrap();
        assert!(matches!(
            store.check(&Fake(signed(&key, old, 4))),
            Err(Error::Revision)
        ));
    }
    #[test]
    fn failed_atomic_install_retains_coherent_previous_state() {
        let (base, trust, key) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog");
        let mut store = Store::open(&path, base.clone(), trust.clone()).unwrap();
        let digest = store
            .check(&Fake(signed(&key, base.entries.clone(), 2)))
            .unwrap()
            .digest
            .clone();
        assert_eq!(
            store.activate_before_commit(&digest, || Err(Error::Storage)),
            Err(Error::Storage)
        );
        assert_eq!(store.snapshot().unwrap().version, 1);
        drop(store);
        let store = Store::open(&path, base, trust).unwrap();
        assert_eq!(store.snapshot().unwrap().version, 1);
    }
    #[test]
    fn another_writer_cannot_open_an_accepted_store() {
        let (base, trust, _) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog");
        let _store = Store::open(&path, base.clone(), trust.clone()).unwrap();
        assert!(matches!(
            Store::open(&path, base, trust),
            Err(Error::Storage)
        ));
    }
    #[test]
    fn missing_state_never_resets_floor_and_invalid_source_keeps_bundled() {
        let (base, trust, _) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog");
        let mut store = Store::open(&path, base.clone(), trust.clone()).unwrap();
        assert!(store.check(&Fake(b"{}".to_vec())).is_err());
        assert_eq!(store.snapshot().unwrap().digest, base.digest);
        drop(store);
        fs::remove_file(path.join("accepted.redb")).unwrap();
        assert!(matches!(
            Store::open(&path, base, trust),
            Err(Error::Storage)
        ));
    }
    #[test]
    fn persisted_signature_corruption_blocks_instead_of_falling_back() {
        let (base, trust, key) = setup();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("catalog");
        let mut store = Store::open(&path, base.clone(), trust.clone()).unwrap();
        let proposal = store
            .check(&Fake(signed(&key, base.entries.clone(), 2)))
            .unwrap()
            .digest
            .clone();
        store.activate(&proposal).unwrap();
        let mut state = store.state.clone();
        state.signed = Some(b"corrupt cache".to_vec());
        let txn = store.db.begin_write().unwrap();
        {
            let bytes = serde_json::to_vec(&state).unwrap();
            txn.open_table(STATE)
                .unwrap()
                .insert("accepted", bytes.as_slice())
                .unwrap();
        }
        txn.commit().unwrap();
        drop(store);
        assert!(matches!(
            Store::open(&path, base, trust),
            Err(Error::Storage)
        ));
    }
    #[test]
    fn signed_invalid_manifest_retains_the_bundled_catalog() {
        let (base, trust, key) = setup();
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(&dir.path().join("catalog"), base.clone(), trust).unwrap();
        let mut invalid = base.entries.clone();
        invalid[0].manifest = "{}".into();
        assert!(matches!(
            store.check(&Fake(signed(&key, invalid, 2))),
            Err(Error::Manifest)
        ));
        assert_eq!(store.snapshot().unwrap().digest, base.digest);
    }
    #[test]
    fn crash_child() {
        let Ok(directory) = std::env::var("EVERYOUT_TEST_CRASH_DIRECTORY") else {
            return;
        };
        let (base, _, _) = setup();
        let public: [u8; 32] = hex::decode(std::env::var("EVERYOUT_TEST_PUBLIC_KEY").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let trust = Trust::new(Some(public), &base).unwrap();
        let mut store = Store::open(&Path::new(&directory).join("catalog"), base, trust).unwrap();
        let bytes = fs::read(Path::new(&directory).join("proposal.json")).unwrap();
        let digest = store.check(&Fake(bytes)).unwrap().digest.clone();
        if std::env::var("EVERYOUT_TEST_CRASH_BOUNDARY").unwrap() == "before" {
            let _ = store.activate_before_commit(&digest, || std::process::exit(42));
        } else {
            store.activate(&digest).unwrap();
            std::process::exit(42);
        }
        panic!("crash boundary was not reached");
    }
    #[test]
    fn process_crashes_before_and_after_commit_recover_coherently() {
        for boundary in ["before", "after"] {
            let (base, trust, key) = setup();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("catalog");
            drop(Store::open(&path, base.clone(), trust.clone()).unwrap());
            fs::write(
                dir.path().join("proposal.json"),
                signed(&key, base.entries.clone(), 2),
            )
            .unwrap();
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "store::tests::crash_child", "--nocapture"])
                .env("EVERYOUT_TEST_CRASH_DIRECTORY", dir.path())
                .env(
                    "EVERYOUT_TEST_PUBLIC_KEY",
                    hex::encode(key.verifying_key().to_bytes()),
                )
                .env("EVERYOUT_TEST_CRASH_BOUNDARY", boundary)
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(42));
            let recovered = Store::open(&path, base, trust).unwrap();
            assert_eq!(
                recovered.snapshot().unwrap().version,
                if boundary == "before" { 1 } else { 2 }
            );
        }
    }
}
