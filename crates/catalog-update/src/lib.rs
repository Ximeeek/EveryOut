//! Catalog configuration only. No session contents or executable update payloads.
#![forbid(unsafe_code)]

pub mod store;
pub mod transport;
use ed25519_dalek::{Signature, VerifyingKey};
use everyout_providers::{CleaningMethod, Manifest};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_BUNDLE: usize = 8 * 1024 * 1024;
pub const MAX_MANIFEST: usize = 256 * 1024;
pub const MAX_PROVIDERS: usize = 256;
pub const DOMAIN: &[u8] = b"EveryOut/catalog/stable/v1\0";
pub const BUNDLED_VERSION: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Bounds,
    Format,
    Signature,
    Compatibility,
    Manifest,
    UnsupportedAdapter,
    Rollback,
    Revision,
    Storage,
    Unconfigured,
    Transport,
    NoProposal,
}
impl Error {
    pub fn code(self) -> &'static str {
        match self {
            Self::Bounds => "catalog-bounds",
            Self::Format => "catalog-format",
            Self::Signature => "catalog-signature",
            Self::Compatibility => "catalog-compatibility",
            Self::Manifest => "catalog-manifest",
            Self::UnsupportedAdapter => "catalog-unsupported-adapter",
            Self::Rollback => "catalog-rollback",
            Self::Revision => "catalog-revision",
            Self::Storage => "catalog-storage",
            Self::Unconfigured => "catalog-unconfigured",
            Self::Transport => "catalog-transport",
            Self::NoProposal => "catalog-no-proposal",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Reject duplicate object keys at every nesting level, before typed parsing.
struct Unique;
impl<'de> Visitor<'de> for Unique {
    type Value = ();
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("unambiguous JSON")
    }
    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> std::result::Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
            map.next_value::<UniqueValue>()?;
        }
        Ok(())
    }
    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> std::result::Result<(), A::Error> {
        while seq.next_element::<UniqueValue>()?.is_some() {}
        Ok(())
    }
    fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<(), E> {
        Ok(())
    }
}
struct UniqueValue;
impl<'de> Deserialize<'de> for UniqueValue {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(Unique)?;
        Ok(Self)
    }
}
pub fn strict_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_slice::<UniqueValue>(bytes).map_err(|_| Error::Format)?;
    serde_json::from_slice(bytes).map_err(|_| Error::Format)
}
pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub id: String,
    pub revision: u64,
    pub length: usize,
    pub sha256: String,
    pub manifest: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: u32,
    pub product: String,
    pub channel: String,
    pub key_id: String,
    pub version: u64,
    pub min_engine: u32,
    pub max_engine: u32,
    pub changelog: String,
    pub entries: Vec<Entry>,
}
/// The signature is detached from the exact UTF-8 payload; no reserialization at verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedBundle {
    pub payload: String,
    pub signature: String,
}
#[derive(Clone)]
pub struct Snapshot {
    pub version: u64,
    pub digest: String,
    pub changelog: String,
    pub entries: Vec<Entry>,
}
pub fn entries(json: impl IntoIterator<Item = String>) -> Result<Vec<Entry>> {
    let mut entries = Vec::new();
    for manifest in json {
        if manifest.len() > MAX_MANIFEST {
            return Err(Error::Bounds);
        }
        let mut value: serde_json::Value = strict_json(manifest.as_bytes())?;
        let m = everyout_providers::load_manifest(&manifest).map_err(|_| Error::Manifest)?;
        value.sort_all_objects();
        let manifest = serde_json::to_string(&value).map_err(|_| Error::Format)?;
        entries.push(Entry {
            id: m.id,
            revision: m.revision,
            length: manifest.len(),
            sha256: digest(manifest.as_bytes()),
            manifest,
        });
    }
    entries.sort_by(|a, b| a.id.cmp(&b.id));
    if entries.is_empty() || entries.len() > MAX_PROVIDERS {
        return Err(Error::Bounds);
    }
    if entries.windows(2).any(|p| p[0].id == p[1].id) {
        return Err(Error::Manifest);
    }
    Ok(entries)
}
pub fn bundled(entries: Vec<Entry>) -> Result<Snapshot> {
    let bytes = serde_json::to_vec(&entries).map_err(|_| Error::Format)?;
    if bytes.len() > MAX_BUNDLE {
        return Err(Error::Bounds);
    }
    Ok(Snapshot {
        version: BUNDLED_VERSION,
        digest: digest(&bytes),
        changelog: "Catalog shipped with this application; provider limitations still apply."
            .into(),
        entries,
    })
}
pub fn envelope(entries: Vec<Entry>, version: u64, changelog: String) -> Envelope {
    Envelope {
        format: 1,
        product: "EveryOut".into(),
        channel: "stable".into(),
        key_id: "stable-v1".into(),
        version,
        min_engine: 1,
        max_engine: 1,
        changelog,
        entries,
    }
}
pub fn signing_bytes(payload: &str) -> Vec<u8> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(payload.as_bytes());
    bytes
}

#[derive(Clone)]
pub struct Trust {
    key: Option<VerifyingKey>,
    adapters: BTreeSet<String>,
}
fn adapter(method: &CleaningMethod) -> Option<String> {
    match method {
        CleaningMethod::LocalApiOperation { operation_id, .. } => {
            Some(format!("api:{operation_id}"))
        }
        CleaningMethod::ExceptionAdapter { adapter_id, .. } => {
            Some(format!("exception:{adapter_id}"))
        }
        _ => None,
    }
}
impl Trust {
    pub fn new(key: Option<[u8; 32]>, bundled: &Snapshot) -> Result<Self> {
        let key = key
            .map(|key| VerifyingKey::from_bytes(&key).map_err(|_| Error::Signature))
            .transpose()?;
        if key.as_ref().is_some_and(VerifyingKey::is_weak) {
            return Err(Error::Signature);
        }
        let mut adapters = BTreeSet::new();
        for entry in &bundled.entries {
            let m =
                everyout_providers::load_manifest(&entry.manifest).map_err(|_| Error::Manifest)?;
            adapters.extend(m.cleaning_methods.iter().filter_map(adapter));
        }
        Ok(Self { key, adapters })
    }
    pub fn configured(&self) -> bool {
        self.key.is_some()
    }
    pub fn verify(&self, bytes: &[u8]) -> Result<Snapshot> {
        if bytes.len() > MAX_BUNDLE {
            return Err(Error::Bounds);
        }
        let bundle: SignedBundle = strict_json(bytes)?;
        let key = self.key.as_ref().ok_or(Error::Unconfigured)?;
        let signature = hex::decode(&bundle.signature).map_err(|_| Error::Signature)?;
        let signature = Signature::from_slice(&signature).map_err(|_| Error::Signature)?;
        key.verify_strict(&signing_bytes(&bundle.payload), &signature)
            .map_err(|_| Error::Signature)?;
        let e: Envelope = strict_json(bundle.payload.as_bytes())?;
        if e.format != 1
            || e.product != "EveryOut"
            || e.channel != "stable"
            || e.key_id != "stable-v1"
            || e.version == 0
            || e.min_engine > 1
            || e.max_engine < 1
            || e.min_engine > e.max_engine
        {
            return Err(Error::Compatibility);
        }
        if e.changelog.trim().is_empty() || e.changelog.len() > 64 * 1024 {
            return Err(Error::Bounds);
        }
        let validated = entries(e.entries.iter().map(|entry| entry.manifest.clone()))?;
        if e.entries.len() != validated.len()
            || e.entries.iter().zip(&validated).any(|(a, b)| {
                a.id != b.id
                    || a.revision != b.revision
                    || a.length != b.length
                    || a.sha256 != b.sha256
                    || a.manifest != b.manifest
            })
        {
            return Err(Error::Manifest);
        }
        for entry in &validated {
            let m: Manifest =
                everyout_providers::load_manifest(&entry.manifest).map_err(|_| Error::Manifest)?;
            if m.cleaning_methods
                .iter()
                .filter_map(adapter)
                .any(|id| !self.adapters.contains(&id))
            {
                return Err(Error::UnsupportedAdapter);
            }
        }
        Ok(Snapshot {
            version: e.version,
            digest: digest(bundle.payload.as_bytes()),
            changelog: e.changelog,
            entries: validated,
        })
    }
}

/// Descriptions retain candidate/unknown assessments rather than inferring successful logout.
pub fn catalog_table(entries: &[Entry]) -> Result<String> {
    fn cell(value: String) -> String {
        value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('|', "&#124;")
            .replace(['\r', '\n'], " ")
    }
    fn label<T: Serialize>(value: &T) -> String {
        serde_json::to_value(value)
            .unwrap()
            .as_str()
            .unwrap_or("unknown")
            .to_owned()
    }
    let mut rows = BTreeMap::new();
    for entry in entries {
        let m = everyout_providers::load_manifest(&entry.manifest).map_err(|_| Error::Manifest)?;
        let locations = m
            .session_locations
            .iter()
            .map(|a| {
                let root = m.roots.iter().find(|r| r.id() == a.root).unwrap();
                let base = serde_json::to_value(root).unwrap()["base"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                format!(
                    "{base}: {}/{} ({})",
                    root.relative(),
                    a.relative,
                    label(&a.scope)
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let methods = m
            .cleaning_methods
            .iter()
            .map(|method| {
                let kind = serde_json::to_value(method).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                format!(
                    "{kind} [{}]; blockers: {}",
                    method.id(),
                    method.blockers().join(", ")
                )
            })
            .collect::<Vec<_>>()
            .join("; ");
        let logout = format!(
            "{}; {}; {}",
            label(&m.true_logout.availability),
            label(&m.true_logout.surface),
            m.true_logout.mechanism
        );
        let loss = format!(
            "{}; affected: {}; {}",
            label(&m.risks.permanent_data_loss),
            m.risks.affected_data.join(", "),
            m.risks.reason.unwrap_or_default()
        );
        let confidence = format!(
            "{}; {}; support: {}; {}; versions: {}",
            label(&m.confidence.level),
            m.confidence.status.unwrap_or_else(|| "unknown".into()),
            label(&m.support),
            m.confidence.rationale,
            m.confidence
                .version_coverage
                .unwrap_or_else(|| "unknown".into())
        );
        rows.insert(
            m.id.clone(),
            format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                cell(format!("{} ({}, revision {})", m.name, m.id, m.revision)),
                cell(locations),
                cell(methods),
                cell(logout),
                cell(loss),
                cell(confidence)
            ),
        );
    }
    let mut output = String::from("# EveryOut catalog\n\nRegenerate with `cargo run -p xtask -- catalog-table`. All manifests are included.\nCandidate and unknown assessments do not establish safe cleanup or server logout.\n\n| name | where the session lives | cleaning method | true logout available? | risk of permanent data loss and which | confidence of the information |\n| --- | --- | --- | --- | --- | --- |\n");
    for row in rows.into_values() {
        output.push_str(&row);
    }
    Ok(output)
}
