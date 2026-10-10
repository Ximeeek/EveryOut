//! Metadata-only Teach records. These are observations, never operation capabilities.
use crate::*;
use std::collections::{BTreeMap, BTreeSet};
type FamilyMetadata = BTreeMap<String, BTreeMap<String, EntryMetadata>>;

macro_rules! vocabulary {
    ($name:ident { $($item:ident),+ }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ts_rs::TS)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $($item),+ }
    };
}
vocabulary!(Completeness {
    Complete,
    RecoveredByRescan,
    Incomplete
});
vocabulary!(TeachPhase {
    ClosedBaseline,
    LaunchLoggedOut,
    Login,
    SettledLoggedIn,
    RestartPersistence,
    VendorLogout,
    ClosedLoggedOut
});
vocabulary!(SessionState {
    Active,
    Finished,
    Stale,
    Incomplete
});
vocabulary!(ArtifactClass {
    CorrelatedAuthCandidate,
    PersistentAppState,
    BackgroundNoise
});
vocabulary!(ObservationVerdict {
    StronglyObserved,
    Observed,
    Inconclusive,
    Noise
});
vocabulary!(LearnedStatus {
    Candidate,
    Observed,
    NeedsReobservation,
    Stale
});
vocabulary!(ChangeKind {
    Create,
    Remove,
    Modify,
    RenameOld,
    RenameNew
});
vocabulary!(TeachStage {
    Discovering,
    Ready,
    Focused,
    Finished,
    Stale
});

#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct TeachView {
    pub id: String,
    pub application: String,
    pub stage: TeachStage,
    pub next_phase: Option<TeachPhase>,
    pub completeness: Completeness,
    pub candidate_roots: Vec<String>,
    pub completed_cycles: usize,
    pub diagnostics: Vec<String>,
    pub result: Option<LearnedObservation>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct FileIdentity {
    pub volume: u32,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub index: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct ApplicationBinding {
    pub identity: EvidenceState<ApplicationIdentity>,
    pub executable_path: String,
    pub executable: FileIdentity,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub executable_size: u64,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub executable_write_ticks: u64,
    pub publisher: Option<String>,
    pub signature: Option<String>,
    pub signature_status: String,
    pub version: Option<String>,
    pub channel: Option<String>,
    pub framework: Vec<String>,
    pub framework_fingerprint: Vec<FrameworkFingerprint>,
    pub selected_process: Option<ProcessBinding>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct FrameworkFingerprint {
    pub artifact: String,
    pub identity: FileIdentity,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub size: u64,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub write_ticks: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct ProcessBinding {
    pub pid: u32,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub creation_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntryMetadata {
    pub directory: bool,
    pub size: u64,
    pub created_ticks: u64,
    pub write_ticks: u64,
    pub change_ticks: u64,
    pub attributes: u32,
    pub identity: FileIdentity,
    pub parent: Option<FileIdentity>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataSnapshot {
    pub root: String,
    pub root_identity: FileIdentity,
    pub entries: BTreeMap<String, EntryMetadata>,
    pub completeness: Completeness,
    pub captured_at_ms: u64,
    pub provenance: Vec<EvidenceProvenance>,
}
impl MetadataSnapshot {
    pub fn families(&self) -> FamilyMetadata {
        let mut families = FamilyMetadata::new();
        for (path, metadata) in &self.entries {
            // Directory timestamps include writes to unrelated children. Keep files
            // and empty directories only; structural changes remain in the snapshot.
            let child_prefix = format!("{path}/");
            if metadata.directory
                && self
                    .entries
                    .range(child_prefix.clone()..)
                    .next()
                    .is_some_and(|(p, _)| p.starts_with(&child_prefix))
            {
                continue;
            }
            let mut metadata = metadata.clone();
            if metadata.directory {
                // Empty-directory existence is structural evidence. Its timestamps
                // can be updated lazily after closing a removed child, so they do
                // not represent another authentication transition.
                metadata.size = 0;
                metadata.write_ticks = 0;
                metadata.change_ticks = 0;
            }
            families
                .entry(artifact_family(path))
                .or_default()
                .insert(path.clone(), metadata);
        }
        families
    }
    pub fn layout(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|(_, m)| m.directory)
            .map(|(p, _)| p.replace('\\', "/").to_lowercase())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

/// Filename/structure normalization only; no database records or values are read.
pub fn artifact_family(path: &str) -> String {
    let normalized = path.replace('\\', "/").to_lowercase();
    let parts: Vec<_> = normalized.split('/').collect();
    for (i, part) in parts.iter().enumerate() {
        if matches!(
            *part,
            "local storage" | "session storage" | "indexeddb" | "cache" | "code cache" | "gpucache"
        ) {
            return parts[..=i].join("/");
        }
        if *part == "leveldb" {
            return parts[..=i].join("/");
        }
    }
    let last = parts.last().copied().unwrap_or("");
    if let Some(base) = last
        .strip_suffix("-wal")
        .or_else(|| last.strip_suffix("-shm"))
        .or_else(|| last.strip_suffix("-journal"))
    {
        return [parts[..parts.len() - 1].join("/"), base.into()]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<String>>()
            .join("/");
    }
    if last.ends_with(".db") || last.ends_with(".sqlite") || last.ends_with(".sqlite3") {
        return normalized;
    }
    // Unknown directories are bounded logical families too, rather than rotating
    // internal files. A root-level ordinary file retains its own family.
    if parts.len() > 1 {
        parts[..parts.len() - 1].join("/")
    } else {
        normalized
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEvent {
    pub path: String,
    pub kind: ChangeKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhaseObservation {
    pub phase: TeachPhase,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub snapshots: Vec<MetadataSnapshot>,
    /// Events are scoped to root, then normalized family; no payloads.
    pub changed_families: BTreeMap<String, BTreeSet<String>>,
    pub completeness: Completeness,
    pub signed_in: Option<bool>,
    pub processes: Vec<ProcessBinding>,
    pub provenance: Vec<EvidenceProvenance>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeachCycle {
    pub phases: Vec<PhaseObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeachSession {
    pub id: String,
    pub binding: ApplicationBinding,
    pub started_at_ms: u64,
    pub ended_at_ms: Option<u64>,
    pub roots: Vec<String>,
    pub corroborated_roots: Vec<String>,
    pub state: SessionState,
    pub completeness: Completeness,
    pub cycles: Vec<TeachCycle>,
    pub discovery_snapshots: Vec<MetadataSnapshot>,
    pub provenance: Vec<EvidenceProvenance>,
}
impl TeachSession {
    pub fn new(id: String, binding: ApplicationBinding, now: u64) -> Option<Self> {
        if binding.identity.state != ApplicationIdentity::Exact {
            return None;
        }
        Some(Self {
            id,
            binding,
            started_at_ms: now,
            ended_at_ms: None,
            roots: vec![],
            corroborated_roots: vec![],
            state: SessionState::Active,
            completeness: Completeness::Complete,
            cycles: vec![],
            discovery_snapshots: vec![],
            provenance: vec![provenance("teach-session", "metadata-only-observation")],
        })
    }
    pub fn revalidate(&mut self, binding: &ApplicationBinding) -> bool {
        // Processes legitimately change during restart; every new process is bound
        // by the native observer before this comparison.
        let mut expected = self.binding.clone();
        expected.selected_process = binding.selected_process;
        if expected != *binding {
            self.state = SessionState::Stale;
            self.completeness = Completeness::Incomplete;
            self.provenance
                .push(provenance("teach-session", "application-binding-changed"));
            return false;
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct CycleDifferential {
    pub complete: bool,
    pub changed: [bool; 6],
    pub persisted: bool,
    pub login_logout: bool,
}
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct FamilyObservation {
    pub family: String,
    pub class: ArtifactClass,
    pub verdict: ObservationVerdict,
    pub cycles: Vec<CycleDifferential>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct RootObservation {
    pub root: String,
    pub physical: FileIdentity,
    pub layout: Vec<String>,
    pub families: Vec<FamilyObservation>,
    pub ownership: EvidenceState<StorageOwnership>,
}
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct LearnedObservation {
    pub session_id: String,
    pub binding: ApplicationBinding,
    pub roots: Vec<RootObservation>,
    pub status: LearnedStatus,
    pub completeness: Completeness,
    pub cycles: usize,
    #[serde(with = "unsigned_decimal")]
    #[ts(type = "string")]
    pub recorded_at_ms: u64,
    pub provenance: Vec<EvidenceProvenance>,
}
impl LearnedObservation {
    pub fn evidence(&self, root: &RootObservation, family: &FamilyObservation) -> ScopeEvidence {
        let current = matches!(
            self.status,
            LearnedStatus::Observed | LearnedStatus::Candidate
        );
        let observed = current
            && self.status == LearnedStatus::Observed
            && matches!(
                family.verdict,
                ObservationVerdict::StronglyObserved | ObservationVerdict::Observed
            );
        ScopeEvidence {
            application_identity: self.binding.identity.clone(),
            storage_ownership: root.ownership.clone(),
            authentication_scope: EvidenceState::new(
                if observed {
                    AuthenticationScope::Observed
                } else {
                    AuthenticationScope::Unknown
                },
                "teach-observation",
                if observed {
                    "repeated-login-logout-differential"
                } else {
                    "insufficient-current-observation"
                },
            ),
            version_applicability: EvidenceState::new(
                if current {
                    VersionApplicability::Current
                } else {
                    VersionApplicability::Stale
                },
                "teach-observation",
                "bound-version-layout-applicability",
            ),
            ..Default::default()
        }
    }
    pub fn invalidate(&mut self, binding: &ApplicationBinding, snapshots: &[MetadataSnapshot]) {
        let mut expected = self.binding.clone();
        expected.selected_process = binding.selected_process;
        if expected != *binding {
            self.status = LearnedStatus::Stale;
        } else if self.roots.iter().any(|root| {
            !snapshots.iter().any(|s| {
                s.root == root.root
                    && s.completeness == Completeness::Complete
                    && s.root_identity == root.physical
                    && s.layout() == root.layout
            })
        }) {
            self.status = LearnedStatus::NeedsReobservation;
        }
    }
}

pub fn provenance(source: &str, reason: &str) -> EvidenceProvenance {
    EvidenceProvenance {
        source: source.into(),
        reason_code: reason.into(),
    }
}

pub fn analyze(
    session: &TeachSession,
    shared_roots: &BTreeSet<String>,
    now: u64,
) -> LearnedObservation {
    let mut roots = vec![];
    for root in &session.roots {
        let snapshots: Vec<_> = session
            .discovery_snapshots
            .iter()
            .chain(
                session
                    .cycles
                    .iter()
                    .flat_map(|c| &c.phases)
                    .flat_map(|p| &p.snapshots),
            )
            .filter(|s| &s.root == root)
            .collect();
        let Some(last) = snapshots.last() else {
            continue;
        };
        let families: BTreeSet<_> = snapshots
            .iter()
            .flat_map(|s| s.families().into_keys())
            .collect();
        // Normalize each endpoint once, rather than rebuilding thousands of
        // metadata maps separately for every family in a large candidate root.
        let normalized_cycles: Vec<Vec<Option<FamilyMetadata>>> = session
            .cycles
            .iter()
            .map(|cycle| {
                cycle
                    .phases
                    .iter()
                    .map(|phase| {
                        phase
                            .snapshots
                            .iter()
                            .find(|s| &s.root == root)
                            .map(MetadataSnapshot::families)
                    })
                    .collect()
            })
            .collect();
        let mut observations = vec![];
        for family in families {
            let cycles: Vec<_> = session
                .cycles
                .iter()
                .zip(&normalized_cycles)
                .map(|(cycle, normalized)| differential(cycle, root, &family, normalized))
                .collect();
            let complete: Vec<_> = cycles.iter().filter(|c| c.complete).collect();
            let hits = complete.iter().filter(|c| c.login_logout).count();
            let conflict =
                complete.iter().any(|c| c.login_logout) && complete.iter().any(|c| !c.login_logout);
            let noise = !complete.is_empty()
                && complete
                    .iter()
                    .all(|c| c.changed[0] && c.changed[1] && c.changed[3] && c.changed[4]);
            let stable_root = snapshots
                .iter()
                .all(|s| s.root_identity == last.root_identity);
            let (class, verdict) = if conflict || !stable_root {
                (
                    ArtifactClass::CorrelatedAuthCandidate,
                    ObservationVerdict::Inconclusive,
                )
            } else if noise {
                (ArtifactClass::BackgroundNoise, ObservationVerdict::Noise)
            } else if hits >= 2 {
                (
                    ArtifactClass::CorrelatedAuthCandidate,
                    if complete.iter().all(|c| c.persisted) {
                        ObservationVerdict::StronglyObserved
                    } else {
                        ObservationVerdict::Observed
                    },
                )
            } else if hits > 0 {
                (
                    ArtifactClass::CorrelatedAuthCandidate,
                    ObservationVerdict::Inconclusive,
                )
            } else {
                (
                    ArtifactClass::PersistentAppState,
                    ObservationVerdict::Inconclusive,
                )
            };
            observations.push(FamilyObservation {
                family,
                class,
                verdict,
                cycles,
            });
        }
        let confirmed = observations.iter().any(|f| {
            matches!(
                f.verdict,
                ObservationVerdict::StronglyObserved | ObservationVerdict::Observed
            )
        });
        roots.push(RootObservation {
            root: root.clone(),
            physical: last.root_identity,
            layout: last.layout(),
            families: observations,
            ownership: EvidenceState::new(
                if shared_roots.contains(root) {
                    StorageOwnership::SharedConflict
                } else if confirmed || session.corroborated_roots.contains(root) {
                    StorageOwnership::Corroborated
                } else {
                    StorageOwnership::Unknown
                },
                "teach-observation",
                if shared_roots.contains(root) {
                    "multiple-application-bindings"
                } else {
                    "repeated-focused-root-correlation"
                },
            ),
        });
    }
    let stale = session.state == SessionState::Stale;
    let observed = !stale
        && session.state != SessionState::Incomplete
        && session.completeness != Completeness::Incomplete
        && roots.iter().any(|r| {
            r.families.iter().any(|f| {
                matches!(
                    f.verdict,
                    ObservationVerdict::StronglyObserved | ObservationVerdict::Observed
                )
            })
        });
    LearnedObservation {
        session_id: session.id.clone(),
        binding: session.binding.clone(),
        roots,
        status: if stale {
            LearnedStatus::Stale
        } else if observed {
            LearnedStatus::Observed
        } else {
            LearnedStatus::Candidate
        },
        completeness: session.completeness,
        cycles: session
            .cycles
            .iter()
            .filter(|c| c.phases.len() == 7)
            .count(),
        recorded_at_ms: now,
        provenance: session.provenance.clone(),
    }
}

fn differential(
    cycle: &TeachCycle,
    root: &str,
    family: &str,
    normalized: &[Option<FamilyMetadata>],
) -> CycleDifferential {
    use TeachPhase::*;
    let order = [
        ClosedBaseline,
        LaunchLoggedOut,
        Login,
        SettledLoggedIn,
        RestartPersistence,
        VendorLogout,
        ClosedLoggedOut,
    ];
    let mut result = CycleDifferential {
        complete: false,
        changed: [false; 6],
        persisted: false,
        login_logout: false,
    };
    if cycle.phases.len() != 7
        || cycle
            .phases
            .iter()
            .zip(order)
            .any(|(p, expected)| p.phase != expected)
    {
        return result;
    }
    let mut states = vec![];
    let empty = BTreeMap::new();
    for (phase, families) in cycle.phases.iter().zip(normalized) {
        let Some(snapshot) = phase.snapshots.iter().find(|s| s.root == root) else {
            return result;
        };
        // Rescan recovers current state, never missing event history. Negative
        // intervals cannot count toward a complete authentication cycle after loss.
        if phase.completeness != Completeness::Complete
            || snapshot.completeness != Completeness::Complete
        {
            return result;
        }
        if cycle.phases[0]
            .snapshots
            .iter()
            .find(|s| s.root == root)
            .is_some_and(|baseline| baseline.root_identity != snapshot.root_identity)
        {
            return result;
        }
        let Some(families) = families else {
            return result;
        };
        states.push(families.get(family).unwrap_or(&empty));
    }
    result.complete = true;
    for i in 0..6 {
        result.changed[i] = states[i] != states[i + 1]
            || cycle.phases[i + 1]
                .changed_families
                .get(root)
                .is_some_and(|f| f.contains(family));
    }
    result.persisted =
        !states[3].is_empty() && states[3] == states[4] && cycle.phases[4].signed_in == Some(true);
    let confirmed = cycle.phases[0].signed_in == Some(false)
        && cycle.phases[1].signed_in == Some(false)
        && cycle.phases[2].signed_in == Some(true)
        && cycle.phases[3].signed_in == Some(true)
        && cycle.phases[5].signed_in == Some(false)
        && cycle.phases[6].signed_in == Some(false);
    // Login/logout alone is insufficient: both quiet intervals and restart
    // persistence distinguish transition activity from recurring launch/cache work.
    result.login_logout = confirmed
        && result.persisted
        && result.changed[1]
        && result.changed[4]
        && !result.changed[0]
        && !result.changed[2]
        && !result.changed[3]
        && !result.changed[5];
    result
}

// File IDs and Windows ticks can exceed JavaScript's exact integer range.
// Serialize IPC metadata as decimal strings without changing native comparisons.
mod unsigned_decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(serde::de::Error::custom(
                "invalid unsigned decimal metadata",
            ));
        }
        value.parse().map_err(serde::de::Error::custom)
    }
}
