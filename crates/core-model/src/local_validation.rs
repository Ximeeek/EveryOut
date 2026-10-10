//! Local causal evidence and bounded search. Serializable records grant no capabilities.
use crate::{observation::*, *};
use std::collections::BTreeSet;

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $($variant),+ }
    };
}
vocabulary!(AppOutcome { SignedIn, SignedOut, Unclear });
vocabulary!(ValidationStage {
    ReadyControl, Control, Intervention, Reversal, AwaitingAcceptance,
    Complete, Failed, Stale, RecoveryBlocked
});
vocabulary!(TrialPurpose { Search, FinalRepeat });
vocabulary!(CausalResult { Sufficient, Insufficient, Inconclusive, FailedRestoreOrExternalStateChange });
vocabulary!(JournalStage { Prepared, Quarantined, AppLaunched, RollingBack, Restored, Completed });
vocabulary!(SlotStage { Prepared, Quarantined, ReplacementPrepared, ReplacementMoved, RestorePrepared, Restored, Cleaned });

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct FamilyScope {
    pub root: String,
    pub family: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct TrialEvidence {
    pub scope: Vec<FamilyScope>,
    pub purpose: TrialPurpose,
    pub a1: AppOutcome,
    pub b: AppOutcome,
    pub a2: AppOutcome,
    pub rollback_verified: bool,
    pub complete_metadata: bool,
    pub collateral_families: Vec<FamilyScope>,
    pub result: CausalResult,
}
impl TrialEvidence {
    pub fn classify(&mut self) {
        self.result = if !self.rollback_verified || self.a2 != AppOutcome::SignedIn {
            CausalResult::FailedRestoreOrExternalStateChange
        } else if !self.complete_metadata || self.a1 != AppOutcome::SignedIn || self.b == AppOutcome::Unclear {
            CausalResult::Inconclusive
        } else if self.b == AppOutcome::SignedOut {
            CausalResult::Sufficient
        } else {
            CausalResult::Insufficient
        };
    }
}

/// Persistent write-ahead metadata. A missing original is represented explicitly,
/// including database sidecars, so app-created replacements can still be removed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineSlot {
    pub scope: FamilyScope,
    pub original_relative: String,
    pub quarantine_relative: String,
    pub generated_relative: String,
    pub original: Option<FileIdentity>,
    pub original_directory: Option<bool>,
    pub generated: Option<FileIdentity>,
    pub parent: FileIdentity,
    pub root: FileIdentity,
    pub stage: SlotStage,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationJournal {
    pub schema: u32,
    pub session_id: String,
    pub observation_id: String,
    pub binding: ApplicationBinding,
    pub roots: Vec<RootObservation>,
    pub slots: Vec<QuarantineSlot>,
    pub processes: Vec<ProcessBinding>,
    pub stage: JournalStage,
    /// Explicit policy: only generated objects may be deleted after all originals
    /// have been restored and verified. Original quarantine is never deleted.
    pub delete_generated_after_verified_restore: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct LocalValidatedRule {
    pub id: String,
    pub observation_id: String,
    pub binding: ApplicationBinding,
    pub roots: Vec<RootObservation>,
    pub scope: Vec<FamilyScope>,
    pub trials: Vec<TrialEvidence>,
    pub repetitions: usize,
    pub preservation: PreservationState,
    pub accepted_bounded_losses: bool,
    pub stale: bool,
}
impl LocalValidatedRule {
    pub fn qualified(&self) -> bool {
        !self.stale && self.accepted_bounded_losses
            && self.binding.identity.state == ApplicationIdentity::Exact
            && !self.scope.is_empty() && self.scope.len() <= MAX_FAMILIES
            && self.roots.iter().all(|r| matches!(r.ownership.state, StorageOwnership::Corroborated | StorageOwnership::Exclusive))
            && self.scope.iter().all(|s| self.roots.iter().any(|r| r.root == s.root && r.families.iter().any(|f| f.family == s.family && approved_family(f))))
            && matches!(self.preservation, PreservationState::BoundedKnownLosses | PreservationState::NoAbnormalCollateralMutationObserved)
            && self.repetitions >= 2
            && self.trials.iter().filter(|t| t.purpose == TrialPurpose::FinalRepeat && t.scope == self.scope).count() == self.repetitions
            && self.trials.iter().filter(|t| t.purpose == TrialPurpose::FinalRepeat).all(|t| {
                let mut classified = t.clone();
                classified.classify();
                t.scope == self.scope && classified.result == CausalResult::Sufficient
            })
    }
    pub fn decision(&self) -> DecisionTrace {
        let qualified = self.qualified();
        ScopeEvidence {
            application_identity: self.binding.identity.clone(),
            storage_ownership: EvidenceState::new(
                if self.roots.iter().any(|r| r.ownership.state == StorageOwnership::SharedConflict) {
                    StorageOwnership::SharedConflict
                } else if qualified { StorageOwnership::Corroborated } else { StorageOwnership::Unknown },
                "local-controlled-validation", "bound-root-ownership"),
            authentication_scope: EvidenceState::new(
                if qualified { AuthenticationScope::LocallyValidated } else { AuthenticationScope::Observed },
                "local-controlled-validation", "repeated-causal-aba"),
            preservation: EvidenceState::new(self.preservation, "local-controlled-validation", "bounded-content-semantics-unknown"),
            version_applicability: EvidenceState::new(
                if self.stale { VersionApplicability::Stale } else { VersionApplicability::Current },
                "local-controlled-validation", "installation-version-layout-binding"),
            authority: if qualified { OperationAuthority::LocalBounded } else { OperationAuthority::Unreviewed },
        }.decide(Support::Candidate, &[], LossAssessment::Known,
            &[RiskFlag::SettingsOrProfiles, RiskFlag::LocalOnlyDocuments, RiskFlag::DraftsOrOfflineMessages], &[ConfirmationId("local-bounded-losses".into())])
    }
}

pub const MAX_FAMILIES: usize = 6;
pub const MAX_SEARCH_TRIALS: usize = 24;
pub fn approved_family(f: &FamilyObservation) -> bool {
    matches!(f.verdict, ObservationVerdict::StronglyObserved | ObservationVerdict::Observed)
        && f.class == ArtifactClass::CorrelatedAuthCandidate
        && f.cycles.len() >= 2
        && f.cycles.iter().all(|c| c.complete && c.login_logout && c.persisted)
}
pub fn candidates(record: &LearnedObservation) -> Result<Vec<FamilyScope>, &'static str> {
    if record.binding.identity.state != ApplicationIdentity::Exact
        || record.status != LearnedStatus::Observed || record.completeness != Completeness::Complete
        || record.cycles < 2 || record.roots.is_empty() || record.roots.len() > 8 {
        return Err("incomplete-observation-or-identity");
    }
    if record.roots.iter().any(|r| !matches!(r.ownership.state, StorageOwnership::Corroborated | StorageOwnership::Exclusive)) {
        return Err("storage-ownership-unconfirmed-or-conflict");
    }
    let mut ranked: Vec<_> = record.roots.iter().flat_map(|r| r.families.iter()
        .filter(|f| approved_family(f)).map(move |f| (f.verdict != ObservationVerdict::StronglyObserved,
            FamilyScope { root: r.root.clone(), family: f.family.clone() }))).collect();
    ranked.sort_by_key(|(weak, s)| (*weak, s.root.clone(), s.family.clone()));
    let result: Vec<_> = ranked.into_iter().map(|(_, s)| s).collect();
    if result.is_empty() || result.len() > MAX_FAMILIES { return Err("unsupported-bounded-search-size"); }
    Ok(result)
}
/// Enumerate by cardinality, strongest single families first. No monotonicity
/// assumption; reaching the budget before finding a sufficient scope fails closed.
pub fn search_scopes(families: &[FamilyScope]) -> Vec<Vec<FamilyScope>> {
    let mut masks: Vec<_> = (1usize..(1 << families.len())).collect();
    masks.sort_by_key(|mask| (mask.count_ones(), *mask));
    masks.into_iter().take(MAX_SEARCH_TRIALS).map(|mask| families.iter().enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0).map(|(_, f)| f.clone()).collect()).collect()
}

/// Compare changed file metadata per family, against the normal A1 interval and
/// P2 noise. A content-independent observation never proves semantic preservation.
pub fn collateral(
    before_a: &[MetadataSnapshot], after_a: &[MetadataSnapshot],
    before_b: &[MetadataSnapshot], after_b: &[MetadataSnapshot],
    scope: &[FamilyScope], learned: &LearnedObservation,
) -> Option<Vec<FamilyScope>> {
    let mut abnormal = vec![];
    for root in &learned.roots {
        let find = |snapshots: &[MetadataSnapshot]| snapshots.iter().find(|s| s.root == root.root).cloned();
        let (a0, a1, b0, b1) = (find(before_a)?, find(after_a)?, find(before_b)?, find(after_b)?);
        if [&a0, &a1, &b0, &b1].iter().any(|s| s.completeness != Completeness::Complete || s.root_identity != root.physical) { return None; }
        let changed = |a: &MetadataSnapshot, b: &MetadataSnapshot| {
            let a = a.families(); let b = b.families();
            a.keys().chain(b.keys()).filter(|f| a.get(*f) != b.get(*f)).cloned().collect::<BTreeSet<_>>()
        };
        let normal = changed(&a0, &a1);
        for family in changed(&b0, &b1) {
            if family.contains(".everyout-validation-") || scope.iter().any(|s| s.root == root.root && s.family == family) { continue; }
            let noise = root.families.iter().any(|f| f.family == family && f.verdict == ObservationVerdict::Noise);
            // Noise in P2 still needs to occur in the contemporaneous control.
            if !normal.contains(&family) || !noise {
                abnormal.push(FamilyScope { root: root.root.clone(), family });
            }
        }
    }
    Some(abnormal)
}

#[derive(Debug, Clone, Serialize, ts_rs::TS)]
pub struct ValidationView {
    pub id: String,
    pub stage: ValidationStage,
    pub scope: Vec<FamilyScope>,
    pub trials: Vec<TrialEvidence>,
    pub diagnostics: Vec<String>,
    pub rule: Option<LocalValidatedRule>,
}
