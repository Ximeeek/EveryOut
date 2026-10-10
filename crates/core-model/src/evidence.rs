//! Independent safety evidence. Confidence and acknowledgments are not evidence.
use crate::*;
use std::collections::BTreeSet;

macro_rules! state {
    ($name:ident { $($variant:ident),+ }) => {
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $($variant,)+ #[default] Unknown }
    };
}
state!(ApplicationIdentity {
    Exact,
    Corroborated,
    Weak
});
state!(StorageOwnership {
    Exclusive,
    Corroborated,
    SharedConflict
});
state!(AuthenticationScope {
    Validated,
    LocallyValidated,
    Observed,
    FrameworkHint
});
state!(PreservationState {
    Validated,
    KnownLosses,
    BoundedKnownLosses,
    NoAbnormalCollateralMutationObserved
});
state!(VersionApplicability { Current, Stale });

/// Extensible source vocabulary with sanitized reason codes, never file payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct EvidenceProvenance {
    pub source: String,
    pub reason_code: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct EvidenceState<T> {
    pub state: T,
    pub provenance: Vec<EvidenceProvenance>,
}
impl<T> EvidenceState<T> {
    pub fn new(state: T, source: &str, reason_code: &str) -> Self {
        Self {
            state,
            provenance: vec![EvidenceProvenance {
                source: source.into(),
                reason_code: reason_code.into(),
            }],
        }
    }
}
impl<T: Default> Default for EvidenceState<T> {
    fn default() -> Self {
        Self::new(T::default(), "missing-evidence", "evidence-not-available")
    }
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS,
)]
#[serde(rename_all = "kebab-case")]
pub enum OperationAuthority {
    #[default]
    Unreviewed,
    ReviewedCatalog,
    SpotifySavedLogin,
    LocalBounded,
}
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
#[serde(deny_unknown_fields)]
pub struct ScopeEvidence {
    pub application_identity: EvidenceState<ApplicationIdentity>,
    pub storage_ownership: EvidenceState<StorageOwnership>,
    pub authentication_scope: EvidenceState<AuthenticationScope>,
    pub preservation: EvidenceState<PreservationState>,
    pub version_applicability: EvidenceState<VersionApplicability>,
    pub authority: OperationAuthority,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, ts_rs::TS)]
pub struct DecisionTrace {
    pub evidence: ScopeEvidence,
    pub support: Support,
    /// Safety permission only. Process/physical revalidation and confirmations still apply.
    pub action_allowed: bool,
    pub blocked_by: Vec<String>,
    pub confirmations_required: Vec<ConfirmationId>,
}
impl Default for DecisionTrace {
    fn default() -> Self {
        ScopeEvidence::default().decide(Support::Candidate, &[], LossAssessment::Unknown, &[], &[])
    }
}
impl DecisionTrace {
    pub fn unverified(&self) -> bool {
        !self.action_allowed
    }
    pub fn block(&mut self, reason: &str) {
        if !self.blocked_by.iter().any(|code| code == reason) {
            self.blocked_by.push(reason.into());
            self.blocked_by.sort();
        }
        self.action_allowed = false;
    }
}
impl ScopeEvidence {
    /// Compatibility projection for already reviewed legacy catalog rules. This does
    /// not promote candidates. Sources explicitly distinguish declarations from runtime.
    pub fn reviewed_catalog(loss: LossAssessment) -> Self {
        Self {
            application_identity: EvidenceState::new(
                ApplicationIdentity::Corroborated,
                "catalog-declaration",
                "reviewed-application-identity",
            ),
            storage_ownership: EvidenceState::new(
                StorageOwnership::Exclusive,
                "catalog-declaration",
                "reviewed-bounded-storage",
            ),
            authentication_scope: EvidenceState::new(
                AuthenticationScope::Validated,
                "catalog-declaration",
                "legacy-reviewed-authentication-scope",
            ),
            preservation: EvidenceState::new(
                match loss {
                    LossAssessment::None => PreservationState::Validated,
                    LossAssessment::Known => PreservationState::KnownLosses,
                    LossAssessment::Unknown => PreservationState::Unknown,
                },
                "catalog-declaration",
                "reviewed-loss-assessment",
            ),
            version_applicability: EvidenceState::new(
                VersionApplicability::Current,
                "catalog-declaration",
                "legacy-reviewed-version-coverage",
            ),
            authority: OperationAuthority::ReviewedCatalog,
        }
    }
    pub fn decide(
        &self,
        support: Support,
        blockers: &[String],
        loss: LossAssessment,
        flags: &[RiskFlag],
        confirmations: &[ConfirmationId],
    ) -> DecisionTrace {
        let mut blocked: BTreeSet<String> = blockers.iter().cloned().collect();
        if !matches!(
            self.application_identity.state,
            ApplicationIdentity::Exact | ApplicationIdentity::Corroborated
        ) {
            blocked.insert("application-identity-unconfirmed".into());
        }
        match self.storage_ownership.state {
            StorageOwnership::SharedConflict => {
                blocked.insert("storage-ownership-conflict".into());
            }
            StorageOwnership::Unknown => {
                blocked.insert("storage-ownership-unconfirmed".into());
            }
            _ => {}
        }
        if !matches!(
            self.authentication_scope.state,
            AuthenticationScope::Validated | AuthenticationScope::LocallyValidated
        ) {
            blocked.insert("unknown-authentication-closure".into());
        }
        if self.preservation.state == PreservationState::Unknown {
            blocked.insert("unreviewed-preservation".into());
        }
        if matches!(
            self.preservation.state,
            PreservationState::KnownLosses
                | PreservationState::BoundedKnownLosses
                | PreservationState::NoAbnormalCollateralMutationObserved
        ) && loss != LossAssessment::Known
        {
            blocked.insert("preservation-loss-assessment-mismatch".into());
        }
        if loss == LossAssessment::Known && flags.is_empty() {
            blocked.insert("known-loss-risk-disclosure-missing".into());
        }
        match self.version_applicability.state {
            VersionApplicability::Unknown => {
                blocked.insert("unvalidated-product-version".into());
            }
            VersionApplicability::Stale => {
                blocked.insert("product-version-revalidation-required".into());
            }
            _ => {}
        }
        let provenance = [
            &self.application_identity.provenance,
            &self.storage_ownership.provenance,
            &self.authentication_scope.provenance,
            &self.preservation.provenance,
            &self.version_applicability.provenance,
        ];
        let established = [
            self.application_identity.state != ApplicationIdentity::Unknown,
            self.storage_ownership.state != StorageOwnership::Unknown,
            self.authentication_scope.state != AuthenticationScope::Unknown,
            self.preservation.state != PreservationState::Unknown,
            self.version_applicability.state != VersionApplicability::Unknown,
        ];
        if provenance.iter().any(|sources| {
            sources.is_empty()
                || sources
                    .iter()
                    .any(|source| !stable_code(&source.source) || !stable_code(&source.reason_code))
        }) {
            blocked.insert("evidence-provenance-missing".into());
        }
        if provenance
            .iter()
            .zip(established)
            .any(|(sources, established)| {
                established
                    && sources
                        .iter()
                        .all(|source| source.source == "missing-evidence")
            })
        {
            blocked.insert("evidence-provenance-missing".into());
        }
        if !matches!(
            (support, self.authority),
            (Support::Validated, OperationAuthority::ReviewedCatalog)
                | (Support::Candidate, OperationAuthority::SpotifySavedLogin)
                | (Support::Candidate, OperationAuthority::LocalBounded)
        ) {
            blocked.insert("automatic-cleanup-unverified".into());
        }
        if self.authority == OperationAuthority::LocalBounded
            && (self.application_identity.state != ApplicationIdentity::Exact
                || self.authentication_scope.state != AuthenticationScope::LocallyValidated
                || !matches!(
                    self.preservation.state,
                    PreservationState::BoundedKnownLosses
                        | PreservationState::NoAbnormalCollateralMutationObserved
                ))
        {
            blocked.insert("local-validation-gates-incomplete".into());
        }
        if loss == LossAssessment::Unknown || flags.contains(&RiskFlag::Unknown) {
            blocked.insert("unknown-permanent-loss".into());
        }
        if flags.contains(&RiskFlag::SavedPasswordsPasskeysAutofillHistory) {
            blocked.insert("protected-credential-data".into());
        }
        DecisionTrace {
            evidence: self.clone(),
            support,
            action_allowed: blocked.is_empty(),
            blocked_by: blocked.into_iter().collect(),
            confirmations_required: confirmations.to_vec(),
        }
    }
}
fn stable_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl ProposedPlan {
    pub fn decision_trace(&self) -> DecisionTrace {
        let blockers: Vec<_> = self
            .blockers
            .iter()
            .chain(self.actions.iter().flat_map(|a| &a.blockers))
            .cloned()
            .collect();
        let confirmations: Vec<_> = self
            .confirmations
            .iter()
            .chain(&self.risks.confirmations)
            .chain(self.actions.iter().flat_map(|a| &a.confirmations))
            .cloned()
            .collect();
        let mut decision = self.scope_evidence.decide(
            self.support,
            &blockers,
            self.risks.permanent_data_loss,
            &self.risks.flags,
            &confirmations,
        );
        if self.actions.is_empty() {
            decision.block("no-reviewed-actions");
        }
        if self.scope_evidence.authority == OperationAuthority::SpotifySavedLogin
            && (self.provider_id.0 != "spotify"
                || self.actions.len() != 1
                || self.actions[0].method != MethodKind::ExceptionAdapter)
        {
            decision.block("reviewed-adapter-scope-mismatch");
        }
        if self.scope_evidence.authority == OperationAuthority::SpotifySavedLogin
            && !self
                .confirmations
                .contains(&ConfirmationId("review-candidate-provider-spotify".into()))
        {
            decision.block("reviewed-adapter-confirmation-missing");
        }
        decision
    }
}
