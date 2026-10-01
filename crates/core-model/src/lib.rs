//! Secret-free domain declarations. No system or Tauri interfaces are implemented here.
#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! id {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
        #[serde(transparent)]
        pub struct $name(pub String);
    )+};
}
id!(
    ProviderId,
    InstanceId,
    ProfileId,
    UserId,
    InstallationId,
    RootId,
    ArtifactId,
    ActionId,
    PlanId,
    SnapshotId,
    EvidenceRef,
    ConfirmationId
);

macro_rules! vocabulary {
    ($name:ident { $($variant:ident),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
        #[serde(rename_all = "kebab-case")]
        pub enum $name { $($variant),+ }
    };
}
vocabulary!(Category {
    Application,
    Browser,
    WindowsMicrosoftAndDevTools
});
vocabulary!(Confidence { High, Medium, Low });
vocabulary!(AccountMode {
    Current,
    AllAccounts
});
vocabulary!(ExecutionMode { DryRun, Apply });
/// Ask never escalates. HardKillAfter2s requires caller review of unsaved-work loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ProcessClosePolicy {
    Ask,
    HardKillAfter2s,
}
vocabulary!(Support {
    Candidate,
    Validated
});
vocabulary!(ActionStatus {
    WouldApply,
    Applied,
    AlreadyAbsent,
    Skipped,
    Blocked,
    Failed
});
vocabulary!(VerificationStatus {
    TargetAbsent,
    TargetPresent,
    Inaccessible,
    Unknown,
    NotPerformed
});
vocabulary!(ErrorKind {
    AccessDenied,
    Locked,
    OwnershipConflict,
    StalePlan,
    Unsupported,
    InvalidManifest,
    ScopeViolation,
    SecurityProductBlocked,
    Cancelled,
    Io
});
vocabulary!(Phase {
    Detect,
    Describe,
    Plan,
    Execute,
    Verify,
    Report,
    Revoke
});
vocabulary!(AggregateStatus {
    CompleteLocalScope,
    Partial,
    Blocked,
    Failed,
    Cancelled,
    DryRun,
    NotRequested
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RiskFlag {
    LocalOnlyDocuments,
    DraftsOrOfflineMessages,
    SettingsOrProfiles,
    WalletOrKeyMaterial,
    #[serde(rename = "vault-or-2fa-recovery")]
    VaultOr2faRecovery,
    SavedPasswordsPasskeysAutofillHistory,
    SharedStore,
    Unknown,
}
vocabulary!(LossAssessment {
    Known,
    None,
    Unknown
});
vocabulary!(ObservationKind {
    Exists,
    ExistsAndSize
});
vocabulary!(ArtifactKind {
    File,
    Directory,
    RegistryKey,
    RegistryValue
});
vocabulary!(Scope {
    OsUser,
    Installation,
    Profile
});
vocabulary!(EvidenceFamily {
    Ownership,
    Installation,
    Package,
    Process,
    Storage
});
vocabulary!(MethodKind {
    DeleteFileFamily,
    DeleteDirectoryFamily,
    DeleteRegistryTarget,
    LocalApiOperation,
    ExceptionAdapter
});
vocabulary!(Uncertainty {
    Unknown,
    Unsupported,
    NotRequested
});

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RiskAssessment {
    pub flags: Vec<RiskFlag>,
    pub affected_data: Vec<String>,
    pub permanent_data_loss: LossAssessment,
    pub reason: Option<String>,
    pub confirmations: Vec<ConfirmationId>,
    pub evidence: Vec<EvidenceRef>,
}

/// Stable explanation codes only: never arbitrary OS messages or captured command output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderIssue {
    pub phase: Phase,
    pub provider_id: ProviderId,
    pub instance_id: Option<InstanceId>,
    pub action_id: Option<ActionId>,
    pub kind: ErrorKind,
    pub os_code: Option<u32>,
    pub explanation_code: String,
    pub blocked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct OwnerIdentity {
    pub user_id: UserId,
    pub installation_id: InstallationId,
    pub root_id: RootId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProfileScope {
    pub profile_id: ProfileId,
    pub root_id: RootId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderDescriptor {
    pub provider_id: ProviderId,
    pub name: String,
    pub category: Category,
    pub revision: u64,
    pub support: Support,
    pub evidence: Vec<EvidenceRef>,
    pub limitations: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderInstance {
    pub provider_id: ProviderId,
    pub instance_id: InstanceId,
    pub owner: OwnerIdentity,
    pub profiles: Vec<ProfileScope>,
    pub confidence: Confidence,
    /// Missing provenance is conservatively treated as heuristic, including old JSON.
    #[serde(default)]
    pub detection_origin: DetectionOrigin,
    pub evidence: Vec<EvidenceRef>,
    pub issues: Vec<ProviderIssue>,
}

/// Identity confidence and catalog support cannot substitute for detection provenance.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum DetectionOrigin {
    KnownProvider,
    #[default]
    Heuristic,
}
impl DetectionOrigin {
    /// S8 has not passed; even high-confidence heuristics remain unchecked.
    pub fn default_selected(self, resolved_owner: bool) -> bool {
        resolved_owner && self == Self::KnownProvider
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct MetadataObservation {
    pub artifact_id: ArtifactId,
    pub kind: ArtifactKind,
    pub exists: bool,
    pub size: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DetectionResult {
    pub snapshot_id: SnapshotId,
    pub instances: Vec<ProviderInstance>,
    pub observations: Vec<MetadataObservation>,
    pub issues: Vec<ProviderIssue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderDescription {
    pub descriptor: ProviderDescriptor,
    pub instance_id: InstanceId,
    pub profiles: Vec<ProfileScope>,
    pub risks: RiskAssessment,
    pub expected_effects: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Selection {
    pub snapshot_id: SnapshotId,
    pub account_mode: AccountMode,
    pub instances: Vec<InstanceId>,
    pub profiles: Vec<ProfileId>,
}

/// Fixed logical target, resolved inside Rust by later platform/engine phases.
/// No arbitrary absolute path, shell command or secret content can be submitted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PlannedAction {
    pub action_id: ActionId,
    pub artifact_id: ArtifactId,
    pub root_id: RootId,
    pub profile_id: Option<ProfileId>,
    pub method_id: String,
    pub method: MethodKind,
    pub owner: OwnerIdentity,
    pub shared_owners: Vec<InstanceId>,
    pub artifact_families: Vec<String>,
    pub effects: Vec<String>,
    pub blockers: Vec<String>,
    pub confirmations: Vec<ConfirmationId>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProposedPlan {
    pub plan_id: PlanId,
    pub provider_id: ProviderId,
    pub manifest_revision: u64,
    pub support: Support,
    pub selection: Selection,
    pub actions: Vec<PlannedAction>,
    pub risks: RiskAssessment,
    pub blockers: Vec<String>,
    pub confirmations: Vec<ConfirmationId>,
    pub limitations: Vec<String>,
}

/// Capability owned by the engine. Deliberately not deserializable from UI input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPlan(ProposedPlan);
impl ValidatedPlan {
    /// Checks the pure review gates; the future engine must also bind ownership and
    /// metadata revalidation to this plan before every operation.
    pub fn review(plan: ProposedPlan, accepted: &[ConfirmationId]) -> Result<Self, ErrorKind> {
        if plan.support != Support::Validated
            || !plan.blockers.is_empty()
            || plan.risks.permanent_data_loss == LossAssessment::Unknown
            || plan
                .risks
                .flags
                .contains(&RiskFlag::SavedPasswordsPasskeysAutofillHistory)
            || plan
                .actions
                .iter()
                .any(|action| !action.blockers.is_empty())
        {
            return Err(ErrorKind::Unsupported);
        }
        let required = plan
            .confirmations
            .iter()
            .chain(plan.risks.confirmations.iter())
            .chain(
                plan.actions
                    .iter()
                    .flat_map(|action| action.confirmations.iter()),
            );
        if required
            .into_iter()
            .any(|confirmation| !accepted.contains(confirmation))
        {
            return Err(ErrorKind::ScopeViolation);
        }
        Ok(Self(plan))
    }
    pub fn plan(&self) -> &ProposedPlan {
        &self.0
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanResult {
    Ready(Box<ProposedPlan>),
    Blocked { issues: Vec<ProviderIssue> },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ActionOutcome {
    pub action_id: ActionId,
    pub status: ActionStatus,
    pub issues: Vec<ProviderIssue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExecutionResult {
    pub plan_id: PlanId,
    pub mode: ExecutionMode,
    pub outcomes: Vec<ActionOutcome>,
    pub issues: Vec<ProviderIssue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactVerification {
    pub artifact_id: ArtifactId,
    pub status: VerificationStatus,
    pub observation: Option<MetadataObservation>,
    pub issues: Vec<ProviderIssue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct VerificationResult {
    pub plan_id: PlanId,
    pub artifacts: Vec<ArtifactVerification>,
    pub issues: Vec<ProviderIssue>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ProviderResult {
    pub description: ProviderDescription,
    pub execution: ExecutionResult,
    pub verification: VerificationResult,
    pub aggregate: AggregateStatus,
}
/// Export projection intentionally excludes OwnerIdentity and concrete targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ReportItem {
    pub provider_id: ProviderId,
    pub instance_id: InstanceId,
    pub user_id: UserId,
    pub profiles: Vec<ProfileId>,
    pub shared_effects: Vec<InstanceId>,
    pub aggregate: AggregateStatus,
    pub outcomes: Vec<ActionOutcome>,
    pub verification: Vec<ArtifactVerification>,
    pub issues: Vec<ProviderIssue>,
    pub risk_flags: Vec<RiskFlag>,
    pub limitations: Vec<String>,
    pub authentication: Uncertainty,
    pub browser_identity: Uncertainty,
    pub sync: Uncertainty,
    pub silent_sso: Uncertainty,
    pub remote_revocation: Uncertainty,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SanitizedReport {
    pub applications: Vec<ReportItem>,
    pub browsers: Vec<ReportItem>,
    pub windows_microsoft_and_dev_tools: Vec<ReportItem>,
}

/// Narrow interfaces, not implementations. Observations contain only existence/type/size.
pub trait MetadataAccess {
    fn observe(
        &self,
        owner: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind>;
}
pub trait LocalOperations: MetadataAccess {
    fn apply(&self, plan: &ValidatedPlan, action: &ActionId) -> ActionOutcome;
}
pub struct DetectionContext<'a> {
    pub snapshot_id: SnapshotId,
    pub account_mode: AccountMode,
    pub metadata: &'a dyn MetadataAccess,
}
pub struct PlanContext<'a> {
    pub inventory: &'a DetectionResult,
}
pub struct OperationContext<'a> {
    pub operations: &'a dyn LocalOperations,
    pub cancelled: &'a dyn Fn() -> bool,
}
pub struct VerificationContext<'a> {
    pub plan: &'a ValidatedPlan,
    pub metadata: &'a dyn MetadataAccess,
}
/// Synchronous contract until runtime needs are established. No network interface exists.
pub trait Provider {
    fn detect(&self, cx: &DetectionContext<'_>) -> DetectionResult;
    fn describe(&self, instance: &ProviderInstance) -> ProviderDescription;
    fn plan(&self, cx: &PlanContext<'_>, selected: &Selection) -> PlanResult;
    fn execute(
        &self,
        cx: &OperationContext<'_>,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult;
    fn verify(&self, cx: &VerificationContext<'_>, result: &ExecutionResult) -> VerificationResult;
    fn report(&self, result: &ProviderResult) -> SanitizedReport;
    fn revoke(&self) -> RevocationResult {
        Err(RevocationUnsupported)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RevocationUnsupported;
impl std::fmt::Display for RevocationUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not supported in V1")
    }
}
impl std::error::Error for RevocationUnsupported {}
pub type RevocationResult = Result<(), RevocationUnsupported>;
