//! IPC projections contain opaque IDs, reviewed relative labels and stable statuses only.
use everyout_core_model::*;
use everyout_engine::{accounts::AccountsReport, ItemReport, RunReport, Stage};
use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub process_close_policy: ProcessClosePolicy,
    pub account_mode: AccountMode,
    pub first_run_completed: bool,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            process_close_policy: ProcessClosePolicy::Ask,
            account_mode: AccountMode::Current,
            first_run_completed: false,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "kebab-case")]
pub enum CommandError {
    Busy,
    StalePlan,
    InvalidSelection,
    ConfirmationRequired,
    SettingsIo,
    HelperUnavailable,
    WorkerUnavailable,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, TS)]
pub struct DetectedItem {
    pub id: String,
    pub account: String,
    pub provider: Option<String>,
    pub name: String,
    pub origin: DetectionOrigin,
    pub default_selected: bool,
    pub selectable: bool,
    pub limitations: Vec<String>,
    pub profiles: Vec<String>,
    pub risks: Vec<RiskFlag>,
    pub loss: LossAssessment,
    pub signals: Vec<String>,
    pub unverified: bool,
    pub sync_warning: bool,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct DetectionGroup {
    pub category: Option<Category>,
    pub confidence: Confidence,
    pub items: Vec<DetectedItem>,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct ScanDto {
    pub inventory_id: String,
    pub mode: AccountMode,
    pub groups: Vec<DetectionGroup>,
    pub coverage: Vec<String>,
    pub accounts: Vec<AccountScanDto>,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct AccountScanDto {
    pub account: String,
    pub logged_on: Option<bool>,
    pub residual_hive: bool,
    pub residual_hku_key: Option<String>,
    pub unload_attempts: usize,
    pub limitations: Vec<String>,
}
impl ScanDto {
    pub fn push(&mut self, category: Option<Category>, confidence: Confidence, item: DetectedItem) {
        if let Some(group) = self
            .groups
            .iter_mut()
            .find(|g| g.category == category && g.confidence == confidence)
        {
            group.items.push(item);
        } else {
            self.groups.push(DetectionGroup {
                category,
                confidence,
                items: vec![item],
            });
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct SelectionRequest {
    pub inventory_id: String,
    pub items: Vec<String>,
    /// Omission preserves the legacy whole-instance selection. Entries narrow scope only.
    #[serde(default)]
    pub profiles: Vec<ProfileSelection>,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ProfileSelection {
    pub item: String,
    pub profiles: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct RiskAcceptance {
    pub account: String,
    pub instance: String,
    pub flags: Vec<RiskFlag>,
    pub confirmations: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(deny_unknown_fields)]
pub struct ExecuteRequest {
    pub plan_id: String,
    pub confirmed_risks: Vec<RiskAcceptance>,
    pub category_tokens: Vec<String>,
    pub force_close_accounts: Vec<String>,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct CategoryToken {
    pub account: String,
    pub category: Category,
    pub token: String,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct PlanDto {
    pub plan_id: String,
    pub category_tokens: Vec<CategoryToken>,
    pub report: ReportDto,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct ActionDto {
    pub id: String,
    pub path: String,
    pub outcome: ActionStatus,
    pub verification: VerificationStatus,
    pub issues: Vec<String>,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct ItemDto {
    pub instance: String,
    pub status: AggregateStatus,
    pub actions: Vec<ActionDto>,
    pub risks: Vec<RiskFlag>,
    pub confirmations: Vec<String>,
    pub profiles: Vec<String>,
    pub processes: Vec<String>,
    pub limitations: Vec<String>,
    pub issues: Vec<String>,
    pub identity: Uncertainty,
    pub sync: Uncertainty,
    pub authentication: Uncertainty,
    pub remote_revocation: Uncertainty,
    pub silent_sso: Uncertainty,
}
impl From<&ItemReport> for ItemDto {
    fn from(item: &ItemReport) -> Self {
        let plan = item.plan.as_ref();
        Self {
            instance: item.instance.0.clone(),
            status: item.aggregate,
            actions: item
                .actions
                .iter()
                .map(|a| ActionDto {
                    id: a.outcome.action_id.0.clone(),
                    path: a.path.clone(),
                    outcome: a.outcome.status,
                    verification: a.verification.status,
                    issues: a
                        .outcome
                        .issues
                        .iter()
                        .chain(&a.verification.issues)
                        .map(|i| i.explanation_code.clone())
                        .collect(),
                })
                .collect(),
            risks: plan.map(|p| p.risks.flags.clone()).unwrap_or_default(),
            confirmations: plan
                .map(|p| {
                    p.confirmations
                        .iter()
                        .chain(&p.risks.confirmations)
                        .chain(p.actions.iter().flat_map(|a| &a.confirmations))
                        .map(|id| id.0.clone())
                        .collect()
                })
                .unwrap_or_default(),
            profiles: plan
                .map(|p| p.selection.profiles.iter().map(|id| id.0.clone()).collect())
                .unwrap_or_default(),
            processes: item.processes.iter().map(|p| p.identity.clone()).collect(),
            limitations: plan
                .map(|p| p.limitations.iter().chain(&p.blockers).cloned().collect())
                .unwrap_or_default(),
            issues: item
                .issues
                .iter()
                .map(|i| i.explanation_code.clone())
                .collect(),
            identity: item.identity_sync.identity,
            sync: item.identity_sync.sync,
            authentication: item.authentication,
            remote_revocation: item.remote_revocation,
            silent_sso: item.silent_sso,
        }
    }
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct SectionDto {
    pub category: Category,
    pub status: AggregateStatus,
    pub warnings: Vec<String>,
    pub items: Vec<ItemDto>,
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub locked: usize,
    pub would_apply: usize,
    pub already_absent: usize,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct AccountDto {
    pub account: String,
    pub sections: Vec<SectionDto>,
    pub limitations: Vec<String>,
    pub issues: Vec<String>,
    pub residual_hive: bool,
    pub residual_hku_key: Option<String>,
    pub unload_attempts: usize,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct ReportDto {
    pub mode: ExecutionMode,
    pub account_mode: AccountMode,
    pub process_close_policy: ProcessClosePolicy,
    pub accounts: Vec<AccountDto>,
}
pub fn sections(runs: &[RunReport]) -> Vec<SectionDto> {
    [
        Category::Application,
        Category::Browser,
        Category::WindowsMicrosoftAndDevTools,
    ]
    .into_iter()
    .map(|category| {
        let selected: Vec<_> = runs
            .iter()
            .flat_map(|r| &r.sections)
            .filter(|s| s.category == category && s.aggregate != AggregateStatus::NotRequested)
            .collect();
        let status = if selected.is_empty() {
            AggregateStatus::NotRequested
        } else if selected
            .iter()
            .all(|s| s.aggregate == selected[0].aggregate)
        {
            selected[0].aggregate
        } else {
            AggregateStatus::Partial
        };
        let mut warnings: Vec<_> = selected.iter().flat_map(|s| s.warnings.clone()).collect();
        if category == Category::WindowsMicrosoftAndDevTools {
            warnings.push(everyout_engine::WINDOWS_DEV_SSO_WARNING.into());
        }
        warnings.sort();
        warnings.dedup();
        SectionDto {
            category,
            status,
            warnings,
            items: selected
                .iter()
                .flat_map(|s| s.items.iter().map(ItemDto::from))
                .collect(),
            succeeded: selected.iter().map(|s| s.counts.succeeded).sum(),
            failed: selected.iter().map(|s| s.counts.failed).sum(),
            skipped: selected.iter().map(|s| s.counts.skipped).sum(),
            locked: selected.iter().map(|s| s.counts.locked).sum(),
            would_apply: selected.iter().map(|s| s.counts.would_apply).sum(),
            already_absent: selected.iter().map(|s| s.counts.already_absent).sum(),
        }
    })
    .collect()
}
impl ReportDto {
    pub fn current(runs: &[RunReport], policy: ProcessClosePolicy, mode: ExecutionMode) -> Self {
        Self {
            mode,
            account_mode: AccountMode::Current,
            process_close_policy: policy,
            accounts: vec![AccountDto {
                account: "current-account".into(),
                sections: sections(runs),
                limitations: vec![],
                issues: vec![],
                residual_hive: false,
                residual_hku_key: None,
                unload_attempts: 0,
            }],
        }
    }
    pub fn elevated(report: &AccountsReport, policy: ProcessClosePolicy) -> Self {
        Self {
            mode: report.mode,
            account_mode: AccountMode::AllAccounts,
            process_close_policy: policy,
            accounts: report
                .accounts
                .iter()
                .map(|a| AccountDto {
                    account: a.account.0.clone(),
                    sections: sections(&a.sections),
                    limitations: a.limitations.clone(),
                    issues: a.issues.clone(),
                    residual_hive: a.residual_hive,
                    residual_hku_key: a.residual_hku_key.clone(),
                    unload_attempts: a.unload_attempts,
                })
                .collect(),
        }
    }
}
#[derive(Debug, Clone, Serialize, TS)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum WipeEvent {
    Progress {
        run_id: String,
        account: String,
        stage: Stage,
        category: Category,
        instance: Option<String>,
        action: Option<String>,
    },
    Item {
        run_id: String,
        account: String,
        category: Category,
        item: ItemDto,
    },
    Finished {
        run_id: String,
        report: ReportDto,
    },
    Failed {
        run_id: String,
        error: CommandError,
    },
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct RunStarted {
    pub run_id: String,
}
#[derive(Debug, Clone, Serialize, TS)]
pub struct ModeResult {
    pub effective_mode: AccountMode,
    pub requires_fresh_review: bool,
    pub reason: Option<ModeFailure>,
}
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "kebab-case")]
pub enum ModeFailure {
    UacDeclined,
    StartFailed,
    AuthenticationFailed,
    Timeout,
    TrustPinUnavailable,
}
