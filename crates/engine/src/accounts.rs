//! Independent account compartments. An account failure never removes another
//! account's results. Approval is bound to an immutable per-account preview.
use crate::RunReport;
use everyout_core_model::*;
use serde::{Deserialize, Serialize};

pub const S6_UNVERIFIED: &str =
    "unverified-s6-profile-logon-races-hive-lifecycle-cross-session-close";
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountReport {
    pub account: UserId,
    pub logged_on: bool,
    pub sections: Vec<RunReport>,
    pub issues: Vec<String>,
    pub residual_hive: bool,
    pub residual_hku_key: Option<String>,
    pub unload_attempts: usize,
    pub limitations: Vec<String>,
}
impl AccountReport {
    pub fn empty(account: UserId, logged_on: bool) -> Self {
        Self {
            account,
            logged_on,
            sections: vec![],
            issues: vec![],
            residual_hive: false,
            residual_hku_key: None,
            unload_attempts: 0,
            limitations: vec![S6_UNVERIFIED.into()],
        }
    }
    pub fn failed(account: UserId, logged_on: bool, kind: ErrorKind) -> Self {
        let mut report = Self::empty(account, logged_on);
        report.issues.push(format!("account-{kind:?}"));
        report
    }
    fn failed_from(&self, kind: ErrorKind) -> Self {
        let mut report = self.clone();
        report.issues.push(format!("account-{kind:?}"));
        for run in &mut report.sections {
            run.mode = ExecutionMode::Apply;
            for section in &mut run.sections {
                if section.aggregate != AggregateStatus::NotRequested {
                    section.aggregate = AggregateStatus::Blocked;
                }
                section.counts = crate::Counts::default();
                for item in &mut section.items {
                    item.aggregate = AggregateStatus::Blocked;
                    for action in &mut item.actions {
                        action.outcome.status = ActionStatus::Blocked;
                        action.verification.status = VerificationStatus::Unknown;
                        action.verification.observation = None;
                    }
                }
            }
        }
        report
    }
}
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountConsent {
    pub account: String,
    pub windows_dev_confirmed: bool,
    pub risks: Vec<RiskFlag>,
    pub confirmations: Vec<ConfirmationId>,
    pub force_close_acknowledged: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountsReport {
    pub scope: AccountScope,
    pub mode: ExecutionMode,
    pub accounts: Vec<AccountReport>,
}
pub struct AccountsPlan {
    id: PlanId,
    preview: AccountsReport,
    policy: ProcessClosePolicy,
}
pub struct AccountsApproval {
    id: PlanId,
    consents: Vec<AccountConsent>,
}
impl AccountsPlan {
    pub fn new(
        id: PlanId,
        accounts: Vec<AccountReport>,
        policy: ProcessClosePolicy,
    ) -> Result<Self, ErrorKind> {
        let mut ids = std::collections::HashSet::new();
        if accounts.is_empty() || accounts.iter().any(|a| !ids.insert(a.account.clone())) {
            return Err(ErrorKind::ScopeViolation);
        }
        Ok(Self {
            id,
            preview: AccountsReport {
                scope: AccountScope::AllUsers,
                mode: ExecutionMode::DryRun,
                accounts,
            },
            policy,
        })
    }
    pub fn id(&self) -> &PlanId {
        &self.id
    }
    pub fn preview(&self) -> &AccountsReport {
        &self.preview
    }
    pub fn policy(&self) -> ProcessClosePolicy {
        self.policy
    }
    pub fn approve(&self, consents: Vec<AccountConsent>) -> Result<AccountsApproval, ErrorKind> {
        let mut seen = std::collections::HashSet::new();
        for consent in &consents {
            if !seen.insert(&consent.account)
                || !self
                    .preview
                    .accounts
                    .iter()
                    .any(|a| a.account.0 == consent.account)
            {
                return Err(ErrorKind::ScopeViolation);
            }
        }
        Ok(AccountsApproval {
            id: self.id.clone(),
            consents,
        })
    }
    /// Trusted helper executor revalidates profile, plan and processes, then uses
    /// Engine::for_account with category/risk tokens for this account only.
    pub fn execute(
        &self,
        approval: &AccountsApproval,
        cancelled: &dyn Fn() -> bool,
        mut work: impl FnMut(
            &AccountReport,
            Option<&AccountConsent>,
        ) -> Result<AccountReport, ErrorKind>,
    ) -> AccountsReport {
        let accounts = self
            .preview
            .accounts
            .iter()
            .map(|expected| {
                if self.id != approval.id {
                    return expected.failed_from(ErrorKind::ScopeViolation);
                }
                if cancelled() {
                    return expected.failed_from(ErrorKind::Cancelled);
                }
                if expected.residual_hive {
                    let mut report = expected.failed_from(ErrorKind::Locked);
                    report
                        .issues
                        .push("residual-hive-requires-recovery-and-new-plan".into());
                    return report;
                }
                let consent = approval
                    .consents
                    .iter()
                    .find(|c| c.account == expected.account.0);
                if consent.is_none() {
                    return expected.failed_from(ErrorKind::ScopeViolation);
                }
                match work(expected, consent) {
                    Ok(report)
                        if report.account == expected.account
                            && report.logged_on == expected.logged_on =>
                    {
                        report
                    }
                    Ok(_) => expected.failed_from(ErrorKind::ScopeViolation),
                    Err(kind) => expected.failed_from(kind),
                }
            })
            .collect();
        AccountsReport {
            scope: AccountScope::AllUsers,
            mode: ExecutionMode::Apply,
            accounts,
        }
    }
}
