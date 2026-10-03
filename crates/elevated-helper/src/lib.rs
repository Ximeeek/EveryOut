//! Phase 27 elevation boundary. S6 transport/UAC experiments remain unverified.
//! Phase 28 adds reviewed owner-bound compartments; S6 remains unverified.
#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(windows)]
mod accounts;
pub mod protocol;
#[cfg(windows)]
mod windows;
use everyout_core_model::AccountMode;
#[cfg(windows)]
pub use windows::{launch, Client};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchFailure {
    UacDeclined,
    StartFailed,
    AuthenticationFailed,
    Timeout,
}

/// A fallback contains no plan or approval. The host must discard expanded state,
/// save Current, inform the user, and rescan/review; UI integration is phase 30.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fallback {
    pub reason: LaunchFailure,
    pub effective_mode: AccountMode,
    pub saved_mode: AccountMode,
    pub requires_fresh_review: bool,
}
impl From<LaunchFailure> for Fallback {
    fn from(reason: LaunchFailure) -> Self {
        Self {
            reason,
            effective_mode: AccountMode::Current,
            saved_mode: AccountMode::Current,
            requires_fresh_review: true,
        }
    }
}
pub enum LaunchOutcome<T> {
    CurrentAccount,
    Elevated(T),
    Fallback(Fallback),
}
/// Precondition is evaluated before any native launch, even in an elevated host.
pub fn launch_on_demand<T>(
    mode: AccountMode,
    privileged_work_needed: bool,
    start: impl FnOnce() -> Result<T, LaunchFailure>,
) -> LaunchOutcome<T> {
    if mode != AccountMode::AllAccounts || !privileged_work_needed {
        return LaunchOutcome::CurrentAccount;
    }
    match start() {
        Ok(client) => LaunchOutcome::Elevated(client),
        Err(reason) => LaunchOutcome::Fallback(reason.into()),
    }
}

#[cfg(windows)]
pub fn helper_main() -> Result<(), LaunchFailure> {
    windows::serve()
}
