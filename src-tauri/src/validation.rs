//! Native controlled-validation worker. IPC accepts outcomes and opaque IDs only.
use crate::{dto::CommandError, mutation_gate::Admission};
use everyout_core_model::{local_validation::*, observation::*, ErrorKind, StorageOwnership};
use everyout_platform_windows::{
    self as platform,
    observation::{local_low, snapshot, SnapshotBudget},
    validation::{self, JournalStore, LocalLogoutAuthority, OwnershipGuard, ValidationController},
    win32_identity::{IdentitySource, UsageBudget},
    AllowedRoot, CurrentUserFolders, KnownFolder, RootResolver,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};
use ts_rs::TS;

#[derive(Debug, Deserialize, TS)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ValidationRequest {
    Status,
    Start {
        observation_id: String,
        accept_session_policy: bool,
    },
    Get {
        id: String,
    },
    BeginTrial {
        id: String,
    },
    Launch {
        id: String,
    },
    Outcome {
        id: String,
        outcome: AppOutcome,
    },
    AcceptLosses {
        id: String,
    },
    Abort {
        id: String,
    },
    Recover,
    Apply {
        rule_id: String,
        accept_bounded_losses: bool,
    },
}
#[derive(Debug, Serialize, TS)]
pub struct ValidationStatus {
    pub recovery_required: bool,
    pub pending_sessions: Vec<String>,
    pub diagnostics: Vec<String>,
    pub rules: Vec<LocalValidatedRule>,
    pub active: Option<ValidationView>,
}
#[derive(Debug, Serialize, TS)]
#[serde(tag = "kind", content = "data", rename_all = "kebab-case")]
pub enum ValidationReply {
    View(Box<ValidationView>),
    Status(Box<ValidationStatus>),
    Applied { rule_id: String, objects: usize },
}
struct Envelope {
    request: ValidationRequest,
    reply: mpsc::Sender<Result<ValidationReply, CommandError>>,
}
#[derive(Clone)]
pub struct ValidationBridge {
    sender: mpsc::Sender<Envelope>,
}
impl ValidationBridge {
    pub fn start(directory: PathBuf) -> Result<Self, CommandError> {
        let admission = Admission::for_directory(&directory)?;
        admission.recovery(true);
        let (sender, receiver) = mpsc::channel::<Envelope>();
        let (ready, initialized) = mpsc::channel();
        std::thread::Builder::new()
            .name("everyout-validation".into())
            .spawn(move || {
                let guard = CurrentOwnership {
                    directory: directory.clone(),
                };
                let mut worker = ValidationWorker {
                    directory: directory.clone(),
                    store: (|| {
                        std::fs::create_dir_all(&directory).map_err(|_| CommandError::ReportIo)?;
                        JournalStore::open(&directory.join("validation-v1")).map_err(command_error)
                    })(),
                    admission,
                    guard,
                    controller: None,
                    started: None,
                    diagnostics: vec![],
                };
                // This completes before the catalog worker is made available.
                if let Err(e) = worker.recover() {
                    worker
                        .diagnostics
                        .push(format!("recovery-{e:?}").to_lowercase());
                }
                let _ = ready.send(());
                loop {
                    worker.tick();
                    match receiver.recv_timeout(Duration::from_millis(100)) {
                        Ok(envelope) => {
                            let result = worker.handle(envelope.request);
                            worker.update_admission();
                            let _ = envelope.reply.send(result);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            if let (Some(controller), Ok(store)) =
                                (&mut worker.controller, &worker.store)
                            {
                                let _ = controller.abort(store, &worker.guard);
                            }
                            worker.update_admission();
                            break;
                        }
                    }
                }
            })
            .map_err(|_| CommandError::WorkerUnavailable)?;
        initialized
            .recv()
            .map_err(|_| CommandError::WorkerUnavailable)?;
        Ok(Self { sender })
    }
    pub fn call(&self, request: ValidationRequest) -> Result<ValidationReply, CommandError> {
        let (reply, result) = mpsc::channel();
        self.sender
            .send(Envelope { request, reply })
            .map_err(|_| CommandError::WorkerUnavailable)?;
        result.recv().map_err(|_| CommandError::WorkerUnavailable)?
    }
}
fn bases() -> Vec<AllowedRoot> {
    let mut roots: Vec<_> = [KnownFolder::LocalAppData, KnownFolder::RoamingAppData]
        .into_iter()
        .filter_map(|f| CurrentUserFolders.resolve(f).ok())
        .collect();
    if let Some(root) = local_low() {
        roots.push(root);
    }
    roots
}
fn command_error(error: platform::PlatformError) -> CommandError {
    match error.kind {
        ErrorKind::StalePlan => CommandError::StalePlan,
        ErrorKind::Locked => CommandError::Busy,
        ErrorKind::Io => CommandError::ReportIo,
        _ => CommandError::InvalidSelection,
    }
}
struct CurrentOwnership {
    directory: PathBuf,
}
impl OwnershipGuard for CurrentOwnership {
    fn check(
        &self,
        expected: &ApplicationBinding,
        roots: &[RootObservation],
    ) -> platform::Result<()> {
        let conflict = || platform::PlatformError {
            kind: ErrorKind::OwnershipConflict,
            os_code: None,
            applied: 0,
        };
        let history = crate::teach::history(&self.directory, false).map_err(|_| conflict())?;
        for other in history {
            if other.binding.executable == expected.executable
                || other
                    .binding
                    .executable_path
                    .eq_ignore_ascii_case(&expected.executable_path)
            {
                continue;
            }
            for root in roots {
                for claim in &other.roots {
                    let a = root.root.replace('\\', "/").to_lowercase();
                    let b = claim.root.replace('\\', "/").to_lowercase();
                    if claim.ownership.state != StorageOwnership::Unknown
                        && (root.physical == claim.physical
                            || a.starts_with(&format!("{b}/"))
                            || b.starts_with(&format!("{a}/")))
                    {
                        return Err(conflict());
                    }
                }
            }
        }
        let mut inventory = platform::inventory::InstalledInventory::collect_current_user();
        let identities = std::rc::Rc::make_mut(&mut inventory.win32);
        identities.observe_executable(
            Path::new(
                expected
                    .executable_path
                    .strip_prefix("\\\\?\\")
                    .unwrap_or(&expected.executable_path),
            ),
            IdentitySource::Selected,
            None,
        )?;
        let mut budget = UsageBudget::default();
        for observed in roots {
            let root = crate::teach::local_root(&observed.root).ok_or_else(conflict)?;
            let actual = snapshot(&root, SnapshotBudget::default())?;
            if actual.root_identity != observed.physical {
                return Err(conflict());
            }
            for family in observed
                .families
                .iter()
                .filter(|f| approved_family(f))
                .take(MAX_FAMILIES)
            {
                // A representative path comes from a complete metadata snapshot,
                // not a framework/product filename allowlist or caller input.
                // It is a runtime ownership probe, never a cleanup unit.
                let probe = actual
                    .entries
                    .iter()
                    .find(|(path, metadata)| {
                        !metadata.directory && artifact_family(path) == family.family
                    })
                    .map(|(path, _)| path.as_str())
                    .unwrap_or(&family.family);
                let usage = budget.corroborate(&root.path(probe)?, &inventory.win32);
                if usage.shared {
                    return Err(conflict());
                }
                if usage.processes.iter().any(|id| {
                    inventory.win32.applications.iter().any(|a| {
                        a.processes.contains(id)
                            && !a
                                .executable
                                .canonical_path
                                .to_string_lossy()
                                .eq_ignore_ascii_case(&expected.executable_path)
                    })
                }) {
                    return Err(conflict());
                }
            }
        }
        Ok(())
    }
}

struct ValidationWorker {
    directory: PathBuf,
    store: Result<JournalStore, CommandError>,
    admission: Admission,
    guard: CurrentOwnership,
    controller: Option<ValidationController>,
    started: Option<Instant>,
    diagnostics: Vec<String>,
}
impl ValidationWorker {
    fn update_admission(&self) {
        let pending = self
            .store
            .as_ref()
            .map(|s| s.pending().unwrap_or(true))
            .unwrap_or(true);
        self.admission.recovery(pending);
        let active = self.controller.as_ref().is_some_and(|c| {
            matches!(
                c.view().stage,
                ValidationStage::ReadyControl
                    | ValidationStage::Control
                    | ValidationStage::Intervention
                    | ValidationStage::Reversal
                    | ValidationStage::AwaitingAcceptance
                    | ValidationStage::RecoveryBlocked
            )
        });
        if !active {
            self.admission.end_validation();
        }
    }
    fn recover(&mut self) -> Result<(), CommandError> {
        self.admission.recovery(true);
        let store = self.store.as_ref().map_err(Clone::clone)?;
        validation::recover_pending(store, &bases(), &self.guard).map_err(command_error)?;
        self.admission.recovery(false);
        self.diagnostics.clear();
        Ok(())
    }
    fn tick(&mut self) {
        if let (Some(controller), Ok(store)) = (&mut self.controller, &self.store) {
            let timed_out = self
                .started
                .is_some_and(|t| t.elapsed() > Duration::from_secs(30 * 60))
                && matches!(
                    controller.view().stage,
                    ValidationStage::ReadyControl
                        | ValidationStage::Control
                        | ValidationStage::Intervention
                        | ValidationStage::Reversal
                        | ValidationStage::AwaitingAcceptance
                );
            let result = if timed_out {
                controller.abort(store, &self.guard)
            } else {
                controller.tick(store)
            };
            if let Err(error) = result {
                let code = format!("validation-{:?}", error.kind).to_lowercase();
                if !self.diagnostics.contains(&code) {
                    self.diagnostics.push(code);
                }
                self.admission.recovery(true);
            }
            if timed_out {
                self.update_admission();
            }
        }
    }
    fn status(&self) -> Result<ValidationReply, CommandError> {
        let mut status = ValidationStatus {
            recovery_required: true,
            pending_sessions: vec![],
            diagnostics: self.diagnostics.clone(),
            rules: vec![],
            active: self.controller.as_ref().map(|c| c.view()),
        };
        if let Ok(store) = &self.store {
            match store.journals() {
                Ok(journals) => {
                    status.pending_sessions = journals
                        .into_iter()
                        .filter(|j| j.stage != JournalStage::Completed)
                        .map(|j| j.session_id)
                        .collect();
                    status.recovery_required = !status.pending_sessions.is_empty();
                }
                Err(_) => status.diagnostics.push("journal-read-blocked".into()),
            }
            status.rules = store.rules().map_err(command_error)?;
            for rule in &mut status.rules {
                if let Err(error) =
                    LocalLogoutAuthority::bind(rule.clone(), &bases(), store, &self.guard)
                {
                    if matches!(
                        error.kind,
                        ErrorKind::StalePlan
                            | ErrorKind::ScopeViolation
                            | ErrorKind::OwnershipConflict
                    ) {
                        store.mark_stale(&rule.id).map_err(command_error)?;
                        rule.stale = true;
                    }
                }
            }
        } else {
            status
                .diagnostics
                .push("validation-store-unavailable".into());
        }
        Ok(ValidationReply::Status(Box::new(status)))
    }
    fn handle(&mut self, request: ValidationRequest) -> Result<ValidationReply, CommandError> {
        if matches!(request, ValidationRequest::Status) {
            return self.status();
        }
        if matches!(request, ValidationRequest::Recover) {
            if self.controller.as_ref().is_some_and(|c| {
                matches!(
                    c.view().stage,
                    ValidationStage::Control
                        | ValidationStage::Intervention
                        | ValidationStage::Reversal
                )
            }) {
                return Err(CommandError::Busy);
            }
            self.admission.end_validation();
            self.admission.begin_validation(true)?;
            let result = self.recover();
            self.admission.end_validation();
            result?;
            self.controller = None;
            return self.status();
        }
        let store = self.store.as_ref().map_err(Clone::clone)?;
        if let ValidationRequest::Start {
            observation_id,
            accept_session_policy,
        } = request
        {
            if !accept_session_policy {
                return Err(CommandError::InvalidSelection);
            }
            self.admission.begin_validation(false)?;
            let result = (|| {
                let learned = crate::teach::history(&self.directory, true)?
                    .into_iter()
                    .find(|r| r.session_id == observation_id)
                    .ok_or(CommandError::StalePlan)?;
                ValidationController::start(learned, &bases(), store, &self.guard)
                    .map_err(command_error)
            })();
            match result {
                Ok(controller) => {
                    self.controller = Some(controller);
                    self.started = Some(Instant::now());
                }
                Err(error) => {
                    self.admission.end_validation();
                    self.diagnostics.push(
                        "validation-entry-blocked-identity-observation-layout-or-needs-adapter"
                            .into(),
                    );
                    return Err(error);
                }
            }
            return Ok(ValidationReply::View(Box::new(
                self.controller.as_ref().expect("started").view(),
            )));
        }
        if let ValidationRequest::Apply {
            rule_id,
            accept_bounded_losses,
        } = request
        {
            if !accept_bounded_losses {
                return Err(CommandError::InvalidSelection);
            }
            self.admission.begin_validation(false)?;
            let result = (|| {
                let rule = store
                    .rules()
                    .map_err(command_error)?
                    .into_iter()
                    .find(|r| r.id == rule_id)
                    .ok_or(CommandError::StalePlan)?;
                let applied = LocalLogoutAuthority::bind(rule, &bases(), store, &self.guard)
                    .and_then(|authority| {
                        authority.apply(accept_bounded_losses, store, &self.guard)
                    });
                if let Err(error) = &applied {
                    if matches!(
                        error.kind,
                        ErrorKind::StalePlan
                            | ErrorKind::ScopeViolation
                            | ErrorKind::OwnershipConflict
                    ) {
                        store.mark_stale(&rule_id).map_err(command_error)?;
                    }
                }
                applied.map_err(command_error)
            })();
            self.admission.end_validation();
            return result.map(|objects| ValidationReply::Applied { rule_id, objects });
        }
        let id = match &request {
            ValidationRequest::Get { id }
            | ValidationRequest::BeginTrial { id }
            | ValidationRequest::Launch { id }
            | ValidationRequest::Outcome { id, .. }
            | ValidationRequest::AcceptLosses { id }
            | ValidationRequest::Abort { id } => id,
            _ => unreachable!(),
        };
        let controller = self
            .controller
            .as_mut()
            .filter(|c| c.view().id == *id)
            .ok_or(CommandError::StalePlan)?;
        let result = match request {
            ValidationRequest::Get { .. } => Ok(()),
            ValidationRequest::BeginTrial { .. } => controller.begin_trial(&self.guard),
            ValidationRequest::Launch { .. } => controller.launch(store, &self.guard),
            ValidationRequest::Outcome { outcome, .. } => {
                controller.confirm(outcome, store, &self.guard)
            }
            ValidationRequest::AcceptLosses { .. } => {
                controller.accept_losses(store, &self.guard).map(|_| ())
            }
            ValidationRequest::Abort { .. } => controller.abort(store, &self.guard),
            _ => unreachable!(),
        };
        if let Err(error) = result {
            self.diagnostics
                .push(format!("validation-{:?}", error.kind).to_lowercase());
            // Return the recovery stage as a concrete UI state after an error.
            if matches!(
                controller.view().stage,
                ValidationStage::RecoveryBlocked | ValidationStage::Failed | ValidationStage::Stale
            ) {
                return Ok(ValidationReply::View(Box::new(controller.view())));
            }
            return Err(command_error(error));
        }
        Ok(ValidationReply::View(Box::new(controller.view())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipc_cannot_supply_paths_scopes_or_evidence_promotions() {
        for value in [
            serde_json::json!({"operation":"start","observation_id":"saved","accept_session_policy":true,"path":"C:/arbitrary"}),
            serde_json::json!({"operation":"outcome","id":"saved","outcome":"exclusive"}),
            serde_json::json!({"operation":"apply","rule_id":"saved","accept_bounded_losses":true,"scope":["C:/arbitrary"]}),
        ] {
            assert!(serde_json::from_value::<ValidationRequest>(value).is_err());
        }
    }
    #[test]
    fn startup_corrupt_journal_blocks_all_new_destructive_admission() {
        let fixture = everyout_test_support::FixtureTree::empty().unwrap();
        std::fs::create_dir(fixture.path().join("validation-v1")).unwrap();
        std::fs::write(
            fixture
                .path()
                .join("validation-v1/00000000000000000000000000000000.journal"),
            b"invalid journal metadata",
        )
        .unwrap();
        let bridge = ValidationBridge::start(fixture.path().into()).unwrap();
        let admission = Admission::for_directory(fixture.path()).unwrap();
        assert!(admission.begin_wipe().is_err());
        match bridge.call(ValidationRequest::Status).unwrap() {
            ValidationReply::Status(status) => assert!(status.recovery_required),
            _ => panic!("expected recovery state"),
        }
        assert!(bridge
            .call(ValidationRequest::Start {
                observation_id: "saved".into(),
                accept_session_policy: true
            })
            .is_err());
        assert!(bridge
            .call(ValidationRequest::Apply {
                rule_id: "saved".into(),
                accept_bounded_losses: true
            })
            .is_err());
        assert!(bridge.call(ValidationRequest::Recover).is_err());
        assert!(admission.begin_wipe().is_err());
    }
}
