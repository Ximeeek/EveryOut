//! Offline, current-account orchestration. All I/O uses narrow trusted capabilities.
#![forbid(unsafe_code)]

use everyout_core_model::*;
use serde::Serialize;
use std::{
    cell::{Cell, RefCell},
    collections::HashSet,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_RUN: AtomicU64 = AtomicU64::new(1);

/// Trusted Rust providers, never UI input. Hooks may only perform reviewed local operations.
/// Closing must validate the exact planned process set; revalidation must detect relaunch.
pub trait EngineProvider: Provider {
    /// Metadata-only identities for the exact retained close set, including potential work loss.
    /// An empty vector explicitly declares that no processes depend on these actions.
    fn process_preview(&self, plan: &ProposedPlan) -> Result<Vec<ProcessPreview>, ErrorKind>;
    fn close(&self, plan: &ValidatedPlan, policy: ProcessClosePolicy) -> Result<(), ErrorKind>;
    fn revalidate(&self, plan: &ValidatedPlan) -> Result<(), ErrorKind>;
    /// None means not applicable; Unknown/Unsupported preserve incomplete coverage.
    fn identity_sync(&self, _plan: &ValidatedPlan) -> Result<Option<IdentitySync>, ErrorKind> {
        Ok(None)
    }
    /// A reviewed logical path (root/profile-relative), never account or credential content.
    fn target_label(&self, action: &PlannedAction) -> String;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessPreview {
    pub identity: String,
    pub label: String,
    pub unsaved_work_loss: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct IdentitySync {
    pub identity: Uncertainty,
    pub sync: Uncertainty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Stage {
    Scan,
    Selection,
    DryRun,
    Review,
    Closing,
    Cleaning,
    IdentitySync,
    Verification,
    Report,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub stage: Stage,
    pub category: Category,
    pub instance: Option<InstanceId>,
    pub action: Option<ActionId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionReport {
    pub path: String,
    pub outcome: ActionOutcome,
    pub verification: ArtifactVerification,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ItemReport {
    pub instance: InstanceId,
    pub plan: Option<ProposedPlan>,
    pub aggregate: AggregateStatus,
    pub actions: Vec<ActionReport>,
    pub processes: Vec<ProcessPreview>,
    pub issues: Vec<ProviderIssue>,
    pub identity_sync: IdentitySync,
    pub authentication: Uncertainty,
    pub remote_revocation: Uncertainty,
    pub silent_sso: Uncertainty,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CategoryReport {
    pub category: Category,
    pub aggregate: AggregateStatus,
    pub items: Vec<ItemReport>,
    pub counts: Counts,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Counts {
    pub succeeded: usize,
    pub failed: usize,
    pub skipped: usize,
    pub locked: usize,
    pub would_apply: usize,
    pub already_absent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunReport {
    pub mode: ExecutionMode,
    pub process_close_policy: ProcessClosePolicy,
    pub sections: Vec<CategoryReport>,
}
impl RunReport {
    pub fn json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
    pub fn text(&self) -> String {
        use std::fmt::Write;
        let mut text = String::new();
        let _ = writeln!(
            text,
            "EveryOut {:?}; process policy: {:?}",
            self.mode, self.process_close_policy
        );
        for section in &self.sections {
            let _ = writeln!(text, "{:?}: {:?}", section.category, section.aggregate);
            let _ = writeln!(text, "  succeeded={}, failed={}, skipped={}, locked={}, would-apply={}, already-absent={}", section.counts.succeeded, section.counts.failed, section.counts.skipped, section.counts.locked, section.counts.would_apply, section.counts.already_absent);
            for item in &section.items {
                let _ = writeln!(text, "  {}: {:?}; identity={:?}; sync={:?}; authentication=unknown; remote-revocation=unsupported", item.instance.0, item.aggregate, item.identity_sync.identity, item.identity_sync.sync);
                if let Some(plan) = &item.plan {
                    let _ = writeln!(
                        text,
                        "    selected profiles: {:?}; risk flags: {:?}",
                        plan.selection.profiles, plan.risks.flags
                    );
                    for limitation in &plan.limitations {
                        let _ = writeln!(text, "    limitation: {limitation}");
                    }
                    for blocker in &plan.blockers {
                        let _ = writeln!(text, "    blocker: {blocker}");
                    }
                }
                for process in &item.processes {
                    let _ = writeln!(
                        text,
                        "    process {}: {}; unsaved-work-loss={}",
                        process.identity, process.label, process.unsaved_work_loss
                    );
                }
                for action in &item.actions {
                    let _ = writeln!(
                        text,
                        "    {}: {:?}, {:?}",
                        action.path, action.outcome.status, action.verification.status
                    );
                    for issue in action
                        .outcome
                        .issues
                        .iter()
                        .chain(&action.verification.issues)
                    {
                        let _ =
                            writeln!(text, "      {:?}: {}", issue.kind, issue.explanation_code);
                    }
                }
                for issue in &item.issues {
                    let _ = writeln!(text, "    {:?}: {}", issue.kind, issue.explanation_code);
                }
            }
        }
        text
    }
}

struct Entry<'a> {
    provider: &'a dyn EngineProvider,
    inventory: DetectionResult,
    instance: ProviderInstance,
    description: ProviderDescription,
}
pub struct Inventory<'a> {
    entries: Vec<Entry<'a>>,
    current_user: UserId,
}
impl Inventory<'_> {
    /// Low-confidence application candidates require explicit selection.
    /// All heuristic results stay unchecked until S8 passes; selection is not approval.
    pub fn default_selection(&self, category: Category) -> Vec<InstanceId> {
        self.entries
            .iter()
            .filter(|entry| {
                entry.description.descriptor.category == category
                    && entry.instance.detection_origin.default_selected(true)
                    && !(category == Category::Application
                        && entry.description.descriptor.support == Support::Candidate
                        && entry.instance.confidence == Confidence::Low)
            })
            .map(|entry| entry.instance.instance_id.clone())
            .collect()
    }
}

struct PreparedItem<'a> {
    entry: Entry<'a>,
    plan: Option<ProposedPlan>,
    blocked: Vec<ProviderIssue>,
    observations: Vec<Result<MetadataObservation, ErrorKind>>,
    processes: Vec<ProcessPreview>,
    paths: Vec<String>,
}
/// Immutable engine-held preview. Cannot be deserialized or expanded by a caller.
pub struct PreparedRun<'a> {
    id: u64,
    engine_id: u64,
    category: Category,
    current_user: UserId,
    policy: ProcessClosePolicy,
    items: Vec<PreparedItem<'a>>,
    preview: RunReport,
}
#[derive(Debug, Clone)]
pub struct CategoryConfirmation {
    run: u64,
}
#[derive(Debug, Clone)]
pub struct RiskConfirmation {
    run: u64,
    instance: InstanceId,
    flags: Vec<RiskFlag>,
}
#[derive(Default)]
pub struct Approval {
    pub confirmed_risks: Vec<RiskConfirmation>,
    pub category_confirmation: Option<CategoryConfirmation>,
    pub confirmations: Vec<ConfirmationId>,
    pub force_close_acknowledged: bool,
}
impl PreparedRun<'_> {
    pub fn preview(&self) -> &RunReport {
        &self.preview
    }
    /// Calling this explicitly acknowledges the separate Windows/developer category.
    pub fn confirm_category(&self) -> CategoryConfirmation {
        CategoryConfirmation { run: self.id }
    }
    /// Acknowledgment is scoped to this instance, flags and immutable preview.
    pub fn confirm_risks(&self, instance: &InstanceId, flags: &[RiskFlag]) -> RiskConfirmation {
        RiskConfirmation {
            run: self.id,
            instance: instance.clone(),
            flags: flags.to_vec(),
        }
    }
}

pub struct Engine<'a> {
    id: u64,
    current_user: UserId,
    operations: &'a dyn LocalOperations,
}
impl<'a> Engine<'a> {
    /// The identity and operations are supplied by the trusted current-user platform layer.
    /// There is deliberately no all-account mode or caller-supplied filesystem root.
    pub fn new(current_user: UserId, operations: &'a dyn LocalOperations) -> Self {
        Self {
            id: NEXT_RUN.fetch_add(1, Ordering::Relaxed),
            current_user,
            operations,
        }
    }
    pub fn scan(
        &self,
        providers: &[&'a dyn EngineProvider],
        category: Category,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<Inventory<'a>, ErrorKind> {
        emit(progress, Stage::Scan, category, None, None);
        let snapshot = SnapshotId(format!(
            "inventory-{}",
            NEXT_RUN.fetch_add(1, Ordering::Relaxed)
        ));
        let mut entries = Vec::new();
        let mut ids = HashSet::new();
        for provider in providers {
            let inventory = provider.detect(&DetectionContext {
                snapshot_id: snapshot.clone(),
                account_mode: AccountMode::Current,
                metadata: self.operations,
            });
            if inventory.snapshot_id != snapshot {
                return Err(ErrorKind::StalePlan);
            }
            for instance in &inventory.instances {
                if instance.owner.user_id != self.current_user {
                    return Err(ErrorKind::ScopeViolation);
                }
                if instance.owner.installation_id.0.trim().is_empty()
                    || instance.owner.root_id.0.trim().is_empty()
                    || instance
                        .issues
                        .iter()
                        .any(|issue| issue.kind == ErrorKind::OwnershipConflict)
                {
                    // Unresolved candidates belong in discovery, never an executable inventory.
                    return Err(ErrorKind::OwnershipConflict);
                }
                let description = provider.describe(instance);
                if description.instance_id != instance.instance_id
                    || description.descriptor.provider_id != instance.provider_id
                    || description.profiles != instance.profiles
                {
                    return Err(ErrorKind::ScopeViolation);
                }
                if description.descriptor.category != category {
                    continue;
                }
                if !ids.insert(instance.instance_id.clone()) {
                    return Err(ErrorKind::OwnershipConflict);
                }
                entries.push(Entry {
                    provider: *provider,
                    inventory: inventory.clone(),
                    instance: instance.clone(),
                    description,
                });
            }
        }
        Ok(Inventory {
            entries,
            current_user: self.current_user.clone(),
        })
    }
    pub fn prepare(
        &self,
        inventory: Inventory<'a>,
        category: Category,
        selection: &[InstanceId],
        policy: ProcessClosePolicy,
        progress: &mut dyn FnMut(Progress),
    ) -> Result<PreparedRun<'a>, ErrorKind> {
        if inventory.current_user != self.current_user {
            return Err(ErrorKind::ScopeViolation);
        }
        let selected: HashSet<_> = selection.iter().collect();
        if selected.len() != selection.len()
            || selection.iter().any(|id| {
                !inventory.entries.iter().any(|entry| {
                    &entry.instance.instance_id == id
                        && entry.description.descriptor.category == category
                })
            })
        {
            return Err(ErrorKind::ScopeViolation);
        }
        emit(progress, Stage::Selection, category, None, None);
        emit(progress, Stage::DryRun, category, None, None);
        let mut items = Vec::new();
        let mut reports = Vec::new();
        let mut targets = HashSet::new();
        let mut path_claims = HashSet::new();
        for entry in inventory
            .entries
            .into_iter()
            .filter(|entry| selected.contains(&entry.instance.instance_id))
        {
            let selection = Selection {
                snapshot_id: entry.inventory.snapshot_id.clone(),
                account_mode: AccountMode::Current,
                instances: vec![entry.instance.instance_id.clone()],
                profiles: entry
                    .instance
                    .profiles
                    .iter()
                    .map(|p| p.profile_id.clone())
                    .collect(),
            };
            let mut blocked = entry.instance.issues.clone();
            blocked.extend(entry.inventory.issues.clone());
            let plan = match entry.provider.plan(
                &PlanContext {
                    inventory: &entry.inventory,
                },
                &selection,
            ) {
                PlanResult::Ready(plan) => {
                    if plan.selection != selection
                        || plan.provider_id != entry.instance.provider_id
                        || plan.manifest_revision != entry.description.descriptor.revision
                        || plan.support != entry.description.descriptor.support
                        || plan.risks != entry.description.risks
                    {
                        return Err(ErrorKind::StalePlan);
                    }
                    let mut actions = HashSet::new();
                    for action in &plan.actions {
                        if action.owner != entry.instance.owner
                            || action.root_id != action.owner.root_id
                            || action
                                .profile_id
                                .as_ref()
                                .is_some_and(|id| !selection.profiles.contains(id))
                            || action.shared_owners.iter().any(|id| !selected.contains(id))
                            || !actions.insert(action.action_id.clone())
                        {
                            return Err(ErrorKind::ScopeViolation);
                        }
                        // Logical aliases must be resolved by providers before planning. Conflicting
                        // claims are refused rather than authorizing a second physical deletion.
                        if !targets.insert((
                            action.owner.user_id.clone(),
                            action.root_id.clone(),
                            action.artifact_id.clone(),
                        )) {
                            return Err(ErrorKind::OwnershipConflict);
                        }
                        if !path_claims.insert((
                            action.owner.user_id.clone(),
                            action.root_id.clone(),
                            entry.provider.target_label(action),
                        )) {
                            return Err(ErrorKind::OwnershipConflict);
                        }
                    }
                    Some(*plan)
                }
                PlanResult::Blocked { issues } => {
                    blocked.extend(issues);
                    None
                }
            };
            let observations = plan
                .as_ref()
                .map(|p| {
                    p.actions
                        .iter()
                        .map(|a| self.operations.observe(&a.owner, &a.artifact_id))
                        .collect()
                })
                .unwrap_or_default();
            let paths = plan
                .as_ref()
                .map(|plan| {
                    plan.actions
                        .iter()
                        .map(|a| entry.provider.target_label(a))
                        .collect()
                })
                .unwrap_or_default();
            let mut item = PreparedItem {
                entry,
                plan,
                blocked,
                observations,
                processes: vec![],
                paths,
            };
            if let Some(plan) = &item.plan {
                match item.entry.provider.process_preview(plan) {
                    Ok(processes) => item.processes = processes,
                    Err(kind) => {
                        item.blocked
                            .push(issue(&item, None, kind, "process-preview-unavailable"))
                    }
                }
            }
            // Provider preview receives a capability that cannot mutate even when
            // the provider accidentally ignores ExecutionMode::DryRun.
            if let Some(plan) = &item.plan {
                let confirmations = all_confirmations(plan);
                if let Ok(valid) = review_plan(plan, &confirmations) {
                    let preview = PreviewOperations {
                        inner: self.operations,
                        plan: &valid,
                        mutation_attempted: Cell::new(false),
                    };
                    let execution = item.entry.provider.execute(
                        &OperationContext {
                            operations: &preview,
                            cancelled: &|| false,
                        },
                        &valid,
                        ExecutionMode::DryRun,
                    );
                    if preview.mutation_attempted.get()
                        || execution.mode != ExecutionMode::DryRun
                        || execution.plan_id != plan.plan_id
                    {
                        item.blocked.push(issue(
                            &item,
                            None,
                            ErrorKind::ScopeViolation,
                            "dry-run-contract-mismatch",
                        ));
                    }
                }
            }
            reports.push(preview_item(&item));
            items.push(item);
        }
        emit(progress, Stage::Review, category, None, None);
        Ok(PreparedRun {
            id: NEXT_RUN.fetch_add(1, Ordering::Relaxed),
            engine_id: self.id,
            category,
            current_user: self.current_user.clone(),
            policy,
            items,
            preview: assemble(ExecutionMode::DryRun, category, policy, reports),
        })
    }
    pub fn apply(
        &self,
        run: PreparedRun<'a>,
        approval: Approval,
        cancelled: &dyn Fn() -> bool,
        progress: &mut dyn FnMut(Progress),
    ) -> RunReport {
        let mut reports = Vec::new();
        for item in &run.items {
            let mut report = preview_item(item);
            report.aggregate = AggregateStatus::Blocked;
            let Some(plan) = &item.plan else {
                reports.push(report);
                continue;
            };
            let gate = (|| {
                if self.current_user != run.current_user || self.id != run.engine_id {
                    return Err(ErrorKind::ScopeViolation);
                }
                if run.category == Category::WindowsMicrosoftAndDevTools
                    && approval
                        .category_confirmation
                        .as_ref()
                        .is_none_or(|token| token.run != run.id)
                {
                    return Err(ErrorKind::ScopeViolation);
                }
                if run.policy == ProcessClosePolicy::HardKillAfter2s
                    && !approval.force_close_acknowledged
                {
                    return Err(ErrorKind::ScopeViolation);
                }
                if !plan.risks.flags.iter().all(|flag| {
                    approval.confirmed_risks.iter().any(|token| {
                        token.run == run.id
                            && token.instance == item.entry.instance.instance_id
                            && token.flags.contains(flag)
                    })
                }) {
                    return Err(ErrorKind::ScopeViolation);
                }
                if item.blocked.iter().any(|issue| issue.blocked) {
                    return Err(ErrorKind::Unsupported);
                }
                let valid = review_plan(plan, &approval.confirmations)?;
                // Re-plan from the retained snapshot to bind manifest, owner and effects.
                match item.entry.provider.plan(
                    &PlanContext {
                        inventory: &item.entry.inventory,
                    },
                    &plan.selection,
                ) {
                    PlanResult::Ready(fresh) if *fresh == *plan => {}
                    _ => return Err(ErrorKind::StalePlan),
                }
                if item.entry.provider.describe(&item.entry.instance) != item.entry.description {
                    return Err(ErrorKind::StalePlan);
                }
                if item.entry.provider.process_preview(plan)? != item.processes {
                    return Err(ErrorKind::StalePlan);
                }
                if plan
                    .actions
                    .iter()
                    .map(|a| item.entry.provider.target_label(a))
                    .collect::<Vec<_>>()
                    != item.paths
                {
                    return Err(ErrorKind::StalePlan);
                }
                for (action, before) in plan.actions.iter().zip(&item.observations) {
                    if let Err(kind) = before {
                        return Err(*kind);
                    }
                    if &self.operations.observe(&action.owner, &action.artifact_id) != before {
                        return Err(ErrorKind::StalePlan);
                    }
                }
                Ok(valid)
            })();
            let valid = match gate {
                Ok(valid) => Some(valid),
                Err(kind) => {
                    block_report(&mut report, item, kind, "review-refused");
                    None
                }
            };
            let mut cancelled_run = cancelled();
            if let Some(valid) = valid {
                emit(
                    progress,
                    Stage::Closing,
                    run.category,
                    Some(&report.instance),
                    None,
                );
                let closed = if cancelled_run {
                    Err(ErrorKind::Cancelled)
                } else {
                    item.entry.provider.close(&valid, run.policy)
                };
                match closed {
                    Err(kind) => {
                        block_report(&mut report, item, kind, "process-prerequisite-failed")
                    }
                    Ok(()) => {
                        emit(
                            progress,
                            Stage::Cleaning,
                            run.category,
                            Some(&report.instance),
                            None,
                        );
                        let guarded = GuardedOperations {
                            inner: self.operations,
                            provider: item.entry.provider,
                            plan: &valid,
                            cancelled,
                            outcomes: RefCell::new(Vec::new()),
                            category: run.category,
                            progress: RefCell::new(&mut *progress),
                        };
                        let execution = item.entry.provider.execute(
                            &OperationContext {
                                operations: &guarded,
                                cancelled,
                            },
                            &valid,
                            ExecutionMode::Apply,
                        );
                        let outcomes = guarded.outcomes.into_inner();
                        for action in &mut report.actions {
                            action.outcome = outcomes
                                .iter()
                                .find(|o| o.action_id == action.outcome.action_id)
                                .cloned()
                                .unwrap_or_else(|| {
                                    let kind = if cancelled() {
                                        ErrorKind::Cancelled
                                    } else {
                                        ErrorKind::Unsupported
                                    };
                                    failed(
                                        item,
                                        &action.outcome.action_id,
                                        kind,
                                        "action-not-executed",
                                        ActionStatus::Skipped,
                                    )
                                });
                        }
                        // Provider return values never overwrite observed mutation outcomes.
                        if execution.plan_id != plan.plan_id
                            || execution.mode != ExecutionMode::Apply
                        {
                            report.issues.push(issue(
                                item,
                                None,
                                ErrorKind::StalePlan,
                                "execution-contract-mismatch",
                            ));
                        }
                        cancelled_run |= cancelled();
                        emit(
                            progress,
                            Stage::IdentitySync,
                            run.category,
                            Some(&report.instance),
                            None,
                        );
                        if !cancelled_run {
                            match item
                                .entry
                                .provider
                                .revalidate(&valid)
                                .and_then(|()| item.entry.provider.identity_sync(&valid))
                            {
                                Ok(Some(state)) => report.identity_sync = state,
                                Ok(None) => {}
                                Err(kind) => report.issues.push(issue(
                                    item,
                                    None,
                                    kind,
                                    "identity-sync-incomplete",
                                )),
                            }
                        }
                    }
                }
                emit(
                    progress,
                    Stage::Verification,
                    run.category,
                    Some(&report.instance),
                    None,
                );
                let quiescent = item.entry.provider.revalidate(&valid);
                for (action, target) in report.actions.iter_mut().zip(&plan.actions) {
                    action.verification =
                        verification(item, target, self.operations, quiescent.err());
                }
            } else {
                emit(
                    progress,
                    Stage::Verification,
                    run.category,
                    Some(&report.instance),
                    None,
                );
                for (action, target) in report.actions.iter_mut().zip(&plan.actions) {
                    action.verification = verification(item, target, self.operations, None);
                }
            }
            cancelled_run |= cancelled();
            report.aggregate = aggregate_item(&report, cancelled_run);
            reports.push(report);
        }
        emit(progress, Stage::Report, run.category, None, None);
        assemble(ExecutionMode::Apply, run.category, run.policy, reports)
    }
}

struct GuardedOperations<'a, 'b> {
    inner: &'a dyn LocalOperations,
    provider: &'a dyn EngineProvider,
    plan: &'a ValidatedPlan,
    cancelled: &'a dyn Fn() -> bool,
    outcomes: RefCell<Vec<ActionOutcome>>,
    category: Category,
    progress: RefCell<&'b mut dyn FnMut(Progress)>,
}
struct PreviewOperations<'a> {
    inner: &'a dyn LocalOperations,
    plan: &'a ValidatedPlan,
    mutation_attempted: Cell<bool>,
}
impl MetadataAccess for PreviewOperations<'_> {
    fn observe(
        &self,
        owner: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind> {
        if !self
            .plan
            .plan()
            .actions
            .iter()
            .any(|a| &a.owner == owner && &a.artifact_id == artifact)
        {
            return Err(ErrorKind::ScopeViolation);
        }
        self.inner.observe(owner, artifact)
    }
}
impl LocalOperations for PreviewOperations<'_> {
    fn apply(&self, _plan: &ValidatedPlan, id: &ActionId) -> ActionOutcome {
        self.mutation_attempted.set(true);
        ActionOutcome {
            action_id: id.clone(),
            status: ActionStatus::Blocked,
            issues: vec![],
        }
    }
}
impl MetadataAccess for GuardedOperations<'_, '_> {
    fn observe(
        &self,
        owner: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind> {
        if !self
            .plan
            .plan()
            .actions
            .iter()
            .any(|a| &a.owner == owner && &a.artifact_id == artifact)
        {
            return Err(ErrorKind::ScopeViolation);
        }
        self.inner.observe(owner, artifact)
    }
}
impl LocalOperations for GuardedOperations<'_, '_> {
    fn apply(&self, plan: &ValidatedPlan, id: &ActionId) -> ActionOutcome {
        let fail = |kind| ActionOutcome {
            action_id: id.clone(),
            status: ActionStatus::Blocked,
            issues: vec![ProviderIssue {
                phase: Phase::Execute,
                provider_id: self.plan.plan().provider_id.clone(),
                instance_id: self.plan.plan().selection.instances.first().cloned(),
                action_id: Some(id.clone()),
                kind,
                os_code: None,
                explanation_code: "operation-gate-refused".into(),
                blocked: true,
            }],
        };
        if plan != self.plan
            || !plan.plan().actions.iter().any(|a| &a.action_id == id)
            || self.outcomes.borrow().iter().any(|o| &o.action_id == id)
        {
            return fail(ErrorKind::ScopeViolation);
        }
        let outcome = if (self.cancelled)() {
            fail(ErrorKind::Cancelled)
        } else if let Err(kind) = self.provider.revalidate(plan) {
            fail(kind)
        } else {
            let mut outcome = self.inner.apply(plan, id);
            outcome.action_id = id.clone();
            // Only stable vocabulary is exposed; discard arbitrary adapter explanations.
            for issue in &mut outcome.issues {
                issue.explanation_code = "local-operation-failed".into();
            }
            outcome
        };
        self.outcomes.borrow_mut().push(outcome.clone());
        emit(
            &mut **self.progress.borrow_mut(),
            Stage::Cleaning,
            self.category,
            plan.plan().selection.instances.first(),
            Some(id),
        );
        outcome
    }
}

fn emit(
    sink: &mut dyn FnMut(Progress),
    stage: Stage,
    category: Category,
    instance: Option<&InstanceId>,
    action: Option<&ActionId>,
) {
    sink(Progress {
        stage,
        category,
        instance: instance.cloned(),
        action: action.cloned(),
    });
}
fn issue(
    item: &PreparedItem<'_>,
    action: Option<&ActionId>,
    kind: ErrorKind,
    code: &str,
) -> ProviderIssue {
    ProviderIssue {
        phase: Phase::Execute,
        provider_id: item.entry.instance.provider_id.clone(),
        instance_id: Some(item.entry.instance.instance_id.clone()),
        action_id: action.cloned(),
        kind,
        os_code: None,
        explanation_code: code.into(),
        blocked: true,
    }
}
fn failed(
    item: &PreparedItem<'_>,
    id: &ActionId,
    kind: ErrorKind,
    code: &str,
    status: ActionStatus,
) -> ActionOutcome {
    ActionOutcome {
        action_id: id.clone(),
        status,
        issues: vec![issue(item, Some(id), kind, code)],
    }
}
fn all_confirmations(plan: &ProposedPlan) -> Vec<ConfirmationId> {
    plan.confirmations
        .iter()
        .chain(&plan.risks.confirmations)
        .chain(plan.actions.iter().flat_map(|a| &a.confirmations))
        .cloned()
        .collect()
}
fn review_plan(
    plan: &ProposedPlan,
    confirmations: &[ConfirmationId],
) -> Result<ValidatedPlan, ErrorKind> {
    if plan.risks.flags.contains(&RiskFlag::Unknown)
        || (plan.risks.permanent_data_loss == LossAssessment::Known && plan.risks.flags.is_empty())
    {
        return Err(ErrorKind::Unsupported);
    }
    ValidatedPlan::review(plan.clone(), confirmations)
}
fn preview_item(item: &PreparedItem<'_>) -> ItemReport {
    let mut report = ItemReport {
        instance: item.entry.instance.instance_id.clone(),
        plan: item.plan.clone(),
        aggregate: AggregateStatus::DryRun,
        actions: Vec::new(),
        processes: item.processes.clone(),
        issues: item.blocked.clone(),
        identity_sync: IdentitySync {
            identity: Uncertainty::Unknown,
            sync: Uncertainty::Unknown,
        },
        authentication: Uncertainty::Unknown,
        remote_revocation: Uncertainty::Unsupported,
        silent_sso: Uncertainty::Unknown,
    };
    if let Some(plan) = &item.plan {
        let unsupported = review_plan(plan, &all_confirmations(plan))
            .err()
            .or_else(|| item.blocked.iter().find(|i| i.blocked).map(|i| i.kind));
        for ((action, observed), path) in
            plan.actions.iter().zip(&item.observations).zip(&item.paths)
        {
            let outcome = match unsupported.or_else(|| observed.as_ref().err().copied()) {
                Some(kind) => failed(
                    item,
                    &action.action_id,
                    kind,
                    "preview-blocked",
                    ActionStatus::Blocked,
                ),
                None => ActionOutcome {
                    action_id: action.action_id.clone(),
                    status: if observed.as_ref().is_ok_and(|m| !m.exists) {
                        ActionStatus::AlreadyAbsent
                    } else {
                        ActionStatus::WouldApply
                    },
                    issues: vec![],
                },
            };
            report.actions.push(ActionReport {
                path: path.clone(),
                outcome,
                verification: ArtifactVerification {
                    artifact_id: action.artifact_id.clone(),
                    status: VerificationStatus::NotPerformed,
                    observation: observed.clone().ok(),
                    issues: vec![],
                },
            });
        }
    } else {
        report.aggregate = AggregateStatus::Blocked;
    }
    report
}
fn block_report(report: &mut ItemReport, item: &PreparedItem<'_>, kind: ErrorKind, code: &str) {
    report.issues.push(issue(item, None, kind, code));
    for action in &mut report.actions {
        action.outcome = failed(
            item,
            &action.outcome.action_id,
            kind,
            code,
            ActionStatus::Blocked,
        );
    }
}
fn verification(
    item: &PreparedItem<'_>,
    action: &PlannedAction,
    metadata: &dyn MetadataAccess,
    liveness: Option<ErrorKind>,
) -> ArtifactVerification {
    let observed = metadata.observe(&action.owner, &action.artifact_id);
    let status = match &observed {
        Ok(_) if liveness.is_some() => VerificationStatus::Unknown,
        Ok(_)
            if !matches!(
                action.method,
                MethodKind::DeleteFileFamily
                    | MethodKind::DeleteDirectoryFamily
                    | MethodKind::DeleteRegistryTarget
            ) =>
        {
            VerificationStatus::Unknown
        }
        Ok(m) if !m.exists => VerificationStatus::TargetAbsent,
        Ok(_) => VerificationStatus::TargetPresent,
        Err(ErrorKind::AccessDenied) => VerificationStatus::Inaccessible,
        Err(_) => VerificationStatus::Unknown,
    };
    let mut issues = Vec::new();
    if let Some(kind) = liveness.or_else(|| observed.as_ref().err().copied()) {
        let mut failure = issue(
            item,
            Some(&action.action_id),
            kind,
            "verification-incomplete",
        );
        failure.phase = Phase::Verify;
        issues.push(failure);
    }
    ArtifactVerification {
        artifact_id: action.artifact_id.clone(),
        status,
        observation: observed.ok(),
        issues,
    }
}
fn aggregate_item(report: &ItemReport, cancelled: bool) -> AggregateStatus {
    if cancelled
        || report
            .issues
            .iter()
            .chain(report.actions.iter().flat_map(|a| &a.outcome.issues))
            .any(|i| i.kind == ErrorKind::Cancelled)
    {
        return AggregateStatus::Cancelled;
    }
    let succeeded = report.actions.iter().any(|a| {
        matches!(
            a.outcome.status,
            ActionStatus::Applied | ActionStatus::AlreadyAbsent
        )
    });
    let complete = report.issues.is_empty()
        && report.actions.iter().all(|a| {
            matches!(
                a.outcome.status,
                ActionStatus::Applied | ActionStatus::AlreadyAbsent
            ) && a.verification.status == VerificationStatus::TargetAbsent
        });
    if complete && report.plan.is_some() {
        AggregateStatus::CompleteLocalScope
    } else if succeeded {
        AggregateStatus::Partial
    } else if report
        .actions
        .iter()
        .any(|a| a.outcome.status == ActionStatus::Failed)
    {
        AggregateStatus::Failed
    } else {
        AggregateStatus::Blocked
    }
}
fn assemble(
    mode: ExecutionMode,
    category: Category,
    policy: ProcessClosePolicy,
    items: Vec<ItemReport>,
) -> RunReport {
    let aggregate = if mode == ExecutionMode::DryRun {
        AggregateStatus::DryRun
    } else if items
        .iter()
        .any(|i| i.aggregate == AggregateStatus::Cancelled)
    {
        AggregateStatus::Cancelled
    } else if items
        .iter()
        .all(|i| i.aggregate == AggregateStatus::CompleteLocalScope)
    {
        AggregateStatus::CompleteLocalScope
    } else if items.iter().any(|i| {
        matches!(
            i.aggregate,
            AggregateStatus::CompleteLocalScope | AggregateStatus::Partial
        )
    }) {
        AggregateStatus::Partial
    } else if items.iter().any(|i| i.aggregate == AggregateStatus::Failed) {
        AggregateStatus::Failed
    } else {
        AggregateStatus::Blocked
    };
    let mut sections = Vec::new();
    for c in [
        Category::Application,
        Category::Browser,
        Category::WindowsMicrosoftAndDevTools,
    ] {
        let mut counts = Counts::default();
        if c == category {
            for action in items.iter().flat_map(|item| &item.actions) {
                match action.outcome.status {
                    ActionStatus::Applied => counts.succeeded += 1,
                    ActionStatus::AlreadyAbsent => {
                        counts.succeeded += 1;
                        counts.already_absent += 1;
                    }
                    ActionStatus::Failed => counts.failed += 1,
                    ActionStatus::Skipped | ActionStatus::Blocked => counts.skipped += 1,
                    ActionStatus::WouldApply => counts.would_apply += 1,
                }
                if action
                    .outcome
                    .issues
                    .iter()
                    .any(|i| i.kind == ErrorKind::Locked)
                {
                    counts.locked += 1;
                }
            }
        }
        sections.push(CategoryReport {
            category: c,
            aggregate: if c == category {
                aggregate
            } else {
                AggregateStatus::NotRequested
            },
            items: if c == category { items.clone() } else { vec![] },
            counts,
        });
    }
    RunReport {
        mode,
        process_close_policy: policy,
        sections,
    }
}
