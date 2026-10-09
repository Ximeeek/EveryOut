//! Single-threaded native session; borrowed engine capabilities never cross IPC.
use crate::dto::*;
use everyout_core_model::*;
use everyout_engine::{Approval, Engine, EngineProvider, Inventory, PreparedRun};
use std::{
    collections::HashSet,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
pub fn opaque(prefix: &str) -> String {
    format!("{prefix}-{}", NEXT_ID.fetch_add(1, Ordering::Relaxed))
}
pub struct HeldCurrent<'a> {
    runs: Vec<PreparedRun<'a>>,
    pub dto: PlanDto,
}
pub struct CurrentSession<'a> {
    engine: Engine<'a>,
    providers: Vec<(Category, &'a dyn EngineProvider)>,
    inventories: Vec<(Category, Inventory<'a>)>,
    inventory_id: String,
    held: Option<HeldCurrent<'a>>,
    blocked_providers: HashSet<String>,
}
impl<'a> CurrentSession<'a> {
    pub fn new(
        operations: &'a dyn LocalOperations,
        providers: Vec<(Category, &'a dyn EngineProvider)>,
    ) -> Self {
        Self {
            engine: Engine::new(UserId("current-account".into()), operations),
            providers,
            inventories: vec![],
            inventory_id: String::new(),
            held: None,
            blocked_providers: HashSet::new(),
        }
    }
    pub fn invalidate(&mut self) {
        self.held = None;
        self.inventories.clear();
        self.inventory_id.clear();
        self.blocked_providers.clear();
    }
    pub fn has_review(&self) -> bool {
        self.held.is_some()
    }
    pub fn block_provider(&mut self, id: String) {
        self.blocked_providers.insert(id);
    }
    pub fn scan(&mut self) -> Result<ScanDto, CommandError> {
        self.invalidate();
        self.inventory_id = opaque("inventory");
        let mut dto = ScanDto {
            inventory_id: self.inventory_id.clone(),
            mode: AccountMode::Current,
            groups: vec![],
            coverage: vec![],
            accounts: vec![AccountScanDto {
                account: "current-account".into(),
                logged_on: None,
                residual_hive: false,
                residual_hku_key: None,
                unload_attempts: 0,
                limitations: vec![],
            }],
        };
        for category in [
            Category::Application,
            Category::Browser,
            Category::WindowsMicrosoftAndDevTools,
        ] {
            let providers: Vec<_> = self
                .providers
                .iter()
                .filter(|(c, _)| *c == category)
                .map(|(_, p)| *p)
                .collect();
            let inventory = self
                .engine
                .scan(&providers, category, &mut |_| {})
                .map_err(|_| CommandError::InvalidSelection)?;
            for (instance, description) in inventory.descriptions() {
                dto.push(
                    Some(category),
                    instance.confidence,
                    DetectedItem {
                        decision: instance.decision.clone(),
                        id: instance.instance_id.0.clone(),
                        account: "current-account".into(),
                        provider: Some(instance.provider_id.0.clone()),
                        name: description.descriptor.name.clone(),
                        origin: instance.detection_origin,
                        default_selected: instance.confidence == Confidence::High,
                        selectable: true,
                        limitations: description.descriptor.limitations.clone(),
                        profiles: instance
                            .profiles
                            .iter()
                            .map(|p| p.profile_id.0.clone())
                            .collect(),
                        risks: description.risks.flags.clone(),
                        loss: description.risks.permanent_data_loss,
                        signals: vec!["known-provider".into()],
                        unverified: false, // Assigned centrally by ScanDto::push.
                        sync_warning: category == Category::Browser,
                    },
                );
            }
            self.inventories.push((category, inventory));
        }
        Ok(dto)
    }
    pub fn build_plan(
        &mut self,
        request: SelectionRequest,
        policy: ProcessClosePolicy,
    ) -> Result<PlanDto, CommandError> {
        self.held = None;
        if request.inventory_id != self.inventory_id || self.inventory_id.is_empty() {
            return Err(CommandError::StalePlan);
        }
        let skipped_ids = request.skipped.unwrap_or_default();
        if skipped_ids.len() > 64
            || skipped_ids.iter().collect::<HashSet<_>>().len() != skipped_ids.len()
            || skipped_ids.iter().any(|id| request.items.contains(id))
        {
            return Err(CommandError::InvalidSelection);
        }
        let mut skipped = Vec::new();
        for id in skipped_ids {
            let (category, instance, description) = self
                .inventories
                .iter()
                .find_map(|(category, inv)| {
                    inv.descriptions()
                        .find(|(i, _)| i.instance_id.0 == id)
                        .map(|(i, d)| (*category, i, d))
                })
                .ok_or(CommandError::InvalidSelection)?;
            skipped.push(SkippedItemDto {
                account: "current-account".into(),
                category,
                instance: id,
                provider: instance.provider_id.0.clone(),
                name: description.descriptor.name.clone(),
            });
        }
        let selected: HashSet<_> = request.items.iter().collect();
        if (selected.is_empty() && skipped.is_empty())
            || selected.len() != request.items.len()
            || request.items.len() > 64
            || request.profiles.len() > 64
            || request.items.iter().any(|id| {
                !self.inventories.iter().any(|(_, inv)| {
                    inv.descriptions().any(|(i, _)| {
                        i.instance_id.0 == *id && !self.blocked_providers.contains(&i.provider_id.0)
                    })
                })
            })
        {
            return Err(CommandError::InvalidSelection);
        }
        let mut profile_ids: std::collections::HashMap<InstanceId, Vec<ProfileId>> =
            std::collections::HashMap::new();
        for scope in request.profiles {
            if !selected.contains(&scope.item)
                || scope.profiles.is_empty()
                || scope.profiles.len() > 256
                || scope.profiles.iter().collect::<HashSet<_>>().len() != scope.profiles.len()
                || profile_ids.contains_key(&InstanceId(scope.item.clone()))
                || !self.inventories.iter().any(|(_, inv)| {
                    inv.descriptions().any(|(i, _)| {
                        i.instance_id.0 == scope.item
                            && scope
                                .profiles
                                .iter()
                                .all(|id| i.profiles.iter().any(|p| p.profile_id.0 == *id))
                    })
                })
            {
                return Err(CommandError::InvalidSelection);
            }
            profile_ids.insert(
                InstanceId(scope.item),
                scope.profiles.into_iter().map(ProfileId).collect(),
            );
        }
        let id = opaque("plan");
        let mut runs = Vec::new();
        let mut tokens = Vec::new();
        // A read-only preview must not consume the discovery snapshot. Rebuilding
        // replaces the held review; execution still revalidates the bound targets.
        for (category, inventory) in self.inventories.iter().cloned() {
            let ids: Vec<_> = inventory
                .descriptions()
                .filter(|(i, _)| selected.contains(&i.instance_id.0))
                .map(|(i, _)| i.instance_id.clone())
                .collect();
            if ids.is_empty() {
                continue;
            }
            let scoped = profile_ids
                .iter()
                .filter(|(id, _)| ids.contains(id))
                .map(|(id, profiles)| (id.clone(), profiles.clone()))
                .collect();
            let run = self
                .engine
                .prepare_scoped(inventory, category, &ids, &scoped, policy, &mut |_| {})
                .map_err(|_| CommandError::InvalidSelection)?;
            if category == Category::WindowsMicrosoftAndDevTools {
                tokens.push(CategoryToken {
                    account: "current-account".into(),
                    category,
                    token: opaque("category"),
                });
            }
            runs.push(run);
        }
        let reports: Vec<_> = runs.iter().map(|r| r.preview().clone()).collect();
        let mut report = ReportDto::current(&reports, policy, ExecutionMode::DryRun);
        report.skipped = skipped;
        let dto = PlanDto {
            plan_id: id,
            category_tokens: tokens,
            report,
        };
        self.held = Some(HeldCurrent {
            runs,
            dto: dto.clone(),
        });
        Ok(dto)
    }
    pub fn dry_run(&self, id: &str) -> Result<PlanDto, CommandError> {
        let held = self
            .held
            .as_ref()
            .filter(|h| h.dto.plan_id == id)
            .ok_or(CommandError::StalePlan)?;
        for run in &held.runs {
            self.engine
                .validate_preview(run)
                .map_err(|_| CommandError::StalePlan)?;
        }
        Ok(held.dto.clone())
    }
    /// Closing is separate from deletion and always consumes the reviewed plan.
    pub fn close_reviewed(&mut self, request: ExecuteRequest) -> Result<ReportDto, CommandError> {
        let plan = self.dry_run(&request.plan_id)?;
        validate_approval(&plan, &request)?;
        if plan.report.process_close_policy != ProcessClosePolicy::Ask {
            return Err(CommandError::InvalidSelection);
        }
        let held = self.held.take().ok_or(CommandError::StalePlan)?;
        self.inventories.clear();
        self.inventory_id.clear();
        let mut reports = Vec::new();
        for run in held.runs {
            let mut approval = Approval {
                category_confirmation: Some(run.confirm_category()),
                ..Default::default()
            };
            for accepted in request
                .confirmed_risks
                .iter()
                .filter(|r| r.account == "current-account")
            {
                approval.confirmed_risks.push(
                    run.confirm_risks(&InstanceId(accepted.instance.clone()), &accepted.flags),
                );
                approval
                    .confirmations
                    .extend(accepted.confirmations.iter().cloned().map(ConfirmationId));
            }
            reports.push(
                self.engine
                    .close_preview(&run, &approval)
                    .map_err(|_| CommandError::StalePlan)?,
            );
        }
        let mut report =
            ReportDto::current(&reports, ProcessClosePolicy::Ask, ExecutionMode::DryRun);
        report.skipped = held.dto.report.skipped;
        Ok(report)
    }
    pub fn execute(
        &mut self,
        request: ExecuteRequest,
        cancelled: &dyn Fn() -> bool,
        events: &mut dyn FnMut(WipeEvent),
    ) -> Result<ReportDto, CommandError> {
        let held = self
            .held
            .as_ref()
            .filter(|h| h.dto.plan_id == request.plan_id)
            .ok_or(CommandError::StalePlan)?;
        validate_approval(&held.dto, &request)?;
        let held = self.held.take().ok_or(CommandError::StalePlan)?;
        self.inventories.clear();
        self.inventory_id.clear();
        let mut reports = Vec::new();
        // Both closures emit to the same sink sequentially through this local cell.
        let sink = std::cell::RefCell::new(events);
        for run in held.runs {
            let category = run
                .preview()
                .sections
                .iter()
                .find(|s| s.aggregate != AggregateStatus::NotRequested)
                .map(|s| s.category)
                .ok_or(CommandError::InvalidSelection)?;
            let mut approval = Approval {
                category_confirmation: (category == Category::WindowsMicrosoftAndDevTools)
                    .then(|| run.confirm_category()),
                force_close_acknowledged: request
                    .force_close_accounts
                    .iter()
                    .any(|a| a == "current-account"),
                ..Default::default()
            };
            for section in &run.preview().sections {
                for item in &section.items {
                    if let Some(accepted) = request
                        .confirmed_risks
                        .iter()
                        .find(|r| r.account == "current-account" && r.instance == item.instance.0)
                    {
                        approval
                            .confirmed_risks
                            .push(run.confirm_risks(&item.instance, &accepted.flags));
                        approval
                            .confirmations
                            .extend(accepted.confirmations.iter().cloned().map(ConfirmationId));
                    }
                }
            }
            let report = self.engine.apply_with_results(
                run,
                approval,
                cancelled,
                &mut |p| {
                    sink.borrow_mut()(WipeEvent::Progress {
                        run_id: request.plan_id.clone(),
                        account: "current-account".into(),
                        stage: p.stage,
                        category: p.category,
                        instance: p.instance.map(|id| id.0),
                        action: p.action.map(|id| id.0),
                    })
                },
                &mut |item| {
                    sink.borrow_mut()(WipeEvent::Item {
                        run_id: request.plan_id.clone(),
                        account: "current-account".into(),
                        category,
                        item: Box::new(ItemDto::from(item)),
                    })
                },
            );
            reports.push(report);
        }
        let mut report = ReportDto::current(
            &reports,
            held.dto.report.process_close_policy,
            ExecutionMode::Apply,
        );
        report.skipped = held.dto.report.skipped;
        Ok(report)
    }
}

/// Reject all missing confirmations before any account starts mutation.
pub fn validate_approval(plan: &PlanDto, request: &ExecuteRequest) -> Result<(), CommandError> {
    if plan.plan_id != request.plan_id {
        return Err(CommandError::StalePlan);
    }
    let mut seen = HashSet::new();
    if request.confirmed_risks.len() > 256
        || request.category_tokens.len() > 64
        || request.force_close_accounts.len() > 64
    {
        return Err(CommandError::InvalidSelection);
    }
    for accepted in &request.confirmed_risks {
        if !seen.insert((&accepted.account, &accepted.instance))
            || accepted.flags.len() > 16
            || accepted.confirmations.len() > 256
            || !plan.report.accounts.iter().any(|a| {
                a.account == accepted.account
                    && a.sections
                        .iter()
                        .any(|s| s.items.iter().any(|i| i.instance == accepted.instance))
            })
        {
            return Err(CommandError::InvalidSelection);
        }
    }
    if request.category_tokens.iter().any(|t| {
        !plan
            .category_tokens
            .iter()
            .any(|expected| &expected.token == t)
    }) || request
        .force_close_accounts
        .iter()
        .any(|id| !plan.report.accounts.iter().any(|a| &a.account == id))
    {
        return Err(CommandError::InvalidSelection);
    }
    if plan
        .category_tokens
        .iter()
        .any(|t| !request.category_tokens.contains(&t.token))
    {
        return Err(CommandError::ConfirmationRequired);
    }
    for account in &plan.report.accounts {
        if plan.report.process_close_policy == ProcessClosePolicy::HardKillAfter2s
            && !request.force_close_accounts.contains(&account.account)
        {
            return Err(CommandError::ConfirmationRequired);
        }
        for item in account.sections.iter().flat_map(|s| &s.items) {
            if item.risks.is_empty() && item.confirmations.is_empty() {
                continue;
            }
            let accepted = request
                .confirmed_risks
                .iter()
                .find(|r| r.account == account.account && r.instance == item.instance)
                .ok_or(CommandError::ConfirmationRequired)?;
            if item.risks.iter().any(|r| !accepted.flags.contains(r))
                || item
                    .confirmations
                    .iter()
                    .any(|c| !accepted.confirmations.contains(c))
            {
                return Err(CommandError::ConfirmationRequired);
            }
        }
    }
    Ok(())
}
