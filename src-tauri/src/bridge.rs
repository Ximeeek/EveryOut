use crate::{
    application::{opaque, validate_approval, CurrentSession},
    dto::*,
    settings::SettingsStore,
};
use everyout_core_model::*;
use everyout_elevated_helper::{
    self as helper,
    protocol::{Command, Response, Status},
    LaunchOutcome,
};
use everyout_engine::accounts::{AccountConsent, AccountsReport};
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
};

pub type EventSink = Box<dyn FnMut(WipeEvent) + Send>;
enum Request {
    Scan,
    Plan(SelectionRequest),
    DryRun(String),
    Execute(ExecuteRequest, EventSink),
    Close(ExecuteRequest),
    Enable,
    Settings(Settings),
}
enum Reply {
    Scan(ScanDto),
    Plan(PlanDto),
    Mode(ModeResult),
    Settings(Settings),
    Started(RunStarted),
    Report(ReportDto),
}
type ResponseSender = mpsc::Sender<Result<Reply, CommandError>>;
struct Envelope {
    request: Request,
    reply: ResponseSender,
}
struct Shared {
    cancelled: AtomicBool,
    active: Mutex<Option<String>>,
    settings: Mutex<Settings>,
    report: Mutex<Option<ReportDto>>,
    reports_directory: std::path::PathBuf,
}
#[derive(Clone)]
pub struct Bridge {
    sender: mpsc::Sender<Envelope>,
    shared: Arc<Shared>,
}
pub struct Worker {
    receiver: mpsc::Receiver<Envelope>,
    shared: Arc<Shared>,
    store: SettingsStore,
    pin: Option<[u8; 32]>,
}

impl Bridge {
    pub fn start(
        directory: std::path::PathBuf,
        pin: Option<[u8; 32]>,
    ) -> Result<Self, CommandError> {
        let (bridge, worker) = Self::channel(SettingsStore::new(directory), pin)?;
        std::thread::Builder::new()
            .name("everyout-native".into())
            .spawn(move || crate::native::serve(worker))
            .map_err(|_| CommandError::WorkerUnavailable)?;
        Ok(bridge)
    }
    pub fn channel(
        store: SettingsStore,
        pin: Option<[u8; 32]>,
    ) -> Result<(Self, Worker), CommandError> {
        let settings = store.load()?;
        let shared = Arc::new(Shared {
            cancelled: AtomicBool::new(false),
            active: Mutex::new(None),
            settings: Mutex::new(settings),
            report: Mutex::new(None),
            reports_directory: store.reports_directory()?,
        });
        let (sender, receiver) = mpsc::channel();
        Ok((
            Self {
                sender,
                shared: shared.clone(),
            },
            Worker {
                receiver,
                shared,
                store,
                pin,
            },
        ))
    }
    fn call(&self, request: Request) -> Result<Reply, CommandError> {
        let (sender, receiver) = mpsc::channel();
        {
            let mut active = self
                .shared
                .active
                .lock()
                .map_err(|_| CommandError::WorkerUnavailable)?;
            if active.is_some() {
                return Err(CommandError::Busy);
            }
            if let Request::Execute(request, _) | Request::Close(request) = &request {
                *active = Some(request.plan_id.clone());
                self.shared.cancelled.store(false, Ordering::Release);
            }
            if self
                .sender
                .send(Envelope {
                    request,
                    reply: sender,
                })
                .is_err()
            {
                *active = None;
                return Err(CommandError::WorkerUnavailable);
            }
        }
        receiver
            .recv()
            .map_err(|_| CommandError::WorkerUnavailable)?
    }
    pub fn scan(&self) -> Result<ScanDto, CommandError> {
        match self.call(Request::Scan)? {
            Reply::Scan(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn build_plan(&self, selection: SelectionRequest) -> Result<PlanDto, CommandError> {
        match self.call(Request::Plan(selection))? {
            Reply::Plan(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn dry_run(&self, id: String) -> Result<PlanDto, CommandError> {
        match self.call(Request::DryRun(id))? {
            Reply::Plan(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn execute(
        &self,
        request: ExecuteRequest,
        sink: EventSink,
    ) -> Result<RunStarted, CommandError> {
        match self.call(Request::Execute(request, sink))? {
            Reply::Started(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn close_reviewed(&self, request: ExecuteRequest) -> Result<ReportDto, CommandError> {
        match self.call(Request::Close(request))? {
            Reply::Report(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn export_report(&self, format: ExportFormat) -> Result<String, CommandError> {
        let report = self.get_last_report()?.ok_or(CommandError::StalePlan)?;
        crate::reports::export(&self.shared.reports_directory, &report, format)
    }
    pub fn enable_all_accounts_mode(&self) -> Result<ModeResult, CommandError> {
        match self.call(Request::Enable)? {
            Reply::Mode(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn get_settings(&self) -> Result<Settings, CommandError> {
        self.shared
            .settings
            .lock()
            .map(|s| s.clone())
            .map_err(|_| CommandError::WorkerUnavailable)
    }
    pub fn set_settings(&self, settings: Settings) -> Result<Settings, CommandError> {
        match self.call(Request::Settings(settings))? {
            Reply::Settings(dto) => Ok(dto),
            _ => Err(CommandError::WorkerUnavailable),
        }
    }
    pub fn get_last_report(&self) -> Result<Option<ReportDto>, CommandError> {
        self.shared
            .report
            .lock()
            .map(|r| r.clone())
            .map_err(|_| CommandError::WorkerUnavailable)
    }
    pub fn cancel(&self, run_id: &str) -> Result<(), CommandError> {
        let active = self
            .shared
            .active
            .lock()
            .map_err(|_| CommandError::WorkerUnavailable)?;
        if active.as_deref() != Some(run_id) {
            return Err(CommandError::StalePlan);
        }
        self.shared.cancelled.store(true, Ordering::Release);
        Ok(())
    }
}
struct HeldElevated {
    dto: PlanDto,
    helper_id: String,
    digest: String,
}
#[derive(Deserialize)]
struct Profiles {
    accounts: Vec<Profile>,
    exclusions: Vec<(String, String)>,
}
#[derive(Deserialize)]
struct Profile {
    account: String,
    scan: everyout_detection::ScanReport,
    residual_hive: bool,
    logged_on: bool,
    residual_hku_key: Option<String>,
    unload_attempts: usize,
    limitations: Vec<String>,
}
struct Elevated {
    client: helper::Client,
    inventory: String,
    selections: HashMap<String, helper::protocol::Selection>,
    held: Option<HeldElevated>,
}

/// Read bounded authenticated pages. Never return arbitrary helper JSON to JavaScript.
fn helper_report(
    client: &mut helper::Client,
    first: Response,
) -> Result<(String, Option<String>, Option<String>), CommandError> {
    let data = first.data.ok_or(CommandError::HelperUnavailable)?;
    if data.page != 0 || data.pages == 0 || data.pages > 2048 {
        return Err(CommandError::HelperUnavailable);
    }
    let mut json = data.report;
    for page in 1..data.pages {
        let response = client
            .request(Command::ReadReport { page })
            .map_err(|_| CommandError::HelperUnavailable)?;
        let next = response.data.ok_or(CommandError::HelperUnavailable)?;
        if next.page != page
            || next.pages != data.pages
            || next.plan_id != data.plan_id
            || next.digest != data.digest
        {
            return Err(CommandError::HelperUnavailable);
        }
        json.push_str(&next.report);
    }
    Ok((json, data.plan_id, data.digest))
}
impl Worker {
    pub fn cancellation(&self) -> Arc<dyn Fn() -> bool + Send + Sync> {
        let shared = self.shared.clone();
        Arc::new(move || shared.cancelled.load(Ordering::Acquire))
    }
    pub fn cancelled(&self) -> bool {
        self.shared.cancelled.load(Ordering::Acquire)
    }
    fn settings(&self) -> Result<Settings, CommandError> {
        self.shared
            .settings
            .lock()
            .map(|s| s.clone())
            .map_err(|_| CommandError::WorkerUnavailable)
    }
    fn save(&self, settings: Settings) -> Result<Settings, CommandError> {
        self.store.save(&settings)?;
        *self
            .shared
            .settings
            .lock()
            .map_err(|_| CommandError::WorkerUnavailable)? = settings.clone();
        Ok(settings)
    }
    fn fallback(&self, reason: ModeFailure) -> Result<ModeResult, CommandError> {
        let mut settings = self.settings()?;
        settings.account_mode = AccountMode::Current;
        self.save(settings)?;
        Ok(ModeResult {
            effective_mode: AccountMode::Current,
            requires_fresh_review: true,
            reason: Some(reason),
        })
    }
    fn enable(&self) -> Result<(Option<Elevated>, ModeResult), CommandError> {
        let Some(pin) = self.pin else {
            return self
                .fallback(ModeFailure::TrustPinUnavailable)
                .map(|m| (None, m));
        };
        match helper::launch(AccountMode::AllAccounts, true, pin) {
            LaunchOutcome::Elevated(client) => {
                let mut settings = self.settings()?;
                settings.account_mode = AccountMode::AllAccounts;
                self.save(settings)?;
                Ok((
                    Some(Elevated {
                        client,
                        inventory: String::new(),
                        selections: HashMap::new(),
                        held: None,
                    }),
                    ModeResult {
                        effective_mode: AccountMode::AllAccounts,
                        requires_fresh_review: true,
                        reason: None,
                    },
                ))
            }
            LaunchOutcome::Fallback(f) => {
                let reason = match f.reason {
                    helper::LaunchFailure::UacDeclined => ModeFailure::UacDeclined,
                    helper::LaunchFailure::StartFailed => ModeFailure::StartFailed,
                    helper::LaunchFailure::AuthenticationFailed => {
                        ModeFailure::AuthenticationFailed
                    }
                    helper::LaunchFailure::Timeout => ModeFailure::Timeout,
                };
                self.fallback(reason).map(|m| (None, m))
            }
            LaunchOutcome::CurrentAccount => {
                self.fallback(ModeFailure::StartFailed).map(|m| (None, m))
            }
        }
    }
    pub fn serve(
        self,
        mut current: CurrentSession<'_>,
        discovery: impl Fn() -> everyout_detection::ScanReport,
        unavailable: Vec<String>,
    ) {
        let mut elevated: Option<Elevated> = None;
        while let Ok(envelope) = self.receiver.recv() {
            let executing = matches!(&envelope.request, Request::Execute(..) | Request::Close(..));
            let mut acknowledged = false;
            let result = (|| {
                let settings = self.settings()?;
                match envelope.request {
                    Request::Enable => {
                        current.invalidate();
                        elevated = None;
                        let (client, mode) = self.enable()?;
                        elevated = client;
                        Ok(Reply::Mode(mode))
                    }
                    Request::Settings(settings) => {
                        // Remembering AllAccounts is allowed, but never launches UAC or grants scope.
                        current.invalidate();
                        elevated = None;
                        self.save(settings).map(Reply::Settings)
                    }
                    Request::Scan => {
                        if settings.account_mode == AccountMode::AllAccounts {
                            let helper =
                                elevated.as_mut().ok_or(CommandError::HelperUnavailable)?;
                            scan_elevated(helper).map(Reply::Scan)
                        } else {
                            let mut dto = current.scan()?;
                            let found = discovery();
                            dto.coverage.extend(found.coverage);
                            dto.coverage.extend(unavailable.clone());
                            let present: HashSet<_> = dto
                                .groups
                                .iter()
                                .flat_map(|g| &g.items)
                                .filter_map(|i| i.provider.clone())
                                .collect();
                            // Discovery-only candidates cannot be submitted as engine instances.
                            for detected in found.known.into_iter().chain(found.candidates) {
                                let prefix = detected.id.split("-instance-").next().unwrap_or("");
                                if detected.category.is_none() && present.contains(prefix) {
                                    current.block_provider(prefix.into());
                                    for item in dto
                                        .groups
                                        .iter_mut()
                                        .flat_map(|g| &mut g.items)
                                        .filter(|i| i.provider.as_deref() == Some(prefix))
                                    {
                                        item.default_selected = false;
                                        item.selectable = false;
                                        item.limitations.extend(detected.limitations.clone());
                                    }
                                }
                                if present.contains(prefix) {
                                    for item in dto
                                        .groups
                                        .iter_mut()
                                        .flat_map(|g| &mut g.items)
                                        .filter(|i| i.provider.as_deref() == Some(prefix))
                                    {
                                        item.signals = detected.signals.clone();
                                    }
                                    continue;
                                }
                                dto.push(
                                    detected.category,
                                    detected.confidence,
                                    DetectedItem {
                                        id: format!("discovery-{}", detected.id),
                                        account: "current-account".into(),
                                        provider: None,
                                        name: detected
                                            .owner
                                            .unwrap_or_else(|| "Unresolved application".into()),
                                        origin: detected.origin,
                                        default_selected: false,
                                        selectable: false,
                                        limitations: detected.limitations,
                                        profiles: vec![],
                                        risks: vec![RiskFlag::Unknown],
                                        loss: LossAssessment::Unknown,
                                        signals: detected.signals,
                                        unverified: true,
                                        sync_warning: detected.category == Some(Category::Browser),
                                    },
                                );
                            }
                            Ok(Reply::Scan(dto))
                        }
                    }
                    Request::Plan(selection) => {
                        if settings.account_mode == AccountMode::AllAccounts {
                            plan_elevated(
                                elevated.as_mut().ok_or(CommandError::HelperUnavailable)?,
                                selection,
                                settings.process_close_policy,
                            )
                            .map(Reply::Plan)
                        } else {
                            current
                                .build_plan(selection, settings.process_close_policy)
                                .map(Reply::Plan)
                        }
                    }
                    Request::DryRun(id) => {
                        if settings.account_mode == AccountMode::AllAccounts {
                            dry_elevated(
                                elevated.as_mut().ok_or(CommandError::HelperUnavailable)?,
                                &id,
                            )
                            .map(Reply::Plan)
                        } else {
                            current.dry_run(&id).map(Reply::Plan)
                        }
                    }
                    Request::Close(request) => {
                        let report = if settings.account_mode == AccountMode::AllAccounts {
                            let helper =
                                elevated.as_mut().ok_or(CommandError::HelperUnavailable)?;
                            let plan = dry_elevated(helper, &request.plan_id)?;
                            validate_approval(&plan, &request)?;
                            if settings.process_close_policy != ProcessClosePolicy::Ask {
                                return Err(CommandError::InvalidSelection);
                            }
                            {
                                let mut sink: EventSink = Box::new(|_| {});
                                execute_elevated(
                                    helper,
                                    request,
                                    &mut sink,
                                    &|| self.cancelled(),
                                    true,
                                )?
                            }
                        } else {
                            current.close_reviewed(request)?
                        };
                        current.invalidate();
                        if let Ok(mut active) = self.shared.active.lock() {
                            *active = None;
                        }
                        Ok(Reply::Report(report))
                    }
                    Request::Execute(request, mut sink) => {
                        let plan = if settings.account_mode == AccountMode::AllAccounts {
                            elevated
                                .as_ref()
                                .and_then(|h| h.held.as_ref())
                                .filter(|h| h.dto.plan_id == request.plan_id)
                                .map(|h| h.dto.clone())
                                .ok_or(CommandError::StalePlan)?
                        } else {
                            current.dry_run(&request.plan_id)?
                        };
                        validate_approval(&plan, &request)?;
                        let run_id = request.plan_id.clone();
                        let _ = envelope.reply.send(Ok(Reply::Started(RunStarted {
                            run_id: run_id.clone(),
                        })));
                        acknowledged = true;
                        let report = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            if settings.account_mode == AccountMode::AllAccounts {
                                execute_elevated(
                                    elevated.as_mut().ok_or(CommandError::HelperUnavailable)?,
                                    request,
                                    &mut sink,
                                    &|| self.cancelled(),
                                    false,
                                )
                            } else {
                                current.execute(request, &|| self.cancelled(), &mut sink)
                            }
                        }))
                        .unwrap_or(Err(CommandError::WorkerUnavailable));
                        let terminal = match report {
                            Ok(report) => {
                                if let Ok(mut last) = self.shared.report.lock() {
                                    *last = Some(report.clone());
                                }
                                WipeEvent::Finished { run_id, report }
                            }
                            Err(error) => WipeEvent::Failed { run_id, error },
                        };
                        current.invalidate();
                        // Plans are consumed by the helper; retain the authenticated owner map for retries.
                        if let Ok(mut active) = self.shared.active.lock() {
                            *active = None;
                            self.shared.cancelled.store(false, Ordering::Release);
                        }
                        sink(terminal);
                        Ok(Reply::Started(RunStarted {
                            run_id: String::new(),
                        }))
                    }
                }
            })();
            if executing && result.is_err() {
                if let Ok(mut active) = self.shared.active.lock() {
                    *active = None;
                    self.shared.cancelled.store(false, Ordering::Release);
                }
            }
            if !acknowledged {
                let _ = envelope.reply.send(result);
            }
        }
    }
}
fn scan_elevated(helper: &mut Elevated) -> Result<ScanDto, CommandError> {
    helper.held = None;
    helper.selections.clear();
    helper.inventory = opaque("inventory");
    let response = helper
        .client
        .request(Command::EnumerateProfiles)
        .map_err(|_| CommandError::HelperUnavailable)?;
    if response.status != Status::ProfilesReady {
        return Err(CommandError::HelperUnavailable);
    }
    let (json, _, _) = helper_report(&mut helper.client, response)?;
    let profiles: Profiles =
        serde_json::from_str(&json).map_err(|_| CommandError::HelperUnavailable)?;
    let catalog = crate::native::catalog()?;
    let mut dto = ScanDto {
        inventory_id: helper.inventory.clone(),
        mode: AccountMode::AllAccounts,
        groups: vec![],
        coverage: profiles
            .exclusions
            .into_iter()
            .map(|(_, reason)| reason)
            .collect(),
        accounts: vec![],
    };
    for account in profiles.accounts {
        dto.accounts.push(AccountScanDto {
            account: account.account.clone(),
            logged_on: Some(account.logged_on),
            residual_hive: account.residual_hive,
            residual_hku_key: account.residual_hku_key,
            unload_attempts: account.unload_attempts,
            limitations: account.limitations,
        });
        dto.coverage.extend(account.scan.coverage);
        if account.residual_hive {
            dto.coverage
                .push("account-scan-residual-hive-requires-recovery".into());
        }
        let mut seen = HashSet::new();
        for detected in account
            .scan
            .known
            .into_iter()
            .chain(account.scan.candidates)
        {
            let provider = detected.id.split("-instance-").next().unwrap_or("");
            let manifest = catalog.iter().find(|(_, m)| m.id == provider);
            if let Some((_, m)) = manifest {
                if !seen.insert(m.id.clone()) {
                    continue;
                }
                let id = opaque("account-provider");
                if detected.category.is_some() && !account.residual_hive {
                    helper.selections.insert(
                        id.clone(),
                        helper::protocol::Selection {
                            provider_id: m.id.clone(),
                            revision: m.revision,
                            account_id: account.account.clone(),
                        },
                    );
                }
                dto.push(
                    detected.category,
                    detected.confidence,
                    DetectedItem {
                        id,
                        account: account.account.clone(),
                        provider: Some(m.id.clone()),
                        name: m.name.clone(),
                        origin: detected.origin,
                        default_selected: detected.confidence == Confidence::High
                            && detected.category.is_some()
                            && !account.residual_hive,
                        selectable: detected.category.is_some() && !account.residual_hive,
                        limitations: detected.limitations,
                        // The helper binds an indivisible provider scope per Windows account.
                        profiles: vec![],
                        risks: m.risks.flags.clone(),
                        loss: m.risks.permanent_data_loss,
                        signals: detected.signals,
                        unverified: m.confidence.status.as_deref() != Some("verified"),
                        sync_warning: m.category == Category::Browser,
                    },
                );
            } else {
                dto.push(
                    detected.category,
                    detected.confidence,
                    DetectedItem {
                        id: opaque("discovery"),
                        account: account.account.clone(),
                        provider: None,
                        name: detected
                            .owner
                            .unwrap_or_else(|| "Unresolved application".into()),
                        origin: detected.origin,
                        default_selected: false,
                        selectable: false,
                        limitations: detected.limitations,
                        profiles: vec![],
                        risks: vec![RiskFlag::Unknown],
                        loss: LossAssessment::Unknown,
                        signals: detected.signals,
                        unverified: true,
                        sync_warning: detected.category == Some(Category::Browser),
                    },
                );
            }
        }
    }
    Ok(dto)
}
fn plan_elevated(
    helper: &mut Elevated,
    selection: SelectionRequest,
    policy: ProcessClosePolicy,
) -> Result<PlanDto, CommandError> {
    helper.held = None;
    // Never silently expand a requested profile subset into the helper's whole-account scope.
    if !selection.profiles.is_empty() {
        return Err(CommandError::InvalidSelection);
    }
    if selection.inventory_id != helper.inventory || helper.inventory.is_empty() {
        return Err(CommandError::StalePlan);
    }
    let skipped_ids = selection.skipped.clone().unwrap_or_default();
    if skipped_ids.len() > 64
        || skipped_ids.iter().collect::<HashSet<_>>().len() != skipped_ids.len()
        || skipped_ids.iter().any(|id| selection.items.contains(id))
    {
        return Err(CommandError::InvalidSelection);
    }
    let catalog = crate::native::catalog()?;
    let skipped = skipped_ids
        .iter()
        .map(|id| {
            let chosen = helper
                .selections
                .get(id)
                .ok_or(CommandError::InvalidSelection)?;
            let manifest = &catalog
                .iter()
                .find(|(_, m)| m.id == chosen.provider_id)
                .ok_or(CommandError::InvalidSelection)?
                .1;
            Ok(SkippedItemDto {
                account: chosen.account_id.clone(),
                category: manifest.category,
                instance: id.clone(),
                provider: manifest.id.clone(),
                name: manifest.name.clone(),
            })
        })
        .collect::<Result<Vec<_>, CommandError>>()?;
    let unique: HashSet<_> = selection.items.iter().collect();
    if unique.len() != selection.items.len()
        || (selection.items.is_empty() && skipped.is_empty())
        || selection.items.len() > 64
    {
        return Err(CommandError::InvalidSelection);
    }
    let selections = selection
        .items
        .iter()
        .map(|id| {
            helper
                .selections
                .get(id)
                .cloned()
                .ok_or(CommandError::InvalidSelection)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if selections.is_empty() {
        let mut report = ReportDto::current(&[], policy, ExecutionMode::DryRun);
        report.account_mode = AccountMode::AllAccounts;
        report.accounts.clear();
        report.skipped = skipped;
        let dto = PlanDto {
            plan_id: opaque("plan"),
            category_tokens: vec![],
            report,
        };
        helper.held = Some(HeldElevated {
            dto: dto.clone(),
            helper_id: String::new(),
            digest: String::new(),
        });
        helper.inventory.clear();
        return Ok(dto);
    }
    let response = helper
        .client
        .request(Command::PlanAccounts { selections, policy })
        .map_err(|_| CommandError::HelperUnavailable)?;
    if response.status != Status::PlanReady {
        return Err(CommandError::InvalidSelection);
    }
    let (json, id, digest) = helper_report(&mut helper.client, response)?;
    let report: AccountsReport =
        serde_json::from_str(&json).map_err(|_| CommandError::HelperUnavailable)?;
    let mut report = ReportDto::elevated(&report, policy);
    report.skipped = skipped;
    let tokens = report
        .accounts
        .iter()
        .filter(|a| {
            a.sections.iter().any(|s| {
                s.category == Category::WindowsMicrosoftAndDevTools
                    && s.status != AggregateStatus::NotRequested
            })
        })
        .map(|a| CategoryToken {
            account: a.account.clone(),
            category: Category::WindowsMicrosoftAndDevTools,
            token: opaque("category"),
        })
        .collect();
    let dto = PlanDto {
        plan_id: opaque("plan"),
        category_tokens: tokens,
        report,
    };
    helper.held = Some(HeldElevated {
        dto: dto.clone(),
        helper_id: id.ok_or(CommandError::HelperUnavailable)?,
        digest: digest.ok_or(CommandError::HelperUnavailable)?,
    });
    helper.inventory.clear();
    Ok(dto)
}
fn dry_elevated(helper: &mut Elevated, id: &str) -> Result<PlanDto, CommandError> {
    let held = helper
        .held
        .as_mut()
        .filter(|h| h.dto.plan_id == id)
        .ok_or(CommandError::StalePlan)?;
    if held.helper_id.is_empty() {
        return Ok(held.dto.clone());
    }
    let response = helper
        .client
        .request(Command::Execute {
            plan_id: held.helper_id.clone(),
            dry_run: true,
        })
        .map_err(|_| CommandError::HelperUnavailable)?;
    if response.status != Status::PlanReady {
        helper.held = None;
        return Err(CommandError::StalePlan);
    }
    let (json, _, _) = helper_report(&mut helper.client, response)?;
    let report: AccountsReport =
        serde_json::from_str(&json).map_err(|_| CommandError::HelperUnavailable)?;
    let skipped = held.dto.report.skipped.clone();
    held.dto.report = ReportDto::elevated(&report, held.dto.report.process_close_policy);
    held.dto.report.skipped = skipped;
    Ok(held.dto.clone())
}
fn execute_elevated(
    helper: &mut Elevated,
    request: ExecuteRequest,
    sink: &mut EventSink,
    cancelled: &dyn Fn() -> bool,
    close_only: bool,
) -> Result<ReportDto, CommandError> {
    let held = helper
        .held
        .take()
        .filter(|h| h.dto.plan_id == request.plan_id)
        .ok_or(CommandError::StalePlan)?;
    if cancelled() {
        return Err(CommandError::Cancelled);
    }
    if held.helper_id.is_empty() {
        let mut report = held.dto.report;
        report.mode = ExecutionMode::Apply;
        return Ok(report);
    }
    let accounts =
        held.dto
            .report
            .accounts
            .iter()
            .map(|a| {
                let accepted: Vec<_> = request
                    .confirmed_risks
                    .iter()
                    .filter(|r| r.account == a.account)
                    .collect();
                AccountConsent {
                    account: a.account.clone(),
                    windows_dev_confirmed: held.dto.category_tokens.iter().any(|t| {
                        t.account == a.account && request.category_tokens.contains(&t.token)
                    }),
                    risks: accepted.iter().flat_map(|r| r.flags.clone()).collect(),
                    confirmations: accepted
                        .iter()
                        .flat_map(|r| r.confirmations.iter().cloned().map(ConfirmationId))
                        .collect(),
                    force_close_acknowledged: request.force_close_accounts.contains(&a.account),
                }
            })
            .collect();
    let review = helper
        .client
        .request(Command::Review {
            plan_id: held.helper_id.clone(),
            digest: held.digest,
            accounts,
        })
        .map_err(|_| CommandError::HelperUnavailable)?;
    if review.status != Status::Reviewed {
        return Err(CommandError::ConfirmationRequired);
    }
    if cancelled() {
        return Err(CommandError::Cancelled);
    }
    let response = helper
        .client
        .request_streamed(
            if close_only {
                Command::CloseProcesses {
                    plan_id: held.helper_id,
                }
            } else {
                Command::Execute {
                    plan_id: held.helper_id,
                    dry_run: false,
                }
            },
            cancelled,
            &mut |event| {
                sink(WipeEvent::Progress {
                    run_id: request.plan_id.clone(),
                    account: event.account,
                    stage: event.progress.stage,
                    category: event.progress.category,
                    instance: event.progress.instance.map(|id| id.0),
                    action: event.progress.action.map(|id| id.0),
                })
            },
        )
        .map_err(|_| {
            if cancelled() {
                CommandError::Cancelled
            } else {
                CommandError::HelperUnavailable
            }
        })?;
    if response.status != Status::Completed {
        return Err(CommandError::StalePlan);
    }
    let (json, _, _) = helper_report(&mut helper.client, response)?;
    let report: AccountsReport =
        serde_json::from_str(&json).map_err(|_| CommandError::HelperUnavailable)?;
    let mut report = ReportDto::elevated(&report, held.dto.report.process_close_policy);
    report.skipped = held.dto.report.skipped;
    for account in &report.accounts {
        for section in &account.sections {
            for item in &section.items {
                sink(WipeEvent::Item {
                    run_id: request.plan_id.clone(),
                    account: account.account.clone(),
                    category: section.category,
                    item: item.clone(),
                });
            }
        }
    }
    let _ = helper.client.request(Command::Finish);
    Ok(report)
}
