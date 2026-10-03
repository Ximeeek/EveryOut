//! Native all-account sequence. S6 remains UNVERIFIED. All effects go through
//! the ordinary engine guard and manifest capabilities, with per-account review.
use crate::protocol::*;
use everyout_core_model::*;
use everyout_engine::{
    accounts::*, Approval, CategoryReport, Counts, Engine, EngineProvider, IdentitySync,
    ItemReport, ProcessPreview, RunReport,
};
use everyout_platform_windows::{accounts::*, AllowedRoot, PhysicalIdentity};
use everyout_providers::{
    executor::{ManifestExecutor, ProcessGate, WindowsProcessGate},
    registry_executor::RegistryExecutor,
    Manifest, Root,
};
use sha2::{Digest, Sha256};
use std::{cell::RefCell, collections::BTreeMap};

type PhysicalSnapshot = Vec<Option<Vec<PhysicalIdentity>>>;
type Fingerprints = BTreeMap<(String, String), PhysicalSnapshot>;
type ExpectedAccount<'a> = Option<(&'a AccountReport, &'a Fingerprints)>;
struct HeldPlan {
    plan: AccountsPlan,
    selections: Vec<crate::protocol::Selection>,
    digest: String,
    approval: Option<AccountsApproval>,
    physical: BTreeMap<(String, String), PhysicalSnapshot>,
    _roots: Vec<AllowedRoot>,
}
fn blocked_section(
    id: &str,
    manifest: &Manifest,
    policy: ProcessClosePolicy,
    kind: ErrorKind,
) -> RunReport {
    let instance = InstanceId(format!("{}-unavailable", manifest.id));
    let plan = ProposedPlan {
        plan_id: PlanId(format!("{}-unavailable", manifest.id)),
        provider_id: ProviderId(manifest.id.clone()),
        manifest_revision: manifest.revision,
        support: manifest.support,
        selection: everyout_core_model::Selection {
            snapshot_id: SnapshotId("unavailable".into()),
            account_mode: AccountMode::Current,
            instances: vec![instance.clone()],
            profiles: vec![],
        },
        actions: vec![],
        risks: manifest.risks.clone(),
        blockers: vec!["account-provider-scope-unavailable".into()],
        confirmations: vec![],
        limitations: manifest.limitations.clone(),
    };
    let item = ItemReport {
        instance: instance.clone(),
        plan: Some(plan),
        aggregate: AggregateStatus::Blocked,
        actions: vec![],
        processes: vec![],
        issues: vec![ProviderIssue {
            phase: Phase::Plan,
            provider_id: ProviderId(manifest.id.clone()),
            instance_id: Some(instance),
            action_id: None,
            kind,
            os_code: None,
            explanation_code: "account-provider-scope-unavailable".into(),
            blocked: true,
        }],
        identity_sync: IdentitySync {
            identity: Uncertainty::Unknown,
            sync: Uncertainty::Unknown,
        },
        authentication: Uncertainty::Unknown,
        remote_revocation: Uncertainty::Unsupported,
        silent_sso: Uncertainty::Unknown,
    };
    RunReport {
        account_scope: AccountScope::AllUsers,
        account: UserId(id.into()),
        mode: ExecutionMode::DryRun,
        process_close_policy: policy,
        sections: [
            Category::Application,
            Category::Browser,
            Category::WindowsMicrosoftAndDevTools,
        ]
        .into_iter()
        .map(|category| CategoryReport {
            category,
            warnings: if category == Category::WindowsMicrosoftAndDevTools {
                vec![everyout_engine::WINDOWS_DEV_SSO_WARNING.into()]
            } else {
                vec![]
            },
            aggregate: if category == manifest.category {
                AggregateStatus::Blocked
            } else {
                AggregateStatus::NotRequested
            },
            items: if category == manifest.category {
                vec![item.clone()]
            } else {
                vec![]
            },
            counts: Counts::default(),
        })
        .collect(),
    }
}
pub(crate) struct NativeAccounts {
    profiles: BTreeMap<String, AccountProfile>,
    held: Option<HeldPlan>,
    report: String,
    serial: u64,
    cancelled: Box<dyn Fn() -> bool>,
    source: Box<dyn ProfileSource>,
    hives: Box<dyn HiveApi>,
}
impl NativeAccounts {
    pub fn new(cancelled: Box<dyn Fn() -> bool>) -> Self {
        Self {
            profiles: BTreeMap::new(),
            held: None,
            report: "{}".into(),
            serial: 0,
            cancelled,
            source: Box::new(NativeProfiles),
            hives: Box::new(NativeHives),
        }
    }
    fn page(&self, page: u32, status: Status) -> BackendReply {
        // ASCII JSON escapes keep exact byte pagination safe for Unicode labels.
        let pages = self.report.len().div_ceil(2048).max(1);
        if page as usize >= pages {
            return BackendReply::status(Status::Rejected);
        }
        let start = page as usize * 2048;
        let end = (start + 2048).min(self.report.len());
        BackendReply {
            status,
            data: Some(ReplyData {
                plan_id: self.held.as_ref().map(|h| h.plan.id().0.clone()),
                digest: self.held.as_ref().map(|h| h.digest.clone()),
                page,
                pages: pages as u32,
                report: self.report[start..end].into(),
            }),
        }
    }
    fn save(&mut self, value: &impl serde::Serialize) -> Result<(), Status> {
        let json = serde_json::to_string(value).map_err(|_| Status::Rejected)?;
        self.report = json
            .chars()
            .flat_map(|c| {
                if c.is_ascii() {
                    c.to_string().chars().collect::<Vec<_>>()
                } else {
                    c.encode_utf16(&mut [0u16; 2])
                        .iter()
                        .flat_map(|u| format!("\\u{u:04x}").chars().collect::<Vec<_>>())
                        .collect()
                }
            })
            .collect();
        if self.report.len() > 4 * 1024 * 1024 {
            return Err(Status::Rejected);
        }
        Ok(())
    }
    fn enumerate(&mut self) -> Result<Status, Status> {
        self.held = None;
        self.profiles.clear();
        let inventory = inventory(&*self.source).map_err(|_| Status::ScopeUnavailable)?;
        let profiles = inventory.profiles;
        if profiles.len() > 64 {
            return Err(Status::ScopeUnavailable);
        }
        self.serial += 1;
        for (index, profile) in profiles.into_iter().enumerate() {
            self.profiles
                .insert(format!("account-{}-{index}", self.serial), profile);
        }
        let summaries: Vec<_> = self.profiles.iter().map(|(id,p)| serde_json::json!({ "account": id, "logged_on": p.logged_on(), "hive_mounted": p.mounted(), "limitations": [S6_UNVERIFIED,"special-temporary-nonlocal-and-ambiguous-profiles-excluded"] })).collect();
        self.save(
            &serde_json::json!({ "accounts": summaries,"exclusions": inventory.exclusions }),
        )?;
        Ok(Status::ProfilesReady)
    }
    fn plan(
        &mut self,
        selections: &[crate::protocol::Selection],
        policy: ProcessClosePolicy,
        catalog: &BTreeMap<String, Manifest>,
        run: &str,
    ) -> Result<Status, Status> {
        self.held = None;
        let mut selected = BTreeMap::<String, Vec<&crate::protocol::Selection>>::new();
        let mut seen = std::collections::HashSet::new();
        for selection in selections {
            if !seen.insert((&selection.account_id, &selection.provider_id)) {
                return Err(Status::Rejected);
            }
            if !self.profiles.contains_key(&selection.account_id) {
                return Err(Status::ScopeUnavailable);
            }
            let manifest = catalog
                .get(&selection.provider_id)
                .ok_or(Status::UnknownProvider)?;
            if manifest.revision != selection.revision {
                return Err(Status::StaleRevision);
            }
            selected
                .entry(selection.account_id.clone())
                .or_default()
                .push(selection);
        }
        let mut accounts = Vec::new();
        let mut roots = Vec::new();
        let mut physical = BTreeMap::new();
        for (id, items) in &selected {
            let profile = &self.profiles[id];
            let root = profile
                .revalidate(&*self.source)
                .and_then(|_| crate_root(profile, &*self.source));
            match root {
                Ok(root) => {
                    roots.push(root);
                    let (report, snapshots) = account_run(
                        id,
                        profile,
                        items,
                        catalog,
                        run,
                        policy,
                        None,
                        None,
                        &*self.cancelled,
                        &*self.source,
                        &*self.hives,
                    );
                    accounts.push(report);
                    physical.extend(snapshots);
                }
                Err(error) => {
                    let mut report =
                        AccountReport::failed(UserId(id.clone()), profile.logged_on(), error.kind);
                    report.sections = items
                        .iter()
                        .map(|s| blocked_section(id, &catalog[&s.provider_id], policy, error.kind))
                        .collect();
                    accounts.push(report);
                }
            }
        }
        let mut targets: Vec<(&str, &[PhysicalIdentity])> = Vec::new();
        let mut conflicts = std::collections::HashSet::new();
        for ((account, _), snapshots) in &physical {
            for chain in snapshots.iter().flatten() {
                if let Some(leaf) = chain.last() {
                    for (previous, prior) in &targets {
                        if prior.contains(leaf) || prior.last().is_some_and(|id| chain.contains(id))
                        {
                            conflicts.insert(account.as_str());
                            conflicts.insert(*previous);
                        }
                    }
                    targets.push((account, chain));
                }
            }
        }
        for account in &mut accounts {
            if conflicts.contains(account.account.0.as_str()) {
                account.issues.push("overlapping-account-targets".into());
            }
        }
        self.serial += 1;
        let plan = AccountsPlan::new(PlanId(format!("plan-{}", self.serial)), accounts, policy)
            .map_err(|_| Status::Rejected)?;
        self.save(plan.preview())?;
        let digest = format!("{:x}", Sha256::digest(self.report.as_bytes()));
        self.held = Some(HeldPlan {
            plan,
            selections: selections.to_vec(),
            digest,
            approval: None,
            physical,
            _roots: roots,
        });
        Ok(Status::PlanReady)
    }
    fn execute(
        &mut self,
        plan_id: &str,
        dry_run: bool,
        catalog: &BTreeMap<String, Manifest>,
        run: &str,
    ) -> Result<Status, Status> {
        let held = self
            .held
            .as_ref()
            .filter(|h| h.plan.id().0 == plan_id)
            .ok_or(Status::ScopeUnavailable)?;
        if dry_run {
            let preview = held.plan.preview().clone();
            let mut current = Vec::new();
            let mut fingerprints = BTreeMap::new();
            for expected in &preview.accounts {
                let profile = &self.profiles[&expected.account.0];
                let items: Vec<_> = held
                    .selections
                    .iter()
                    .filter(|s| s.account_id == expected.account.0)
                    .collect();
                let (report, physical) = account_run(
                    &expected.account.0,
                    profile,
                    &items,
                    catalog,
                    run,
                    held.plan.policy(),
                    None,
                    None,
                    &*self.cancelled,
                    &*self.source,
                    &*self.hives,
                );
                current.push(report);
                fingerprints.extend(physical);
            }
            let current = AccountsReport {
                scope: AccountScope::AllUsers,
                mode: ExecutionMode::DryRun,
                accounts: current,
            };
            let stable = canonical_value(&current).map_err(|_| Status::Rejected)?
                == canonical_value(&preview).map_err(|_| Status::Rejected)?
                && fingerprints == held.physical;
            self.save(&current)?;
            if !stable {
                self.held = None;
                return Err(Status::StaleRevision);
            }
            return Ok(Status::PlanReady);
        }
        let approval = held.approval.as_ref().ok_or(Status::ApprovalRequired)?;
        let report = held
            .plan
            .execute(approval, &*self.cancelled, |expected, consent| {
                if consent.is_none() {
                    return Err(ErrorKind::ScopeViolation);
                }
                if expected
                    .issues
                    .iter()
                    .any(|i| i == "overlapping-account-targets")
                {
                    return Err(ErrorKind::OwnershipConflict);
                }
                let profile = self
                    .profiles
                    .get(&expected.account.0)
                    .ok_or(ErrorKind::ScopeViolation)?;
                profile.revalidate(&*self.source).map_err(|e| e.kind)?;
                let items: Vec<_> = held
                    .selections
                    .iter()
                    .filter(|s| s.account_id == expected.account.0)
                    .collect();
                let (report, _) = account_run(
                    &expected.account.0,
                    profile,
                    &items,
                    catalog,
                    run,
                    held.plan.policy(),
                    Some((expected, &held.physical)),
                    consent,
                    &*self.cancelled,
                    &*self.source,
                    &*self.hives,
                );
                Ok(report)
            });
        // Consume the capability BEFORE returning results. Replay requires new
        // inventory, plan and review, even when a subset failed or was blocked.
        self.held = None;
        self.save(&report)?;
        Ok(Status::Completed)
    }
}
fn crate_root(
    profile: &AccountProfile,
    source: &dyn ProfileSource,
) -> everyout_platform_windows::Result<AllowedRoot> {
    AccountFolders {
        source,
        profile,
        hive: profile.sid(),
    }
    .resolve(KnownFolder::UserProfile)
}
use everyout_platform_windows::{KnownFolder, RootResolver};
impl AccountBackend for NativeAccounts {
    fn dispatch(
        &mut self,
        command: &Command,
        catalog: &BTreeMap<String, Manifest>,
        run: &str,
    ) -> BackendReply {
        let result = match command {
            Command::EnumerateProfiles => self.enumerate(),
            Command::Plan { selections } => {
                self.plan(selections, ProcessClosePolicy::Ask, catalog, run)
            }
            Command::PlanAccounts { selections, policy } => {
                self.plan(selections, *policy, catalog, run)
            }
            Command::Review {
                plan_id,
                digest,
                accounts,
            } => (|| {
                let held = self
                    .held
                    .as_mut()
                    .filter(|h| h.plan.id().0 == *plan_id && h.digest == *digest)
                    .ok_or(Status::Rejected)?;
                held.approval = Some(
                    held.plan
                        .approve(accounts.clone())
                        .map_err(|_| Status::Rejected)?,
                );
                Ok(Status::Reviewed)
            })(),
            Command::Execute { plan_id, dry_run } => self.execute(plan_id, *dry_run, catalog, run),
            // Closure runs as part of Engine::apply after review; standalone
            // closure cannot bypass account/category/loss acknowledgments.
            Command::CloseProcesses { .. } => Err(Status::ApprovalRequired),
            Command::ReadReport { page } => return self.page(*page, Status::Completed),
            Command::Report => return self.page(0, Status::Completed),
            Command::Finish => Ok(Status::Finished),
        };
        match result {
            Ok(status) => self.page(0, status),
            Err(status) => BackendReply::status(status),
        }
    }
}

struct AccountProcesses<'a> {
    profile: &'a AccountProfile,
    hive: &'a str,
    names: Vec<String>,
    gate: RefCell<Option<WindowsProcessGate>>,
    source: &'a dyn ProfileSource,
    cancelled: &'a dyn Fn() -> bool,
}
impl AccountProcesses<'_> {
    fn check(&self) -> Result<bool, ErrorKind> {
        if self.names.is_empty() {
            return Ok(false);
        }
        let inventory = everyout_platform_windows::process::enumerate_account_matches(
            self.profile,
            &self.names,
        )
        .map_err(|e| e.kind)?;
        if !inventory.unavailable.is_empty() {
            return Err(ErrorKind::AccessDenied);
        }
        if inventory.processes.is_empty() {
            return Ok(false);
        }
        let paths = NativeProfiles
            .installation_paths(self.hive, &self.names)
            .map_err(|e| e.kind)?;
        if paths.is_empty()
            || inventory
                .processes
                .iter()
                .any(|p| !p.matches(&self.names, &paths))
        {
            return Err(ErrorKind::OwnershipConflict);
        }
        let mut gate = self.gate.borrow_mut();
        if gate.is_none() {
            *gate = Some(WindowsProcessGate::reviewed_account(
                self.profile.clone(),
                self.names.clone(),
                paths,
            )?);
        }
        Ok(true)
    }
}
impl ProcessGate for AccountProcesses<'_> {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
        if !self.check()? {
            return Ok(vec![]);
        }
        self.gate
            .borrow()
            .as_ref()
            .ok_or(ErrorKind::StalePlan)?
            .preview()
    }
    fn close(&self, policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        if !self.check()? {
            return Ok(());
        }
        self.gate
            .borrow()
            .as_ref()
            .ok_or(ErrorKind::StalePlan)?
            .close_with_cancellation(policy, self.cancelled)
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        self.profile.revalidate(self.source).map_err(|e| e.kind)?;
        if self.check()? {
            Err(ErrorKind::Locked)
        } else {
            Ok(())
        }
    }
}
fn canonical(report: &RunReport) -> Result<serde_json::Value, ErrorKind> {
    canonical_value(report)
}
fn canonical_value(report: &impl serde::Serialize) -> Result<serde_json::Value, ErrorKind> {
    let mut value = serde_json::to_value(report).map_err(|_| ErrorKind::Io)?;
    fn strip(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(map) => {
                map.remove("snapshot_id");
                map.remove("plan_id");
                for v in map.values_mut() {
                    strip(v);
                }
            }
            serde_json::Value::Array(values) => {
                for v in values {
                    strip(v);
                }
            }
            _ => {}
        }
    }
    strip(&mut value);
    Ok(value)
}
#[allow(clippy::too_many_arguments)]
fn run_provider<P: EngineProvider + LocalOperations>(
    provider: &P,
    id: &str,
    category: Category,
    policy: ProcessClosePolicy,
    expected: Option<&RunReport>,
    consent: Option<&AccountConsent>,
    cancelled: &dyn Fn() -> bool,
    validate_binding: &dyn Fn() -> Result<(), ErrorKind>,
) -> Result<RunReport, ErrorKind> {
    let engine = Engine::for_account(UserId(id.into()), provider);
    let inventory = engine.scan(&[provider], category, &mut |_| {})?;
    let selected = inventory.default_selection(category);
    let prepared = engine.prepare(inventory, category, &selected, policy, &mut |_| {})?;
    if let Some(expected) = expected {
        if canonical(prepared.preview())? != canonical(expected)? {
            return Err(ErrorKind::StalePlan);
        }
    } else {
        return Ok(prepared.preview().clone());
    }
    validate_binding()?;
    let consent = consent.ok_or(ErrorKind::ScopeViolation)?;
    let mut approval = Approval {
        confirmations: consent.confirmations.clone(),
        force_close_acknowledged: consent.force_close_acknowledged,
        ..Default::default()
    };
    if consent.windows_dev_confirmed {
        approval.category_confirmation = Some(prepared.confirm_category());
    }
    for item in prepared.preview().sections.iter().flat_map(|s| &s.items) {
        approval
            .confirmed_risks
            .push(prepared.confirm_risks(&item.instance, &consent.risks));
    }
    Ok(engine.apply(prepared, approval, cancelled, &mut |_| {}))
}
#[allow(clippy::too_many_arguments)]
fn account_run(
    id: &str,
    profile: &AccountProfile,
    selections: &[&crate::protocol::Selection],
    catalog: &BTreeMap<String, Manifest>,
    run: &str,
    policy: ProcessClosePolicy,
    expected: ExpectedAccount<'_>,
    consent: Option<&AccountConsent>,
    cancelled: &dyn Fn() -> bool,
    source: &dyn ProfileSource,
    hives: &dyn HiveApi,
) -> (AccountReport, BTreeMap<(String, String), PhysicalSnapshot>) {
    let mut physical = BTreeMap::new();
    let result = with_hive(hives, profile, run, |hive| {
        let mut report = AccountReport::empty(UserId(id.into()), profile.logged_on());
        if profile.logged_on() {
            report.limitations.push(
                "unverified-cross-session-graceful-access-hard-kill-may-have-zero-window-requests"
                    .into(),
            );
        }
        let resolver = AccountFolders {
            source,
            profile,
            hive,
        };
        for selection in selections {
            let manifest = &catalog[&selection.provider_id];
            if cancelled() {
                report.issues.push("account-cancelled".into());
                report
                    .sections
                    .push(blocked_section(id, manifest, policy, ErrorKind::Cancelled));
                continue;
            }
            if manifest.revision != selection.revision {
                report
                    .issues
                    .push(format!("{}-stale-revision", manifest.id));
                continue;
            }
            let processes = AccountProcesses {
                profile,
                hive,
                names: manifest.identity.process_names.clone(),
                gate: RefCell::new(None),
                source,
                cancelled,
            };
            let json = serde_json::to_string(manifest).map_err(|_| {
                everyout_platform_windows::PlatformError {
                    kind: ErrorKind::InvalidManifest,
                    os_code: None,
                    applied: 0,
                }
            })?;
            let before = expected.and_then(|(e, _)| {
                e.sections.iter().find(|s| {
                    s.sections.iter().flat_map(|c| &c.items).any(|i| {
                        i.plan
                            .as_ref()
                            .is_some_and(|p| p.provider_id.0 == manifest.id)
                    })
                })
            });
            let mut execute = || -> Result<RunReport, ErrorKind> {
                if expected.is_some() && before.is_none() {
                    return Err(ErrorKind::Unsupported);
                }
                if matches!(manifest.roots[0], Root::Registry { .. }) {
                    let provider =
                        RegistryExecutor::load(&json, hive, UserId(id.into()), &processes)?;
                    run_provider(
                        &provider,
                        id,
                        manifest.category,
                        policy,
                        before,
                        consent,
                        cancelled,
                        &|| Ok(()),
                    )
                } else {
                    let provider = ManifestExecutor::load(
                        &json,
                        &resolver,
                        UserId(id.into()),
                        InstallationId(manifest.id.clone()),
                        &processes,
                    )?;
                    // Prepare first to collect opaque file identity bindings.
                    let preview = run_provider(
                        &provider,
                        id,
                        manifest.category,
                        policy,
                        None,
                        None,
                        cancelled,
                        &|| Ok(()),
                    )?;
                    let snapshot = provider.physical_snapshot()?;
                    if let Some((_, held)) = expected {
                        if held.get(&(id.into(), manifest.id.clone())) != Some(&snapshot) {
                            return Err(ErrorKind::StalePlan);
                        }
                    }
                    physical.insert((id.into(), manifest.id.clone()), snapshot);
                    if before.is_none() {
                        Ok(preview)
                    } else {
                        run_provider(
                            &provider,
                            id,
                            manifest.category,
                            policy,
                            before,
                            consent,
                            cancelled,
                            &|| {
                                let snapshot = provider.physical_snapshot()?;
                                if expected.is_some_and(|(_, held)| {
                                    held.get(&(id.into(), manifest.id.clone())) != Some(&snapshot)
                                }) {
                                    return Err(ErrorKind::StalePlan);
                                }
                                Ok(())
                            },
                        )
                    }
                }
            };
            match execute() {
                Ok(section) => report.sections.push(section),
                Err(kind) => {
                    report.issues.push(format!("{}-{kind:?}", manifest.id));
                    report
                        .sections
                        .push(blocked_section(id, manifest, policy, kind));
                }
            }
            if manifest.category == Category::WindowsMicrosoftAndDevTools {
                report
                    .limitations
                    .push(everyout_engine::WINDOWS_DEV_SSO_WARNING.into());
            }
        }
        Ok(report)
    });
    let mut report = match result.operation {
        Ok(report) => report,
        Err(e) => {
            let mut report = AccountReport::failed(UserId(id.into()), profile.logged_on(), e.kind);
            report.sections = selections
                .iter()
                .map(|selection| {
                    blocked_section(id, &catalog[&selection.provider_id], policy, e.kind)
                })
                .collect();
            report
        }
    };
    if expected.is_some() {
        for section in &mut report.sections {
            section.mode = ExecutionMode::Apply;
        }
    }
    report.residual_hive = result.cleanup.residual;
    report.residual_hku_key = if result.cleanup.residual {
        result.cleanup.temporary_key
    } else {
        None
    };
    report.unload_attempts = result.cleanup.unload_attempts;
    if report.residual_hive {
        report
            .issues
            .push("temporary-hku-mount-remains-manual-recovery-required".into());
    }
    (report, physical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeSet,
        path::PathBuf,
        rc::Rc,
    };
    const A: &str = "S-1-5-21-11-22-33-1001";
    const B: &str = "S-1-5-21-11-22-33-1002";
    type PlatformResult<T> = everyout_platform_windows::Result<T>;
    struct Source(Rc<RefCell<Vec<ProfileRecord>>>);
    impl ProfileSource for Source {
        fn records(&self) -> PlatformResult<Vec<ProfileRecord>> {
            Ok(self.0.borrow().clone())
        }
        fn folder(&self, _hive: &str, _folder: KnownFolder) -> PlatformResult<Option<String>> {
            Ok(None)
        }
    }
    #[derive(Default)]
    struct Hives {
        temporary: RefCell<BTreeSet<String>>,
        loads: RefCell<Vec<String>>,
        unloads: Cell<usize>,
        failures: Cell<usize>,
        fail_load: Cell<bool>,
    }
    struct FakeHives(Rc<Hives>);
    impl std::ops::Deref for FakeHives {
        type Target = Hives;
        fn deref(&self) -> &Hives {
            &self.0
        }
    }
    impl HiveApi for FakeHives {
        fn mounted(&self, key: &str) -> PlatformResult<bool> {
            Ok(key == B || self.temporary.borrow().contains(key))
        }
        fn logged_on(&self, sid: &str) -> PlatformResult<bool> {
            Ok(sid == B)
        }
        fn load(&self, p: &AccountProfile, key: &str) -> PlatformResult<()> {
            assert_ne!(p.sid(), B);
            if self.fail_load.get() {
                return Err(everyout_platform_windows::PlatformError {
                    kind: ErrorKind::AccessDenied,
                    os_code: Some(5),
                    applied: 0,
                });
            }
            self.loads.borrow_mut().push(p.sid().into());
            self.temporary.borrow_mut().insert(key.into());
            Ok(())
        }
        fn unload(&self, key: &str) -> PlatformResult<()> {
            assert!(key.starts_with("EveryOut-"));
            self.unloads.set(self.unloads.get() + 1);
            if self.failures.get() > 0 {
                self.failures.set(self.failures.get() - 1);
                return Err(everyout_platform_windows::PlatformError {
                    kind: ErrorKind::Locked,
                    os_code: Some(170),
                    applied: 0,
                });
            }
            self.temporary.borrow_mut().remove(key);
            Ok(())
        }
    }
    fn catalog() -> BTreeMap<String, Manifest> {
        let mut value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../catalog/apps/example-electron-cef.json"
        ))
        .unwrap();
        value["support"] = "validated".into();
        value["compatibility"]["product_versions"] = "synthetic-only-v1".into();
        value["confidence"]["version_coverage"] = "synthetic-only-v1".into();
        value["confidence"]["status"] = "verified".into();
        value["open_spikes"] = serde_json::json!([]);
        value["identity"]["process_names"] = serde_json::json!([]);
        value["risks"] = serde_json::json!({"flags":[],"affected_data":[],"permanent_data_loss":"none","confirmations":[],"evidence":["fixture-evidence"]});
        for method in value["cleaning_methods"].as_array_mut().unwrap() {
            method["blockers"] = serde_json::json!([]);
        }
        let manifest = everyout_providers::load_manifest(&value.to_string()).unwrap();
        BTreeMap::from([(manifest.id.clone(), manifest)])
    }
    type Lab = (
        tempfile::TempDir,
        NativeAccounts,
        Rc<RefCell<Vec<ProfileRecord>>>,
        Rc<Hives>,
        BTreeMap<String, Manifest>,
    );
    fn lab() -> Lab {
        let fixture = tempfile::tempdir().unwrap();
        let catalog = catalog();
        let mut records = Vec::new();
        for (sid, leaf, live) in [(A, "alpha", false), (B, "beta", true)] {
            let root = fixture.path().join(leaf);
            let app = root
                .join("AppData")
                .join("Roaming")
                .join("EveryOutFixtureElectron");
            std::fs::create_dir_all(&app).unwrap();
            std::fs::write(app.join("Cookies"), b"fixture-only").unwrap();
            std::fs::write(app.join("canary.txt"), b"preserve").unwrap();
            records.push(ProfileRecord {
                sid: sid.into(),
                path: root,
                local_user: true,
                special: false,
                temporary: false,
                logged_on: live,
                hive_mounted: live,
            });
        }
        let records = Rc::new(RefCell::new(records));
        let hives = Rc::new(Hives::default());
        let mut backend = NativeAccounts::new(Box::new(|| false));
        backend.source = Box::new(Source(records.clone()));
        backend.hives = Box::new(FakeHives(hives.clone()));
        (fixture, backend, records, hives, catalog)
    }
    fn selections(backend: &NativeAccounts) -> Vec<crate::protocol::Selection> {
        backend
            .profiles
            .keys()
            .map(|id| crate::protocol::Selection {
                provider_id: "example-electron-cef".into(),
                revision: 1,
                account_id: id.clone(),
            })
            .collect()
    }
    fn review(
        backend: &mut NativeAccounts,
        catalog: &BTreeMap<String, Manifest>,
        run: &str,
    ) -> String {
        let held = backend.held.as_ref().unwrap();
        let id = held.plan.id().0.clone();
        let digest = held.digest.clone();
        let accounts = backend
            .profiles
            .keys()
            .map(|id| AccountConsent {
                account: id.clone(),
                ..Default::default()
            })
            .collect();
        assert_eq!(
            backend
                .dispatch(
                    &Command::Review {
                        plan_id: id.clone(),
                        digest,
                        accounts
                    },
                    catalog,
                    run
                )
                .status,
            Status::Reviewed
        );
        id
    }
    #[test]
    fn native_sequence_uses_fake_hives_and_temp_accounts_and_requires_review() {
        let (fixture, mut backend, _records, hives, catalog) = lab();
        let run = "a".repeat(64);
        assert_eq!(
            backend
                .dispatch(&Command::EnumerateProfiles, &catalog, &run)
                .status,
            Status::ProfilesReady
        );
        let selected = selections(&backend);
        assert_eq!(
            backend
                .dispatch(
                    &Command::Plan {
                        selections: selected
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::PlanReady
        );
        let plan_id = backend.held.as_ref().unwrap().plan.id().0.clone();
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: plan_id.clone(),
                        dry_run: false
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::ApprovalRequired
        );
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: plan_id.clone(),
                        dry_run: true
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::PlanReady
        );
        for leaf in ["alpha", "beta"] {
            assert!(fixture
                .path()
                .join(leaf)
                .join("AppData/Roaming/EveryOutFixtureElectron/Cookies")
                .exists());
        }
        let id = review(&mut backend, &catalog, &run);
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: id.clone(),
                        dry_run: false
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::Completed
        );
        for leaf in ["alpha", "beta"] {
            let app = fixture
                .path()
                .join(leaf)
                .join("AppData/Roaming/EveryOutFixtureElectron");
            assert!(!app.join("Cookies").exists());
            assert!(app.join("canary.txt").exists());
        }
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: id,
                        dry_run: false
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::ScopeUnavailable
        );
        assert!(hives.temporary.borrow().is_empty());
        assert!(hives.loads.borrow().iter().all(|sid| sid == A));
        let output: serde_json::Value = serde_json::from_str(&backend.report).unwrap();
        assert_eq!(output["accounts"].as_array().unwrap().len(), 2);
        assert!(backend.report.contains(S6_UNVERIFIED));
        assert!(!backend.report.contains(A));
        assert!(!backend.report.contains(B));
        assert!(!backend.report.contains("fixture-only"));
    }
    #[test]
    fn stale_account_does_not_abort_other_account_and_hive_residual_blocks_apply() {
        let (fixture, mut backend, records, hives, catalog) = lab();
        let run = "b".repeat(64);
        backend.enumerate().unwrap();
        backend
            .plan(
                &selections(&backend),
                ProcessClosePolicy::Ask,
                &catalog,
                &run,
            )
            .unwrap();
        let id = review(&mut backend, &catalog, &run);
        records.borrow_mut()[0].path = PathBuf::from(r"C:\missing-synthetic-profile");
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: id,
                        dry_run: false
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::Completed
        );
        assert!(fixture
            .path()
            .join("alpha/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        assert!(!fixture
            .path()
            .join("beta/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        records.borrow_mut()[0].path = fixture.path().join("alpha");
        backend.enumerate().unwrap();
        hives.failures.set(3);
        backend
            .plan(
                &selections(&backend),
                ProcessClosePolicy::Ask,
                &catalog,
                &run,
            )
            .unwrap();
        assert!(backend.held.as_ref().unwrap().plan.preview().accounts[0].residual_hive);
        let id = review(&mut backend, &catalog, &run);
        backend.dispatch(
            &Command::Execute {
                plan_id: id,
                dry_run: false,
            },
            &catalog,
            &run,
        );
        assert!(fixture
            .path()
            .join("alpha/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        assert!(backend.report.contains("temporary-hku-mount-remains"));
    }
    #[test]
    fn preview_digest_wrong_account_stale_files_and_unicode_paging_are_checked() {
        let (fixture, mut backend, _records, _hives, catalog) = lab();
        let run = "c".repeat(64);
        backend.enumerate().unwrap();
        backend
            .plan(
                &selections(&backend),
                ProcessClosePolicy::Ask,
                &catalog,
                &run,
            )
            .unwrap();
        let held = backend.held.as_ref().unwrap();
        let id = held.plan.id().0.clone();
        assert_eq!(
            backend
                .dispatch(
                    &Command::Review {
                        plan_id: id.clone(),
                        digest: "0".repeat(64),
                        accounts: vec![]
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::Rejected
        );
        review(&mut backend, &catalog, &run);
        std::fs::write(
            fixture
                .path()
                .join("alpha/AppData/Roaming/EveryOutFixtureElectron/Cookies"),
            b"changed-fixture-size",
        )
        .unwrap();
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: id,
                        dry_run: true
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::StaleRevision
        );
        assert!(backend.held.is_none());
        let value = serde_json::json!({"text":"żółć🐈".repeat(1000)});
        backend.save(&value).unwrap();
        let mut output = String::new();
        let pages = backend.page(0, Status::Completed).data.unwrap().pages;
        for page in 0..pages {
            let reply = backend.page(page, Status::Completed);
            assert!(encode(&Response {
                version: VERSION,
                sequence: page as u64,
                status: reply.status,
                data: reply.data
            })
            .is_ok());
            output.push_str(&backend.page(page, Status::Completed).data.unwrap().report);
        }
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&output).unwrap(),
            value
        );
    }
    #[test]
    fn same_size_replacement_refuses_one_account_and_preserves_the_other() {
        let (fixture, mut backend, _records, _hives, catalog) = lab();
        let run = "d".repeat(64);
        backend.enumerate().unwrap();
        backend
            .plan(
                &selections(&backend),
                ProcessClosePolicy::Ask,
                &catalog,
                &run,
            )
            .unwrap();
        let id = review(&mut backend, &catalog, &run);
        let cookie = fixture
            .path()
            .join("alpha/AppData/Roaming/EveryOutFixtureElectron/Cookies");
        std::fs::rename(&cookie, cookie.with_file_name("old-fixture")).unwrap();
        std::fs::write(&cookie, b"fixture-only").unwrap();
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: id,
                        dry_run: false
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::Completed
        );
        assert!(cookie.exists());
        assert!(!fixture
            .path()
            .join("beta/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        assert!(backend.report.contains("StalePlan"));
    }
    #[test]
    fn failed_mount_retains_provider_sections_while_live_account_completes() {
        let (fixture, mut backend, _records, hives, catalog) = lab();
        let run = "f".repeat(64);
        hives.fail_load.set(true);
        backend.enumerate().unwrap();
        backend
            .plan(
                &selections(&backend),
                ProcessClosePolicy::Ask,
                &catalog,
                &run,
            )
            .unwrap();
        let preview = backend.held.as_ref().unwrap().plan.preview();
        assert_eq!(preview.accounts[0].sections.len(), 1);
        assert_eq!(preview.accounts[0].sections[0].sections.len(), 3);
        let id = review(&mut backend, &catalog, &run);
        assert_eq!(
            backend
                .dispatch(
                    &Command::Execute {
                        plan_id: id,
                        dry_run: false
                    },
                    &catalog,
                    &run
                )
                .status,
            Status::Completed
        );
        assert!(fixture
            .path()
            .join("alpha/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        assert!(!fixture
            .path()
            .join("beta/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        let report: serde_json::Value = serde_json::from_str(&backend.report).unwrap();
        assert_eq!(report["accounts"][0]["sections"][0]["mode"], "apply");
        assert_eq!(
            report["accounts"][0]["sections"][0]["sections"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        assert!(backend.report.contains("AccessDenied"));
        assert_eq!(hives.unloads.get(), 0);
        assert!(hives.temporary.borrow().is_empty());
    }
    #[test]
    fn cancellation_keeps_completed_effects_unloads_offline_hive_and_skips_next_account() {
        let (fixture, mut backend, _records, hives, catalog) = lab();
        let run = "e".repeat(64);
        let cookie = fixture
            .path()
            .join("alpha/AppData/Roaming/EveryOutFixtureElectron/Cookies");
        let cancellation_cookie = cookie.clone();
        backend.cancelled = Box::new(move || !cancellation_cookie.exists());
        backend.enumerate().unwrap();
        backend
            .plan(
                &selections(&backend),
                ProcessClosePolicy::Ask,
                &catalog,
                &run,
            )
            .unwrap();
        let id = review(&mut backend, &catalog, &run);
        backend.dispatch(
            &Command::Execute {
                plan_id: id,
                dry_run: false,
            },
            &catalog,
            &run,
        );
        assert!(!cookie.exists());
        assert!(fixture
            .path()
            .join("beta/AppData/Roaming/EveryOutFixtureElectron/Cookies")
            .exists());
        assert!(hives.temporary.borrow().is_empty());
        assert_eq!(hives.loads.borrow().len(), 2);
        assert_eq!(hives.unloads.get(), 2);
        assert!(backend.report.contains("applied"));
        assert!(backend.report.contains("cancelled"));
    }
}
