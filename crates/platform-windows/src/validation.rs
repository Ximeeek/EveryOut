//! Filesystem-first controlled validation. No manifest wipe router, registry,
//! credential API, token parser, database reader or payload-copy primitive.
use crate::{
    native::{self, Info},
    observation::{self, snapshot, SnapshotBudget},
    process,
    win32_identity::{IdentitySource, Win32Snapshot},
    AllowedRoot, PlatformError, Result,
};
use everyout_core_model::{local_validation::*, observation::*, *};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use windows_sys::Win32::Storage::FileSystem::*;
mod journal;
pub use journal::JournalStore;

fn error(kind: ErrorKind) -> PlatformError {
    PlatformError::new(kind)
}
fn physical(info: &Info) -> FileIdentity {
    FileIdentity {
        volume: info.identity.volume,
        index: info.identity.index,
    }
}
pub fn random_id() -> Result<String> {
    use windows_sys::Win32::Security::Cryptography::{
        BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    };
    let mut bytes = [0u8; 16];
    if unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err(error(ErrorKind::Io));
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn binding(expected: &ApplicationBinding) -> Result<ApplicationBinding> {
    // P2's optional channel field is a descriptive UI label. No native channel
    // source exists yet; echoing that label would manufacture applicability.
    // A known channel requires an adapter/independent resolver before mutation.
    if expected.channel.is_some() {
        return Err(error(ErrorKind::Unsupported));
    }
    let path = expected
        .executable_path
        .strip_prefix("\\\\?\\")
        .unwrap_or(&expected.executable_path);
    let mut selected = Win32Snapshot::default();
    selected.observe_executable(Path::new(path), IdentitySource::Selected, None)?;
    let actual =
        observation::application_binding(&selected.applications[0], expected.channel.clone())?;
    let mut prior = expected.clone();
    prior.selected_process = actual.selected_process;
    if prior != actual {
        return Err(error(ErrorKind::StalePlan));
    }
    Ok(actual)
}

/// Resolve only descendants of already granted user storage roots. Broad bases,
/// shared browser/WebView/SSO layouts and roots containing other identities fail.
fn resolve_roots(learned: &LearnedObservation, bases: &[AllowedRoot]) -> Result<Vec<AllowedRoot>> {
    let mut roots = vec![];
    for observed in &learned.roots {
        let target = Path::new(
            observed
                .root
                .strip_prefix("\\\\?\\")
                .unwrap_or(&observed.root),
        );
        let root = bases
            .iter()
            .find_map(|base| {
                let base_path = base.metadata_path().ok()?;
                let relative = target.strip_prefix(base_path).ok()?.to_str()?;
                base.discovery_descendant(relative).ok()
            })
            .ok_or_else(|| error(ErrorKind::ScopeViolation))?;
        if physical(&root.handle().info()?) != observed.physical {
            return Err(error(ErrorKind::StalePlan));
        }
        let path = root
            .metadata_path()?
            .to_string_lossy()
            .replace('\\', "/")
            .to_lowercase();
        let unsafe_parts = [
            "user data",
            "webview",
            "webview2",
            "ebwebview",
            "identitycache",
            "tokenbroker",
            "packages",
        ];
        if path.split('/').any(|part| unsafe_parts.contains(&part)) {
            return Err(error(ErrorKind::Unsupported));
        }
        let captured = snapshot(&root, SnapshotBudget::default())?;
        let names: BTreeSet<_> = captured
            .entries
            .keys()
            .map(|p| p.rsplit('/').next().unwrap_or(p).to_ascii_lowercase())
            .collect();
        let shared_browser_layout = names.contains("cookies.sqlite")
            && names.contains("places.sqlite")
            || names.contains("local state")
                && names.contains("web data")
                && names.contains("login data");
        if captured.completeness != Completeness::Complete
            || shared_browser_layout
            || captured
                .entries
                .keys()
                .any(|p| p.to_lowercase().ends_with(".exe"))
        {
            return Err(error(ErrorKind::Unsupported));
        }
        roots.push(root);
    }
    Ok(roots)
}

/// Additional owner records are consulted at every effect; matching is physical,
/// not based on product names. Inventory supplies independently bound root claims.
pub trait OwnershipGuard {
    fn check(&self, binding: &ApplicationBinding, roots: &[RootObservation]) -> Result<()>;
}
fn check_ownership(guard: &dyn OwnershipGuard, learned: &LearnedObservation) -> Result<()> {
    if learned.roots.iter().any(|r| {
        !matches!(
            r.ownership.state,
            StorageOwnership::Corroborated | StorageOwnership::Exclusive
        )
    }) {
        return Err(error(ErrorKind::OwnershipConflict));
    }
    guard.check(&learned.binding, &learned.roots)
}
fn app_path(binding: &ApplicationBinding) -> &Path {
    Path::new(
        binding
            .executable_path
            .strip_prefix("\\\\?\\")
            .unwrap_or(&binding.executable_path),
    )
}
fn track(
    binding: &ApplicationBinding,
    retained: &mut Vec<ProcessBinding>,
) -> Result<process::ProcessInventory> {
    let inventory = process::enumerate_bound_tree(app_path(binding), retained)?;
    for p in &inventory.processes {
        let id = ProcessBinding {
            pid: p.pid(),
            creation_ticks: p.creation_ticks(),
        };
        if !retained.contains(&id) {
            retained.push(id);
        }
    }
    Ok(inventory)
}
fn close_gate(binding: &ApplicationBinding, retained: &mut Vec<ProcessBinding>) -> Result<()> {
    let inventory = track(binding, retained)?;
    let selected: Vec<_> = inventory.processes.iter().collect();
    let report = process::close_processes(&selected, ProcessClosePolicy::Ask, false);
    if !report.remaining.is_empty() {
        return Err(error(ErrorKind::Locked));
    }
    for _ in 0..3 {
        if !track(binding, retained)?.processes.is_empty() {
            return Err(error(ErrorKind::Locked));
        }
        thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}

fn root_index(learned: &LearnedObservation, scope: &FamilyScope) -> Result<usize> {
    learned
        .roots
        .iter()
        .position(|r| {
            r.root == scope.root
                && r.families
                    .iter()
                    .any(|f| f.family == scope.family && approved_family(f))
        })
        .ok_or_else(|| error(ErrorKind::ScopeViolation))
}
fn relatives(root: &AllowedRoot, family: &str) -> Result<Vec<String>> {
    crate::components(family)?;
    let normalized = family.replace('\\', "/").to_lowercase();
    if normalized.contains(".everyout-validation-")
        || normalized.split('/').any(|p| {
            matches!(p, "cache" | "code cache" | "gpucache" | "leveldb")
                && !normalized.ends_with("/leveldb")
        })
    {
        return Err(error(ErrorKind::Unsupported));
    }
    if normalized.ends_with(".ldb") || normalized.ends_with(".log") {
        return Err(error(ErrorKind::Unsupported));
    }
    let target = root.path(family)?;
    let info = target.observation_info()?;
    let actual = if info.is_some() {
        target
            .canonical_metadata_path()?
            .strip_prefix(root.metadata_path()?)
            .map_err(|_| error(ErrorKind::ScopeViolation))?
            .to_string_lossy()
            .replace('\\', "/")
    } else {
        family.into()
    };
    if info.as_ref().is_some_and(|i| i.directory) {
        return Ok(vec![actual]);
    }
    if [".db", ".sqlite", ".sqlite3"]
        .iter()
        .any(|e| normalized.ends_with(e))
    {
        return Ok(["", "-wal", "-shm", "-journal"]
            .iter()
            .map(|suffix| format!("{actual}{suffix}"))
            .collect());
    }
    if info.is_some() {
        return Ok(vec![actual]);
    }
    Err(error(ErrorKind::Unsupported))
}
fn parent(root: &AllowedRoot, relative: &str) -> Result<(AllowedRoot, String)> {
    let parts = crate::components(relative)?;
    let name = parts.last().expect("nonempty").clone();
    let parent = if parts.len() == 1 {
        root.clone()
    } else {
        root.discovery_descendant(&parts[..parts.len() - 1].join("/"))?
    };
    Ok((parent, name))
}
fn object(root: &AllowedRoot, relative: &str) -> Result<Option<FileIdentity>> {
    Ok(root
        .path(relative)?
        .observation_info()?
        .map(|i| physical(&i)))
}
fn rename(
    root: &AllowedRoot,
    from: &str,
    to: &str,
    expected: FileIdentity,
    parent_id: FileIdentity,
) -> Result<()> {
    let (parent, name) = parent(root, from)?;
    let (target_parent, target_name) = self::parent(root, to)?;
    if physical(&parent.handle().info()?) != parent_id
        || physical(&target_parent.handle().info()?) != parent_id
    {
        return Err(error(ErrorKind::StalePlan));
    }
    if object(root, to)?.is_some() {
        return Err(error(ErrorKind::ScopeViolation));
    }
    let target = native::child(parent.handle(), OsStr::new(&name), None, true)?;
    if physical(&target.info()?) != expected {
        return Err(error(ErrorKind::StalePlan));
    }
    target.rename(parent.handle(), &target_name)?;
    if physical(&target.info()?) != expected {
        return Err(error(ErrorKind::StalePlan));
    }
    drop(target);
    if object(root, to)? != Some(expected) {
        return Err(error(ErrorKind::StalePlan));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checkpoint {
    Prepared,
    Quarantined,
    AppLaunched,
    ReplacementObserved,
    BeforeRollback,
    ReplacementMoved,
    RestoreTransition,
}
/// Fault injection exists only in the fresh-fixture build. Production cannot
/// bypass any gate; errors leave a durable recoverable session.
#[derive(Default)]
pub struct Faults {
    #[cfg(feature = "test-fixtures")]
    pub crash_at: Option<Checkpoint>,
}
impl Faults {
    fn hit(&mut self, checkpoint: Checkpoint) -> Result<()> {
        #[cfg(feature = "test-fixtures")]
        if self.crash_at == Some(checkpoint) {
            self.crash_at = None;
            return Err(error(ErrorKind::Io));
        }
        let _ = checkpoint;
        Ok(())
    }
}

struct Quarantine {
    learned: LearnedObservation,
    roots: Vec<AllowedRoot>,
    journal: ValidationJournal,
}
impl Quarantine {
    fn prepare(
        learned: &LearnedObservation,
        roots: Vec<AllowedRoot>,
        scope: &[FamilyScope],
        store: &JournalStore,
    ) -> Result<Self> {
        let id = random_id()?;
        let mut slots = vec![];
        let mut used = BTreeSet::new();
        for family in scope {
            let root = &roots[root_index(learned, family)?];
            for relative in relatives(root, &family.family)? {
                if !used.insert((family.root.clone(), relative.clone())) {
                    return Err(error(ErrorKind::ScopeViolation));
                }
                let (parent, _) = self::parent(root, &relative)?;
                let prefix = relative
                    .rsplit_once('/')
                    .map(|(p, _)| format!("{p}/"))
                    .unwrap_or_default();
                let quarantine =
                    format!("{prefix}.everyout-validation-{id}-{}-original", slots.len());
                let generated = format!(
                    "{prefix}.everyout-validation-{id}-{}-generated",
                    slots.len()
                );
                if object(root, &quarantine)?.is_some() || object(root, &generated)?.is_some() {
                    return Err(error(ErrorKind::ScopeViolation));
                }
                let info = root.path(&relative)?.observation_info()?;
                slots.push(QuarantineSlot {
                    scope: family.clone(),
                    original_relative: relative,
                    quarantine_relative: quarantine,
                    generated_relative: generated,
                    original: info.as_ref().map(physical),
                    original_directory: info.as_ref().map(|i| i.directory),
                    generated: None,
                    parent: physical(&parent.handle().info()?),
                    root: physical(&root.handle().info()?),
                    stage: SlotStage::Prepared,
                });
            }
        }
        // Refuse overlapping families: a parent quarantine would hide another
        // saved object and make inference on recovery ambiguous.
        for a in &slots {
            for b in &slots {
                if a.scope.root == b.scope.root
                    && a.original_relative != b.original_relative
                    && b.original_relative
                        .starts_with(&format!("{}/", a.original_relative))
                {
                    return Err(error(ErrorKind::ScopeViolation));
                }
            }
        }
        let journal = ValidationJournal {
            schema: 1,
            session_id: id,
            observation_id: learned.session_id.clone(),
            binding: learned.binding.clone(),
            roots: learned.roots.clone(),
            slots,
            processes: vec![],
            stage: JournalStage::Prepared,
            delete_generated_after_verified_restore: true,
        };
        store.save(&journal)?;
        Ok(Self {
            learned: learned.clone(),
            roots,
            journal,
        })
    }
    fn gate(&mut self, guard: &dyn OwnershipGuard) -> Result<()> {
        binding(&self.learned.binding)?;
        check_ownership(guard, &self.learned)?;
        close_gate(&self.learned.binding, &mut self.journal.processes)?;
        for (root, saved) in self.roots.iter().zip(&self.learned.roots) {
            root.metadata_path()?;
            if physical(&root.handle().info()?) != saved.physical {
                return Err(error(ErrorKind::StalePlan));
            }
        }
        Ok(())
    }
    fn intervene(
        &mut self,
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
        faults: &mut Faults,
    ) -> Result<()> {
        faults.hit(Checkpoint::Prepared)?;
        for index in 0..self.journal.slots.len() {
            self.gate(guard)?;
            store.save(&self.journal)?;
            let slot = &self.journal.slots[index];
            let root = &self.roots[root_index(&self.learned, &slot.scope)?];
            if object(root, &slot.original_relative)? != slot.original {
                return Err(error(ErrorKind::StalePlan));
            }
            if let Some(original) = slot.original {
                rename(
                    root,
                    &slot.original_relative,
                    &slot.quarantine_relative,
                    original,
                    slot.parent,
                )?;
            }
            self.journal.slots[index].stage = SlotStage::Quarantined;
            store.save(&self.journal)?;
        }
        self.journal.stage = JournalStage::Quarantined;
        store.save(&self.journal)?;
        faults.hit(Checkpoint::Quarantined)
    }
    fn rollback(
        &mut self,
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
        faults: &mut Faults,
    ) -> Result<()> {
        self.gate(guard)?;
        faults.hit(Checkpoint::BeforeRollback)?;
        self.journal.stage = JournalStage::RollingBack;
        store.save(&self.journal)?;
        for i in (0..self.journal.slots.len()).rev() {
            self.gate(guard)?;
            let slot = self.journal.slots[i].clone();
            let root = &self.roots[root_index(&self.learned, &slot.scope)?];
            let (parent, _) = self::parent(root, &slot.original_relative)?;
            if physical(&parent.handle().info()?) != slot.parent
                || physical(&root.handle().info()?) != slot.root
            {
                return Err(error(ErrorKind::StalePlan));
            }
            let original = object(root, &slot.original_relative)?;
            let quarantined = object(root, &slot.quarantine_relative)?;
            if original == slot.original && quarantined.is_none() {
                self.journal.slots[i].stage = SlotStage::Restored;
                store.save(&self.journal)?;
                continue;
            }
            if quarantined != slot.original {
                return Err(error(ErrorKind::StalePlan));
            }
            if let Some(replacement) = original {
                faults.hit(Checkpoint::ReplacementObserved)?;
                let generated = object(root, &slot.generated_relative)?;
                if generated.is_some() {
                    return Err(error(ErrorKind::ScopeViolation));
                }
                self.journal.slots[i].generated = Some(replacement);
                self.journal.slots[i].stage = SlotStage::ReplacementPrepared;
                store.save(&self.journal)?;
                self.gate(guard)?;
                let root = &self.roots[root_index(&self.learned, &slot.scope)?];
                rename(
                    root,
                    &slot.original_relative,
                    &slot.generated_relative,
                    replacement,
                    slot.parent,
                )?;
                faults.hit(Checkpoint::ReplacementMoved)?;
                self.journal.slots[i].stage = SlotStage::ReplacementMoved;
                store.save(&self.journal)?;
            }
            self.journal.slots[i].stage = SlotStage::RestorePrepared;
            store.save(&self.journal)?;
            self.gate(guard)?;
            let root = &self.roots[root_index(&self.learned, &slot.scope)?];
            if let Some(original) = slot.original {
                rename(
                    root,
                    &slot.quarantine_relative,
                    &slot.original_relative,
                    original,
                    slot.parent,
                )?;
            }
            faults.hit(Checkpoint::RestoreTransition)?;
            if object(root, &slot.original_relative)? != slot.original {
                return Err(error(ErrorKind::StalePlan));
            }
            self.journal.slots[i].stage = SlotStage::Restored;
            store.save(&self.journal)?;
        }
        // Verify every original before any generated-data cleanup.
        for slot in &self.journal.slots {
            let root = &self.roots[root_index(&self.learned, &slot.scope)?];
            if object(root, &slot.original_relative)? != slot.original
                || object(root, &slot.quarantine_relative)?.is_some()
            {
                return Err(error(ErrorKind::StalePlan));
            }
        }
        self.journal.stage = JournalStage::Restored;
        store.save(&self.journal)?;
        if !self.journal.delete_generated_after_verified_restore {
            return Err(error(ErrorKind::Unsupported));
        }
        for i in 0..self.journal.slots.len() {
            self.gate(guard)?;
            let slot = &self.journal.slots[i];
            let root = &self.roots[root_index(&self.learned, &slot.scope)?];
            if let Some(generated) = object(root, &slot.generated_relative)? {
                if slot.generated != Some(generated) {
                    return Err(error(ErrorKind::StalePlan));
                }
                let target = root.path(&slot.generated_relative)?;
                if target.is_directory()? {
                    target.delete_tree(false)?;
                } else {
                    target.delete_file(false)?;
                }
            }
            self.journal.slots[i].stage = SlotStage::Cleaned;
            store.save(&self.journal)?;
        }
        self.journal.stage = JournalStage::Completed;
        store.save(&self.journal)
    }
}

fn learned_from_journal(j: &ValidationJournal) -> LearnedObservation {
    LearnedObservation {
        session_id: j.observation_id.clone(),
        binding: j.binding.clone(),
        roots: j.roots.clone(),
        status: LearnedStatus::Observed,
        completeness: Completeness::Complete,
        cycles: 2,
        recorded_at_ms: 0,
        provenance: vec![],
    }
}
fn journal_shape(j: &ValidationJournal) -> Result<()> {
    if j.schema != 1
        || j.session_id.len() != 32
        || !j.session_id.bytes().all(|b| b.is_ascii_hexdigit())
        || j.slots.is_empty()
        || j.slots.len() > MAX_FAMILIES * 4
        || j.processes.len() > 128
    {
        return Err(error(ErrorKind::ScopeViolation));
    }
    let learned = learned_from_journal(j);
    candidates(&learned).map_err(|_| error(ErrorKind::Unsupported))?;
    let mut paths = BTreeSet::new();
    for (i, s) in j.slots.iter().enumerate() {
        let root = &j.roots[root_index(&learned, &s.scope)?];
        crate::components(&s.original_relative)?;
        let db = [".db", ".sqlite", ".sqlite3"]
            .iter()
            .any(|e| s.scope.family.ends_with(e));
        if !s.original_relative.eq_ignore_ascii_case(&s.scope.family)
            && !(db
                && ["-wal", "-shm", "-journal"].iter().any(|suffix| {
                    s.original_relative
                        .eq_ignore_ascii_case(&format!("{}{suffix}", s.scope.family))
                }))
        {
            return Err(error(ErrorKind::ScopeViolation));
        }
        let prefix = s
            .original_relative
            .rsplit_once('/')
            .map(|(p, _)| format!("{p}/"))
            .unwrap_or_default();
        if s.quarantine_relative
            != format!("{prefix}.everyout-validation-{}-{i}-original", j.session_id)
            || s.generated_relative
                != format!(
                    "{prefix}.everyout-validation-{}-{i}-generated",
                    j.session_id
                )
            || s.root != root.physical
            || s.parent.volume != s.root.volume
            || s.original.is_some_and(|p| p.volume != s.root.volume)
            || s.generated.is_some_and(|p| p.volume != s.root.volume)
            || s.original.is_some() != s.original_directory.is_some()
            || s.original.is_some() && s.generated == s.original
            || !paths.insert((s.scope.root.clone(), s.original_relative.clone()))
        {
            return Err(error(ErrorKind::ScopeViolation));
        }
    }
    Ok(())
}
/// Startup recovery has priority over all mutation admission. It infers progress
/// from saved physical IDs, including crashes between rename and journal update.
pub fn recover_pending(
    store: &JournalStore,
    bases: &[AllowedRoot],
    guard: &dyn OwnershipGuard,
) -> Result<usize> {
    let mut recovered = 0;
    for journal in store.journals()? {
        if journal.stage == JournalStage::Completed {
            continue;
        }
        journal_shape(&journal)?;
        let learned = learned_from_journal(&journal);
        binding(&learned.binding)?;
        check_ownership(guard, &learned)?;
        let roots = resolve_roots(&learned, bases)?;
        let mut quarantine = Quarantine {
            learned,
            roots,
            journal,
        };
        quarantine.rollback(store, guard, &mut Faults::default())?;
        recovered += 1;
    }
    Ok(recovered)
}

pub struct ValidationController {
    learned: LearnedObservation,
    roots: Vec<AllowedRoot>,
    scopes: Vec<Vec<FamilyScope>>,
    cursor: usize,
    purpose: TrialPurpose,
    final_scope: Option<Vec<FamilyScope>>,
    repetitions: usize,
    view: ValidationView,
    quarantine: Option<Quarantine>,
    processes: Vec<ProcessBinding>,
    before_a: Vec<MetadataSnapshot>,
    after_a: Vec<MetadataSnapshot>,
    before_b: Vec<MetadataSnapshot>,
    after_b: Vec<MetadataSnapshot>,
    outcomes: [AppOutcome; 3],
    pub faults: Faults,
}
impl ValidationController {
    pub fn start(
        learned: LearnedObservation,
        bases: &[AllowedRoot],
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
    ) -> Result<Self> {
        if store.pending()? {
            return Err(error(ErrorKind::Locked));
        }
        let families = candidates(&learned).map_err(|_| error(ErrorKind::Unsupported))?;
        binding(&learned.binding)?;
        check_ownership(guard, &learned)?;
        let roots = resolve_roots(&learned, bases)?;
        let scopes = search_scopes(&families);
        let mut controller = Self {
            learned,
            roots,
            scopes,
            cursor: 0,
            purpose: TrialPurpose::Search,
            final_scope: None,
            repetitions: 0,
            view: ValidationView {
                id: random_id()?,
                stage: ValidationStage::ReadyControl,
                scope: vec![],
                trials: vec![],
                diagnostics: vec![],
                rule: None,
            },
            quarantine: None,
            processes: vec![],
            before_a: vec![],
            after_a: vec![],
            before_b: vec![],
            after_b: vec![],
            outcomes: [AppOutcome::Unclear; 3],
            faults: Faults::default(),
        };
        controller.view.scope = controller.scopes[0].clone();
        controller.revalidate_layout(false)?;
        // Check that every eligible family has a safe atomic boundary before the
        // first trial. Neither UI nor outcome confirmation may submit a path.
        for scope in families {
            relatives(
                &controller.roots[root_index(&controller.learned, &scope)?],
                &scope.family,
            )?;
        }
        Ok(controller)
    }
    pub fn view(&self) -> ValidationView {
        self.view.clone()
    }
    fn snapshots(&self) -> Result<Vec<MetadataSnapshot>> {
        self.roots
            .iter()
            .map(|r| snapshot(r, SnapshotBudget::default()))
            .collect()
    }
    fn revalidate_layout(&self, intervention: bool) -> Result<()> {
        binding(&self.learned.binding)?;
        let snapshots = self.snapshots()?;
        for (saved, current) in self.learned.roots.iter().zip(snapshots) {
            if current.completeness != Completeness::Complete
                || current.root_identity != saved.physical
            {
                return Err(error(ErrorKind::StalePlan));
            }
            let exclude = |p: &String| {
                intervention
                    && (p.contains(".everyout-validation-")
                        || self.view.scope.iter().any(|s| {
                            s.root == saved.root
                                && (p == &s.family || p.starts_with(&format!("{}/", s.family)))
                        }))
            };
            let expected: Vec<_> = saved
                .layout
                .iter()
                .filter(|p| !exclude(p))
                .cloned()
                .collect();
            let actual: Vec<_> = current
                .layout()
                .into_iter()
                .filter(|p| !exclude(p))
                .collect();
            if expected != actual {
                return Err(error(ErrorKind::StalePlan));
            }
        }
        Ok(())
    }
    pub fn begin_trial(&mut self, guard: &dyn OwnershipGuard) -> Result<()> {
        if self.view.stage != ValidationStage::ReadyControl {
            return Err(error(ErrorKind::ScopeViolation));
        }
        self.revalidate_layout(false)?;
        check_ownership(guard, &self.learned)?;
        close_gate(&self.learned.binding, &mut self.processes)?;
        self.before_a = self.snapshots()?;
        self.outcomes = [AppOutcome::Unclear; 3];
        self.view.stage = ValidationStage::Control;
        Ok(())
    }
    /// Launch only the exact bound image, without caller-supplied commands,
    /// arguments or environment. A read pin prevents image substitution at spawn.
    pub fn launch(&mut self, store: &JournalStore, guard: &dyn OwnershipGuard) -> Result<()> {
        if !matches!(
            self.view.stage,
            ValidationStage::Control | ValidationStage::Intervention | ValidationStage::Reversal
        ) {
            return Err(error(ErrorKind::ScopeViolation));
        }
        self.revalidate_layout(self.view.stage == ValidationStage::Intervention)?;
        check_ownership(guard, &self.learned)?;
        if !track(&self.learned.binding, &mut self.processes)?
            .processes
            .is_empty()
        {
            return Err(error(ErrorKind::Locked));
        }
        let image =
            crate::win32_identity::ExecutableBinding::capture(app_path(&self.learned.binding))?;
        binding(&self.learned.binding)?;
        if let Some(q) = &mut self.quarantine {
            if q.journal.stage != JournalStage::Completed {
                q.journal.stage = JournalStage::AppLaunched;
                store.save(&q.journal)?;
            }
        }
        let child = std::process::Command::new(&image.canonical_path)
            .current_dir(
                image
                    .canonical_path
                    .parent()
                    .ok_or_else(|| error(ErrorKind::ScopeViolation))?,
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|_| error(ErrorKind::Io))?;
        let process =
            process::observe_current_user(child.id())?.ok_or_else(|| error(ErrorKind::Locked))?;
        self.processes.push(ProcessBinding {
            pid: process.pid(),
            creation_ticks: process.creation_ticks(),
        });
        self.tick(store)
    }
    /// Called by the native worker while awaiting outcomes. Persist process object
    /// identities for recovery before advancing any intervention phase.
    pub fn tick(&mut self, store: &JournalStore) -> Result<()> {
        let result = self.tick_inner(store);
        if let Err(e) = &result {
            self.view.stage = if self
                .quarantine
                .as_ref()
                .is_some_and(|q| q.journal.stage != JournalStage::Completed)
            {
                ValidationStage::RecoveryBlocked
            } else {
                ValidationStage::Stale
            };
            self.view
                .diagnostics
                .push(format!("validation-{:?}", e.kind).to_lowercase());
        }
        result
    }
    fn tick_inner(&mut self, store: &JournalStore) -> Result<()> {
        if !matches!(
            self.view.stage,
            ValidationStage::Control | ValidationStage::Intervention | ValidationStage::Reversal
        ) {
            return Ok(());
        }
        binding(&self.learned.binding)?;
        let inventory = track(&self.learned.binding, &mut self.processes)?;
        if let Some(q) = &mut self.quarantine {
            if q.journal.stage != JournalStage::Completed
                && (q.journal.processes != self.processes
                    || !inventory.processes.is_empty()
                        && q.journal.stage == JournalStage::Quarantined)
            {
                q.journal.processes = self.processes.clone();
                if !inventory.processes.is_empty() {
                    q.journal.stage = JournalStage::AppLaunched;
                }
                store.save(&q.journal)?;
                self.faults.hit(Checkpoint::AppLaunched)?;
            }
        }
        Ok(())
    }
    pub fn confirm(
        &mut self,
        outcome: AppOutcome,
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
    ) -> Result<()> {
        let result = self.confirm_inner(outcome, store, guard);
        if let Err(e) = result {
            self.view.stage = if self
                .quarantine
                .as_ref()
                .is_some_and(|q| q.journal.stage != JournalStage::Completed)
            {
                ValidationStage::RecoveryBlocked
            } else if e.kind == ErrorKind::StalePlan {
                ValidationStage::Stale
            } else {
                ValidationStage::Failed
            };
            self.view
                .diagnostics
                .push(format!("validation-{:?}", e.kind).to_lowercase());
            if self
                .quarantine
                .as_ref()
                .is_some_and(|q| q.journal.stage == JournalStage::Prepared)
                && e.os_code.is_some()
            {
                self.view
                    .diagnostics
                    .push("unsupported-for-safe-rollback".into());
            }
        }
        result
    }
    fn confirm_inner(
        &mut self,
        outcome: AppOutcome,
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
    ) -> Result<()> {
        if !matches!(
            self.view.stage,
            ValidationStage::Control | ValidationStage::Intervention | ValidationStage::Reversal
        ) {
            return Err(error(ErrorKind::ScopeViolation));
        }
        self.tick(store)?;
        self.revalidate_layout(self.view.stage == ValidationStage::Intervention)?;
        check_ownership(guard, &self.learned)?;
        if track(&self.learned.binding, &mut self.processes)?
            .processes
            .is_empty()
        {
            return Err(error(ErrorKind::Locked));
        }
        match self.view.stage {
            ValidationStage::Control => {
                self.outcomes[0] = outcome;
                self.after_a = self.snapshots()?;
                close_gate(&self.learned.binding, &mut self.processes)?;
                if outcome != AppOutcome::SignedIn {
                    return Err(error(ErrorKind::Unsupported));
                }
                // Prepare after A1 exit: originals remain immutable through B.
                let mut q = Quarantine::prepare(
                    &self.learned,
                    self.roots.clone(),
                    &self.view.scope,
                    store,
                )?;
                q.journal.processes = self.processes.clone();
                self.quarantine = Some(q);
                self.quarantine.as_mut().expect("prepared").intervene(
                    store,
                    guard,
                    &mut self.faults,
                )?;
                self.before_b = self.snapshots()?;
                self.view.stage = ValidationStage::Intervention;
            }
            ValidationStage::Intervention => {
                self.outcomes[1] = outcome;
                self.after_b = self.snapshots()?;
                self.quarantine.as_mut().expect("intervention").rollback(
                    store,
                    guard,
                    &mut self.faults,
                )?;
                self.view.stage = ValidationStage::Reversal;
            }
            ValidationStage::Reversal => {
                self.outcomes[2] = outcome;
                close_gate(&self.learned.binding, &mut self.processes)?;
                self.revalidate_layout(false)?;
                let collateral = collateral(
                    &self.before_a,
                    &self.after_a,
                    &self.before_b,
                    &self.after_b,
                    &self.view.scope,
                    &self.learned,
                );
                let mut trial = TrialEvidence {
                    scope: self.view.scope.clone(),
                    purpose: self.purpose,
                    a1: self.outcomes[0],
                    b: self.outcomes[1],
                    a2: self.outcomes[2],
                    rollback_verified: self
                        .quarantine
                        .as_ref()
                        .is_some_and(|q| q.journal.stage == JournalStage::Completed),
                    complete_metadata: collateral.is_some(),
                    collateral_families: collateral.unwrap_or_default(),
                    result: CausalResult::Inconclusive,
                };
                trial.classify();
                let result = trial.result;
                self.view.trials.push(trial);
                self.quarantine = None;
                if matches!(
                    result,
                    CausalResult::Inconclusive | CausalResult::FailedRestoreOrExternalStateChange
                ) {
                    self.view.stage = ValidationStage::Failed;
                    self.view
                        .diagnostics
                        .push("failed-restore-or-external-state-change".into());
                } else if self.purpose == TrialPurpose::FinalRepeat {
                    if result != CausalResult::Sufficient {
                        self.repetitions = 0;
                        self.view.stage = ValidationStage::Failed;
                        self.view
                            .diagnostics
                            .push("contradictory-causal-evidence-retained".into());
                    } else {
                        self.repetitions += 1;
                        self.view.stage = if self.repetitions >= 2 {
                            ValidationStage::AwaitingAcceptance
                        } else {
                            ValidationStage::ReadyControl
                        };
                    }
                } else if result == CausalResult::Sufficient {
                    self.final_scope = Some(self.view.scope.clone());
                    self.purpose = TrialPurpose::FinalRepeat;
                    self.view.stage = ValidationStage::ReadyControl;
                } else {
                    self.cursor += 1;
                    if let Some(scope) = self.scopes.get(self.cursor) {
                        self.view.scope = scope.clone();
                        self.view.stage = ValidationStage::ReadyControl;
                    } else {
                        self.view.stage = ValidationStage::Failed;
                        self.view
                            .diagnostics
                            .push("no-sufficient-scope-within-trial-budget".into());
                    }
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
    pub fn accept_losses(
        &mut self,
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
    ) -> Result<LocalValidatedRule> {
        if self.view.stage != ValidationStage::AwaitingAcceptance || store.pending()? {
            return Err(error(ErrorKind::Unsupported));
        }
        self.revalidate_layout(false)?;
        check_ownership(guard, &self.learned)?;
        close_gate(&self.learned.binding, &mut self.processes)?;
        let clean = self
            .view
            .trials
            .iter()
            .filter(|t| t.purpose == TrialPurpose::FinalRepeat)
            .all(|t| t.complete_metadata && t.collateral_families.is_empty());
        let scope = self
            .final_scope
            .clone()
            .ok_or_else(|| error(ErrorKind::Unsupported))?;
        let mut artifacts = vec![];
        for family in &scope {
            let root = &self.roots[root_index(&self.learned, family)?];
            for relative in relatives(root, &family.family)? {
                let (parent, _) = parent(root, &relative)?;
                artifacts.push(LocalArtifactBinding {
                    scope: family.clone(),
                    physical: object(root, &relative)?,
                    parent: physical(&parent.handle().info()?),
                    relative,
                });
            }
        }
        let rule = LocalValidatedRule {
            id: self.view.id.clone(),
            observation_id: self.learned.session_id.clone(),
            binding: self.learned.binding.clone(),
            roots: self.learned.roots.clone(),
            scope,
            artifacts,
            trials: self.view.trials.clone(),
            repetitions: self.repetitions,
            preservation: if clean {
                PreservationState::NoAbnormalCollateralMutationObserved
            } else {
                PreservationState::BoundedKnownLosses
            },
            accepted_bounded_losses: true,
            stale: false,
        };
        store.save_rule(&rule)?;
        self.view.rule = Some(rule.clone());
        self.view.stage = ValidationStage::Complete;
        Ok(rule)
    }
    pub fn abort(&mut self, store: &JournalStore, guard: &dyn OwnershipGuard) -> Result<()> {
        if let Some(q) = &mut self.quarantine {
            q.rollback(store, guard, &mut Faults::default())
                .inspect_err(|_| {
                    self.view.stage = ValidationStage::RecoveryBlocked;
                })?;
        }
        self.quarantine = None;
        self.view.stage = ValidationStage::Failed;
        self.view
            .diagnostics
            .push("validation-cancelled-originals-restored".into());
        Ok(())
    }
}

/// Non-serializable installation-local destructive authority. UI supplies only a
/// saved rule ID and disclosures; the authority independently binds every target.
pub struct LocalLogoutAuthority {
    rule: LocalValidatedRule,
    learned: LearnedObservation,
    roots: Vec<AllowedRoot>,
    targets: Vec<(usize, crate::SafePath)>,
}
impl LocalLogoutAuthority {
    pub fn bind(
        rule: LocalValidatedRule,
        bases: &[AllowedRoot],
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
    ) -> Result<Self> {
        if !rule.qualified() || store.pending()? {
            return Err(error(ErrorKind::Unsupported));
        }
        binding(&rule.binding)?;
        let learned = LearnedObservation {
            session_id: rule.observation_id.clone(),
            binding: rule.binding.clone(),
            roots: rule.roots.clone(),
            status: LearnedStatus::Observed,
            completeness: Completeness::Complete,
            cycles: 2,
            recorded_at_ms: 0,
            provenance: vec![],
        };
        candidates(&learned).map_err(|_| error(ErrorKind::Unsupported))?;
        check_ownership(guard, &learned)?;
        let roots = resolve_roots(&learned, bases)?;
        for (root, saved) in roots.iter().zip(&rule.roots) {
            let current = snapshot(root, SnapshotBudget::default())?;
            if current.layout() != saved.layout {
                return Err(error(ErrorKind::StalePlan));
            }
        }
        let mut targets = vec![];
        for scope in &rule.scope {
            let index = root_index(&learned, scope)?;
            for relative in relatives(&roots[index], &scope.family)? {
                let saved = rule
                    .artifacts
                    .iter()
                    .find(|a| a.scope == *scope && a.relative == relative)
                    .ok_or_else(|| error(ErrorKind::ScopeViolation))?;
                let (parent, _) = parent(&roots[index], &relative)?;
                if object(&roots[index], &relative)? != saved.physical
                    || physical(&parent.handle().info()?) != saved.parent
                {
                    return Err(error(ErrorKind::StalePlan));
                }
                targets.push((index, roots[index].path(&relative)?));
            }
        }
        if targets.len() != rule.artifacts.len() {
            return Err(error(ErrorKind::ScopeViolation));
        }
        Ok(Self {
            rule,
            learned,
            roots,
            targets,
        })
    }
    pub fn apply(
        self,
        accepted_bounded_losses: bool,
        store: &JournalStore,
        guard: &dyn OwnershipGuard,
    ) -> Result<usize> {
        if !accepted_bounded_losses || store.pending()? {
            return Err(error(ErrorKind::ScopeViolation));
        }
        binding(&self.rule.binding)?;
        check_ownership(guard, &self.learned)?;
        let mut processes = vec![];
        close_gate(&self.rule.binding, &mut processes)?;
        // Review handles revalidate their target identity after processes close.
        // Bind the complete scope before the first irreversible operation.
        for (_, target) in &self.targets {
            target.probe_shallow()?;
        }
        for (root, saved) in self.roots.iter().zip(&self.rule.roots) {
            let current = snapshot(root, SnapshotBudget::default())?;
            if current.completeness != Completeness::Complete || current.layout() != saved.layout {
                return Err(error(ErrorKind::StalePlan));
            }
        }
        let mut deleted = 0;
        for (index, target) in self.targets {
            binding(&self.rule.binding)?;
            check_ownership(guard, &self.learned)?;
            close_gate(&self.rule.binding, &mut processes)?;
            if physical(&self.roots[index].handle().info()?) != self.rule.roots[index].physical {
                return Err(error(ErrorKind::StalePlan));
            }
            let metadata = target.probe_shallow()?;
            let result = if metadata.is_directory {
                target.delete_tree(false)
            } else {
                target.delete_file(false)
            };
            deleted += result?.objects;
        }
        Ok(deleted)
    }
}
