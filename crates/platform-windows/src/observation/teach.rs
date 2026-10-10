use super::*;
use crate::{
    process,
    win32_identity::{ExecutableBinding, IdentitySource, UsageBudget, Win32Snapshot},
};
use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

const BROAD_WINDOW: Duration = Duration::from_secs(20);
const FOCUSED_WINDOW: Duration = Duration::from_secs(20 * 60);
const MAX_ROOTS: usize = 8;
const MAX_CYCLES: usize = 4;
const MAX_SESSION_ENTRIES: usize = 100_000;
const PHASES: [TeachPhase; 7] = [
    TeachPhase::ClosedBaseline,
    TeachPhase::LaunchLoggedOut,
    TeachPhase::Login,
    TeachPhase::SettledLoggedIn,
    TeachPhase::RestartPersistence,
    TeachPhase::VendorLogout,
    TeachPhase::ClosedLoggedOut,
];

struct Watched {
    root: AllowedRoot,
    path: String,
    watcher: Option<DirectoryWatcherBackend>,
    changed: BTreeSet<String>,
    completeness: Completeness,
    provenance: Vec<everyout_core_model::EvidenceProvenance>,
}
impl Watched {
    fn start(root: AllowedRoot) -> Result<Self> {
        let path = native::metadata_path(root.handle())?
            .to_string_lossy()
            .into();
        let watcher = DirectoryWatcherBackend::start(root.clone())?;
        Ok(Self {
            root,
            path,
            watcher: Some(watcher),
            changed: BTreeSet::new(),
            completeness: Completeness::Complete,
            provenance: vec![],
        })
    }
    fn poll(&mut self) {
        let Some(watcher) = &mut self.watcher else {
            return;
        };
        match watcher.poll() {
            Ok(batch) => {
                for event in batch.events {
                    // Directory write notifications can arrive after the child
                    // removal has already been captured, as Windows closes handles.
                    // They are aggregate signals, not another family mutation.
                    // Structural create/remove/rename events and all file modifies
                    // remain evidence; snapshots retain directory identities.
                    if event.kind == ChangeKind::Modify
                        && self
                            .root
                            .path(&event.path)
                            .and_then(|p| p.probe_shallow())
                            .is_ok_and(|m| m.exists && m.is_directory)
                    {
                        continue;
                    }
                    if self.changed.len() < 10_000 {
                        self.changed.insert(event.path);
                    } else {
                        self.completeness = Completeness::Incomplete;
                    }
                }
                if batch.fallback {
                    self.provenance.push(provenance(
                        "directory-watcher",
                        "standard-notifications-fallback",
                    ));
                }
                if batch.history_lost {
                    let previous = self.completeness;
                    self.completeness = Completeness::Incomplete;
                    if let Ok(captured) = recover_snapshot(&self.root, SnapshotBudget::default()) {
                        self.completeness = combine(previous, captured.completeness);
                        self.provenance.extend(captured.provenance);
                        // Endpoint enumeration can discover candidates, but it cannot
                        // recreate intermediate modify/rename history.
                        self.changed
                            .extend(captured.entries.into_keys().take(10_000));
                    }
                }
            }
            Err(_) => {
                self.completeness = Completeness::Incomplete;
                self.provenance
                    .push(provenance("directory-watcher", "backend-unavailable"));
                self.watcher = None;
                // Even if rearming failed after a lost-history completion, recover
                // an endpoint. A stopped backend still remains Incomplete.
                if let Ok(captured) = recover_snapshot(&self.root, SnapshotBudget::default()) {
                    self.provenance.extend(captured.provenance);
                }
            }
        }
    }
}

pub struct TeachController {
    pub session: TeachSession,
    watched: Vec<Watched>,
    hints: Vec<AllowedRoot>,
    stage: TeachStage,
    deadline: Instant,
    interval_start: u64,
    diagnostics: Vec<String>,
    broad_baselines: Vec<MetadataSnapshot>,
    shared: BTreeSet<String>,
    phase_index: usize,
    last_processes: Vec<ProcessBinding>,
    restart_processes: Vec<ProcessBinding>,
    last_validation: Instant,
    result: Option<LearnedObservation>,
}
impl TeachController {
    /// The executable is a selection, resolved through P1 before any observation.
    /// Broad roots and optional scanner/P1/framework/MSIX candidates are capabilities.
    pub fn start(
        executable: &Path,
        channel: Option<String>,
        broad: Vec<AllowedRoot>,
        mut candidates: Vec<AllowedRoot>,
        id: String,
    ) -> Result<Self> {
        if broad.len() > 8 || candidates.len() > 500 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let mut selected = Win32Snapshot::default();
        selected.observe_executable(executable, IdentitySource::Selected, None)?;
        // P1 metadata name hints supply additional candidates, not authority.
        // Broad discovery can still find roots whose names have no relation to EXE.
        for root in &broad {
            if let Ok((children, _)) = root.discovery_children() {
                for (name, directory) in children {
                    if directory
                        && candidates.len() < 500
                        && selected.applications[0].storage_name_hint(&name)
                    {
                        if let Ok(candidate) = root.discovery_descendant(&name) {
                            candidates.push(candidate);
                        }
                    }
                }
            }
        }
        let binding = application_binding(&selected.applications[0], channel)?;
        let session = TeachSession::new(id, binding, now_ms())
            .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?;
        let mut controller = Self {
            session,
            watched: vec![],
            hints: candidates,
            stage: TeachStage::Discovering,
            deadline: Instant::now() + BROAD_WINDOW,
            interval_start: now_ms(),
            diagnostics: vec![],
            broad_baselines: vec![],
            shared: BTreeSet::new(),
            phase_index: 0,
            last_processes: vec![],
            restart_processes: vec![],
            last_validation: Instant::now(),
            result: None,
        };
        controller.validate()?;
        if !controller.last_processes.is_empty() {
            return Err(PlatformError::new(ErrorKind::Locked));
        }
        for root in broad {
            match Watched::start(root) {
                Ok(watched) => {
                    if let Ok(baseline) = snapshot(&watched.root, SnapshotBudget::default()) {
                        controller.broad_baselines.push(baseline);
                    }
                    controller.watched.push(watched);
                }
                Err(_) => controller.diagnostics.push("broad-root-unavailable".into()),
            }
        }
        if controller.watched.is_empty() {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        controller.session.provenance.push(provenance(
            "teach-discovery",
            "short-broad-pass-before-focused-cycles",
        ));
        Ok(controller)
    }
    fn validate(&mut self) -> Result<()> {
        if self.stage == TeachStage::Stale {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        let mut selected = Win32Snapshot::default();
        let executable_path = self.session.binding.executable_path.clone();
        let path = Path::new(&executable_path);
        // P1 canonical paths use the Win32 long-path prefix; selection grammar uses
        // ordinary absolute disk paths, with the same physical identity rechecked.
        let lexical = self
            .session
            .binding
            .executable_path
            .strip_prefix("\\\\?\\")
            .unwrap_or(&self.session.binding.executable_path);
        if selected
            .observe_executable(Path::new(lexical), IdentitySource::Selected, None)
            .is_err()
        {
            return self.stale();
        }
        let binding = application_binding(
            &selected.applications[0],
            self.session.binding.channel.clone(),
        )?;
        if !self.session.revalidate(&binding) {
            return self.stale();
        }
        let name = path
            .file_name()
            .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?
            .to_string_lossy()
            .into_owned();
        let inventory = process::enumerate_current_user_matches(&[name])?;
        if !inventory.unavailable.is_empty() {
            self.session.completeness = Completeness::Incomplete;
            return Err(PlatformError::new(ErrorKind::AccessDenied));
        }
        let mut processes = vec![];
        for process in inventory.processes {
            let Ok(image) = ExecutableBinding::capture(process.image_path()) else {
                return self.stale();
            };
            if image.physical != selected.applications[0].executable.physical {
                return self.stale();
            }
            processes.push(ProcessBinding {
                pid: process.pid(),
                creation_ticks: process.creation_ticks(),
            });
        }
        self.last_processes = processes;
        self.last_validation = Instant::now();
        Ok(())
    }
    fn stale<T>(&mut self) -> Result<T> {
        self.stage = TeachStage::Stale;
        self.session.state = SessionState::Stale;
        self.session.completeness = Completeness::Incomplete;
        self.session
            .provenance
            .push(provenance("teach-session", "application-binding-changed"));
        self.watched.clear();
        Err(PlatformError::new(ErrorKind::StalePlan))
    }
    pub fn tick(&mut self) {
        if !matches!(self.stage, TeachStage::Discovering | TeachStage::Focused) {
            return;
        }
        if self.last_validation.elapsed() >= Duration::from_secs(1)
            && self.validate().is_err()
            && self.stage != TeachStage::Stale
        {
            self.session.completeness = Completeness::Incomplete;
            self.diagnostics
                .push("process-observation-incomplete".into());
        }
        for watched in &mut self.watched {
            watched.poll();
        }
        if Instant::now() >= self.deadline {
            if self.stage == TeachStage::Discovering {
                self.end_discovery();
            } else if self.stage == TeachStage::Focused {
                self.session.completeness = Completeness::Incomplete;
                self.diagnostics
                    .push("focused-observation-time-limit".into());
                self.finish();
            }
        }
    }
    pub fn end_discovery(&mut self) {
        if self.stage != TeachStage::Discovering {
            return;
        }
        let mut candidates: HashMap<String, (usize, AllowedRoot)> = HashMap::new();
        for watched in &mut self.watched {
            watched.poll();
            // Boundary snapshot corroborates endpoints and finds changes missed
            // between polling calls. Never infer absence from a partial broad scan.
            if let Ok(final_snapshot) = snapshot(&watched.root, SnapshotBudget::default()) {
                if let Some(baseline) = self.broad_baselines.iter().find(|s| s.root == watched.path)
                {
                    for (path, metadata) in &final_snapshot.entries {
                        if baseline.entries.get(path) != Some(metadata) {
                            watched.changed.insert(path.clone());
                        }
                    }
                }
            }
            for path in &watched.changed {
                let parts: Vec<_> = path.split('/').collect();
                // Aggregate at the highest bounded app/vendor directory, keeping
                // each independently registered MSIX container separate.
                let count = if parts
                    .first()
                    .is_some_and(|p| p.eq_ignore_ascii_case("Packages"))
                {
                    2
                } else {
                    1
                };
                if parts.len() < count {
                    continue;
                }
                let relative = parts[..count].join("/");
                if let Ok(root) = watched.root.discovery_descendant(&relative) {
                    if let Ok(path) = native::metadata_path(root.handle()) {
                        let candidate = candidates
                            .entry(path.to_string_lossy().into())
                            .or_insert((0, root));
                        candidate.0 += 1;
                    }
                }
            }
            self.session.provenance.append(&mut watched.provenance);
            if watched.completeness != Completeness::Complete {
                self.diagnostics
                    .push("broad-history-incomplete-focused-cycles-required".into());
            }
        }
        // Scanner, framework and P1 roots refine candidates only if their physical
        // subtree actually changed. Neither labels nor layouts grant ownership.
        for hint in &self.hints {
            let Ok(path) = native::metadata_path(hint.handle()) else {
                continue;
            };
            let path = path.to_string_lossy().into_owned();
            let changed = self.watched.iter().any(|w| {
                w.changed.iter().any(|event| {
                    format!("{}/{}", w.path.replace('\\', "/"), event)
                        .to_lowercase()
                        .starts_with(&format!("{}/", path.replace('\\', "/").to_lowercase()))
                })
            });
            if changed {
                candidates.entry(path).or_insert((1, hint.clone()));
            }
        }
        let mut sorted: Vec<_> = candidates.into_iter().collect();
        sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0).then(a.0.cmp(&b.0)));
        if sorted.len() > MAX_ROOTS {
            self.diagnostics
                .push("candidate-shortlist-truncated".into());
        }
        self.watched.clear(); // Broad watchers always end after the short pass.
        for (_, (_, root)) in sorted.into_iter().take(MAX_ROOTS) {
            if let Ok(watched) = Watched::start(root) {
                self.watched.push(watched);
            } else {
                self.diagnostics.push("focused-root-unavailable".into());
            }
        }
        self.session.roots = self.watched.iter().map(|w| w.path.clone()).collect();
        self.session.discovery_snapshots = self
            .watched
            .iter()
            .filter_map(|w| {
                snapshot(
                    &w.root,
                    SnapshotBudget {
                        entries: 2000,
                        ..Default::default()
                    },
                )
                .ok()
            })
            .collect();
        self.stage = TeachStage::Ready;
        // No watcher stays active while waiting for the user to start a cycle.
        for watched in &mut self.watched {
            watched.watcher = None;
        }
        if self.session.roots.is_empty() {
            self.diagnostics
                .push("filesystem-incomplete-needs-adapter".into());
            self.session.completeness = Completeness::Incomplete;
        }
        self.broad_baselines.clear();
        self.hints.clear();
    }
    pub fn begin_cycle(&mut self) -> Result<()> {
        if self.stage != TeachStage::Ready
            || self.session.cycles.len() >= MAX_CYCLES
            || self.watched.is_empty()
        {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        self.validate()?;
        if !self.last_processes.is_empty() {
            return Err(PlatformError::new(ErrorKind::Locked));
        }
        let watched = self
            .watched
            .iter()
            .map(|w| Watched::start(w.root.clone()))
            .collect::<Result<Vec<_>>>()?;
        self.watched = watched;
        self.stage = TeachStage::Focused;
        self.deadline = Instant::now() + FOCUSED_WINDOW;
        self.phase_index = 0;
        self.interval_start = now_ms();
        self.session.cycles.push(TeachCycle { phases: vec![] });
        self.advance(Some(false))
    }
    pub fn advance(&mut self, signed_in: Option<bool>) -> Result<()> {
        if self.stage != TeachStage::Focused || self.phase_index >= 7 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        self.validate()?;
        let phase = PHASES[self.phase_index];
        let closed = matches!(
            phase,
            TeachPhase::ClosedBaseline | TeachPhase::ClosedLoggedOut
        );
        if closed != self.last_processes.is_empty() {
            return Err(PlatformError::new(ErrorKind::Locked));
        }
        let expected = match phase {
            TeachPhase::Login | TeachPhase::SettledLoggedIn => Some(true),
            TeachPhase::RestartPersistence => signed_in,
            _ => Some(false),
        };
        if signed_in.is_none() || signed_in != expected {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        if phase == TeachPhase::RestartPersistence
            && self
                .last_processes
                .iter()
                .any(|p| self.restart_processes.contains(p))
        {
            return Err(PlatformError::new(ErrorKind::Locked));
        }
        if phase == TeachPhase::SettledLoggedIn {
            self.restart_processes = self.last_processes.clone();
        }
        if let Some(process) = self.last_processes.first() {
            self.session
                .binding
                .selected_process
                .get_or_insert(*process);
        }
        let retained: usize = self
            .session
            .cycles
            .iter()
            .flat_map(|c| &c.phases)
            .flat_map(|p| &p.snapshots)
            .map(|s| s.entries.len())
            .sum();
        if retained >= MAX_SESSION_ENTRIES {
            self.session.completeness = Completeness::Incomplete;
            self.finish();
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        let mut observation = PhaseObservation {
            phase,
            started_at_ms: self.interval_start,
            ended_at_ms: now_ms(),
            snapshots: vec![],
            changed_families: BTreeMap::new(),
            completeness: Completeness::Complete,
            signed_in,
            processes: self.last_processes.clone(),
            provenance: vec![provenance("teach-phase", "user-labelled-session-state")],
        };
        for watched in &mut self.watched {
            watched.poll();
            let captured = snapshot(
                &watched.root,
                SnapshotBudget {
                    entries: 2000,
                    ..Default::default()
                },
            );
            let mut captured = match captured {
                Ok(captured) => captured,
                Err(error) => {
                    self.session.completeness = Completeness::Incomplete;
                    self.diagnostics.push("phase-snapshot-unavailable".into());
                    return Err(error);
                }
            };
            watched.poll();
            let completeness = combine(watched.completeness, captured.completeness);
            captured.completeness = completeness;
            observation.completeness = combine(observation.completeness, completeness);
            observation.provenance.append(&mut watched.provenance);
            observation.changed_families.insert(
                watched.path.clone(),
                std::mem::take(&mut watched.changed)
                    .into_iter()
                    .map(|p| artifact_family(&p))
                    .collect(),
            );
            watched.completeness = Completeness::Complete;
            observation.snapshots.push(captured);
        }
        self.session.completeness = combine(self.session.completeness, observation.completeness);
        self.session
            .cycles
            .last_mut()
            .expect("active cycle")
            .phases
            .push(observation);
        self.interval_start = now_ms();
        self.phase_index += 1;
        if self.phase_index == 7 {
            self.stage = TeachStage::Ready;
            for watched in &mut self.watched {
                watched.watcher = None;
            }
        }
        Ok(())
    }
    /// Optional bounded P1 Restart Manager corroboration. It cannot supply auth.
    pub fn corroborate(&mut self, snapshot: &Win32Snapshot) {
        let Some(app) = snapshot.applications.iter().find(|a| {
            application_binding(a, self.session.binding.channel.clone())
                .is_ok_and(|b| b.executable == self.session.binding.executable)
        }) else {
            return;
        };
        let mut budget = UsageBudget::default();
        for watched in &self.watched {
            // Register a representative directory candidate through the bounded
            // P1 API, which registers at most four child files, never AppData itself.
            let Some(parent) = Path::new(&watched.path).parent() else {
                continue;
            };
            let Some(name) = Path::new(&watched.path)
                .file_name()
                .and_then(|n| n.to_str())
            else {
                continue;
            };
            let parent = parent.to_string_lossy();
            let parent = parent.strip_prefix("\\\\?\\").unwrap_or(&parent);
            let Ok(base) = AllowedRoot::absolute(Path::new(parent)) else {
                continue;
            };
            let Ok(candidate) = base.path(name) else {
                continue;
            };
            let usage = budget.corroborate(&candidate, snapshot);
            let same = usage.processes.iter().any(|p| app.processes.contains(p));
            let unrelated = usage.processes.iter().any(|p| !app.processes.contains(p));
            if usage.shared || (same && unrelated) {
                self.shared.insert(watched.path.clone());
            }
            if same {
                if !self.session.corroborated_roots.contains(&watched.path) {
                    self.session.corroborated_roots.push(watched.path.clone());
                }
                self.session.provenance.push(provenance(
                    "restart-manager",
                    "bounded-active-resource-corroboration",
                ));
            }
        }
    }
    pub fn mark_shared(&mut self, roots: impl IntoIterator<Item = String>) {
        self.shared.extend(roots);
    }
    pub fn finish(&mut self) -> LearnedObservation {
        if self.stage != TeachStage::Stale && self.validate().is_err() {
            self.session.completeness = Completeness::Incomplete;
        }
        for watched in &mut self.watched {
            watched.watcher = None;
        }
        self.session.ended_at_ms = Some(now_ms());
        if self.stage != TeachStage::Stale {
            self.session.state = SessionState::Finished;
            self.stage = TeachStage::Finished;
        }
        let result = analyze(&self.session, &self.shared, now_ms());
        self.result = Some(result.clone());
        self.watched.clear();
        self.hints.clear();
        self.broad_baselines.clear();
        result
    }
    pub fn view(&self) -> TeachView {
        TeachView {
            id: self.session.id.clone(),
            application: Path::new(&self.session.binding.executable_path)
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into(),
            stage: self.stage,
            next_phase: if self.stage == TeachStage::Focused {
                PHASES.get(self.phase_index).copied()
            } else {
                None
            },
            completeness: self
                .watched
                .iter()
                .fold(self.session.completeness, |state, w| {
                    combine(state, w.completeness)
                }),
            candidate_roots: self.session.roots.clone(),
            completed_cycles: self
                .session
                .cycles
                .iter()
                .filter(|c| c.phases.len() == 7)
                .count(),
            diagnostics: self.diagnostics.clone(),
            result: self.result.clone(),
        }
    }
}
fn combine(a: Completeness, b: Completeness) -> Completeness {
    if a == Completeness::Incomplete || b == Completeness::Incomplete {
        Completeness::Incomplete
    } else if a == Completeness::RecoveredByRescan || b == Completeness::RecoveredByRescan {
        Completeness::RecoveredByRescan
    } else {
        Completeness::Complete
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FixtureFolders, KnownFolder, RootResolver};
    #[test]
    fn real_buffer_overflow_forces_rescan_and_preserves_lost_history_provenance() {
        let fixture = FixtureFolders::create().unwrap();
        let mut watched =
            Watched::start(fixture.resolve(KnownFolder::LocalAppData).unwrap()).unwrap();
        // Stop consuming a real 64 KiB notification buffer while generating
        // structural changes that cannot collapse into a single modify event.
        for index in 0..2000 {
            let path = fixture.path().join(format!("storm-{index}.tmp"));
            std::fs::write(&path, b"invented").unwrap();
            std::fs::remove_file(path).unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && watched.completeness == Completeness::Complete {
            watched.poll();
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(watched.completeness, Completeness::RecoveredByRescan);
        assert!(watched
            .provenance
            .iter()
            .any(|p| p.reason_code == "history-lost-metadata-rescan"));
        assert!(snapshot(&watched.root, SnapshotBudget::default())
            .unwrap()
            .entries
            .is_empty());
    }
}
