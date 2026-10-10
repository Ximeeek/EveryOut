//! Isolated read-only Teach worker. It has no engine, provider or mutation router.
use crate::{application::opaque, dto::CommandError};
use everyout_core_model::observation::*;
use everyout_platform_windows::observation::local_low;
use everyout_platform_windows::{
    observation::{self, TeachController},
    win32_identity::{IdentitySource, Win32Snapshot},
    AllowedRoot, CurrentUserFolders, KnownFolder, RootResolver,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::mpsc,
    time::Duration,
};
use ts_rs::TS;

#[derive(Debug, Deserialize, TS)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TeachRequest {
    Start {
        executable: String,
        channel: Option<String>,
    },
    Get {
        id: String,
    },
    Discover {
        id: String,
    },
    BeginCycle {
        id: String,
    },
    Advance {
        id: String,
        signed_in: bool,
    },
    Finish {
        id: String,
    },
    History,
}
#[derive(Debug, Serialize, TS)]
#[serde(tag = "kind", content = "data", rename_all = "kebab-case")]
pub enum TeachReply {
    View(Box<TeachView>),
    History(Vec<LearnedObservation>),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSession {
    session: TeachSession,
    observation: LearnedObservation,
}
struct Envelope {
    request: TeachRequest,
    reply: mpsc::Sender<Result<TeachReply, CommandError>>,
}
#[derive(Clone)]
pub struct TeachBridge {
    sender: mpsc::Sender<Envelope>,
}
impl TeachBridge {
    pub fn start(directory: PathBuf) -> Result<Self, CommandError> {
        let (sender, receiver) = mpsc::channel::<Envelope>();
        std::thread::Builder::new()
            .name("everyout-teach".into())
            .spawn(move || {
                let mut worker = TeachWorker {
                    directory: directory.join("observations"),
                    controller: None,
                    saved: false,
                    save_failed: false,
                };
                loop {
                    if let Some(controller) = &mut worker.controller {
                        controller.tick();
                    }
                    if worker.controller.as_ref().is_some_and(|c| {
                        matches!(c.view().stage, TeachStage::Finished | TeachStage::Stale)
                    }) && !worker.saved
                        && !worker.save_failed
                    {
                        worker.save_failed = worker.persist().is_err();
                    }
                    match receiver.recv_timeout(Duration::from_millis(50)) {
                        Ok(envelope) => {
                            let _ = envelope.reply.send(worker.handle(envelope.request));
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            })
            .map_err(|_| CommandError::WorkerUnavailable)?;
        Ok(Self { sender })
    }
    pub fn call(&self, request: TeachRequest) -> Result<TeachReply, CommandError> {
        let (reply, result) = mpsc::channel();
        self.sender
            .send(Envelope { request, reply })
            .map_err(|_| CommandError::WorkerUnavailable)?;
        result.recv().map_err(|_| CommandError::WorkerUnavailable)?
    }
}
struct TeachWorker {
    directory: PathBuf,
    controller: Option<TeachController>,
    saved: bool,
    save_failed: bool,
}
pub(crate) fn history(
    directory: &Path,
    revalidate: bool,
) -> Result<Vec<LearnedObservation>, CommandError> {
    TeachWorker {
        directory: directory.join("observations"),
        controller: None,
        saved: false,
        save_failed: false,
    }
    .history(revalidate)
}
impl TeachWorker {
    fn handle(&mut self, request: TeachRequest) -> Result<TeachReply, CommandError> {
        if matches!(request, TeachRequest::History) {
            return Ok(TeachReply::History(self.history(true)?));
        }
        if let TeachRequest::Start {
            executable,
            channel,
        } = request
        {
            if self.controller.as_ref().is_some_and(|c| {
                matches!(
                    c.view().stage,
                    TeachStage::Discovering | TeachStage::Ready | TeachStage::Focused
                )
            }) {
                return Err(CommandError::Busy);
            }
            if self.controller.is_some() && !self.saved {
                self.persist()?;
            }
            if executable.len() > 4096
                || channel
                    .as_ref()
                    .is_some_and(|c| c.len() > 80 || c.chars().any(char::is_control))
            {
                return Err(CommandError::InvalidSelection);
            }
            let inventory =
                everyout_platform_windows::inventory::InstalledInventory::collect_current_user();
            let mut broad = vec![];
            for folder in [KnownFolder::LocalAppData, KnownFolder::RoamingAppData] {
                if let Ok(root) = CurrentUserFolders.resolve(folder) {
                    broad.push(root);
                }
            }
            if let Some(low) = local_low() {
                broad.push(low);
            }
            let (_, _, candidates) = everyout_detection::storage::discover_with_roots(
                &CurrentUserFolders,
                &inventory,
                &|| false,
            );
            let controller = TeachController::start(
                Path::new(&executable),
                channel,
                broad,
                candidates,
                format!("{}-{}", observation::now_ms(), opaque("teach")),
            )
            .map_err(platform_error)?;
            self.controller = Some(controller);
            self.saved = false;
            self.save_failed = false;
            return Ok(TeachReply::View(Box::new(
                self.controller.as_ref().expect("started").view(),
            )));
        }
        let id = match &request {
            TeachRequest::Get { id }
            | TeachRequest::Discover { id }
            | TeachRequest::BeginCycle { id }
            | TeachRequest::Advance { id, .. }
            | TeachRequest::Finish { id } => id,
            _ => unreachable!(),
        };
        let controller = self
            .controller
            .as_mut()
            .filter(|c| c.session.id == *id)
            .ok_or(CommandError::StalePlan)?;
        match request {
            TeachRequest::Get { .. } => {}
            TeachRequest::Discover { .. } => controller.end_discovery(),
            TeachRequest::BeginCycle { .. } => controller.begin_cycle().map_err(platform_error)?,
            TeachRequest::Advance { signed_in, .. } => {
                controller
                    .advance(Some(signed_in))
                    .map_err(platform_error)?;
                let inventory =
                    everyout_platform_windows::inventory::InstalledInventory::collect_current_user(
                    );
                controller.corroborate(&inventory.win32);
            }
            TeachRequest::Finish { .. } => {
                controller.finish();
                self.save_failed = false;
                if let Err(error) = self.persist() {
                    self.save_failed = true;
                    return Err(error);
                }
            }
            _ => unreachable!(),
        }
        let mut view = self.controller.as_ref().expect("retained").view();
        if self.save_failed {
            view.diagnostics.push("observation-save-failed".into());
        }
        if view.stage == TeachStage::Finished && self.saved {
            view.result = self
                .history(true)?
                .into_iter()
                .find(|record| record.session_id == view.id);
        }
        Ok(TeachReply::View(Box::new(view)))
    }
    fn persist(&mut self) -> Result<(), CommandError> {
        if self.saved {
            return Ok(());
        }
        let previous = self.history(false)?;
        if previous.len() >= 128 {
            return Err(CommandError::ReportIo);
        }
        let controller = self.controller.as_mut().ok_or(CommandError::StalePlan)?;
        let provisional = controller.finish();
        let conflicts = provisional
            .roots
            .iter()
            .filter(|root| {
                previous.iter().any(|record| {
                    unrelated(&record.binding, &provisional.binding)
                        && record.roots.iter().any(|other| {
                            root.physical == other.physical
                                && other.ownership.state
                                    != everyout_core_model::StorageOwnership::Unknown
                        })
                })
            })
            .map(|r| r.root.clone())
            .collect::<Vec<_>>();
        controller.mark_shared(conflicts);
        let observation = controller.finish();
        let record = SavedSession {
            session: controller.session.clone(),
            observation,
        };
        let bytes = serde_json::to_vec_pretty(&record).map_err(|_| CommandError::ReportIo)?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(CommandError::ReportIo);
        }
        fs::create_dir_all(&self.directory).map_err(|_| CommandError::ReportIo)?;
        // Session IDs are produced in Rust, never caller-controlled filenames.
        let path = self.directory.join(format!("{}.json", record.session.id));
        let mut file =
            tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| CommandError::ReportIo)?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| CommandError::ReportIo)?;
        file.persist_noclobber(path)
            .map_err(|_| CommandError::ReportIo)?;
        self.saved = true;
        Ok(())
    }
    fn history(&self, revalidate: bool) -> Result<Vec<LearnedObservation>, CommandError> {
        let files = match fs::read_dir(&self.directory) {
            Ok(files) => files,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(_) => return Err(CommandError::ReportIo),
        };
        let mut paths: Vec<_> = files
            .take(129)
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|e| e == "json"))
            .collect();
        if paths.len() > 128 {
            return Err(CommandError::ReportIo);
        }
        paths.sort();
        paths.reverse();
        let mut history = vec![];
        let mut loaded_bytes = 0u64;
        for path in paths {
            let Ok(metadata) = fs::symlink_metadata(&path) else {
                continue;
            };
            use std::os::windows::fs::MetadataExt;
            if !metadata.is_file()
                || metadata.file_attributes() & 0x400 != 0
                || metadata.len() > 32 * 1024 * 1024
            {
                continue;
            }
            loaded_bytes += metadata.len();
            if loaded_bytes > 64 * 1024 * 1024 {
                return Err(CommandError::ReportIo);
            }
            let Ok(bytes) = fs::read(path) else {
                continue;
            };
            let Ok(saved) = serde_json::from_slice::<SavedSession>(&bytes) else {
                continue;
            };
            let mut record = saved.observation;
            if revalidate {
                let mut selected = Win32Snapshot::default();
                let path = record
                    .binding
                    .executable_path
                    .strip_prefix("\\\\?\\")
                    .unwrap_or(&record.binding.executable_path);
                let binding = selected
                    .observe_executable(Path::new(path), IdentitySource::Selected, None)
                    .ok()
                    .and_then(|_| {
                        observation::application_binding(
                            &selected.applications[0],
                            record.binding.channel.clone(),
                        )
                        .ok()
                    });
                if let Some(binding) = binding {
                    let snapshots: Vec<_> = record
                        .roots
                        .iter()
                        .take(8)
                        .filter_map(|r| {
                            local_root(&r.root).and_then(|root| {
                                observation::snapshot(
                                    &root,
                                    observation::SnapshotBudget {
                                        entries: 2000,
                                        duration: Duration::from_millis(100),
                                        ..Default::default()
                                    },
                                )
                                .ok()
                            })
                        })
                        .collect();
                    record.invalidate(&binding, &snapshots);
                } else {
                    record.status = LearnedStatus::Stale;
                }
            }
            history.push(record);
        }
        // Conflict remains visible in both historical projections; no record is
        // erased or rewritten, and physical roots, rather than labels, are compared.
        let owners: Vec<_> = history
            .iter()
            .flat_map(|r| {
                r.roots
                    .iter()
                    .filter(|root| {
                        root.ownership.state != everyout_core_model::StorageOwnership::Unknown
                    })
                    .map(|root| (root.physical, r.binding.clone()))
            })
            .collect();
        for record in &mut history {
            for root in &mut record.roots {
                if owners.iter().any(|(physical, binding)| {
                    *physical == root.physical && unrelated(binding, &record.binding)
                }) {
                    root.ownership = everyout_core_model::EvidenceState::new(
                        everyout_core_model::StorageOwnership::SharedConflict,
                        "teach-observation",
                        "multiple-application-bindings",
                    );
                }
            }
        }
        Ok(history)
    }
}
fn unrelated(a: &ApplicationBinding, b: &ApplicationBinding) -> bool {
    a.executable != b.executable && !a.executable_path.eq_ignore_ascii_case(&b.executable_path)
}
fn platform_error(error: everyout_platform_windows::PlatformError) -> CommandError {
    match error.kind {
        everyout_core_model::ErrorKind::StalePlan => CommandError::StalePlan,
        everyout_core_model::ErrorKind::Locked => CommandError::Busy,
        _ => CommandError::InvalidSelection,
    }
}
pub(crate) fn local_root(path: &str) -> Option<AllowedRoot> {
    let path = path.strip_prefix("\\\\?\\").unwrap_or(path);
    let target = Path::new(path);
    let mut bases: Vec<_> = [KnownFolder::LocalAppData, KnownFolder::RoamingAppData]
        .into_iter()
        .filter_map(|f| CurrentUserFolders.resolve(f).ok())
        .collect();
    if let Some(low) = local_low() {
        bases.push(low);
    }
    bases.into_iter().find_map(|base| {
        // Canonical base path is supplied by a metadata-only snapshot, never env vars.
        let base_path = base.metadata_path().ok()?.to_string_lossy().into_owned();
        let base_path = base_path.strip_prefix("\\\\?\\").unwrap_or(&base_path);
        let relative = target.strip_prefix(base_path).ok()?.to_str()?;
        base.discovery_descendant(relative).ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use everyout_core_model::StorageOwnership;
    use everyout_platform_windows::{
        observation::{snapshot, SnapshotBudget},
        FixtureFolders,
    };
    use std::collections::BTreeMap;

    fn observed_controller(
        fixture: &FixtureFolders,
        executable: &Path,
        id: &str,
    ) -> TeachController {
        let profile = fixture.path().join("SharedRoot/RandomProfile");
        fs::create_dir_all(profile.join("Local Storage/leveldb")).unwrap();
        fs::create_dir_all(profile.join("Logs")).unwrap();
        let mut controller = TeachController::start(
            executable,
            None,
            vec![fixture.resolve(KnownFolder::LocalAppData).unwrap()],
            vec![],
            id.into(),
        )
        .unwrap();
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(profile.join("Logs/activity.log"))
            .unwrap()
            .write_all(b"discovery\n")
            .unwrap();
        controller.end_discovery();
        let root = fixture
            .resolve(KnownFolder::LocalAppData)
            .unwrap()
            .discovery_descendant("SharedRoot")
            .unwrap();
        let path = root.metadata_path().unwrap().to_string_lossy().into_owned();
        controller.session.roots = vec![path];
        let phases = [
            TeachPhase::ClosedBaseline,
            TeachPhase::LaunchLoggedOut,
            TeachPhase::Login,
            TeachPhase::SettledLoggedIn,
            TeachPhase::RestartPersistence,
            TeachPhase::VendorLogout,
            TeachPhase::ClosedLoggedOut,
        ];
        for _ in 0..2 {
            let mut cycle = TeachCycle { phases: vec![] };
            for (index, phase) in phases.into_iter().enumerate() {
                let auth = profile.join("Local Storage/leveldb/000123.ldb");
                if phase == TeachPhase::Login {
                    fs::write(&auth, b"opaque synthetic state").unwrap();
                }
                if phase == TeachPhase::VendorLogout {
                    fs::remove_file(&auth).unwrap();
                }
                fs::OpenOptions::new()
                    .append(true)
                    .open(profile.join("Logs/activity.log"))
                    .unwrap()
                    .write_all(b"phase\n")
                    .unwrap();
                cycle.phases.push(PhaseObservation {
                    phase,
                    started_at_ms: index as u64,
                    ended_at_ms: index as u64 + 1,
                    snapshots: vec![snapshot(&root, SnapshotBudget::default()).unwrap()],
                    changed_families: BTreeMap::new(),
                    completeness: Completeness::Complete,
                    signed_in: Some((2..=4).contains(&index)),
                    processes: vec![],
                    provenance: vec![provenance("teach-phase", "synthetic-metadata-fixture")],
                });
            }
            controller.session.cycles.push(cycle);
        }
        controller
    }

    #[test]
    fn persistence_retains_cycles_and_projects_shared_conflict_for_both_apps() {
        let fixture = FixtureFolders::create().unwrap();
        fs::create_dir(fixture.path().join("installation")).unwrap();
        let first = fixture.path().join("installation/UnknownOne.exe");
        let second = fixture.path().join("installation/UnknownTwo.exe");
        for path in [&first, &second] {
            fs::copy(std::env::current_exe().unwrap(), path).unwrap();
        }
        let mut worker = TeachWorker {
            directory: fixture.path().join("observations"),
            controller: Some(observed_controller(&fixture, &first, "first")),
            saved: false,
            save_failed: false,
        };
        worker.persist().unwrap();
        assert_eq!(
            worker.history(false).unwrap()[0].status,
            LearnedStatus::Observed
        );
        worker.controller = Some(observed_controller(&fixture, &second, "second"));
        worker.saved = false;
        worker.persist().unwrap();
        let history = worker.history(false).unwrap();
        assert_eq!(history.len(), 2);
        for record in &history {
            assert_eq!(
                record.roots[0].ownership.state,
                StorageOwnership::SharedConflict
            );
            assert_eq!(record.cycles, 2);
            for family in &record.roots[0].families {
                assert!(
                    !record
                        .evidence(&record.roots[0], family)
                        .decide(
                            everyout_core_model::Support::Candidate,
                            &[],
                            everyout_core_model::LossAssessment::Unknown,
                            &[],
                            &[]
                        )
                        .action_allowed
                );
            }
        }
        let persisted: SavedSession =
            serde_json::from_slice(&fs::read(worker.directory.join("first.json")).unwrap())
                .unwrap();
        assert_eq!(persisted.session.cycles.len(), 2);
        assert_eq!(persisted.session.cycles[0].phases.len(), 7);
        // Re-reading applicability outside production AppData cannot adopt the
        // temporary root as a capability, and requests reobservation conservatively.
        assert!(worker
            .history(true)
            .unwrap()
            .iter()
            .all(|r| r.status == LearnedStatus::NeedsReobservation));
        let before = fs::read(worker.directory.join("first.json")).unwrap();
        worker.persist().unwrap();
        assert_eq!(
            fs::read(worker.directory.join("first.json")).unwrap(),
            before
        );
    }
}
