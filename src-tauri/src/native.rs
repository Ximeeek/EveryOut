//! Production capabilities are constructed on a dedicated native worker, never in the webview.
use crate::{application::CurrentSession, dto::*};
use everyout_core_model::*;
use everyout_engine::{EngineProvider, ProcessPreview};
use everyout_platform_windows::{inventory::InstalledInventory, process, CurrentUserFolders};
use everyout_providers::{
    executor::{ManifestExecutor, ProcessGate, WindowsProcessGate},
    Manifest,
};
use std::cell::RefCell;
include!(concat!(env!("OUT_DIR"), "/catalog.rs"));
include!(concat!(env!("OUT_DIR"), "/catalog_trust.rs"));

pub(crate) fn source(
) -> everyout_catalog_update::Result<everyout_catalog_update::transport::HttpsSource> {
    everyout_catalog_update::transport::HttpsSource::new(
        CATALOG_URL.ok_or(everyout_catalog_update::Error::Unconfigured)?,
    )
}
pub(crate) fn catalog_status(
    store: &Option<Result<everyout_catalog_update::store::Store, everyout_catalog_update::Error>>,
    error: Option<everyout_catalog_update::Error>,
) -> CatalogUpdateDto {
    let store = store.as_ref().and_then(|s| s.as_ref().ok());
    let active = store.and_then(|s| s.snapshot().ok());
    let proposed = store.and_then(|s| s.proposed());
    CatalogUpdateDto {
        installed_version: active
            .map(|s| s.version.to_string())
            .unwrap_or_else(|| "unavailable".into()),
        proposed_version: proposed.map(|s| s.version.to_string()),
        digest: proposed.map(|s| s.digest.clone()),
        changelog: proposed.map(|s| s.changelog.clone()),
        error: error.map(|e| e.code().into()),
        helper_compatible: store.is_some_and(|s| s.helper_compatible()),
    }
}

/// Conservative current-session gate: unresolved active process ownership blocks mutation.
/// The reviewed App Paths exception is used by the account helper; the current host does
/// not infer installation authority from an arbitrary process image or a basename.
struct CurrentProcesses {
    names: Vec<String>,
    gate: RefCell<Option<WindowsProcessGate>>,
    cancelled: std::sync::Arc<dyn Fn() -> bool + Send + Sync>,
}
impl CurrentProcesses {
    fn check(&self) -> Result<bool, ErrorKind> {
        if self.names.is_empty() {
            return Ok(false);
        }
        let inventory = process::enumerate_current_user().map_err(|e| e.kind)?;
        if !inventory.unavailable.is_empty() {
            return Err(ErrorKind::AccessDenied);
        }
        let matches: Vec<_> = inventory
            .processes
            .iter()
            .filter(|p| p.matches(&self.names, &[]))
            .collect();
        if matches.is_empty() {
            return Ok(false);
        }
        let paths = everyout_platform_windows::accounts::NativeProfiles
            .current_installation_paths(&self.names)
            .map_err(|e| e.kind)?;
        if paths.is_empty() || matches.iter().any(|p| !p.matches(&self.names, &paths)) {
            return Err(ErrorKind::OwnershipConflict);
        }
        if self.gate.borrow().is_none() {
            self.gate
                .replace(Some(WindowsProcessGate::reviewed_installation(
                    self.names.clone(),
                    paths,
                )?));
        }
        Ok(true)
    }
}
impl ProcessGate for CurrentProcesses {
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
            .close_with_cancellation(policy, &*self.cancelled)
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        if self.check()? {
            Err(ErrorKind::Locked)
        } else {
            Ok(())
        }
    }
}

struct Router<'a> {
    providers: &'a [ManifestExecutor<'a>],
}
impl MetadataAccess for Router<'_> {
    fn observe(
        &self,
        owner: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind> {
        // An installation is a trusted catalog ID; each capability checks the complete owner.
        let mut matches = self
            .providers
            .iter()
            .filter_map(|p| match p.observe(owner, artifact) {
                Ok(m) => Some(Ok(m)),
                Err(ErrorKind::ScopeViolation | ErrorKind::StalePlan) => None,
                Err(e) => Some(Err(e)),
            });
        let result = matches.next().ok_or(ErrorKind::ScopeViolation)?;
        if matches.next().is_some() {
            return Err(ErrorKind::OwnershipConflict);
        }
        result
    }
}
impl LocalOperations for Router<'_> {
    fn apply(&self, plan: &ValidatedPlan, action: &ActionId) -> ActionOutcome {
        // Engine-held provider IDs select one capability; failed adapters cannot broaden scope.
        for provider in self.providers {
            let result = provider.apply(plan, action);
            if !result.issues.iter().any(|i| i.kind == ErrorKind::StalePlan) {
                return result;
            }
        }
        ActionOutcome {
            action_id: action.clone(),
            status: ActionStatus::Blocked,
            issues: vec![],
        }
    }
}

pub fn catalog() -> Result<Vec<(&'static str, Manifest)>, CommandError> {
    BUNDLED
        .iter()
        .map(|json| {
            everyout_providers::load_manifest(json)
                .map(|m| (*json, m))
                .map_err(|_| CommandError::WorkerUnavailable)
        })
        .collect()
}
pub fn serve(mut worker: crate::bridge::Worker) {
    worker.catalog = Some((|| {
        let bundled = everyout_catalog_update::bundled(everyout_catalog_update::entries(
            BUNDLED.iter().map(|s| (*s).to_owned()),
        )?)?;
        let trust = everyout_catalog_update::Trust::new(CATALOG_KEY, &bundled)?;
        if CATALOG_URL.is_some() {
            source()?;
        }
        let path = worker
            .catalog_directory()
            .map_err(|_| everyout_catalog_update::Error::Storage)?;
        everyout_catalog_update::store::Store::open(&path, bundled, trust)
    })());
    loop {
        let catalog: Vec<(String, Manifest)> = worker
            .catalog
            .as_ref()
            .and_then(|s| s.as_ref().ok())
            .and_then(|s| s.snapshot().ok())
            .map(|s| {
                s.entries
                    .iter()
                    .map(|e| {
                        (
                            e.manifest.clone(),
                            everyout_providers::load_manifest(&e.manifest)
                                .expect("verified manifest"),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let resolver = CurrentUserFolders;
        let cancelled = worker.cancellation();
        let gates: Vec<_> = catalog
            .iter()
            .map(|(_, m)| CurrentProcesses {
                names: m.identity.process_names.clone(),
                gate: RefCell::new(None),
                cancelled: cancelled.clone(),
            })
            .collect();
        let mut providers = Vec::new();
        let mut categories = Vec::new();
        let mut unavailable = Vec::new();
        for ((json, manifest), gate) in catalog.iter().zip(&gates) {
            match ManifestExecutor::load(
                json,
                &resolver,
                UserId("current-account".into()),
                InstallationId(manifest.id.clone()),
                gate,
            ) {
                Ok(provider) => {
                    providers.push(provider);
                    categories.push(manifest.category);
                }
                Err(_) => {
                    unavailable.push(format!("{}-execution-adapter-unavailable", manifest.id))
                }
            }
        }
        let router = Router {
            providers: &providers,
        };
        let entries: Vec<_> = providers
            .iter()
            .zip(categories)
            .map(|(p, c)| (c, p as &dyn EngineProvider))
            .collect();
        let session = CurrentSession::new(&router, entries);
        let discovery = || {
            let reviewed: Vec<_> = catalog
                .iter()
                .filter_map(|(json, _)| {
                    everyout_detection::scanner::ReviewedManifest::load(json).ok()
                })
                .collect();
            everyout_detection::scanner::scan(
                &resolver,
                &InstalledInventory::collect_current_user(),
                &reviewed,
                &*cancelled,
            )
        };
        // Rc/RefCell-backed executors and all borrowed capabilities remain on this worker.
        match worker.serve(session, discovery, unavailable) {
            Some(next) => worker = next,
            None => break,
        }
    }
}
