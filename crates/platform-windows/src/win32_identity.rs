//! One read-only Win32 identity resolver. Names select candidates, never authority.
//! All executable bindings reuse the filesystem capability and retain physical objects.
mod metadata;
mod registration;
mod runtime;

use crate::{native, AllowedRoot, PhysicalIdentity, PlatformError, Result, SafePath};
use everyout_core_model::*;
pub use registration::executable_path_hint;
pub(crate) use registration::{app_paths_under, registry_metadata, shortcuts};
pub use runtime::{ProcessIdentity, RuntimeObserver, RuntimeUsage, UsageBudget};
use std::{
    cell::RefCell,
    path::{Path, PathBuf},
    rc::Rc,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentitySource {
    AppPaths,
    Uninstall,
    Shortcut,
    Process,
    Selected,
}
impl IdentitySource {
    fn code(self) -> &'static str {
        match self {
            Self::AppPaths => "app-paths",
            Self::Uninstall => "uninstall-metadata",
            Self::Shortcut => "start-menu-target",
            Self::Process => "runtime-process-identity",
            Self::Selected => "selected-executable",
        }
    }
}
#[derive(Debug, Clone, Default)]
pub struct RegistrationMetadata {
    pub provenance: Vec<EvidenceProvenance>,
    pub name: String,
    pub display_name: Option<String>,
    pub publisher: Option<String>,
    pub install_location: Option<PathBuf>,
    pub display_version: Option<String>,
    pub executable: Option<PathBuf>,
    pub source: Option<IdentitySource>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PeMetadata {
    pub executable_header: bool,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub file_description: Option<String>,
    pub product_version: Option<String>,
    pub file_version: Option<String>,
    pub original_filename: Option<String>,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SignatureStatus {
    Valid,
    Unsigned,
    Invalid,
    #[default]
    Unknown,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureMetadata {
    pub status: SignatureStatus,
    pub publisher: Option<String>,
    /// SHA-256 of the signing certificate, not a display-name assertion.
    pub certificate_sha256: Option<String>,
}
pub struct ExecutableBinding {
    pub lexical_path: PathBuf,
    pub canonical_path: PathBuf,
    pub physical: PhysicalIdentity,
    path: SafePath,
    image_pin: RefCell<Option<native::Handle>>,
    image_stamp: (u64, u64),
}
impl std::fmt::Debug for ExecutableBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExecutableBinding")
            .field("physical", &self.physical)
            .finish_non_exhaustive()
    }
}
impl ExecutableBinding {
    pub fn capture(path: &Path) -> Result<Self> {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?;
        if !name.to_ascii_lowercase().ends_with(".exe") {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let root = AllowedRoot::absolute(
            path.parent()
                .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?,
        )?;
        let safe = root.path(name)?;
        if !safe.probe_shallow()?.exists || safe.probe_shallow()?.is_directory {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let chain = safe
            .physical_chain()?
            .ok_or(PlatformError::new(ErrorKind::StalePlan))?;
        let canonical_path = safe.canonical_metadata_path()?;
        let file = safe.retain_executable_image()?;
        let info = file.info()?;
        Ok(Self {
            lexical_path: path.into(),
            canonical_path,
            physical: *chain.last().expect("file"),
            path: safe,
            image_stamp: (info.size, info.modified_ticks),
            image_pin: RefCell::new(Some(file)),
        })
    }
    pub fn revalidate(&self) -> Result<()> {
        let pin = self.path.retain_executable_image()?;
        let info = pin.info()?;
        if self.path.physical_chain()?.and_then(|c| c.last().copied()) != Some(self.physical)
            || self.path.canonical_metadata_path()? != self.canonical_path
            || (info.size, info.modified_ticks) != self.image_stamp
        {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        Ok(())
    }
    /// Discovery grants no operation: release the image read lock after metadata collection.
    /// SafePath retains the original physical binding; every later use reopens and rechecks it.
    fn release_observation_pin(&self) {
        self.image_pin.borrow_mut().take();
    }
    /// Only executable bytes, through the existing no-reparse capability; never storage.
    pub fn sha256(&self) -> Result<String> {
        metadata::executable_hash(self)
    }
}
#[derive(Debug, Clone)]
pub struct Win32Application {
    pub executable: Rc<ExecutableBinding>,
    pub pe: PeMetadata,
    pub signature: SignatureMetadata,
    pub registrations: Vec<RegistrationMetadata>,
    pub sources: Vec<IdentitySource>,
    pub processes: Vec<ProcessIdentity>,
    pub framework_hints: Vec<String>,
    pub metadata_conflict: bool,
}
impl Win32Application {
    pub(crate) fn executable_metadata(&self) -> Result<native::Info> {
        self.executable.revalidate()?;
        self.executable.path.retain_executable_image()?.info()
    }
    pub fn installation_metadata(&self, relative: &str) -> Result<SafePath> {
        self.executable.revalidate()?;
        AllowedRoot::absolute(
            self.executable
                .canonical_path
                .parent()
                .expect("executable parent"),
        )?
        .path(relative)
    }
    pub fn label(&self) -> String {
        self.pe
            .product_name
            .clone()
            .or_else(|| {
                self.registrations
                    .iter()
                    .find_map(|r| r.display_name.clone())
            })
            .unwrap_or_else(|| {
                self.executable
                    .lexical_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into()
            })
    }
    pub fn identity(&self) -> EvidenceState<ApplicationIdentity> {
        let intact = self.executable.revalidate().is_ok();
        let state = if !intact || self.metadata_conflict {
            ApplicationIdentity::Unknown
        } else if self.sources.contains(&IdentitySource::Selected)
            || self.sources.contains(&IdentitySource::Process)
        {
            // A concrete observed/selected physical executable also supports portable apps.
            ApplicationIdentity::Exact
        } else if self.sources.contains(&IdentitySource::AppPaths)
            || self.sources.contains(&IdentitySource::Shortcut)
        {
            ApplicationIdentity::Corroborated
        } else {
            ApplicationIdentity::Weak
        };
        let mut result = EvidenceState::new(
            state,
            "physical-identity",
            if intact {
                "win32-executable-physical-binding"
            } else {
                "win32-executable-binding-stale"
            },
        );
        for source in &self.sources {
            result.provenance.push(EvidenceProvenance {
                source: source.code().into(),
                reason_code: match source {
                    IdentitySource::Uninstall => "physical-installation-metadata-binding",
                    IdentitySource::Process => "process-start-and-image-binding",
                    IdentitySource::Selected => "selected-physical-executable",
                    _ => "same-physical-executable",
                }
                .into(),
            });
        }
        for registration in &self.registrations {
            result.provenance.extend(registration.provenance.clone());
        }
        if self.pe.executable_header {
            result.provenance.push(EvidenceProvenance {
                source: "pe-metadata".into(),
                reason_code: "static-product-metadata".into(),
            });
        }
        if self.signature.status == SignatureStatus::Valid {
            result.provenance.push(EvidenceProvenance {
                source: "authenticode".into(),
                reason_code: "offline-signature-verified".into(),
            });
        }
        if self.metadata_conflict {
            result.provenance.push(EvidenceProvenance {
                source: "win32-correlation".into(),
                reason_code: "win32-metadata-conflict".into(),
            });
        }
        result
    }
    pub fn matches_names(&self, names: &[String]) -> bool {
        self.executable
            .lexical_path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| names.iter().any(|wanted| wanted.eq_ignore_ascii_case(n)))
    }
    pub fn storage_name_hint(&self, folder: &str) -> bool {
        let stem = self
            .executable
            .lexical_path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy();
        let folder = folder.strip_suffix(".WebView2").unwrap_or(folder);
        [
            Some(stem.as_ref()),
            self.pe.product_name.as_deref(),
            self.pe.file_description.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|s| s.eq_ignore_ascii_case(folder))
            || self.registrations.iter().any(|r| {
                r.display_name
                    .as_deref()
                    .is_some_and(|n| n.eq_ignore_ascii_case(folder))
            })
    }
    /// Runtime use may corroborate ownership; no name/layout/publisher grants exclusivity.
    pub fn storage_evidence(
        &self,
        name_hint: bool,
        layout: bool,
        usage: &RuntimeUsage,
    ) -> EvidenceState<StorageOwnership> {
        let same = usage.processes.iter().any(|p| self.processes.contains(p));
        let unrelated = usage.processes.iter().any(|p| !self.processes.contains(p));
        let state = if usage.shared || (same && unrelated) {
            StorageOwnership::SharedConflict
        } else if same
            && layout
            && matches!(
                self.identity().state,
                ApplicationIdentity::Exact | ApplicationIdentity::Corroborated
            )
        {
            StorageOwnership::Corroborated
        } else {
            StorageOwnership::Unknown
        };
        let mut result =
            EvidenceState::new(state, "win32-correlation", "win32-storage-candidate-only");
        if name_hint {
            result.provenance.push(EvidenceProvenance {
                source: "folder-name-hint".into(),
                reason_code: "product-folder-similarity-only".into(),
            });
        }
        if layout {
            result.provenance.push(EvidenceProvenance {
                source: "framework-inference".into(),
                reason_code: "candidate-layout-consistent".into(),
            });
        }
        if same {
            result.provenance.push(EvidenceProvenance {
                source: "restart-manager".into(),
                reason_code: "exact-process-uses-representative-file".into(),
            });
        }
        result
    }
    /// A trusted record must bind to actual metadata, never its own expected fields.
    pub fn bind_validation(
        &self,
        record: &ProductValidationRecord,
        application_id: &str,
        channel: &str,
        layout: &str,
        families: &[String],
    ) -> Result<ScopeEvidence> {
        let observed =
            if self.identity().state == ApplicationIdentity::Exact {
                self.pe
                    .product_name
                    .as_ref()
                    .zip(
                        self.pe
                            .product_version
                            .as_ref()
                            .or(self.pe.file_version.as_ref()),
                    )
                    .map(|(product, version)| -> Result<ObservedProduct> {
                        Ok(ObservedProduct {
                            application_id: application_id.into(),
                            channel: channel.into(),
                            product_identity: ProductIdentity {
                                executable_name: self
                                    .executable
                                    .canonical_path
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .into(),
                                product_name: product.clone(),
                                sha256: if record.product_identity.sha256.is_some() {
                                    Some(self.executable.sha256()?)
                                } else {
                                    None
                                },
                                publisher: record.product_identity.publisher.as_ref().and(
                                    self.signature.publisher.clone().filter(|_| {
                                        self.signature.status == SignatureStatus::Valid
                                    }),
                                ),
                                signature_identity: record
                                    .product_identity
                                    .signature_identity
                                    .as_ref()
                                    .and(self.signature.certificate_sha256.clone().filter(|_| {
                                        self.signature.status == SignatureStatus::Valid
                                    })),
                            },
                            version: version.clone(),
                            storage_layout: layout.into(),
                            artifact_families: families.to_vec(),
                        })
                    })
                    .transpose()?
            } else {
                None
            };
        let mut evidence = record
            .bind(observed.as_ref())
            .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?;
        if observed.is_none() {
            evidence.version_applicability = EvidenceState::new(
                VersionApplicability::Stale,
                "win32-correlation",
                "validation-runtime-binding-missing",
            );
        }
        Ok(evidence)
    }
}
#[derive(Debug, Clone, Default)]
pub struct Win32Snapshot {
    pub applications: Vec<Win32Application>,
    pub registrations: Vec<RegistrationMetadata>,
    pub coverage: Vec<String>,
    storage_correlations: RefCell<
        Vec<(
            PhysicalIdentity,
            PhysicalIdentity,
            EvidenceState<StorageOwnership>,
        )>,
    >,
}
impl Win32Snapshot {
    pub const MAX_APPLICATIONS: usize = 512;
    pub fn remember_storage(
        &self,
        app: &Win32Application,
        candidate: &SafePath,
        evidence: EvidenceState<StorageOwnership>,
    ) {
        if let Ok(Some(chain)) = candidate.physical_chain() {
            if let Some(physical) = chain.last() {
                let mut correlations = self.storage_correlations.borrow_mut();
                if let Some((_, _, previous)) = correlations
                    .iter_mut()
                    .find(|(exe, store, _)| *exe == app.executable.physical && store == physical)
                {
                    if previous.state != StorageOwnership::SharedConflict {
                        *previous = evidence;
                    }
                } else {
                    correlations.push((app.executable.physical, *physical, evidence));
                }
            }
        }
    }
    pub fn storage_for(
        &self,
        app: &Win32Application,
        candidate: &SafePath,
    ) -> Option<EvidenceState<StorageOwnership>> {
        let physical = candidate.physical_chain().ok()??.last().copied()?;
        let correlations = self.storage_correlations.borrow();
        let mut matches = correlations
            .iter()
            .filter(|(exe, store, _)| *exe == app.executable.physical && *store == physical)
            .map(|(_, _, evidence)| evidence);
        let first = matches.next()?.clone();
        if matches.any(|e| e.state == StorageOwnership::SharedConflict) {
            Some(EvidenceState::new(
                StorageOwnership::SharedConflict,
                "physical-identity",
                "win32-storage-conflicting-observations",
            ))
        } else {
            Some(first)
        }
    }
    pub fn matching(&self, names: &[String]) -> Option<&Win32Application> {
        for name in names {
            let mut matches = self
                .applications
                .iter()
                .filter(|a| a.matches_names(std::slice::from_ref(name)));
            if let Some(first) = matches.next() {
                return matches.next().is_none().then_some(first);
            }
        }
        None
    }
    /// Text selects an already physically resolved candidate; it cannot create identity evidence.
    pub fn matching_product(
        &self,
        names: &[String],
        product_name: &str,
    ) -> Option<&Win32Application> {
        if !names.is_empty() {
            return self.matching(names);
        }
        let mut apps = self.applications.iter().filter(|a| {
            a.pe.product_name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case(product_name))
                || a.executable
                    .canonical_path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.eq_ignore_ascii_case(product_name))
        });
        let first = apps.next()?;
        apps.next().is_none().then_some(first)
    }
    pub fn observe_executable(
        &mut self,
        path: &Path,
        source: IdentitySource,
        process: Option<ProcessIdentity>,
    ) -> Result<()> {
        if source == IdentitySource::Process
            && !process.is_some_and(|p| p.pid != 0 && p.creation_ticks != 0)
            || source != IdentitySource::Process && process.is_some()
        {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let binding = Rc::new(ExecutableBinding::capture(path)?);
        if let Some(app) = self
            .applications
            .iter_mut()
            .find(|a| a.executable.physical == binding.physical)
        {
            if !app.sources.contains(&source) {
                app.sources.push(source);
            }
            if let Some(p) = process {
                if !app.processes.contains(&p) {
                    app.processes.push(p);
                }
            }
            return Ok(());
        }
        if self.applications.len() >= Self::MAX_APPLICATIONS {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        let (pe, signature) = metadata::collect(&binding);
        if !pe.executable_header {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        let metadata_conflict = signature.status == SignatureStatus::Invalid
            || (signature.status == SignatureStatus::Valid
                && pe
                    .company_name
                    .as_deref()
                    .zip(signature.publisher.as_deref())
                    .is_some_and(|(company, publisher)| publisher_conflict(company, publisher)));
        let root =
            AllowedRoot::absolute(binding.canonical_path.parent().expect("executable parent"))?;
        let framework_hints = [
            ("resources/app.asar", "electron"),
            ("libcef.dll", "cef"),
            ("WebView2Loader.dll", "webview2"),
            ("Update.exe", "squirrel"),
        ]
        .into_iter()
        .filter_map(|(path, hint)| {
            root.path(path)
                .and_then(|p| p.probe_shallow())
                .ok()
                .filter(|m| m.exists && !m.is_directory)
                .map(|_| hint.into())
        })
        .collect();
        self.applications.push(Win32Application {
            executable: binding.clone(),
            pe,
            signature,
            registrations: vec![],
            sources: vec![source],
            processes: process.into_iter().collect(),
            framework_hints,
            metadata_conflict,
        });
        binding.release_observation_pin();
        Ok(())
    }
    pub(crate) fn finish(&mut self) {
        self.observe_registrations();
        self.observe_processes();
        self.correlate_registrations();
        self.coverage.sort();
        self.coverage.dedup();
    }
    /// Injection boundary for secret-free registration fixtures; never queries host inventory.
    pub fn from_registrations(registrations: Vec<RegistrationMetadata>) -> Self {
        let mut snapshot = Self {
            registrations,
            ..Default::default()
        };
        snapshot.observe_registrations();
        snapshot.correlate_registrations();
        snapshot
    }
    fn observe_registrations(&mut self) {
        for r in self.registrations.clone() {
            if !matches!(
                r.source,
                Some(
                    IdentitySource::AppPaths | IdentitySource::Uninstall | IdentitySource::Shortcut
                )
            ) {
                continue;
            }
            if let (Some(path), Some(source)) = (&r.executable, r.source) {
                if self.observe_executable(path, source, None).is_err() {
                    self.coverage
                        .push("win32-registration-executable-unavailable".into());
                }
            }
        }
    }
    fn observe_processes(&mut self) {
        match crate::process::enumerate_current_user_bounded(Self::MAX_APPLICATIONS) {
            Ok(processes) => {
                if !processes.unavailable.is_empty() {
                    self.coverage
                        .push("win32-process-coverage-incomplete".into());
                }
                if processes
                    .unavailable
                    .iter()
                    .any(|(pid, e)| *pid == 0 && e.kind == ErrorKind::Unsupported)
                {
                    self.coverage.push("win32-process-entry-limit".into());
                }
                for p in processes.processes.iter().take(Self::MAX_APPLICATIONS) {
                    if p.pid() == std::process::id() {
                        continue;
                    }
                    let id = ProcessIdentity {
                        pid: p.pid(),
                        creation_ticks: p.creation_ticks(),
                    };
                    if self
                        .observe_executable(p.image_path(), IdentitySource::Process, Some(id))
                        .is_err()
                    {
                        self.coverage
                            .push("win32-process-executable-unavailable".into());
                    }
                }
            }
            Err(_) => self
                .coverage
                .push("win32-process-inventory-unavailable".into()),
        }
    }
    fn correlate_registrations(&mut self) {
        for r in &self.registrations {
            if !matches!(
                r.source,
                Some(
                    IdentitySource::AppPaths | IdentitySource::Uninstall | IdentitySource::Shortcut
                )
            ) {
                continue;
            }
            let registered_physical = r
                .executable
                .as_ref()
                .and_then(|p| ExecutableBinding::capture(p).ok())
                .map(|p| p.physical);
            let installed_physical = r
                .install_location
                .as_ref()
                .and_then(|p| AllowedRoot::absolute(p).ok())
                .and_then(|root| root.handle().info().ok())
                .map(|i| PhysicalIdentity::from_native(i.identity));
            for app in &mut self.applications {
                let exact = registered_physical == Some(app.executable.physical);
                let installed = installed_physical.is_some_and(|physical| {
                    // Physical ancestor binding, not a lexical path-prefix assertion.
                    let Ok(Some(exe_chain)) = app.executable.path.physical_chain() else {
                        return false;
                    };
                    exe_chain.contains(&physical)
                });
                if exact || installed {
                    if app.signature.status == SignatureStatus::Valid
                        && r.publisher
                            .as_deref()
                            .zip(app.signature.publisher.as_deref())
                            .is_some_and(|(declared, signed)| publisher_conflict(declared, signed))
                    {
                        app.metadata_conflict = true;
                    }
                    if let Some(source) = r.source {
                        if !app.sources.contains(&source) {
                            app.sources.push(source);
                        }
                    }
                    app.registrations.push(r.clone());
                }
            }
        }
    }
}
fn publisher_conflict(a: &str, b: &str) -> bool {
    let normalize = |value: &str| {
        value
            .split(|c: char| !c.is_alphanumeric())
            .filter(|part| !part.is_empty())
            .map(str::to_lowercase)
            .filter(|part| {
                !matches!(
                    part.as_str(),
                    "inc"
                        | "incorporated"
                        | "corp"
                        | "corporation"
                        | "ltd"
                        | "limited"
                        | "llc"
                        | "ab"
                        | "gmbh"
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let a = normalize(a);
    let b = normalize(b);
    !a.is_empty() && !b.is_empty() && a != b
}
