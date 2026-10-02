//! Declarative execution with a fixed profiles.ini exception. Shipping rules remain unverified
//! candidates until versioned VM evidence resolves S1-S4 and extension isolation.
use crate::{load_manifest, CleaningMethod, Manifest, Root};
use everyout_core_model::*;
use everyout_engine::{EngineProvider, ProcessPreview};
use everyout_platform_windows::{AllowedRoot, KnownFolder, RootResolver, SafePath};
use std::{cell::RefCell, rc::Rc};

/// Trusted process coordinator supplied by the application, never by UI input.
/// Preview retains exact process identities; close refuses a changed set and
/// revalidate detects relaunch before every engine-held operation.
pub trait ProcessGate {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind>;
    fn close(&self, policy: ProcessClosePolicy) -> Result<(), ErrorKind>;
    fn revalidate(&self) -> Result<(), ErrorKind>;
}

/// Uses only current-user/current-session process metadata and reviewed executable
/// paths. Names alone never authorize closing another application's process.
pub struct WindowsProcessGate {
    names: Vec<String>,
    paths: Vec<std::path::PathBuf>,
    retained: RefCell<Option<everyout_platform_windows::process::ProcessInventory>>,
}
impl WindowsProcessGate {
    pub fn reviewed_installation(
        names: Vec<String>,
        paths: Vec<std::path::PathBuf>,
    ) -> Result<Self, ErrorKind> {
        if names.is_empty() || paths.is_empty() || paths.iter().any(|p| !p.is_absolute()) {
            return Err(ErrorKind::OwnershipConflict);
        }
        Ok(Self {
            names,
            paths,
            retained: RefCell::new(None),
        })
    }
    fn inventory(&self) -> Result<everyout_platform_windows::process::ProcessInventory, ErrorKind> {
        let mut inventory =
            everyout_platform_windows::process::enumerate_current_user().map_err(|e| e.kind)?;
        if !inventory.unavailable.is_empty() {
            return Err(ErrorKind::AccessDenied);
        }
        inventory
            .processes
            .retain(|p| p.matches(&self.names, &self.paths));
        Ok(inventory)
    }
}
impl ProcessGate for WindowsProcessGate {
    fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
        let inventory = self.inventory()?;
        let result = inventory
            .processes
            .iter()
            .map(|p| ProcessPreview {
                identity: format!("process-{}-{}", p.pid(), p.creation_ticks()),
                label: "browser-process".into(),
                unsaved_work_loss: true,
            })
            .collect();
        self.retained.replace(Some(inventory));
        Ok(result)
    }
    fn close(&self, policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        let current = self.inventory()?;
        let retained = self.retained.borrow();
        let retained = retained.as_ref().ok_or(ErrorKind::StalePlan)?;
        let identities = |i: &everyout_platform_windows::process::ProcessInventory| {
            let mut ids: Vec<_> = i
                .processes
                .iter()
                .map(|p| (p.pid(), p.creation_ticks()))
                .collect();
            ids.sort();
            ids
        };
        if identities(&current) != identities(retained) {
            return Err(ErrorKind::StalePlan);
        }
        let targets: Vec<_> = retained.processes.iter().collect();
        let report = everyout_platform_windows::process::close_processes(&targets, policy, false);
        if let Some(error) = report.results.iter().find_map(|r| r.error) {
            return Err(error.kind);
        }
        if !report.remaining.is_empty() {
            return Err(ErrorKind::Locked);
        }
        self.revalidate()
    }
    fn revalidate(&self) -> Result<(), ErrorKind> {
        if self.inventory()?.processes.is_empty() {
            Ok(())
        } else {
            Err(ErrorKind::Locked)
        }
    }
}

struct Target {
    action: PlannedAction,
    path: Rc<SafePath>,
    kind: ArtifactKind,
    label: String,
}
struct Binding {
    instance: ProviderInstance,
    targets: Vec<Target>,
    risks: RiskAssessment,
    issues: Vec<ProviderIssue>,
    root: AllowedRoot,
    profile_names: Vec<String>,
    extension_scopes: Vec<ExtensionScope>,
    origin_scopes: Vec<(String, Vec<(String, bool)>)>,
}
struct ExtensionScope {
    path: Rc<SafePath>,
    root: Option<AllowedRoot>,
    children: Vec<(String, bool)>,
}

/// One reviewed installation and root. Multi-root manifests must be split into
/// independent ownership scopes; unsupported adapters never fall back to deletion.
pub struct ManifestExecutor<'a> {
    manifest: Manifest,
    resolver: &'a dyn RootResolver,
    user: UserId,
    installation: InstallationId,
    processes: &'a dyn ProcessGate,
    binding: RefCell<Option<Binding>>,
    snapshot: RefCell<Option<SnapshotId>>,
}
impl<'a> ManifestExecutor<'a> {
    pub fn load(
        json: &str,
        resolver: &'a dyn RootResolver,
        user: UserId,
        installation: InstallationId,
        processes: &'a dyn ProcessGate,
    ) -> Result<Self, ErrorKind> {
        let manifest = load_manifest(json).map_err(|_| ErrorKind::InvalidManifest)?;
        if manifest.roots.len() != 1
            || user.0.is_empty()
            || installation.0.is_empty()
            || matches!(manifest.roots[0], Root::Registry { .. })
        {
            return Err(ErrorKind::Unsupported);
        }
        Ok(Self {
            manifest,
            resolver,
            user,
            installation,
            processes,
            binding: RefCell::new(None),
            snapshot: RefCell::new(None),
        })
    }
    fn issue(&self, phase: Phase, kind: ErrorKind, blocked: bool) -> ProviderIssue {
        ProviderIssue {
            phase,
            provider_id: ProviderId(self.manifest.id.clone()),
            instance_id: Some(InstanceId(format!("{}-installation", self.manifest.id))),
            action_id: None,
            kind,
            os_code: None,
            explanation_code: "manifest-scope-incomplete".into(),
            blocked,
        }
    }
    fn base(&self) -> (KnownFolder, &str) {
        match &self.manifest.roots[0] {
            Root::LocalAppData { relative, .. } => (KnownFolder::LocalAppData, relative),
            Root::RoamingAppData { relative, .. } => (KnownFolder::RoamingAppData, relative),
            Root::Registry { .. } => unreachable!("constructor refuses registry roots"),
        }
    }
    fn discover(&self) -> Result<Binding, ErrorKind> {
        let m = &self.manifest;
        let (base, relative) = self.base();
        let root = AllowedRoot::from_manifest(self.resolver, base, relative).map_err(|e| e.kind)?;
        let owner = OwnerIdentity {
            user_id: self.user.clone(),
            installation_id: self.installation.clone(),
            root_id: RootId(format!("{}-{}", m.id, m.roots[0].id())),
        };
        let mut instance = ProviderInstance {
            provider_id: ProviderId(m.id.clone()),
            instance_id: InstanceId(format!("{}-installation", m.id)),
            owner,
            profiles: vec![],
            confidence: m.confidence.level,
            detection_origin: DetectionOrigin::KnownProvider,
            evidence: m
                .evidence
                .iter()
                .map(|e| EvidenceRef(e.id.clone()))
                .collect(),
            issues: vec![],
        };
        let mut profiles = Vec::new();
        let issues = Vec::new();
        if let Some(p) = &m.profiles {
            profiles = self.discover_profiles(&root, p)?;
        } else {
            profiles.push(String::new());
        }
        let mut binding = Binding {
            instance: instance.clone(),
            targets: vec![],
            risks: m.risks.clone(),
            issues,
            root: root.clone(),
            profile_names: profiles.clone(),
            extension_scopes: vec![],
            origin_scopes: vec![],
        };
        for (index, profile) in profiles.iter().enumerate() {
            let profile_id = ProfileId(format!("{}-profile-{index}", m.id));
            if m.profiles.is_some() {
                instance.profiles.push(ProfileScope {
                    profile_id: profile_id.clone(),
                    root_id: instance.owner.root_id.clone(),
                });
            }
            for artifact in &m.session_locations {
                if artifact.scope != Scope::Profile && index != 0 {
                    continue;
                }
                let method = m
                    .cleaning_methods
                    .iter()
                    .find(|method| method.id() == artifact.method)
                    .expect("validated method");
                let (kind, suffixes, unsupported) = match method {
                    CleaningMethod::DeleteFileFamily { companions, .. } => {
                        (MethodKind::DeleteFileFamily, companions.as_slice(), false)
                    }
                    CleaningMethod::DeleteDirectoryFamily { exclusions, .. } => (
                        MethodKind::DeleteDirectoryFamily,
                        &[][..],
                        !exclusions.is_empty(),
                    ),
                    _ => (MethodKind::ExceptionAdapter, &[][..], true),
                };
                let mut blockers = method.blockers().to_vec();
                if unsupported {
                    blockers.push("unsupported-declarative-method".into());
                }
                if artifact
                    .artifact_family
                    .as_ref()
                    .is_some_and(|f| m.preserve.artifact_families.contains(f))
                    || (m.category == Category::Browser
                        && !browser_target(&m.id, &artifact.relative, artifact.kind))
                {
                    blockers.push("preservation-conflict".into());
                }
                let prefix = if artifact.scope == Scope::Profile && !profile.is_empty() {
                    format!("{profile}/")
                } else {
                    String::new()
                };
                let path = format!("{prefix}{}", artifact.relative.replace('\\', "/"));
                self.bind_target(
                    &mut binding,
                    &root,
                    &path,
                    &format!("p{index}-{}", artifact.id),
                    (artifact.scope == Scope::Profile).then_some(profile_id.clone()),
                    kind,
                    artifact.kind,
                    method.id(),
                    method.effects(),
                    &blockers,
                    artifact.artifact_family.as_deref(),
                )?;
                for (sidecar, suffix) in suffixes.iter().enumerate() {
                    self.bind_target(
                        &mut binding,
                        &root,
                        &format!("{path}{suffix}"),
                        &format!("p{index}-{}-companion-{sidecar}", artifact.id),
                        (artifact.scope == Scope::Profile).then_some(profile_id.clone()),
                        kind,
                        ArtifactKind::File,
                        method.id(),
                        method.effects(),
                        &blockers,
                        artifact.artifact_family.as_deref(),
                    )?;
                }
            }
            if m.id == "firefox" {
                // UUID origins and sync databases cannot be mapped to extension IDs
                // without prohibited prefs/extension payload reads. Block, never guess.
                for store in ["storage/default", "storage/temporary", "storage/permanent"] {
                    let path = format!("{profile}/{store}");
                    let children = self.origin_children(&root, &path)?;
                    if children
                        .iter()
                        .any(|(name, _)| name.starts_with("moz-extension"))
                    {
                        binding
                            .issues
                            .push(self.issue(Phase::Plan, ErrorKind::Unsupported, true));
                        if !binding.risks.flags.contains(&RiskFlag::Unknown) {
                            binding.risks.flags.push(RiskFlag::Unknown);
                        }
                        binding.risks.permanent_data_loss = LossAssessment::Unknown;
                    }
                    binding.origin_scopes.push((path, children));
                }
                for store in ["storage-sync-v2.sqlite", "storage-sync.sqlite"] {
                    for suffix in ["", "-wal", "-shm", "-journal"] {
                        let path = root
                            .path(&format!("{profile}/{store}{suffix}"))
                            .map_err(|e| e.kind)?;
                        if path.probe_shallow().map_err(|e| e.kind)?.exists {
                            if !binding.risks.flags.contains(&RiskFlag::Unknown) {
                                binding.risks.flags.push(RiskFlag::Unknown);
                            }
                            binding.risks.permanent_data_loss = LossAssessment::Unknown;
                            binding.issues.push(self.issue(
                                Phase::Plan,
                                ErrorKind::Unsupported,
                                true,
                            ));
                        }
                        // These mixed stores are preserved; appearance after review
                        // invalidates the plan just like a newly added extension store.
                        binding.extension_scopes.push(ExtensionScope {
                            path: Rc::new(path),
                            root: None,
                            children: vec![],
                        });
                    }
                }
            }
            if let Some(policy) = &m.extensions {
                for store in &policy.stores {
                    let path = if profile.is_empty() {
                        store.clone()
                    } else {
                        format!("{profile}/{store}")
                    };
                    let candidate = root.path(&path).map_err(|e| e.kind)?;
                    if !candidate.probe_shallow().map_err(|e| e.kind)?.exists {
                        binding.extension_scopes.push(ExtensionScope {
                            path: Rc::new(candidate),
                            root: None,
                            children: vec![],
                        });
                        continue;
                    }
                    let scope = AllowedRoot::from_manifest(
                        self.resolver,
                        base,
                        &format!("{relative}/{path}"),
                    )
                    .map_err(|e| e.kind)?;
                    let (children, omitted) = scope.discovery_children().map_err(|e| e.kind)?;
                    binding.extension_scopes.push(ExtensionScope {
                        path: Rc::new(candidate),
                        root: Some(scope),
                        children: children.clone(),
                    });
                    if omitted {
                        binding.issues.push(self.issue(
                            Phase::Detect,
                            ErrorKind::ScopeViolation,
                            true,
                        ));
                    }
                    for (id, directory) in children {
                        if !directory {
                            binding.issues.push(self.issue(
                                Phase::Detect,
                                ErrorKind::ScopeViolation,
                                true,
                            ));
                            continue;
                        }
                        let known = policy.known.iter().find(|e| e.id == id);
                        let blockers = if known.is_some_and(|risk| risk.confidence == "verified") {
                            vec![]
                        } else if known.is_some() {
                            vec!["unverified-extension-identity".into()]
                        } else {
                            vec!["unknown-extension-storage".into()]
                        };
                        if let Some(risk) = known {
                            if !binding.risks.flags.contains(&risk.flag) {
                                binding.risks.flags.push(risk.flag);
                            }
                            if binding.risks.permanent_data_loss != LossAssessment::Unknown {
                                binding.risks.permanent_data_loss = LossAssessment::Known;
                            }
                            binding
                                .risks
                                .affected_data
                                .push(format!("extension-{}", risk.id));
                            binding.risks.reason =
                                Some("extension-vault-wallet-or-2fa-data".into());
                            binding
                                .risks
                                .confirmations
                                .push(ConfirmationId("extension-permanent-data-loss".into()));
                        } else {
                            if !binding.risks.flags.contains(&RiskFlag::Unknown) {
                                binding.risks.flags.push(RiskFlag::Unknown);
                            }
                            binding.risks.permanent_data_loss = LossAssessment::Unknown;
                            binding.issues.push(self.issue(
                                Phase::Plan,
                                ErrorKind::Unsupported,
                                true,
                            ));
                        }
                        let index_target = binding.targets.len();
                        self.bind_target(
                            &mut binding,
                            &root,
                            &format!("{path}/{id}"),
                            &format!("extension-{index_target}"),
                            Some(profile_id.clone()),
                            MethodKind::DeleteDirectoryFamily,
                            ArtifactKind::Directory,
                            "remove-extension-store",
                            &["extension-persistent-data".into()],
                            &blockers,
                            Some("extension-storage"),
                        )?;
                    }
                }
            }
        }
        // Every failed discovery blocks the scope, including shared origin storage.
        // Knowing an extension ID cannot establish safe exclusions in opaque stores.
        instance.issues = binding.issues.clone();
        binding.instance = instance;
        Ok(binding)
    }
    #[allow(clippy::too_many_arguments)]
    fn bind_target(
        &self,
        binding: &mut Binding,
        root: &AllowedRoot,
        relative: &str,
        id: &str,
        profile: Option<ProfileId>,
        method: MethodKind,
        kind: ArtifactKind,
        method_id: &str,
        effects: &[String],
        blockers: &[String],
        family: Option<&str>,
    ) -> Result<(), ErrorKind> {
        if binding.targets.len() >= 10_000 {
            return Err(ErrorKind::ScopeViolation);
        }
        let id = format!("{}-{id}", self.manifest.id);
        let path = root.path(relative).map_err(|e| e.kind)?;
        let metadata = path.probe_shallow().map_err(|e| e.kind)?;
        if metadata.exists && metadata.is_directory != (kind == ArtifactKind::Directory) {
            return Err(ErrorKind::ScopeViolation);
        }
        binding.targets.push(Target {
            action: PlannedAction {
                action_id: ActionId(id.clone()),
                artifact_id: ArtifactId(id),
                root_id: binding.instance.owner.root_id.clone(),
                profile_id: profile,
                method_id: method_id.into(),
                method,
                owner: binding.instance.owner.clone(),
                shared_owners: vec![],
                artifact_families: family.into_iter().map(str::to_owned).collect(),
                effects: effects.to_vec(),
                blockers: blockers.to_vec(),
                confirmations: vec![],
            },
            path: Rc::new(path),
            kind,
            label: relative.to_owned(),
        });
        Ok(())
    }
    fn matches_plan(&self, plan: &ProposedPlan) -> bool {
        let binding = self.binding.borrow();
        let Some(binding) = binding.as_ref() else {
            return false;
        };
        plan.provider_id.0 == self.manifest.id
            && plan.manifest_revision == self.manifest.revision
            && plan.support == self.manifest.support
            && plan.risks == binding.risks
            && self.snapshot.borrow().as_ref() == Some(&plan.selection.snapshot_id)
            && plan.selection.account_mode == AccountMode::Current
            && plan.selection.instances == [binding.instance.instance_id.clone()]
            && plan
                .actions
                .iter()
                .all(|a| binding.targets.iter().any(|t| &t.action == a))
    }
    fn discover_profiles(
        &self,
        root: &AllowedRoot,
        profiles: &crate::Profiles,
    ) -> Result<Vec<String>, ErrorKind> {
        if profiles.metadata_adapter.as_deref() == Some(crate::firefox::ADAPTER) {
            return crate::firefox::discover(root);
        }
        let (children, omitted) = root.discovery_children().map_err(|e| e.kind)?;
        if omitted {
            return Err(ErrorKind::ScopeViolation);
        }
        let mut names = Vec::new();
        if profiles.root_profile == Some(true) {
            names.push(String::new());
        }
        names.extend(
            children
                .into_iter()
                .filter(|(name, directory)| {
                    *directory
                        && profiles
                            .directory_patterns
                            .iter()
                            .any(|p| profile_matches(p, name))
                })
                .map(|(name, _)| name),
        );
        if names.len() > 100 {
            return Err(ErrorKind::ScopeViolation);
        }
        Ok(names)
    }
    fn origin_children(
        &self,
        root: &AllowedRoot,
        path: &str,
    ) -> Result<Vec<(String, bool)>, ErrorKind> {
        if !root
            .path(path)
            .map_err(|e| e.kind)?
            .probe_shallow()
            .map_err(|e| e.kind)?
            .exists
        {
            return Ok(vec![]);
        }
        let (base, relative) = self.base();
        let scope = AllowedRoot::from_manifest(self.resolver, base, &format!("{relative}/{path}"))
            .map_err(|e| e.kind)?;
        let (children, omitted) = scope.discovery_children().map_err(|e| e.kind)?;
        if omitted {
            return Err(ErrorKind::ScopeViolation);
        }
        Ok(children)
    }
    fn revalidate_scope(&self) -> Result<(), ErrorKind> {
        self.processes.revalidate()?;
        let binding = self.binding.borrow();
        let binding = binding.as_ref().ok_or(ErrorKind::StalePlan)?;
        if let Some(profiles) = &self.manifest.profiles {
            if self.discover_profiles(&binding.root, profiles)? != binding.profile_names {
                return Err(ErrorKind::StalePlan);
            }
        }
        for (path, expected) in &binding.origin_scopes {
            let children = self.origin_children(&binding.root, path)?;
            if children.iter().any(|entry| !expected.contains(entry)) {
                return Err(ErrorKind::StalePlan);
            }
        }
        for ExtensionScope {
            path,
            root,
            children: expected,
        } in &binding.extension_scopes
        {
            let present = path.probe_shallow().map_err(|e| e.kind)?.exists;
            if present != root.is_some() {
                return Err(ErrorKind::StalePlan);
            }
            if let Some(root) = root {
                let (children, omitted) = root.discovery_children().map_err(|e| e.kind)?;
                if omitted || children.iter().any(|entry| !expected.contains(entry)) {
                    return Err(ErrorKind::StalePlan);
                }
            }
        }
        Ok(())
    }
}

fn profile_matches(pattern: &str, name: &str) -> bool {
    if pattern == "Profile *" {
        return name
            .strip_prefix("Profile ")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
    }
    match pattern.split_once('*') {
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        }
        None => name == pattern,
    }
}
fn browser_target(browser: &str, path: &str, kind: ArtifactKind) -> bool {
    if browser == "firefox" {
        return match kind {
            ArtifactKind::File => matches!(
                path.replace('\\', "/").as_str(),
                "cookies.sqlite"
                    | "storage.sqlite"
                    | "webappsstore.sqlite"
                    | "chromeappsstore.sqlite"
                    | "ls-archive-tmp.sqlite"
                    | "serviceworker.txt"
                    | "sessionstore.jsonlz4"
            ),
            ArtifactKind::Directory => matches!(
                path.replace('\\', "/").as_str(),
                "storage" | "indexedDB" | "sessionstore-backups"
            ),
            _ => false,
        };
    }
    let path = path.replace('\\', "/");
    match kind {
        ArtifactKind::File => matches!(
            path.as_str(),
            "Cookies"
                | "Network/Cookies"
                | "Network/Device Bound Sessions"
                | "Extension Cookies"
                | "Current Session"
                | "Current Tabs"
                | "Last Session"
                | "Last Tabs"
                | "QuotaManager"
                | "LocalStorage"
                | "SessionStorage"
                | "SharedStorage"
        ),
        ArtifactKind::Directory => matches!(
            path.as_str(),
            "Local Storage"
                | "Session Storage"
                | "IndexedDB"
                | "Service Worker"
                | "File System"
                | "WebStorage"
                | "databases"
                | "Application Cache"
                | "blob_storage"
                | "Sessions"
                | "Sessions_Encrypted"
        ),
        _ => false,
    }
}

impl MetadataAccess for ManifestExecutor<'_> {
    fn observe(
        &self,
        owner: &OwnerIdentity,
        artifact: &ArtifactId,
    ) -> Result<MetadataObservation, ErrorKind> {
        let binding = self.binding.borrow();
        let binding = binding.as_ref().ok_or(ErrorKind::StalePlan)?;
        if owner != &binding.instance.owner {
            return Err(ErrorKind::ScopeViolation);
        }
        let target = binding
            .targets
            .iter()
            .find(|t| &t.action.artifact_id == artifact)
            .ok_or(ErrorKind::ScopeViolation)?;
        let m = target.path.probe_shallow().map_err(|e| e.kind)?;
        if m.exists && m.is_directory != (target.kind == ArtifactKind::Directory) {
            return Err(ErrorKind::ScopeViolation);
        }
        Ok(MetadataObservation {
            artifact_id: artifact.clone(),
            kind: target.kind,
            exists: m.exists,
            size: m.size,
        })
    }
}
impl LocalOperations for ManifestExecutor<'_> {
    fn apply(&self, plan: &ValidatedPlan, id: &ActionId) -> ActionOutcome {
        let operation = || -> Result<ActionStatus, ErrorKind> {
            if !self.matches_plan(plan.plan()) {
                return Err(ErrorKind::StalePlan);
            }
            self.revalidate_scope()?;
            let binding = self.binding.borrow();
            let target = binding
                .as_ref()
                .and_then(|b| b.targets.iter().find(|t| &t.action.action_id == id))
                .ok_or(ErrorKind::ScopeViolation)?;
            if !plan.plan().actions.contains(&target.action) {
                return Err(ErrorKind::ScopeViolation);
            }
            let result = if target.kind == ArtifactKind::Directory {
                target.path.delete_tree(false)
            } else {
                target.path.delete_file(false)
            };
            result.map(|m| m.status).map_err(|e| e.kind)
        };
        match operation() {
            Ok(status) => ActionOutcome {
                action_id: id.clone(),
                status,
                issues: vec![],
            },
            Err(kind) => {
                let mut issue = self.issue(Phase::Execute, kind, true);
                issue.action_id = Some(id.clone());
                ActionOutcome {
                    action_id: id.clone(),
                    status: ActionStatus::Failed,
                    issues: vec![issue],
                }
            }
        }
    }
}
impl Provider for ManifestExecutor<'_> {
    fn detect(&self, cx: &DetectionContext<'_>) -> DetectionResult {
        let mut result = DetectionResult {
            snapshot_id: cx.snapshot_id.clone(),
            instances: vec![],
            observations: vec![],
            issues: vec![],
        };
        self.binding.replace(None);
        self.snapshot.replace(Some(cx.snapshot_id.clone()));
        if cx.account_mode != AccountMode::Current {
            result
                .issues
                .push(self.issue(Phase::Detect, ErrorKind::Unsupported, true));
            return result;
        }
        match self.discover() {
            Ok(binding) => {
                for target in &binding.targets {
                    match target.path.probe_shallow() {
                        Ok(m) => result.observations.push(MetadataObservation {
                            artifact_id: target.action.artifact_id.clone(),
                            kind: target.kind,
                            exists: m.exists,
                            size: m.size,
                        }),
                        Err(e) => result.issues.push(self.issue(Phase::Detect, e.kind, true)),
                    }
                }
                result.instances.push(binding.instance.clone());
                result.issues.extend(binding.issues.clone());
                self.binding.replace(Some(binding));
            }
            Err(kind) => result.issues.push(self.issue(Phase::Detect, kind, true)),
        }
        result
    }
    fn describe(&self, instance: &ProviderInstance) -> ProviderDescription {
        let risks = self
            .binding
            .borrow()
            .as_ref()
            .map(|b| b.risks.clone())
            .unwrap_or_else(|| self.manifest.risks.clone());
        ProviderDescription {
            descriptor: ProviderDescriptor {
                provider_id: ProviderId(self.manifest.id.clone()),
                name: self.manifest.name.clone(),
                category: self.manifest.category,
                revision: self.manifest.revision,
                support: self.manifest.support,
                evidence: self
                    .manifest
                    .evidence
                    .iter()
                    .map(|e| EvidenceRef(e.id.clone()))
                    .collect(),
                limitations: self.manifest.limitations.clone(),
            },
            instance_id: instance.instance_id.clone(),
            profiles: instance.profiles.clone(),
            risks,
            expected_effects: self
                .manifest
                .cleaning_methods
                .iter()
                .flat_map(|m| m.effects().iter().cloned())
                .collect(),
        }
    }
    fn plan(&self, cx: &PlanContext<'_>, selection: &Selection) -> PlanResult {
        let binding = self.binding.borrow();
        let blocked = |kind| PlanResult::Blocked {
            issues: vec![self.issue(Phase::Plan, kind, true)],
        };
        let Some(b) = binding.as_ref() else {
            return blocked(ErrorKind::StalePlan);
        };
        if cx.inventory.snapshot_id != selection.snapshot_id
            || self.snapshot.borrow().as_ref() != Some(&selection.snapshot_id)
            || !cx.inventory.instances.contains(&b.instance)
            || selection.instances != [b.instance.instance_id.clone()]
            || selection.account_mode != AccountMode::Current
            || selection
                .profiles
                .iter()
                .any(|id| !b.instance.profiles.iter().any(|p| &p.profile_id == id))
        {
            return blocked(ErrorKind::ScopeViolation);
        }
        let actions = b
            .targets
            .iter()
            .filter(|t| {
                t.action
                    .profile_id
                    .as_ref()
                    .is_none_or(|p| selection.profiles.contains(p))
            })
            .map(|t| t.action.clone())
            .collect();
        PlanResult::Ready(Box::new(ProposedPlan {
            plan_id: PlanId(format!("{}-{}", self.manifest.id, selection.snapshot_id.0)),
            provider_id: b.instance.provider_id.clone(),
            manifest_revision: self.manifest.revision,
            support: self.manifest.support,
            selection: selection.clone(),
            actions,
            risks: b.risks.clone(),
            blockers: if b.issues.iter().any(|i| i.blocked) {
                vec!["incomplete-metadata-scope".into()]
            } else {
                vec![]
            },
            confirmations: vec![],
            limitations: self.manifest.limitations.clone(),
        }))
    }
    fn execute(
        &self,
        cx: &OperationContext<'_>,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult {
        let mut result = ExecutionResult {
            plan_id: plan.plan().plan_id.clone(),
            mode,
            outcomes: vec![],
            issues: vec![],
        };
        if !self.matches_plan(plan.plan()) {
            result
                .issues
                .push(self.issue(Phase::Execute, ErrorKind::StalePlan, true));
            return result;
        }
        for action in &plan.plan().actions {
            let outcome = if (cx.cancelled)() {
                ActionOutcome {
                    action_id: action.action_id.clone(),
                    status: ActionStatus::Skipped,
                    issues: vec![self.issue(Phase::Execute, ErrorKind::Cancelled, true)],
                }
            } else if mode == ExecutionMode::Apply {
                cx.operations.apply(plan, &action.action_id)
            } else {
                match cx.operations.observe(&action.owner, &action.artifact_id) {
                    Ok(m) => ActionOutcome {
                        action_id: action.action_id.clone(),
                        status: if m.exists {
                            ActionStatus::WouldApply
                        } else {
                            ActionStatus::AlreadyAbsent
                        },
                        issues: vec![],
                    },
                    Err(kind) => ActionOutcome {
                        action_id: action.action_id.clone(),
                        status: ActionStatus::Blocked,
                        issues: vec![self.issue(Phase::Execute, kind, true)],
                    },
                }
            };
            result.outcomes.push(outcome);
        }
        result
    }
    fn verify(&self, cx: &VerificationContext<'_>, result: &ExecutionResult) -> VerificationResult {
        let mut verification = VerificationResult {
            plan_id: result.plan_id.clone(),
            artifacts: vec![],
            issues: vec![],
        };
        if result.plan_id != cx.plan.plan().plan_id || !self.matches_plan(cx.plan.plan()) {
            verification
                .issues
                .push(self.issue(Phase::Verify, ErrorKind::StalePlan, true));
            return verification;
        }
        let quiescent = self.revalidate_scope();
        for action in &cx.plan.plan().actions {
            let observed = cx.metadata.observe(&action.owner, &action.artifact_id);
            let status = if result.mode == ExecutionMode::DryRun {
                VerificationStatus::NotPerformed
            } else {
                match &observed {
                    Ok(_) if quiescent.is_err() => VerificationStatus::Unknown,
                    Ok(m) if !m.exists => VerificationStatus::TargetAbsent,
                    Ok(_) => VerificationStatus::TargetPresent,
                    Err(ErrorKind::AccessDenied) => VerificationStatus::Inaccessible,
                    Err(_) => VerificationStatus::Unknown,
                }
            };
            let issues = quiescent
                .err()
                .or_else(|| observed.as_ref().err().copied())
                .map(|kind| self.issue(Phase::Verify, kind, true))
                .into_iter()
                .collect();
            verification.artifacts.push(ArtifactVerification {
                artifact_id: action.artifact_id.clone(),
                status,
                observation: observed.ok(),
                issues,
            });
        }
        verification
    }
    fn report(&self, result: &ProviderResult) -> SanitizedReport {
        let item = ReportItem {
            provider_id: result.description.descriptor.provider_id.clone(),
            instance_id: result.description.instance_id.clone(),
            user_id: UserId("current-user".into()),
            profiles: result
                .description
                .profiles
                .iter()
                .map(|p| p.profile_id.clone())
                .collect(),
            shared_effects: vec![],
            aggregate: result.aggregate,
            outcomes: result.execution.outcomes.clone(),
            verification: result.verification.artifacts.clone(),
            issues: result
                .execution
                .issues
                .iter()
                .chain(&result.verification.issues)
                .cloned()
                .collect(),
            risk_flags: result.description.risks.flags.clone(),
            limitations: result.description.descriptor.limitations.clone(),
            authentication: Uncertainty::Unknown,
            browser_identity: Uncertainty::Unknown,
            sync: Uncertainty::Unknown,
            silent_sso: Uncertainty::Unknown,
            remote_revocation: Uncertainty::Unsupported,
        };
        let mut report = SanitizedReport {
            applications: vec![],
            browsers: vec![],
            windows_microsoft_and_dev_tools: vec![],
        };
        match self.manifest.category {
            Category::Browser => report.browsers.push(item),
            Category::Application => report.applications.push(item),
            Category::WindowsMicrosoftAndDevTools => {
                report.windows_microsoft_and_dev_tools.push(item)
            }
        }
        report
    }
}
impl EngineProvider for ManifestExecutor<'_> {
    fn process_preview(&self, plan: &ProposedPlan) -> Result<Vec<ProcessPreview>, ErrorKind> {
        if !self.matches_plan(plan) {
            return Err(ErrorKind::StalePlan);
        }
        self.processes.preview()
    }
    fn close(&self, plan: &ValidatedPlan, policy: ProcessClosePolicy) -> Result<(), ErrorKind> {
        if !self.matches_plan(plan.plan()) {
            return Err(ErrorKind::StalePlan);
        }
        self.processes.close(policy)
    }
    fn revalidate(&self, plan: &ValidatedPlan) -> Result<(), ErrorKind> {
        if !self.matches_plan(plan.plan()) {
            return Err(ErrorKind::StalePlan);
        }
        self.revalidate_scope()
    }
    fn target_label(&self, action: &PlannedAction) -> String {
        self.binding
            .borrow()
            .as_ref()
            .and_then(|b| b.targets.iter().find(|t| &t.action == action))
            .map(|t| t.label.clone())
            .unwrap_or_else(|| "unbound-target".into())
    }
}
