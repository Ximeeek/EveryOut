//! Only resolved AppData capabilities, registered package containers and reviewed
//! manifest roots are inspected. No filesystem payload or profile configuration reads.
use crate::{
    classification::{classify, Claim},
    heuristic::{excluded, score, Evidence},
    Detection, ScanReport, SignalObservation,
};
use everyout_core_model::{
    ApplicationIdentity, ArtifactKind, AuthenticationScope, Category, Confidence, DetectionOrigin,
    EvidenceState, LossAssessment, Scope, ScopeEvidence, StorageOwnership, Support,
};
use everyout_platform_windows::{
    inventory::{InstalledInventory, InventorySource},
    AllowedRoot, KnownFolder, PhysicalIdentity, RootResolver, SafePath, ShallowMetadata,
};
use everyout_providers::{load_manifest, Manifest, ManifestError, Ownership, Root};

/// Loader-validated catalog configuration, supplied from memory by trusted Rust code.
/// No caller paths or profile configuration payloads are accepted.
pub struct ReviewedManifest(Manifest);
impl ReviewedManifest {
    pub fn load(json: &str) -> Result<Self, ManifestError> {
        load_manifest(json).map(Self)
    }
}
struct Found {
    candidate_name: String,
    application_executable: Option<PhysicalIdentity>,
    provider_id: Option<String>,
    detection: Detection,
    stores: Vec<Vec<PhysicalIdentity>>,
    // Keep ancestor/root identities retained until overlap resolution completes.
    _paths: Vec<SafePath>,
}
// Bound retained handles and the pairwise physical-overlap pass, not only enumeration.
const MAX_DETECTIONS: usize = 1_000;
fn probe(root: &AllowedRoot, relative: &str) -> Option<ShallowMetadata> {
    root.path(relative)
        .and_then(|path| path.probe_shallow())
        .ok()
}
const LAYOUTS: [&str; 8] = [
    "",
    "User Data/Default",
    "EBWebView/Default",
    "LocalCache",
    "LocalState",
    "RoamingState",
    "LocalCache/Roaming",
    "LocalCache/Local",
];
const STORAGE: [(&str, bool); 6] = [
    ("Cookies", false),
    ("Network/Cookies", false),
    ("Local Storage", true),
    ("Session Storage", true),
    ("IndexedDB", true),
    ("Local State", false),
];
fn storage(root: &AllowedRoot, relative: &str) -> (bool, Vec<SignalObservation>) {
    let observations: Vec<_> = STORAGE
        .iter()
        .enumerate()
        .map(|(index, (path, directory))| {
            let metadata = probe(root, &format!("{relative}/{path}"));
            SignalObservation {
                id: format!("storage-artifact-{index}"),
                present: metadata.as_ref().and_then(|m| {
                    if m.exists && m.is_directory != *directory {
                        None
                    } else {
                        Some(m.exists)
                    }
                }),
                size: metadata.and_then(|m| m.size),
            }
        })
        .collect();
    let present = |index: usize| observations[index].present == Some(true);
    let cookies = present(0) || present(1);
    let count = usize::from(cookies) + (2..6).filter(|&i| present(i)).count();
    (count >= 3 && (cookies || present(4)), observations)
}

/// A separately reviewed browser-wrapper mapping; filenames or shortcut arguments
/// alone cannot create one. It is applied only to identical observed physical stores.
pub struct ReviewedBrowserAlias {
    pub provider_id: String,
    pub browser_owner: String,
}

/// Inventory is injected: fixture tests never invoke the live OS inventory.
/// Cancellation stops discovery and leaves an explicit incomplete-coverage code.
pub fn scan(
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    manifests: &[ReviewedManifest],
    cancelled: &dyn Fn() -> bool,
) -> ScanReport {
    scan_with_aliases(resolver, inventory, manifests, &[], cancelled)
}
pub fn scan_with_aliases(
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    manifests: &[ReviewedManifest],
    aliases: &[ReviewedBrowserAlias],
    cancelled: &dyn Fn() -> bool,
) -> ScanReport {
    scan_with_runtime(
        resolver,
        inventory,
        manifests,
        aliases,
        cancelled,
        &mut everyout_platform_windows::win32_identity::UsageBudget::default(),
    )
}
/// Trusted read-only observation injection for isolated fixtures, not a provider factory.
pub fn scan_with_runtime(
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    manifests: &[ReviewedManifest],
    aliases: &[ReviewedBrowserAlias],
    cancelled: &dyn Fn() -> bool,
    runtime: &mut dyn everyout_platform_windows::win32_identity::RuntimeObserver,
) -> ScanReport {
    let mut report = ScanReport {
        coverage: inventory.coverage.clone(),
        ..Default::default()
    };
    let (storage, coverage) = crate::storage::discover(resolver, inventory, cancelled);
    report.storage = storage;
    report.coverage.extend(coverage);
    let mut found = Vec::new();
    for reviewed in manifests {
        if found.len() >= MAX_DETECTIONS {
            report.coverage.push("detection-limit".into());
            break;
        }
        if cancelled() {
            report.coverage.push("cancelled".into());
            break;
        }
        manifest(
            &reviewed.0,
            resolver,
            inventory,
            &mut found,
            &mut report.coverage,
            cancelled,
        );
    }
    for (base, label) in [
        (KnownFolder::LocalAppData, "local"),
        (KnownFolder::RoamingAppData, "roaming"),
    ] {
        if cancelled() {
            report.coverage.push("cancelled".into());
            break;
        }
        let Ok(root) = resolver.resolve(base) else {
            report.coverage.push(format!("{label}-root-unavailable"));
            continue;
        };
        match root.discovery_children() {
            Ok((children, omitted)) => {
                if omitted {
                    report
                        .coverage
                        .push(format!("{label}-redirected-or-invalid-entries-omitted"));
                }
                for (index, (name, directory)) in children.into_iter().enumerate() {
                    if found.len() >= MAX_DETECTIONS {
                        report.coverage.push("detection-limit".into());
                        break;
                    }
                    if cancelled() {
                        report.coverage.push("cancelled".into());
                        break;
                    }
                    if !directory || excluded(&name) {
                        continue;
                    }
                    layouts(
                        &root,
                        &name,
                        &format!("{label}-{index}"),
                        None,
                        &mut found,
                        &mut report.coverage,
                    );
                }
            }
            Err(_) => report
                .coverage
                .push(format!("{label}-enumeration-incomplete")),
        }
        if base == KnownFolder::LocalAppData {
            for (index, package) in inventory.registrations.iter().enumerate() {
                if found.len() >= MAX_DETECTIONS {
                    report.coverage.push("detection-limit".into());
                    break;
                }
                if cancelled() {
                    report.coverage.push("cancelled".into());
                    break;
                }
                let Some(family) = &package.package_family else {
                    continue;
                };
                if package.source != InventorySource::Package || excluded(family) {
                    continue;
                }
                // root.path grammar validates the OS-supplied PFN as a single component.
                if family.contains(['/', '\\']) {
                    report.coverage.push("package-family-invalid".into());
                    continue;
                }
                layouts(
                    &root,
                    &format!("Packages/{family}"),
                    &format!("package-{index}"),
                    Some(package),
                    &mut found,
                    &mut report.coverage,
                );
            }
        }
    }
    for alias in aliases {
        for i in 0..found.len() {
            if found[i].provider_id.as_deref() != Some(alias.provider_id.as_str()) {
                continue;
            }
            let corroborated = found.iter().any(|browser| {
                browser.detection.category == Some(everyout_core_model::Category::Browser)
                    && browser.detection.owner.as_ref() == Some(&alias.browser_owner)
                    && exact_stores(&found[i].stores, &browser.stores)
            });
            if corroborated {
                found[i].detection.owner = Some(alias.browser_owner.clone());
                found[i].detection.category = Some(everyout_core_model::Category::Browser);
            } else {
                found[i].detection.owner = None;
                found[i].detection.decision.evidence.storage_ownership = EvidenceState::new(
                    StorageOwnership::Unknown,
                    "physical-identity",
                    "browser-alias-ownership-uncorroborated",
                );
                found[i]
                    .detection
                    .decision
                    .block("browser-alias-ownership-uncorroborated");
                found[i].detection.category = None;
                found[i].detection.selected = false;
                found[i]
                    .detection
                    .limitations
                    .push("browser-alias-ownership-uncorroborated".into());
            }
        }
    }
    correlate_win32(
        resolver,
        inventory,
        manifests,
        &mut found,
        &mut report.coverage,
        cancelled,
        runtime,
    );
    resolve_overlaps(&mut found);
    for item in &found {
        if item.detection.decision.evidence.storage_ownership.state
            == StorageOwnership::SharedConflict
        {
            if let Some(app) = inventory
                .win32
                .applications
                .iter()
                .find(|a| Some(a.executable.physical) == item.application_executable)
            {
                for path in &item._paths {
                    inventory.win32.remember_storage(
                        app,
                        path,
                        item.detection.decision.evidence.storage_ownership.clone(),
                    );
                }
            }
        }
    }
    for item in found {
        if item.detection.origin == DetectionOrigin::KnownProvider
            && item.detection.category.is_some()
        {
            report.known.push(item.detection);
        } else {
            report.candidates.push(item.detection);
        }
    }
    report.coverage.extend(
        [
            "s8-unverified-heuristic-preselection-blocked",
            "profile-configuration-and-authentication-discovery-blocked",
        ]
        .map(str::to_owned),
    );
    report.coverage.sort();
    report.coverage.dedup();
    report
}
fn layouts(
    root: &AllowedRoot,
    candidate: &str,
    id: &str,
    package: Option<&everyout_platform_windows::inventory::Registration>,
    found: &mut Vec<Found>,
    coverage: &mut Vec<String>,
) {
    for (index, layout) in LAYOUTS.iter().enumerate() {
        if found.len() >= MAX_DETECTIONS {
            coverage.push("detection-limit".into());
            return;
        }
        let relative = if layout.is_empty() {
            candidate.to_owned()
        } else {
            format!("{candidate}/{layout}")
        };
        let Some(metadata) = probe(root, &relative) else {
            coverage.push("candidate-metadata-unavailable".into());
            continue;
        };
        if !metadata.exists || !metadata.is_directory {
            continue;
        }
        let (storage, observations) = storage(root, &relative);
        if observations.iter().any(|o| o.present.is_none()) {
            coverage.push("storage-metadata-incomplete".into());
        }
        // Inventory/root presence without a session-storage layout is not a session candidate.
        if !storage {
            continue;
        }
        let installed = package.is_some_and(|p| p.installation_exists == Some(true));
        let owned = installed && package.is_some_and(|p| p.exclusive_container);
        if package.is_some_and(|p| p.installation_exists == Some(false)) {
            coverage.push("package-registration-residue".into());
        }
        if package.is_some_and(|p| p.installation_exists.is_none()) {
            coverage.push("package-installation-unknown".into());
        }
        let evidence = Evidence {
            storage,
            identity: installed,
            ownership: owned,
            plausible_owner: installed,
            runtime: installed && package.is_some_and(|p| p.runtime_present == Some(true)),
            ..Default::default()
        };
        let scored = score(evidence);
        let Some(confidence) = scored.confidence else {
            continue;
        };
        let owner = owned.then(|| {
            package
                .and_then(|p| p.package_family.clone())
                .expect("registered package")
        });
        let classified = owner.as_ref().and_then(|owner| {
            classify(&[Claim {
                owner: owner.clone(),
                ownership: Ownership::Application,
            }])
        });
        let Ok(path) = root.path(&relative) else {
            coverage.push("candidate-binding-unavailable".into());
            continue;
        };
        let Ok(Some(chain)) = path.physical_chain() else {
            coverage.push("candidate-identity-unavailable".into());
            continue;
        };
        let mut limitations = vec![
            "s8-unverified".into(),
            "no-authentication-or-cleaning-scope-proof".into(),
        ];
        if !owned {
            limitations.push("exclusive-owner-unresolved".into());
        }
        found.push(Found {
            candidate_name: candidate.rsplit('/').next().unwrap_or(candidate).into(),
            application_executable: None,
            provider_id: None,
            detection: Detection {
                application_label: None,
                decision: ScopeEvidence {
                    application_identity: EvidenceState::new(
                        if installed {
                            ApplicationIdentity::Exact
                        } else {
                            ApplicationIdentity::Weak
                        },
                        if installed {
                            "package-identity"
                        } else {
                            "framework-inference"
                        },
                        "discovery-application-identity",
                    ),
                    storage_ownership: EvidenceState::new(
                        if owned {
                            StorageOwnership::Exclusive
                        } else {
                            StorageOwnership::Unknown
                        },
                        if owned {
                            "package-identity"
                        } else {
                            "missing-evidence"
                        },
                        "discovery-storage-ownership",
                    ),
                    authentication_scope: EvidenceState::new(
                        AuthenticationScope::FrameworkHint,
                        "framework-inference",
                        "no-authentication-or-cleaning-scope-proof",
                    ),
                    ..Default::default()
                }
                .decide(
                    Support::Candidate,
                    &["discovery-only-no-provider".into()],
                    LossAssessment::Unknown,
                    &[],
                    &[],
                ),
                id: format!("{id}-layout-{index}"),
                origin: DetectionOrigin::Heuristic,
                confidence,
                points: Some(scored.points),
                signals: scored.signals,
                observations,
                owner: classified.as_ref().map(|c| c.0.clone()),
                category: classified.map(|c| c.1),
                selected: false,
                executable: false,
                aliases: vec![],
                limitations,
            },
            stores: vec![chain],
            _paths: vec![path],
        });
    }
}
fn manifest(
    manifest: &Manifest,
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    found: &mut Vec<Found>,
    coverage: &mut Vec<String>,
    cancelled: &dyn Fn() -> bool,
) {
    if manifest
        .roots
        .iter()
        .any(|r| matches!(r, Root::Unresolved { .. }))
    {
        coverage.push(format!("{}-session-location-unresolved", manifest.id));
        return;
    }
    if manifest
        .roots
        .iter()
        .any(|r| matches!(r, Root::ReviewedInstallation { .. }))
    {
        coverage.push(format!("{}-installation-scope-unavailable", manifest.id));
        return;
    }
    let mut profiles = vec![None];
    if let Some(configuration) = &manifest.profiles {
        let Some(root) = manifest.roots.iter().find(|r| r.id() == configuration.root) else {
            return;
        };
        let (base, relative) = file_root(root);
        let Ok(root) = AllowedRoot::from_manifest(resolver, base, relative) else {
            coverage.push(format!("{}-profile-root-unavailable", manifest.id));
            return;
        };
        profiles.clear();
        if configuration.root_profile == Some(true) {
            profiles.push(Some(String::new()));
        }
        // Enumerate the reviewed profile root at most once, even with several patterns.
        let children = configuration
            .directory_patterns
            .iter()
            .any(|p| p.contains('*'))
            .then(|| root.discovery_children());
        for pattern in &configuration.directory_patterns {
            if !pattern.contains('*') {
                profiles.push(Some(pattern.clone()));
                continue;
            }
            match children.as_ref().expect("wildcard needs enumeration") {
                Ok((children, omitted)) => {
                    if *omitted {
                        coverage.push("profile-entries-omitted".into());
                    }
                    for (name, directory) in children {
                        if *directory && matches_pattern(name, pattern) {
                            profiles.push(Some(name.clone()));
                        }
                    }
                }
                Err(_) => coverage.push("profile-enumeration-incomplete".into()),
            }
        }
        profiles.sort();
        profiles.dedup();
        if configuration.metadata_adapter.is_some() {
            coverage.push("profile-configuration-adapter-blocked".into());
        }
    }
    for (index, profile) in profiles.into_iter().enumerate() {
        if found.len() >= MAX_DETECTIONS {
            coverage.push("detection-limit".into());
            return;
        }
        if cancelled() {
            coverage.push("cancelled".into());
            return;
        }
        let mut fired = Vec::new();
        let mut observations = Vec::new();
        let mut paths = Vec::new();
        let mut stores = Vec::new();
        let mut complete = true;
        for signal in &manifest.detection.signals {
            let (root_id, artifact, kind) = if let Some(artifact) = &signal.artifact {
                let Some(artifact) = manifest
                    .session_locations
                    .iter()
                    .find(|a| &a.id == artifact)
                else {
                    complete = false;
                    break;
                };
                (&artifact.root, Some(artifact), artifact.kind)
            } else {
                let Some(root) = &signal.root else {
                    complete = false;
                    break;
                };
                (root, None, ArtifactKind::Directory)
            };
            let Some(root) = manifest.roots.iter().find(|r| r.id() == root_id) else {
                complete = false;
                break;
            };
            if let Root::Registry { key, .. } = root {
                if artifact.is_none() && inventory_key_present(key, inventory) {
                    fired.push(signal.id.clone());
                    observations.push(SignalObservation {
                        id: signal.id.clone(),
                        present: Some(true),
                        size: None,
                    });
                } else {
                    complete = false;
                    coverage.push(format!(
                        "{}-registry-signal-outside-observed-inventory-or-unavailable",
                        manifest.id
                    ));
                }
                continue;
            }
            let (base, relative) = file_root(root);
            let suffix = match artifact {
                Some(a) if a.scope == Scope::Profile => {
                    let Some(profile) = &profile else {
                        complete = false;
                        break;
                    };
                    if profile.is_empty() {
                        format!("{relative}/{}", a.relative)
                    } else {
                        format!("{relative}/{profile}/{}", a.relative)
                    }
                }
                Some(a) => format!("{relative}/{}", a.relative),
                None => relative.to_owned(),
            };
            let path = resolver.resolve(base).and_then(|root| root.path(&suffix));
            let Ok(path) = path else {
                coverage.push(format!("{}-signal-unavailable", manifest.id));
                complete = false;
                continue;
            };
            match path.probe_shallow() {
                Ok(m) if m.exists && m.is_directory == (kind == ArtifactKind::Directory) => {
                    observations.push(SignalObservation {
                        id: signal.id.clone(),
                        present: Some(true),
                        size: m.size,
                    });
                    fired.push(signal.id.clone());
                    // Artifact claims take priority over broad detection root markers.
                    if artifact.is_some() {
                        match path.physical_chain() {
                            Ok(Some(chain)) => stores.push(chain),
                            _ => {
                                complete = false;
                                coverage.push("manifest-physical-identity-unavailable".into());
                            }
                        }
                    }
                    paths.push(path);
                }
                Ok(m) => {
                    complete = false;
                    if m.exists {
                        coverage.push(format!("{}-signal-type-unknown", manifest.id));
                    }
                }
                Err(_) => {
                    coverage.push(format!("{}-signal-unavailable", manifest.id));
                    complete = false;
                }
            }
        }
        if !complete || fired.is_empty() {
            continue;
        }
        if stores.is_empty() {
            for path in &paths {
                if let Ok(Some(chain)) = path.physical_chain() {
                    stores.push(chain);
                }
            }
            if stores.is_empty() {
                coverage.push("registry-physical-overlap-unverified".into());
            }
        }
        let owner = manifest
            .identity
            .browser_id
            .clone()
            .unwrap_or_else(|| manifest.id.clone());
        let claims: Vec<_> = manifest
            .session_locations
            .iter()
            .map(|a| Claim {
                owner: owner.clone(),
                ownership: a.ownership,
            })
            .collect();
        let classified = classify(&claims);
        if let Some(identity) = manifest
            .identity
            .installation_id
            .as_ref()
            .or(manifest.identity.package_id.as_ref())
        {
            if inventory.registrations.iter().any(|r| {
                r.name.eq_ignore_ascii_case(identity) || r.package_family.as_ref() == Some(identity)
            }) {
                fired.push("inventory-registration-present".into());
            } else {
                coverage.push(format!(
                    "{}-installation-registration-uncorroborated",
                    manifest.id
                ));
            }
        }
        found.push(Found {
            candidate_name: manifest.name.clone(),
            application_executable: None,
            provider_id: Some(manifest.id.clone()),
            detection: Detection {
                application_label: None,
                decision: everyout_providers::evidence::assess(manifest, resolver),
                id: format!("{}-instance-{index}", manifest.id),
                origin: DetectionOrigin::KnownProvider,
                confidence: manifest.confidence.level,
                points: None,
                signals: fired,
                observations,
                owner: classified.as_ref().map(|c| c.0.clone()),
                category: classified.as_ref().map(|c| c.1),
                selected: DetectionOrigin::KnownProvider.default_selected(classified.is_some())
                    && !(manifest.category == Category::Application
                        && manifest.support == Support::Candidate
                        && manifest.confidence.level == Confidence::Low),
                executable: false,
                aliases: vec![],
                limitations: vec![
                    "manifest-evidence-confidence-is-not-heuristic-calibration".into(),
                    "discovery-is-not-plan-approval".into(),
                ],
            },
            stores,
            _paths: paths,
        });
    }
}
fn correlate_win32(
    resolver: &dyn RootResolver,
    inventory: &InstalledInventory,
    manifests: &[ReviewedManifest],
    found: &mut Vec<Found>,
    coverage: &mut Vec<String>,
    cancelled: &dyn Fn() -> bool,
    runtime: &mut dyn everyout_platform_windows::win32_identity::RuntimeObserver,
) {
    use everyout_platform_windows::win32_identity::RuntimeUsage;
    let snapshot = &inventory.win32;
    for item in found.iter_mut() {
        if cancelled() {
            coverage.push("cancelled".into());
            return;
        }
        let manifest = item
            .provider_id
            .as_ref()
            .and_then(|id| manifests.iter().find(|m| &m.0.id == id))
            .map(|m| &m.0);
        // The fixed adapter keeps its independent executable hash and preservation gates.
        if manifest.is_some_and(|m| m.id == "spotify") {
            continue;
        }
        let app = if let Some(m) = manifest {
            snapshot.matching_product(&m.identity.process_names, &m.name)
        } else {
            let mut apps = snapshot
                .applications
                .iter()
                .filter(|a| a.storage_name_hint(&item.candidate_name));
            let first = apps.next();
            if apps.next().is_none() {
                first
            } else {
                None
            }
        };
        let Some(app) = app else {
            continue;
        };
        item.application_executable = Some(app.executable.physical);
        item.detection.application_label = Some(app.label());
        let mut evidence = item.detection.decision.evidence.clone();
        evidence.application_identity = app.identity();
        if let Some(candidate) = item._paths.first() {
            let usage = runtime.observe(candidate, snapshot);
            coverage.extend(usage.coverage.clone());
            let layout = item
                .detection
                .observations
                .iter()
                .any(|o| o.present == Some(true));
            evidence.storage_ownership =
                app.storage_evidence(app.storage_name_hint(&item.candidate_name), layout, &usage);
            if manifest.is_some_and(|m| m.category == Category::Browser) {
                evidence.storage_ownership = EvidenceState::new(
                    StorageOwnership::SharedConflict,
                    "browser-profile",
                    "browser-profile-shared-storage",
                );
            }
            snapshot.remember_storage(app, candidate, evidence.storage_ownership.clone());
        }
        item.detection.decision = if let Some(m) = manifest {
            everyout_providers::evidence::decision(m, evidence, &[])
        } else {
            evidence.decide(
                Support::Candidate,
                &["discovery-only-no-provider".into()],
                LossAssessment::Unknown,
                &[],
                &[],
            )
        };
        if manifest.is_none() {
            item.detection.owner = Some(
                manifests
                    .iter()
                    .find(|m| {
                        snapshot
                            .matching_product(&m.0.identity.process_names, &m.0.name)
                            .is_some_and(|a| a.executable.physical == app.executable.physical)
                    })
                    .map(|m| m.0.id.clone())
                    .unwrap_or_else(|| app.label()),
            );
            item.detection.category = Some(Category::Application);
        }
    }
    // Installation identity remains visible even when no framework/storage layout exists.
    for (index, app) in snapshot.applications.iter().enumerate() {
        if found.len() >= MAX_DETECTIONS || cancelled() {
            break;
        }
        if found
            .iter()
            .any(|f| f.application_executable == Some(app.executable.physical))
        {
            continue;
        }
        // A catalog-backed fixed adapter has its own row and evidence, never a generic provider.
        if manifests
            .iter()
            .any(|m| m.0.id == "spotify" && app.matches_names(&m.0.identity.process_names))
        {
            continue;
        }
        let mut paths = Vec::new();
        let mut stores = Vec::new();
        let mut observations = Vec::new();
        let names = [
            app.executable
                .canonical_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            app.label(),
        ];
        for base in [KnownFolder::RoamingAppData, KnownFolder::LocalAppData] {
            let Ok(root) = resolver.resolve(base) else {
                continue;
            };
            for name in &names {
                let Ok(path) = root.path(name) else {
                    continue;
                };
                if path
                    .probe_shallow()
                    .is_ok_and(|m| m.exists && m.is_directory)
                {
                    if let Ok(Some(chain)) = path.physical_chain() {
                        if !stores
                            .iter()
                            .any(|c: &Vec<PhysicalIdentity>| c.last() == chain.last())
                        {
                            let (_, signals) = storage(&root, name);
                            observations.extend(signals);
                            stores.push(chain);
                            paths.push(path);
                        }
                    }
                }
            }
        }
        // Reviewed installation slots supply metadata candidates only, never executable scopes.
        for m in manifests.iter().filter(|m| {
            snapshot
                .matching_product(&m.0.identity.process_names, &m.0.name)
                .is_some_and(|a| a.executable.physical == app.executable.physical)
        }) {
            for artifact in &m.0.session_locations {
                if artifact.name_prefix.is_some()
                    || !m.0.roots.iter().any(|r| {
                        r.id() == artifact.root && matches!(r, Root::ReviewedInstallation { .. })
                    })
                {
                    continue;
                }
                if let Ok(path) = app.installation_metadata(&artifact.relative) {
                    if path
                        .probe_shallow()
                        .is_ok_and(|m| m.exists && !m.is_directory)
                    {
                        observations.push(SignalObservation {
                            id: "catalog-installation-candidate-present".into(),
                            present: Some(true),
                            size: path.probe_shallow().ok().and_then(|m| m.size),
                        });
                        if let Ok(Some(chain)) = path.physical_chain() {
                            stores.push(chain);
                            paths.push(path);
                        }
                    }
                }
            }
        }
        // Adjacent WebView2 UDF is a candidate even with no AppData registration.
        let udf = format!(
            "{}.WebView2",
            app.executable
                .canonical_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
        );
        if let Ok(path) = app.installation_metadata(&udf) {
            if path
                .probe_shallow()
                .is_ok_and(|m| m.exists && m.is_directory)
            {
                if let Ok(Some(chain)) = path.physical_chain() {
                    stores.push(chain);
                    paths.push(path);
                }
            }
        }
        let mut evidence = ScopeEvidence {
            application_identity: app.identity(),
            ..Default::default()
        };
        let mut ownerships = Vec::new();
        for path in &paths {
            let observed = runtime.observe(path, snapshot);
            let layout = path.probe_shallow().is_ok_and(|m| !m.is_directory)
                || [
                    "Local Storage",
                    "IndexedDB",
                    "Network/Cookies",
                    "state.db",
                    "EBWebView/Default/Network/Cookies",
                    "Default/Network/Cookies",
                ]
                .iter()
                .any(|relative| {
                    path.metadata_descendant(relative)
                        .and_then(|p| p.probe_shallow())
                        .is_ok_and(|m| m.exists)
                });
            let ownership = app.storage_evidence(true, layout, &observed);
            snapshot.remember_storage(app, path, ownership.clone());
            ownerships.push(ownership);
            coverage.extend(observed.coverage);
        }
        evidence.storage_ownership = ownerships
            .iter()
            .find(|o| o.state == StorageOwnership::SharedConflict)
            .cloned()
            .or_else(|| {
                (!ownerships.is_empty()
                    && ownerships
                        .iter()
                        .all(|o| o.state == StorageOwnership::Corroborated))
                .then(|| ownerships[0].clone())
            })
            .unwrap_or_else(|| {
                app.storage_evidence(!paths.is_empty(), false, &RuntimeUsage::default())
            });
        found.push(Found {
            candidate_name: app.label(),
            application_executable: Some(app.executable.physical),
            provider_id: None,
            detection: Detection {
                application_label: Some(app.label()),
                decision: evidence.decide(
                    Support::Candidate,
                    &["discovery-only-no-provider".into()],
                    LossAssessment::Unknown,
                    &[],
                    &[],
                ),
                id: format!("win32-application-{index}"),
                origin: DetectionOrigin::Heuristic,
                confidence: Confidence::Low,
                points: None,
                signals: vec!["win32-application-identity".into()],
                observations,
                owner: Some(app.label()),
                category: Some(Category::Application),
                selected: false,
                executable: false,
                aliases: vec![],
                limitations: vec![
                    "win32-storage-candidates-only".into(),
                    "no-authentication-or-cleaning-scope-proof".into(),
                ],
            },
            stores,
            _paths: paths,
        });
    }
}

fn inventory_key_present(key: &str, inventory: &InstalledInventory) -> bool {
    let normalized = key.replace('/', "\\").to_ascii_lowercase();
    for (source, kind) in [
        ("uninstall", InventorySource::Uninstall),
        ("app paths", InventorySource::AppPaths),
    ] {
        let prefix = format!("software\\microsoft\\windows\\currentversion\\{source}\\");
        if let Some(name) = normalized.strip_prefix(&prefix) {
            if name.contains('\\') {
                return false;
            }
            return inventory.registrations.iter().any(|r| {
                r.source == kind
                    && r.name.eq_ignore_ascii_case(name)
                    && r.provenance.iter().any(|p| p.starts_with("hkcu-"))
            });
        }
    }
    false
}
fn file_root(root: &Root) -> (KnownFolder, &str) {
    match root {
        Root::LocalAppData { relative, .. } => (KnownFolder::LocalAppData, relative),
        Root::UserProfile { relative, .. } => (KnownFolder::UserProfile, relative),
        Root::RoamingAppData { relative, .. } => (KnownFolder::RoamingAppData, relative),
        Root::Registry { .. } | Root::ReviewedInstallation { .. } | Root::Unresolved { .. } => {
            unreachable!("non-AppData roots are excluded before file detection")
        }
    }
}
fn matches_pattern(name: &str, pattern: &str) -> bool {
    match pattern.split_once('*') {
        Some((start, end)) => {
            name.len() >= start.len() + end.len() && name.starts_with(start) && name.ends_with(end)
        }
        None => name == pattern,
    }
}
fn resolve_overlaps(found: &mut Vec<Found>) {
    let mut remove = Vec::new();
    let mut conflicts = Vec::new();
    for i in 0..found.len() {
        for j in i + 1..found.len() {
            if remove.contains(&i) || remove.contains(&j) {
                continue;
            }
            let left = &found[i];
            let right = &found[j];
            let overlapping = left.stores.iter().any(|l| {
                right.stores.iter().any(|r| {
                    l.last().is_some_and(|leaf| r.contains(leaf))
                        || r.last().is_some_and(|leaf| l.contains(leaf))
                })
            });
            if !overlapping {
                continue;
            }
            let exact = exact_stores(&left.stores, &right.stores);
            let same_application_view = left.application_executable.is_some()
                && left.application_executable == right.application_executable
                && (left.provider_id.is_some() != right.provider_id.is_some());
            let compatible_identity =
                match (left.application_executable, right.application_executable) {
                    (Some(left), Some(right)) => left == right,
                    _ => true,
                };
            if (exact || same_application_view)
                && compatible_identity
                && left.detection.owner.is_some()
                && left.detection.owner == right.detection.owner
                && left.detection.category == right.detection.category
            {
                let (keep, drop) = if right.detection.origin == DetectionOrigin::KnownProvider
                    && left.detection.origin != DetectionOrigin::KnownProvider
                {
                    (j, i)
                } else {
                    (i, j)
                };
                let alias = found[drop].detection.id.clone();
                let mut aliases = found[drop].detection.aliases.clone();
                aliases.push(alias);
                found[keep].detection.aliases.extend(aliases);
                remove.push(drop);
            } else {
                conflicts.extend([i, j]);
            }
        }
    }
    for index in conflicts {
        let detection = &mut found[index].detection;
        detection.owner = None;
        detection.category = None;
        detection.selected = false;
        detection.executable = false;
        detection.confidence = Confidence::Low;
        detection.decision.evidence.storage_ownership = EvidenceState::new(
            StorageOwnership::SharedConflict,
            "physical-identity",
            "physical-store-ownership-or-ancestor-overlap-conflict",
        );
        detection
            .decision
            .block("physical-store-ownership-or-ancestor-overlap-conflict");
        if !detection
            .limitations
            .iter()
            .any(|l| l == "physical-store-ownership-or-ancestor-overlap-conflict")
        {
            detection
                .limitations
                .push("physical-store-ownership-or-ancestor-overlap-conflict".into());
        }
    }
    remove.sort_unstable();
    remove.dedup();
    for index in remove.into_iter().rev() {
        found.remove(index);
    }
}
fn exact_stores(left: &[Vec<PhysicalIdentity>], right: &[Vec<PhysicalIdentity>]) -> bool {
    !left.is_empty()
        && left.len() == right.len()
        && left
            .iter()
            .all(|l| right.iter().any(|r| l.last() == r.last()))
        && right
            .iter()
            .all(|r| left.iter().any(|l| r.last() == l.last()))
}
