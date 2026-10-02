use std::collections::HashSet;
use std::sync::OnceLock;

use crate::manifest::*;
use everyout_core_model::*;

pub const MANIFEST_SCHEMA: &str =
    include_str!("../../../catalog/schema/provider-manifest.schema.json");
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestErrorKind {
    Json,
    Schema,
    Semantic,
}
/// Stable codes and configuration field names only; input values never enter diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestError {
    pub kind: ManifestErrorKind,
    pub code: &'static str,
}
impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for ManifestError {}
fn invalid(code: &'static str) -> ManifestError {
    ManifestError {
        kind: ManifestErrorKind::Semantic,
        code,
    }
}

/// Load project configuration from caller-supplied JSON, without any file or network access.
pub fn load_manifest(input: &str) -> Result<Manifest, ManifestError> {
    let value: serde_json::Value = serde_json::from_str(input).map_err(|_| ManifestError {
        kind: ManifestErrorKind::Json,
        code: "invalid-json",
    })?;
    static VALIDATOR: OnceLock<jsonschema::Validator> = OnceLock::new();
    let validator = VALIDATOR.get_or_init(|| {
        let schema = serde_json::from_str(MANIFEST_SCHEMA).expect("bundled schema is JSON");
        jsonschema::validator_for(&schema).expect("bundled schema is valid")
    });
    if !validator.is_valid(&value) {
        return Err(ManifestError {
            kind: ManifestErrorKind::Schema,
            code: "invalid-schema",
        });
    }
    let manifest: Manifest = serde_json::from_value(value).map_err(|_| ManifestError {
        kind: ManifestErrorKind::Schema,
        code: "invalid-model",
    })?;
    validate(&manifest)?;
    Ok(manifest)
}

fn stable_id(value: &str) -> bool {
    !value.is_empty()
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}
fn ids<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<HashSet<&'a str>, ManifestError> {
    let mut result = HashSet::new();
    for id in values {
        if !stable_id(id) || !result.insert(id) {
            return Err(invalid("invalid-or-duplicate-id"));
        }
    }
    Ok(result)
}
/// Windows grammar checked independently of the host OS. Reject ADS, environment
/// expansion, device names, normalized dot suffixes and rooted/UNC/device paths.
fn relative_path(value: &str) -> bool {
    !value.is_empty()
        && !value
            .chars()
            .any(|c| c.is_control() || ":*?<>|\"%".contains(c))
        && value.split(['/', '\\']).all(|part| {
            if part.is_empty() || part == "." || part == ".." || part.ends_with(['.', ' ']) {
                return false;
            }
            let stem = part
                .split('.')
                .next()
                .unwrap_or_default()
                .to_ascii_uppercase();
            !matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) && !(stem.starts_with("COM") || stem.starts_with("LPT"))
                .then(|| &stem[3..])
                .is_some_and(|s| {
                    matches!(
                        s,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
        })
}
fn profile_pattern(value: &str) -> bool {
    if value == "*"
        || value.contains(['/', '\\'])
        || value.contains("**")
        || value.matches('*').count() > 1
    {
        return false;
    }
    relative_path(&value.replace('*', "x"))
}
fn refs(values: &[EvidenceRef], evidence: &HashSet<&str>) -> Result<(), ManifestError> {
    if values.is_empty() || values.iter().any(|id| !evidence.contains(id.0.as_str())) {
        return Err(invalid("missing-evidence-reference"));
    }
    Ok(())
}
fn unknown_coverage(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "" | "unknown" | "unvalidated"
    )
}
fn validate(m: &Manifest) -> Result<(), ManifestError> {
    if m.confidence
        .status
        .as_ref()
        .is_some_and(|s| !matches!(s.as_str(), "verified" | "unverified"))
    {
        return Err(invalid("invalid-confidence-status"));
    }
    let roots = ids(m.roots.iter().map(Root::id))?;
    let artifacts = ids(m.session_locations.iter().map(|a| a.id.as_str()))?;
    let methods = ids(m.cleaning_methods.iter().map(CleaningMethod::id))?;
    let evidence = ids(m.evidence.iter().map(|e| e.id.as_str()))?;
    ids(m.detection.signals.iter().map(|s| s.id.as_str()))?;
    if m.name.trim().is_empty()
        || m.compatibility.os.is_empty()
        || m.compatibility.channel.trim().is_empty()
        || m.compatibility.product_versions.trim().is_empty()
        || m.confidence.rationale.trim().is_empty()
        || m.true_logout.mechanism.trim().is_empty()
        || m.detection.signals.is_empty()
        || !m.detection.require_exclusive_owner
    {
        return Err(invalid("missing-coverage-or-ownership"));
    }
    if m.identity.process_names.iter().any(|name| {
        !relative_path(name)
            || name.contains(['/', '\\'])
            || !name.to_ascii_lowercase().ends_with(".exe")
    }) {
        return Err(invalid("invalid-process-name"));
    }
    match m.category {
        Category::Browser
            if m.identity.browser_id.as_deref() != Some(m.id.as_str()) || m.profiles.is_none() =>
        {
            return Err(invalid("browser-requires-identity-and-profiles"))
        }
        Category::Application | Category::WindowsMicrosoftAndDevTools
            if m.identity
                .installation_id
                .as_deref()
                .is_none_or(str::is_empty)
                && m.identity.package_id.as_deref().is_none_or(str::is_empty) =>
        {
            return Err(invalid("category-requires-installation-or-package"))
        }
        _ => {}
    }
    if m.category != Category::Browser && m.identity.browser_id.is_some() {
        return Err(invalid("conflicting-category-identity"));
    }
    for root in &m.roots {
        if !relative_path(root.relative()) || root.scope() == Scope::Profile || root.owner() != m.id
        {
            return Err(invalid("invalid-root-scope-or-path"));
        }
        if let Root::Registry { key, .. } = root {
            if !key
                .replace('/', "\\")
                .to_ascii_lowercase()
                .starts_with("software\\")
            {
                return Err(invalid("registry-root-outside-software"));
            }
            if m.category == Category::Browser {
                return Err(invalid("browser-registry-root-unsupported"));
            }
        }
    }
    if m.profiles
        .as_ref()
        .is_some_and(|p| p.metadata_adapter.as_deref() == Some(crate::firefox::ADAPTER))
        && (m.roots.len() != 1
            || !matches!(&m.roots[0],
            Root::RoamingAppData { relative, .. } if relative.replace('\\', "/") == "Mozilla/Firefox"))
    {
        return Err(invalid("invalid-firefox-config-root"));
    }
    if let Some(profiles) = &m.profiles {
        if !roots.contains(profiles.root.as_str())
            || (profiles.directory_patterns.is_empty()
                && profiles.metadata_adapter.as_deref() != Some(crate::firefox::ADAPTER))
            || profiles
                .directory_patterns
                .iter()
                .any(|p| !profile_pattern(p))
            || profiles.metadata_adapter.as_ref().is_some_and(|adapter| {
                adapter != crate::firefox::ADAPTER
                    || m.id != "firefox"
                    || m.category != Category::Browser
                    || !profiles.directory_patterns.is_empty()
                    || profiles.root_profile == Some(true)
            })
            || m.roots
                .iter()
                .any(|r| r.id() == profiles.root && matches!(r, Root::Registry { .. }))
        {
            return Err(invalid("invalid-profile-discovery"));
        }
    }
    for signal in &m.detection.signals {
        if signal.root.is_some() == signal.artifact.is_some()
            || signal
                .root
                .as_ref()
                .is_some_and(|r| !roots.contains(r.as_str()))
            || signal
                .artifact
                .as_ref()
                .is_some_and(|a| !artifacts.contains(a.as_str()))
        {
            return Err(invalid("invalid-detection-reference"));
        }
    }
    for artifact in &m.session_locations {
        if let Some(e) = &artifact.evidence {
            refs(e, &evidence)?;
        }
        if artifact
            .confidence
            .as_ref()
            .is_some_and(|c| !matches!(c.as_str(), "verified" | "unverified"))
        {
            return Err(invalid("invalid-artifact-confidence"));
        }
        if !roots.contains(artifact.root.as_str())
            || !methods.contains(artifact.method.as_str())
            || !relative_path(&artifact.relative)
        {
            return Err(invalid("invalid-artifact-reference-or-path"));
        }
        if artifact.scope == Scope::Profile
            && m.profiles.as_ref().is_none_or(|p| p.root != artifact.root)
        {
            return Err(invalid("missing-profile-scope"));
        }
        let registry = m
            .roots
            .iter()
            .any(|r| r.id() == artifact.root && matches!(r, Root::Registry { .. }));
        let method = m
            .cleaning_methods
            .iter()
            .find(|method| method.id() == artifact.method)
            .unwrap();
        let compatible = match method {
            CleaningMethod::DeleteFileFamily { .. } => {
                !registry && artifact.kind == ArtifactKind::File
            }
            CleaningMethod::DeleteDirectoryFamily { .. } => {
                !registry && artifact.kind == ArtifactKind::Directory
            }
            CleaningMethod::DeleteRegistryTarget { .. } => {
                registry
                    && matches!(
                        artifact.kind,
                        ArtifactKind::RegistryKey | ArtifactKind::RegistryValue
                    )
            }
            CleaningMethod::LocalApiOperation { .. } | CleaningMethod::ExceptionAdapter { .. } => {
                !registry
            }
        };
        if !compatible
            || (artifact.kind != ArtifactKind::File
                && artifact.observe == ObservationKind::ExistsAndSize)
        {
            return Err(invalid("incompatible-artifact-method"));
        }
        let ownership = match m.category {
            Category::Browser => artifact.ownership == Ownership::BrowserProfile,
            Category::Application => artifact.ownership == Ownership::Application,
            Category::WindowsMicrosoftAndDevTools => matches!(
                artifact.ownership,
                Ownership::SharedIdentity | Ownership::DeveloperTool
            ),
        };
        if !ownership {
            return Err(invalid("category-ownership-conflict"));
        }
        if artifact
            .artifact_family
            .as_ref()
            .is_some_and(|family| m.preserve.artifact_families.contains(family))
            && m.support == Support::Validated
        {
            return Err(invalid("preservation-conflict"));
        }
    }
    for method in &m.cleaning_methods {
        match method {
            CleaningMethod::DeleteFileFamily { companions, .. } => {
                if companions
                    .iter()
                    .any(|c| !matches!(c.as_str(), "-wal" | "-shm" | "-journal"))
                    || companions.iter().collect::<HashSet<_>>().len() != companions.len()
                {
                    return Err(invalid("invalid-companion"));
                }
            }
            CleaningMethod::DeleteDirectoryFamily { exclusions, .. } => {
                if exclusions.iter().any(|p| !relative_path(p)) {
                    return Err(invalid("invalid-exclusion"));
                }
            }
            CleaningMethod::LocalApiOperation { operation_id, .. }
                if !stable_id(operation_id) || m.support == Support::Validated =>
            {
                return Err(invalid("unreviewed-local-api"));
            }
            CleaningMethod::ExceptionAdapter { adapter_id, .. }
                if !stable_id(adapter_id) || m.support == Support::Validated =>
            {
                return Err(invalid("unreviewed-exception-adapter"));
            }
            _ => {}
        }
    }
    refs(&m.risks.evidence, &evidence)?;
    if let Some(policy) = &m.extensions {
        if m.category != Category::Browser
            || policy.unknown != "block"
            || policy.stores.is_empty()
            || policy.stores.iter().any(|p| {
                if m.id == "firefox" {
                    p != "browser-extension-data"
                } else {
                    !matches!(
                        p.as_str(),
                        "Local Extension Settings"
                            | "Sync Extension Settings"
                            | "Local App Settings"
                            | "Sync App Settings"
                    )
                }
            })
        {
            return Err(invalid("invalid-extension-policy"));
        }
        let mut seen = HashSet::new();
        for entry in &policy.known {
            if (if m.id == "firefox" {
                !crate::firefox::extension_id(&entry.id) || !relative_path(&entry.id)
            } else {
                entry.id.len() != 32 || !entry.id.bytes().all(|b| (b'a'..=b'p').contains(&b))
            }) || !seen.insert(&entry.id)
                || entry.name.trim().is_empty()
                || !matches!(
                    entry.flag,
                    RiskFlag::WalletOrKeyMaterial | RiskFlag::VaultOr2faRecovery
                )
                || !entry.source.starts_with("https://")
                || (m.id != "firefox" && !entry.source.contains(&entry.id))
                || entry.accessed.is_empty()
                || !matches!(entry.confidence.as_str(), "verified" | "unverified")
            {
                return Err(invalid("invalid-extension-risk"));
            }
        }
    }
    refs(&m.true_logout.evidence, &evidence)?;
    ids(m.risks.confirmations.iter().map(|id| id.0.as_str()))?;
    if m.risks.permanent_data_loss == LossAssessment::Known
        && (m.risks.flags.is_empty()
            || m.risks.affected_data.is_empty()
            || m.risks.reason.as_deref().is_none_or(str::is_empty)
            || m.risks.confirmations.is_empty())
    {
        return Err(invalid("incomplete-known-loss-assessment"));
    }
    if m.risks.flags.contains(&RiskFlag::Unknown)
        && m.risks.permanent_data_loss != LossAssessment::Unknown
    {
        return Err(invalid("unknown-risk-treated-as-known"));
    }
    if m.risks.permanent_data_loss == LossAssessment::None
        && m.risks
            .flags
            .iter()
            .any(|flag| !matches!(flag, RiskFlag::SharedStore))
    {
        return Err(invalid("loss-flags-conflict-with-no-loss"));
    }
    for item in &m.evidence {
        if !item.dossier.contains('#')
            || item.status.trim().is_empty()
            || item
                .source
                .as_ref()
                .is_some_and(|s| !s.starts_with("https://") || item.accessed.is_none())
        {
            return Err(invalid("incomplete-evidence"));
        }
    }
    if m.category == Category::Browser {
        for family in [
            "password-stores",
            "web-data",
            "history",
            "passkeys",
            "encryption-key-metadata",
        ] {
            if !m.preserve.artifact_families.iter().any(|p| p == family) {
                return Err(invalid("missing-browser-preservation"));
            }
        }
    }
    if m.support == Support::Validated {
        if m.confidence.status.as_deref() == Some("unverified")
            || unknown_coverage(&m.compatibility.product_versions)
            || m.confidence
                .version_coverage
                .as_deref()
                .is_none_or(unknown_coverage)
            || !m.open_spikes.is_empty()
            || m.risks.permanent_data_loss == LossAssessment::Unknown
            || m.risks
                .flags
                .contains(&RiskFlag::SavedPasswordsPasskeysAutofillHistory)
            || m.cleaning_methods.iter().any(|method| {
                !method.blockers().is_empty()
                    || method.effects().is_empty()
                    || method
                        .effects()
                        .iter()
                        .any(|effect| effect.trim().is_empty())
            })
        {
            return Err(invalid("validated-support-has-unresolved-coverage"));
        }
        if m.category == Category::WindowsMicrosoftAndDevTools && m.risks.confirmations.is_empty() {
            return Err(invalid("special-category-requires-confirmation"));
        }
    }
    Ok(())
}
