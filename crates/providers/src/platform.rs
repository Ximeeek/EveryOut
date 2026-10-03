//! Bind only loader-validated, immutable manifest artifacts to narrow capabilities.
//! This is not the future engine's approval, ownership or preservation planner.
use crate::{load_manifest, CleaningMethod, Manifest, ManifestError, Root};
use everyout_core_model::{ArtifactKind, ErrorKind, Scope, Support};
use everyout_platform_windows::{
    AllowedRoot, KnownFolder, Metadata, Mutation, PlatformError, RegistryRoot, RegistryTarget,
    Result, RootResolver, SafePath,
};

pub struct PlatformManifest(Manifest);
impl PlatformManifest {
    pub fn load(json: &str) -> std::result::Result<Self, ManifestError> {
        load_manifest(json).map(Self)
    }
    /// Manifest names identify candidates only; installation ownership and explicit
    /// selection must be reviewed by the caller before passing targets to closing.
    /// The current manifest schema declares names, not executable paths. Resolved
    /// installation paths may additionally narrow this match without schema changes.
    pub fn match_processes<'a>(
        &self,
        inventory: &'a everyout_platform_windows::process::ProcessInventory,
        image_paths: &[std::path::PathBuf],
    ) -> Vec<&'a everyout_platform_windows::process::Process> {
        inventory
            .processes
            .iter()
            .filter(|process| {
                !self.0.identity.process_names.is_empty()
                    && process.matches(&self.0.identity.process_names, image_paths)
            })
            .collect()
    }
    pub fn file(
        &self,
        artifact_id: &str,
        profile: Option<&str>,
        resolver: &dyn RootResolver,
    ) -> Result<FileArtifact> {
        let artifact = self
            .0
            .session_locations
            .iter()
            .find(|a| a.id == artifact_id)
            .ok_or_else(scope)?;
        if artifact.name_prefix.is_some() {
            return Err(scope());
        }
        let root = self
            .0
            .roots
            .iter()
            .find(|r| r.id() == artifact.root)
            .ok_or_else(scope)?;
        let (base, relative) = match root {
            Root::LocalAppData { relative, .. } => (KnownFolder::LocalAppData, relative),
            Root::UserProfile { relative, .. } => (KnownFolder::UserProfile, relative),
            Root::RoamingAppData { relative, .. } => (KnownFolder::RoamingAppData, relative),
            _ => return Err(scope()),
        };
        let relative_target = match (artifact.scope, profile) {
            (Scope::Profile, Some(profile)) => {
                if profile.contains(['/', '\\']) {
                    return Err(scope());
                }
                let profiles = self.0.profiles.as_ref().ok_or_else(scope)?;
                if !(profile.is_empty() && profiles.root_profile == Some(true))
                    && !profiles.directory_patterns.iter().any(|pattern| {
                        match pattern.split_once('*') {
                            Some((start, end)) => {
                                profile.len() >= start.len() + end.len()
                                    && profile.starts_with(start)
                                    && profile.ends_with(end)
                            }
                            None => profile == pattern,
                        }
                    })
                {
                    return Err(scope());
                }
                if profile.is_empty() {
                    artifact.relative.clone()
                } else {
                    format!("{profile}\\{}", artifact.relative)
                }
            }
            (Scope::Profile, None) | (_, Some(_)) => return Err(scope()),
            (_, None) => artifact.relative.clone(),
        };
        let root = AllowedRoot::from_manifest(resolver, base, relative)?;
        let exclusions = self.0.cleaning_methods.iter().any(|method| matches!(method, CleaningMethod::DeleteDirectoryFamily { id, exclusions, .. } if id == &artifact.method && !exclusions.is_empty()));
        Ok(FileArtifact {
            path: root.path(&relative_target)?,
            directory: artifact.kind == ArtifactKind::Directory,
            support: self.0.support,
            exclusions,
        })
    }
    pub fn registry(&self, artifact_id: &str) -> Result<RegistryArtifact> {
        self.registry_bound(artifact_id, None)
    }
    pub fn registry_for_account(&self, artifact_id: &str, hive: &str) -> Result<RegistryArtifact> {
        self.registry_bound(artifact_id, Some(hive))
    }
    fn registry_bound(&self, artifact_id: &str, hive: Option<&str>) -> Result<RegistryArtifact> {
        let artifact = self
            .0
            .session_locations
            .iter()
            .find(|a| a.id == artifact_id)
            .ok_or_else(scope)?;
        let Some(Root::Registry { key, .. }) =
            self.0.roots.iter().find(|r| r.id() == artifact.root)
        else {
            return Err(scope());
        };
        let value = match artifact.kind {
            ArtifactKind::RegistryKey => false,
            ArtifactKind::RegistryValue => true,
            _ => return Err(scope()),
        };
        let target = if value {
            RegistryTarget::Value(artifact.relative.clone())
        } else {
            RegistryTarget::Key(artifact.relative.clone())
        };
        Ok(RegistryArtifact {
            root: match hive {
                Some(hive) => RegistryRoot::for_account(key, &[target], hive)?,
                None => RegistryRoot::from_manifest(key, &[target])?,
            },
            relative: artifact.relative.clone(),
            value,
            support: self.0.support,
        })
    }
}
fn scope() -> PlatformError {
    PlatformError {
        kind: ErrorKind::ScopeViolation,
        os_code: None,
        applied: 0,
    }
}
fn require_execution(support: Support, dry_run: bool) -> Result<()> {
    if !dry_run && support != Support::Validated {
        return Err(PlatformError {
            kind: ErrorKind::Unsupported,
            os_code: None,
            applied: 0,
        });
    }
    Ok(())
}
pub struct FileArtifact {
    path: SafePath,
    directory: bool,
    support: Support,
    exclusions: bool,
}
impl FileArtifact {
    pub fn probe(&self) -> Result<Metadata> {
        self.path.probe()
    }
    pub fn delete(&self, dry_run: bool) -> Result<Mutation> {
        require_execution(self.support, dry_run)?;
        if self.exclusions {
            return Err(PlatformError {
                kind: ErrorKind::Unsupported,
                os_code: None,
                applied: 0,
            });
        }
        if self.directory {
            self.path.delete_tree(dry_run)
        } else {
            self.path.delete_file(dry_run)
        }
    }
}
pub struct RegistryArtifact {
    root: RegistryRoot,
    relative: String,
    value: bool,
    support: Support,
}
impl RegistryArtifact {
    pub fn exists(&self) -> Result<bool> {
        if self.value {
            self.root.value_exists(&self.relative)
        } else {
            self.root.key_exists(&self.relative)
        }
    }
    pub fn delete(&self, dry_run: bool) -> Result<Mutation> {
        require_execution(self.support, dry_run)?;
        if self.value {
            self.root.delete_value(&self.relative, dry_run)
        } else {
            self.root.delete_key_tree(&self.relative, dry_run)
        }
    }
}
