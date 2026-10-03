//! Owner-bound metadata and hive lifecycle. S6 session races and crash recovery
//! remain UNVERIFIED; a process crash cannot guarantee unloading a temporary hive.
use crate::{KnownFolder, PlatformError, Result};
use everyout_core_model::ErrorKind;
use std::{
    collections::HashSet,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{NativeHives, NativeProfiles};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileRecord {
    pub sid: String,
    pub path: PathBuf,
    pub local_user: bool,
    pub special: bool,
    pub temporary: bool,
    pub logged_on: bool,
    pub hive_mounted: bool,
}
/// Trusted OS adapter or synthetic test data; never deserialized from IPC.
pub trait ProfileSource {
    fn records(&self) -> Result<Vec<ProfileRecord>>;
    /// Only AppData/Local AppData path metadata may be read from User Shell Folders.
    fn folder(&self, hive: &str, folder: KnownFolder) -> Result<Option<String>>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountProfile {
    pub(crate) record: ProfileRecord,
}
impl AccountProfile {
    pub fn sid(&self) -> &str {
        &self.record.sid
    }
    pub fn profile_path(&self) -> &std::path::Path {
        &self.record.path
    }
    pub fn logged_on(&self) -> bool {
        self.record.logged_on
    }
    pub fn mounted(&self) -> bool {
        self.record.hive_mounted
    }
    pub fn revalidate(&self, source: &dyn ProfileSource) -> Result<()> {
        if enumerate(source)?.iter().any(|p| p == self) {
            Ok(())
        } else {
            Err(PlatformError::new(ErrorKind::StalePlan))
        }
    }
}
pub fn valid_user_sid(sid: &str) -> bool {
    let parts: Vec<_> = sid.split('-').collect();
    parts.len() == 8
        && parts[..4] == ["S", "1", "5", "21"]
        && parts[4..].iter().all(|v| v.parse::<u32>().is_ok())
}
fn local_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() > 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/')
        && crate::components(&path[3..]).is_ok()
}
pub fn enumerate(source: &dyn ProfileSource) -> Result<Vec<AccountProfile>> {
    Ok(inventory(source)?.profiles)
}
pub struct ProfileInventory {
    pub profiles: Vec<AccountProfile>,
    /// Neutral labels/codes only; excluded SIDs and paths stay native.
    pub exclusions: Vec<(String, String)>,
}
pub fn inventory(source: &dyn ProfileSource) -> Result<ProfileInventory> {
    let mut seen = HashSet::new();
    let mut profiles = Vec::new();
    let mut exclusions = Vec::new();
    for record in source.records()? {
        let path = record.path.to_str().unwrap_or("");
        let leaf = path
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        if !record.local_user
            || record.special
            || record.temporary
            || !valid_user_sid(&record.sid)
            || !local_path(path)
            || [
                "default",
                "default user",
                "public",
                "systemprofile",
                "localservice",
                "networkservice",
            ]
            .contains(&leaf.as_str())
            || leaf == "temp"
            || leaf.starts_with("temp.")
        {
            let reason = if record.special || !valid_user_sid(&record.sid) {
                "special-service-or-stale-profile"
            } else if path.is_empty() {
                "profile-metadata-unavailable"
            } else if record.temporary || leaf == "temp" || leaf.starts_with("temp.") {
                "temporary-or-unrecognized-profile-state"
            } else if !record.local_user {
                "nonlocal-or-unresolved-account"
            } else {
                "unsupported-profile-location"
            };
            exclusions.push((
                format!("excluded-profile-{}", exclusions.len()),
                reason.into(),
            ));
            continue;
        }
        if !seen.insert(record.sid.clone())
            || profiles.iter().any(|p: &AccountProfile| {
                p.record.path.to_string_lossy().eq_ignore_ascii_case(path)
            })
        {
            return Err(PlatformError::new(ErrorKind::OwnershipConflict));
        }
        profiles.push(AccountProfile { record });
    }
    profiles.sort_by(|a, b| a.sid().cmp(b.sid()));
    Ok(ProfileInventory {
        profiles,
        exclusions,
    })
}

/// Expands only the target owner's variables; no std::env or helper HKCU fallback.
/// Redirected/UNC/out-of-profile known folders are deliberately unsupported.
pub fn resolve_path(
    source: &dyn ProfileSource,
    profile: &AccountProfile,
    hive: &str,
    folder: KnownFolder,
) -> Result<PathBuf> {
    if hive != profile.sid() && !hive.starts_with("EveryOut-") {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let home = profile
        .record
        .path
        .to_str()
        .ok_or(PlatformError::new(ErrorKind::ScopeViolation))?;
    if folder == KnownFolder::UserProfile {
        return Ok(profile.record.path.clone());
    }
    let default = match folder {
        KnownFolder::LocalAppData => "AppData\\Local",
        KnownFolder::RoamingAppData => "AppData\\Roaming",
        KnownFolder::UserProfile => unreachable!(),
    };
    let raw = source
        .folder(hive, folder)?
        .unwrap_or_else(|| format!("%USERPROFILE%\\{default}"));
    let mut expanded = raw;
    for (var, value) in [
        ("%USERPROFILE%", home.to_owned()),
        ("%APPDATA%", format!("{home}\\AppData\\Roaming")),
        ("%LOCALAPPDATA%", format!("{home}\\AppData\\Local")),
    ] {
        while let Some(index) = expanded.to_ascii_uppercase().find(var) {
            expanded.replace_range(index..index + var.len(), &value);
        }
    }
    let normalized = expanded.replace('/', "\\");
    let prefix = format!("{}\\", home.replace('/', "\\").trim_end_matches('\\'));
    if normalized.contains('%')
        || !local_path(&normalized)
        || !normalized
            .get(..prefix.len())
            .is_some_and(|v| v.eq_ignore_ascii_case(&prefix))
    {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    Ok(PathBuf::from(normalized))
}

#[cfg(windows)]
pub struct AccountFolders<'a> {
    pub source: &'a dyn ProfileSource,
    pub profile: &'a AccountProfile,
    pub hive: &'a str,
}
#[cfg(windows)]
impl crate::RootResolver for AccountFolders<'_> {
    fn resolve(&self, folder: KnownFolder) -> Result<crate::AllowedRoot> {
        self.profile.revalidate(self.source)?;
        crate::AllowedRoot::absolute(&resolve_path(self.source, self.profile, self.hive, folder)?)
    }
}

pub trait HiveApi {
    fn mounted(&self, key: &str) -> Result<bool>;
    fn logged_on(&self, sid: &str) -> Result<bool>;
    fn load(&self, profile: &AccountProfile, key: &str) -> Result<()>;
    fn unload(&self, key: &str) -> Result<()>;
    fn retry_delay(&self) {}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HiveCleanup {
    pub temporary_key: Option<String>,
    pub unload_attempts: usize,
    pub residual: bool,
    pub error: Option<PlatformError>,
}
pub struct HiveResult<T> {
    pub operation: Result<T>,
    pub cleanup: HiveCleanup,
}
static NEXT_HIVE: AtomicU64 = AtomicU64::new(1);
struct Mount<'a> {
    api: &'a dyn HiveApi,
    key: String,
    loaded: bool,
}
impl Mount<'_> {
    fn cleanup(&mut self) -> HiveCleanup {
        let mut report = HiveCleanup {
            temporary_key: Some(self.key.clone()),
            unload_attempts: 0,
            residual: true,
            error: None,
        };
        for _ in 0..3 {
            report.unload_attempts += 1;
            match self.api.unload(&self.key) {
                Ok(()) => {
                    self.loaded = false;
                    match self.api.mounted(&self.key) {
                        Ok(mounted) => report.residual = mounted,
                        Err(error) => {
                            report.residual = true;
                            report.error = Some(error);
                        }
                    }
                    break;
                }
                Err(e) => report.error = Some(e),
            }
            self.api.retry_delay();
        }
        if !report.residual {
            report.error = None;
        }
        report
    }
}
impl Drop for Mount<'_> {
    fn drop(&mut self) {
        if self.loaded {
            let _ = self.cleanup();
        }
    }
}
/// Every successful mount is paired with bounded unload retries, including callback
/// errors/panics. The callback must drop all registry handles before returning.
/// Live SID hives are borrowed and are NEVER loaded or unloaded by this function.
pub fn with_hive<T>(
    api: &dyn HiveApi,
    profile: &AccountProfile,
    run: &str,
    work: impl FnOnce(&str) -> Result<T>,
) -> HiveResult<T> {
    let empty = HiveCleanup {
        temporary_key: None,
        unload_attempts: 0,
        residual: false,
        error: None,
    };
    let prepare = || -> Result<Option<String>> {
        let mounted = api.mounted(profile.sid())?;
        let logged = api.logged_on(profile.sid())?;
        if mounted != profile.mounted() || logged != profile.logged_on() {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        if mounted {
            return Ok(None);
        }
        if logged {
            return Err(PlatformError::new(ErrorKind::Locked));
        }
        if run.len() != 64 || !run.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let key = format!(
            "EveryOut-{run}-{}",
            NEXT_HIVE.fetch_add(1, Ordering::Relaxed)
        );
        if api.mounted(&key)? || api.mounted(profile.sid())? || api.logged_on(profile.sid())? {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        api.load(profile, &key)?;
        Ok(Some(key))
    };
    match prepare() {
        Err(e) => HiveResult {
            operation: Err(e),
            cleanup: empty,
        },
        Ok(None) => HiveResult {
            operation: std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                work(profile.sid())
            }))
            .unwrap_or_else(|_| Err(PlatformError::new(ErrorKind::Io))),
            cleanup: empty,
        },
        Ok(Some(key)) => {
            let mut mount = Mount {
                api,
                key,
                loaded: true,
            };
            let operation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if api.mounted(profile.sid())? || api.logged_on(profile.sid())? {
                    return Err(PlatformError::new(ErrorKind::StalePlan));
                }
                work(&mount.key)
            }))
            .unwrap_or_else(|_| Err(PlatformError::new(ErrorKind::Io)));
            let cleanup = mount.cleanup();
            // Report exactly the bounded attempts; do not silently retry after reporting.
            mount.loaded = false;
            HiveResult { operation, cleanup }
        }
    }
}
