use crate::{
    components,
    native::{self, child, Handle, Identity, Info},
    KnownFolder, Mutation, PlatformError, Result, RootResolver,
};
use everyout_core_model::{ActionStatus, ErrorKind};
use std::{
    ffi::OsStr,
    path::{Component, Path, Prefix},
    ptr,
    rc::Rc,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::{ERROR_DIR_NOT_EMPTY, INVALID_HANDLE_VALUE},
    Storage::FileSystem::*,
};

const MAX_OBJECTS: usize = 10_000;
const MAX_DEPTH: usize = 64;
const RETRIES: usize = 2;

/// Ancestors and root stay open without delete sharing for this capability's
/// entire lifetime. No public absolute-path constructor exists in the shipping API.
#[derive(Clone)]
pub struct AllowedRoot {
    chain: Rc<Vec<Handle>>,
}
impl AllowedRoot {
    fn validate(&self) -> Result<()> {
        for handle in self.chain.iter() {
            if !handle.info()?.directory {
                return Err(PlatformError::new(ErrorKind::ScopeViolation));
            }
        }
        Ok(())
    }
    pub fn from_manifest(
        resolver: &dyn RootResolver,
        base: KnownFolder,
        relative: &str,
    ) -> Result<Self> {
        let base = resolver.resolve(base)?;
        let mut chain = Vec::new();
        // Retain the base capability through a parent field encoded in RootChain.
        let parts = components(relative)?;
        let mut parent = base.handle();
        for part in &parts {
            chain.push(child(parent, OsStr::new(part), Some(true), false)?);
            parent = chain.last().expect("just pushed");
        }
        // Duplicate ownership is unnecessary: retain base handles in a separate Rc.
        // RootChain below holds both the base and the final extension.
        Self::retain(base, chain)
    }
    fn retain(base: Self, chain: Vec<Handle>) -> Result<Self> {
        // The handle wrapper supports a retained parent capability through its own
        // directory chain. Duplicate handles preserve identical share constraints.
        let mut combined = Vec::new();
        for handle in base.chain.iter() {
            combined.push(native::duplicate(handle)?);
        }
        combined.extend(chain);
        Ok(Self {
            chain: Rc::new(combined),
        })
    }
    pub(crate) fn handle(&self) -> &Handle {
        self.chain.last().expect("nonempty root chain")
    }
    pub(crate) fn absolute(path: &Path) -> Result<Self> {
        let mut parts = path.components();
        let drive = match parts.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) => drive,
                _ => return Err(PlatformError::new(ErrorKind::ScopeViolation)),
            },
            _ => return Err(PlatformError::new(ErrorKind::ScopeViolation)),
        };
        if parts.next() != Some(Component::RootDir) {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let drive_path = native::wide(format!("{}:\\", char::from(drive)));
        let mut fs_name = [0u16; 32];
        // SAFETY: fixed local drive-root string and bounded writable metadata buffer.
        if unsafe { GetDriveTypeW(drive_path.as_ptr()) } != 3
            || unsafe {
                GetVolumeInformationW(
                    drive_path.as_ptr(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    fs_name.as_mut_ptr(),
                    fs_name.len() as u32,
                )
            } == 0
        {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        if !fs_name.starts_with(&native::wide("NTFS")) {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        // SAFETY: open an existing local volume-root directory for metadata/enumeration.
        let drive_handle = unsafe {
            CreateFileW(
                drive_path.as_ptr(),
                FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if drive_handle == INVALID_HANDLE_VALUE {
            return Err(native::last_error());
        }
        let mut chain = vec![Handle(drive_handle)];
        chain[0].info()?;
        for part in parts {
            let Component::Normal(part) = part else {
                return Err(PlatformError::new(ErrorKind::ScopeViolation));
            };
            components(
                part.to_str()
                    .ok_or_else(|| PlatformError::new(ErrorKind::ScopeViolation))?,
            )?;
            chain.push(child(
                chain.last().expect("drive present"),
                part,
                Some(true),
                false,
            )?);
        }
        if chain.len() < 2 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        Ok(Self {
            chain: Rc::new(chain),
        })
    }
    pub fn path(&self, relative: &str) -> Result<SafePath> {
        self.validate()?;
        let parts = components(relative)?;
        if parts.len() > MAX_DEPTH {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        let mut handles = Vec::new();
        let mut identities = Vec::new();
        let mut parent = self.handle();
        let mut missing = false;
        let mut directory = false;
        for (index, part) in parts.iter().enumerate() {
            if missing {
                identities.push(None);
                continue;
            }
            match child(
                parent,
                OsStr::new(part),
                if index + 1 == parts.len() {
                    None
                } else {
                    Some(true)
                },
                false,
            ) {
                Ok(handle) => {
                    let info = handle.info()?;
                    directory = info.directory;
                    identities.push(Some(info.identity));
                    handles.push(handle);
                    parent = handles.last().expect("just pushed");
                }
                Err(e) if native::absent(&e) => {
                    missing = true;
                    identities.push(None);
                }
                Err(e) => return Err(e),
            }
        }
        Ok(SafePath {
            root: self.clone(),
            parts,
            identities,
            directory,
        })
    }
}

/// Not serializable and has no unchecked constructor. Binds ancestor and target
/// identities when resolved; substitution before a later operation is rejected.
pub struct SafePath {
    root: AllowedRoot,
    parts: Vec<String>,
    identities: Vec<Option<Identity>>,
    directory: bool,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    pub exists: bool,
    pub is_directory: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}
impl SafePath {
    fn open(&self, delete: bool) -> Result<Option<Vec<Handle>>> {
        self.root.validate()?;
        let mut handles = Vec::new();
        let mut parent = self.root.handle();
        for (index, part) in self.parts.iter().enumerate() {
            let final_component = index + 1 == self.parts.len();
            let kind = if final_component && self.identities[index].is_none() {
                None
            } else {
                Some(!final_component || self.directory)
            };
            match child(parent, OsStr::new(part), kind, delete && final_component) {
                Ok(handle) => {
                    if self.identities[index] != Some(handle.info()?.identity) {
                        return Err(PlatformError::new(ErrorKind::StalePlan));
                    }
                    handles.push(handle);
                    parent = handles.last().expect("just pushed");
                }
                Err(e) if native::absent(&e) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
        Ok(Some(handles))
    }
    pub fn probe(&self) -> Result<Metadata> {
        let Some(handles) = self.open(false)? else {
            return Ok(Metadata {
                exists: false,
                is_directory: false,
                size: 0,
                modified: None,
            });
        };
        let leaf = handles.last().expect("nonempty path");
        let info = leaf.info()?;
        let size = if info.directory {
            let mut count = 0;
            directory_size(leaf, 0, &mut count)?
        } else {
            info.size
        };
        let ticks = info.modified_ticks;
        let modified = UNIX_EPOCH
            .checked_sub(Duration::from_secs(11_644_473_600))
            .and_then(|epoch| {
                epoch.checked_add(Duration::new(
                    ticks / 10_000_000,
                    ((ticks % 10_000_000) * 100) as u32,
                ))
            });
        Ok(Metadata {
            exists: true,
            is_directory: info.directory,
            size,
            modified,
        })
    }
    pub fn exists(&self) -> Result<bool> {
        Ok(self.open(false)?.is_some())
    }
    pub fn is_directory(&self) -> Result<bool> {
        let Some(handles) = self.open(false)? else {
            return Ok(false);
        };
        Ok(handles.last().expect("nonempty path").info()?.directory)
    }
    pub fn size(&self) -> Result<u64> {
        Ok(self.probe()?.size)
    }
    pub fn modified(&self) -> Result<Option<SystemTime>> {
        Ok(self.probe()?.modified)
    }
    pub fn delete_file(&self, dry_run: bool) -> Result<Mutation> {
        self.mutate(false, dry_run)
    }
    pub fn delete_tree(&self, dry_run: bool) -> Result<Mutation> {
        self.mutate(true, dry_run)
    }
    fn mutate(&self, directory: bool, dry_run: bool) -> Result<Mutation> {
        let Some(mut ancestors) = self.open(!dry_run)? else {
            return Ok(Mutation {
                status: ActionStatus::AlreadyAbsent,
                objects: 0,
            });
        };
        let leaf = ancestors.pop().expect("nonempty path");
        if leaf.info()?.directory != directory {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        let mut objects = Vec::new();
        collect(leaf, !dry_run, 0, &mut objects)?;
        if dry_run {
            return Ok(Mutation {
                status: ActionStatus::WouldApply,
                objects: objects.len(),
            });
        }
        let mut applied = 0;
        // Children are opened and pinned before mutation. Remove in postorder; retries
        // use the same object handle and cannot widen/reopen a replaced pathname.
        for handle in objects.into_iter().rev() {
            let mut result = handle.delete(false);
            for _ in 0..RETRIES {
                if result.as_ref().is_err_and(|e| {
                    e.kind == ErrorKind::Locked || e.os_code == Some(ERROR_DIR_NOT_EMPTY)
                }) {
                    thread::sleep(Duration::from_millis(10));
                    result = handle.delete(false);
                } else {
                    break;
                }
            }
            result.map_err(|mut e| {
                e.applied = applied;
                e
            })?;
            applied += 1;
            drop(handle);
        }
        Ok(Mutation {
            status: ActionStatus::Applied,
            objects: applied,
        })
    }
}
fn directory_size(handle: &Handle, depth: usize, count: &mut usize) -> Result<u64> {
    if depth >= MAX_DEPTH {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    let mut total: u64 = 0;
    for (name, directory) in handle.children()? {
        *count += 1;
        if *count > MAX_OBJECTS {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        components(
            name.to_str()
                .ok_or_else(|| PlatformError::new(ErrorKind::ScopeViolation))?,
        )?;
        let child = child(handle, &name, Some(directory), false)?;
        let info = child.info()?;
        let size = if directory {
            directory_size(&child, depth + 1, count)?
        } else {
            info.size
        };
        total = total
            .checked_add(size)
            .ok_or_else(|| PlatformError::new(ErrorKind::Unsupported))?;
    }
    Ok(total)
}
fn collect(handle: Handle, delete: bool, depth: usize, result: &mut Vec<Handle>) -> Result<()> {
    if depth >= MAX_DEPTH || result.len() >= MAX_OBJECTS {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    let info: Info = handle.info()?;
    let children = if info.directory {
        handle.children()?
    } else {
        Vec::new()
    };
    result.push(handle);
    let index = result.len() - 1;
    for (name, directory) in children {
        components(
            name.to_str()
                .ok_or_else(|| PlatformError::new(ErrorKind::ScopeViolation))?,
        )?;
        let child = child(&result[index], &name, Some(directory), delete)?;
        collect(child, delete, depth + 1, result)?;
    }
    Ok(())
}

#[cfg(test)]
mod confinement_tests {
    use super::*;
    use std::fs;

    #[test]
    fn forced_substitution_between_open_and_disposition_is_blocked() {
        let fixture = tempfile::Builder::new()
            .prefix("everyout-race-")
            .tempdir()
            .unwrap();
        let root = AllowedRoot::absolute(fixture.path()).unwrap();
        fs::create_dir(fixture.path().join("parent")).unwrap();
        fs::write(fixture.path().join("parent/file"), b"synthetic").unwrap();
        fs::write(fixture.path().join("canary"), b"untouched").unwrap();
        let path = root.path("parent/file").unwrap();
        let handles = path.open(true).unwrap().unwrap();
        let leaf = handles.last().unwrap();
        leaf.info().unwrap();
        // Force the hostile interleaving after open/validation and before the real
        // disposition API. Held object handles must prevent every substitution.
        assert!(fs::rename(
            fixture.path().join("parent/file"),
            fixture.path().join("old")
        )
        .is_err());
        assert!(fs::rename(
            fixture.path().join("parent"),
            fixture.path().join("old-parent")
        )
        .is_err());
        assert!(fs::OpenOptions::new()
            .write(true)
            .open(fixture.path().join("parent/file"))
            .is_err());
        leaf.delete(true).unwrap();
        assert!(fixture.path().join("parent/file").exists());
        leaf.delete(false).unwrap();
        drop(handles);
        assert!(!fixture.path().join("parent/file").exists());
        assert_eq!(
            fs::metadata(fixture.path().join("canary")).unwrap().len(),
            9
        );
    }
}
