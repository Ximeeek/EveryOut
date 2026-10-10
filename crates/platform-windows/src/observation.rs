//! Filesystem observation with metadata-only rights, bounded snapshots and async watches.
use crate::{
    native::{self, Handle, Info},
    win32_identity::Win32Application,
    AllowedRoot, PlatformError, Result,
};
use everyout_core_model::{observation::*, ErrorKind};
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    mem::offset_of,
    ptr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{LibraryLoader::*, Threading::*, IO::*},
};
mod teach;
pub use teach::TeachController;

pub fn local_low() -> Option<AllowedRoot> {
    use crate::{CurrentUserFolders, KnownFolder, RootResolver};
    use std::{os::windows::ffi::OsStringExt, path::PathBuf};
    use windows_sys::Win32::{
        System::Com::CoTaskMemFree,
        UI::Shell::{FOLDERID_LocalAppDataLow, SHGetKnownFolderPath},
    };
    let mut value = ptr::null_mut();
    if unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppDataLow, 0, ptr::null_mut(), &mut value) }
        < 0
    {
        if !value.is_null() {
            unsafe {
                CoTaskMemFree(value.cast());
            }
        }
        return None;
    }
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    let path = PathBuf::from(std::ffi::OsString::from_wide(unsafe {
        std::slice::from_raw_parts(value, length)
    }));
    unsafe {
        CoTaskMemFree(value.cast());
    }
    let profile = CurrentUserFolders.resolve(KnownFolder::UserProfile).ok()?;
    let profile_path = profile.metadata_path().ok()?;
    let profile_path = profile_path.to_string_lossy();
    let lexical = profile_path
        .strip_prefix("\\\\?\\")
        .unwrap_or(&profile_path);
    profile
        .discovery_descendant(path.strip_prefix(lexical).ok()?.to_str()?)
        .ok()
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn identity(info: &Info) -> FileIdentity {
    FileIdentity {
        volume: info.identity.volume,
        index: info.identity.index,
    }
}

pub fn application_binding(
    app: &Win32Application,
    channel: Option<String>,
) -> Result<ApplicationBinding> {
    app.executable.revalidate()?;
    let file = app.executable_metadata()?;
    let mut framework_fingerprint = vec![];
    for artifact in [
        "resources/app.asar",
        "libcef.dll",
        "WebView2Loader.dll",
        "Update.exe",
    ] {
        if let Some(info) = app.installation_metadata(artifact)?.observation_info()? {
            framework_fingerprint.push(FrameworkFingerprint {
                artifact: artifact.into(),
                identity: identity(&info),
                size: info.size,
                write_ticks: info.modified_ticks,
            });
        }
    }
    Ok(ApplicationBinding {
        identity: app.identity(),
        executable_path: app.executable.canonical_path.to_string_lossy().into(),
        executable: identity(&file),
        executable_size: file.size,
        executable_write_ticks: file.modified_ticks,
        publisher: app
            .signature
            .publisher
            .clone()
            .or_else(|| app.pe.company_name.clone()),
        signature: app.signature.certificate_sha256.clone(),
        signature_status: format!("{:?}", app.signature.status).to_lowercase(),
        version: app
            .pe
            .file_version
            .clone()
            .or_else(|| app.pe.product_version.clone()),
        channel,
        framework: app.framework_hints.clone(),
        framework_fingerprint,
        selected_process: app.processes.first().map(|p| ProcessBinding {
            pid: p.pid,
            creation_ticks: p.creation_ticks,
        }),
    })
}

#[derive(Debug, Clone, Copy)]
pub struct SnapshotBudget {
    pub entries: usize,
    pub depth: usize,
    pub duration: Duration,
}
impl Default for SnapshotBudget {
    fn default() -> Self {
        Self {
            entries: 10_000,
            depth: 32,
            duration: Duration::from_secs(2),
        }
    }
}
pub fn snapshot(root: &AllowedRoot, budget: SnapshotBudget) -> Result<MetadataSnapshot> {
    let info = root.handle().info()?;
    let mut result = MetadataSnapshot {
        root: native::metadata_path(root.handle())?
            .to_string_lossy()
            .into(),
        root_identity: identity(&info),
        entries: BTreeMap::new(),
        completeness: Completeness::Complete,
        captured_at_ms: now_ms(),
        provenance: vec![provenance(
            "metadata-snapshot",
            "bounded-handle-enumeration",
        )],
    };
    capture(root.handle(), "", 0, &mut result, budget, Instant::now());
    Ok(result)
}
fn capture(
    handle: &Handle,
    prefix: &str,
    depth: usize,
    result: &mut MetadataSnapshot,
    budget: SnapshotBudget,
    start: Instant,
) {
    if depth >= budget.depth
        || start.elapsed() >= budget.duration
        || result.entries.len() >= budget.entries
    {
        result.completeness = Completeness::Incomplete;
        result.provenance.push(provenance(
            "metadata-snapshot",
            "enumeration-budget-exhausted",
        ));
        return;
    }
    let Ok(parent) = handle.info() else {
        result.completeness = Completeness::Incomplete;
        return;
    };
    let Ok((children, omitted)) = handle.discovery_children() else {
        result.completeness = Completeness::Incomplete;
        return;
    };
    if omitted {
        result.completeness = Completeness::Incomplete;
    }
    for (name, directory) in children {
        if start.elapsed() >= budget.duration || result.entries.len() >= budget.entries {
            result.completeness = Completeness::Incomplete;
            break;
        }
        let Some(name) = name.to_str() else {
            result.completeness = Completeness::Incomplete;
            continue;
        };
        if crate::components(name).is_err() {
            result.completeness = Completeness::Incomplete;
            continue;
        }
        let Ok(child) = native::child(handle, OsStr::new(name), Some(directory), false) else {
            result.completeness = Completeness::Incomplete;
            continue;
        };
        let Ok(info) = child.info() else {
            result.completeness = Completeness::Incomplete;
            continue;
        };
        let path = if prefix.is_empty() {
            name.into()
        } else {
            format!("{prefix}/{name}")
        };
        result.entries.insert(
            path.clone(),
            EntryMetadata {
                directory,
                size: info.size,
                created_ticks: info.created_ticks,
                write_ticks: info.modified_ticks,
                change_ticks: info.change_ticks,
                attributes: info.attributes,
                identity: identity(&info),
                parent: Some(identity(&parent)),
            },
        );
        if directory {
            capture(&child, &path, depth + 1, result, budget, start);
        }
    }
}

type ExtendedRead = unsafe extern "system" fn(
    HANDLE,
    *mut std::ffi::c_void,
    u32,
    i32,
    u32,
    *mut u32,
    *mut OVERLAPPED,
    LPOVERLAPPED_COMPLETION_ROUTINE,
    READ_DIRECTORY_NOTIFY_INFORMATION_CLASS,
) -> i32;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatcherMode {
    Extended,
    Standard,
}
pub struct WatchBatch {
    pub events: Vec<MetadataEvent>,
    pub history_lost: bool,
    pub fallback: bool,
}
pub trait ObservationBackend {
    fn poll(&mut self) -> Result<WatchBatch>;
}
/// Never reads file bytes. The boxed OVERLAPPED and aligned buffer stay at fixed
/// addresses until cancellation has completed, including on every failure path.
pub struct DirectoryWatcherBackend {
    _root: AllowedRoot,
    handle: Handle,
    event: Handle,
    overlapped: Box<OVERLAPPED>,
    buffer: Box<[u64]>,
    extended: Option<ExtendedRead>,
    pending: bool,
    mode: WatcherMode,
    fallback: bool,
}
impl DirectoryWatcherBackend {
    pub fn start(root: AllowedRoot) -> Result<Self> {
        Self::start_mode(root, false)
    }
    /// Standard-mode injection for testing the documented fallback independently.
    pub fn start_standard(root: AllowedRoot) -> Result<Self> {
        Self::start_mode(root, true)
    }
    fn start_mode(root: AllowedRoot, standard: bool) -> Result<Self> {
        let expected = root.handle().info()?.identity;
        let path = native::wide(native::metadata_path(root.handle())?);
        let raw = unsafe {
            CreateFileW(
                path.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(native::last_error());
        }
        let handle = Handle(raw);
        if handle.info()?.identity != expected {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        let event = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
        if event.is_null() {
            return Err(native::last_error());
        }
        let module = unsafe { GetModuleHandleW(native::wide("kernel32.dll").as_ptr()) };
        let extended = if standard || module.is_null() {
            None
        } else {
            unsafe { GetProcAddress(module, c"ReadDirectoryChangesExW".as_ptr().cast()) }.map(
                |f| unsafe {
                    std::mem::transmute::<unsafe extern "system" fn() -> isize, ExtendedRead>(f)
                },
            )
        };
        let mut watcher = Self {
            _root: root,
            handle,
            event: Handle(event),
            overlapped: Box::new(OVERLAPPED::default()),
            buffer: vec![0u64; 8192].into_boxed_slice(),
            extended,
            pending: false,
            mode: if extended.is_some() {
                WatcherMode::Extended
            } else {
                WatcherMode::Standard
            },
            fallback: extended.is_none(),
        };
        watcher.arm()?;
        Ok(watcher)
    }
    pub fn mode(&self) -> WatcherMode {
        self.mode
    }
    fn arm(&mut self) -> Result<()> {
        unsafe {
            ResetEvent(self.event.0);
        }
        *self.overlapped = OVERLAPPED::default();
        self.overlapped.hEvent = self.event.0;
        let filter = FILE_NOTIFY_CHANGE_FILE_NAME
            | FILE_NOTIFY_CHANGE_DIR_NAME
            | FILE_NOTIFY_CHANGE_SIZE
            | FILE_NOTIFY_CHANGE_LAST_WRITE
            | FILE_NOTIFY_CHANGE_CREATION
            | FILE_NOTIFY_CHANGE_ATTRIBUTES;
        let ok = unsafe {
            if let Some(read) = self.extended {
                read(
                    self.handle.0,
                    self.buffer.as_mut_ptr().cast(),
                    (self.buffer.len() * 8) as u32,
                    1,
                    filter,
                    ptr::null_mut(),
                    &mut *self.overlapped,
                    None,
                    ReadDirectoryNotifyExtendedInformation,
                )
            } else {
                ReadDirectoryChangesW(
                    self.handle.0,
                    self.buffer.as_mut_ptr().cast(),
                    (self.buffer.len() * 8) as u32,
                    1,
                    filter,
                    ptr::null_mut(),
                    &mut *self.overlapped,
                    None,
                )
            }
        };
        if ok == 0 {
            let error = native::last_error();
            if error.os_code != Some(ERROR_IO_PENDING) {
                if self.extended.take().is_some() {
                    self.mode = WatcherMode::Standard;
                    self.fallback = true;
                    return self.arm();
                }
                return Err(error);
            }
        }
        self.pending = true;
        Ok(())
    }
}
impl ObservationBackend for DirectoryWatcherBackend {
    fn poll(&mut self) -> Result<WatchBatch> {
        let mut batch = WatchBatch {
            events: vec![],
            history_lost: false,
            fallback: std::mem::take(&mut self.fallback),
        };
        match unsafe { WaitForSingleObject(self.event.0, 0) } {
            WAIT_TIMEOUT => return Ok(batch),
            WAIT_OBJECT_0 => {}
            _ => return Err(native::last_error()),
        }
        let mut bytes = 0;
        let ok = unsafe { GetOverlappedResult(self.handle.0, &*self.overlapped, &mut bytes, 0) };
        if ok == 0 && unsafe { GetLastError() } == ERROR_IO_INCOMPLETE {
            return Ok(batch);
        }
        self.pending = false;
        if ok == 0 || bytes == 0 {
            batch.history_lost = true;
            if ok == 0 && self.extended.take().is_some() {
                self.mode = WatcherMode::Standard;
                batch.fallback = true;
            }
        } else if bytes as usize > self.buffer.len() * 8 {
            batch.history_lost = true;
        } else {
            let data = unsafe {
                std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), bytes as usize)
            };
            match parse_notifications(data, self.mode) {
                Some(events) => batch.events = events,
                None => {
                    batch.history_lost = true;
                    if self.extended.take().is_some() {
                        self.mode = WatcherMode::Standard;
                        batch.fallback = true;
                    }
                }
            }
        }
        self.arm()?;
        Ok(batch)
    }
}
impl Drop for DirectoryWatcherBackend {
    fn drop(&mut self) {
        if self.pending {
            unsafe {
                CancelIoEx(self.handle.0, &*self.overlapped);
                let mut bytes = 0;
                // Cancellation completion must precede freeing the I/O memory.
                GetOverlappedResult(self.handle.0, &*self.overlapped, &mut bytes, 1);
            }
        }
    }
}

fn parse_notifications(bytes: &[u8], mode: WatcherMode) -> Option<Vec<MetadataEvent>> {
    let name_offset = match mode {
        WatcherMode::Extended => offset_of!(FILE_NOTIFY_EXTENDED_INFORMATION, FileName),
        WatcherMode::Standard => offset_of!(FILE_NOTIFY_INFORMATION, FileName),
    };
    let length_offset = match mode {
        WatcherMode::Extended => offset_of!(FILE_NOTIFY_EXTENDED_INFORMATION, FileNameLength),
        WatcherMode::Standard => offset_of!(FILE_NOTIFY_INFORMATION, FileNameLength),
    };
    let word = |at: usize| -> Option<u32> {
        Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    let mut result = vec![];
    let mut offset = 0;
    loop {
        let next = word(offset)? as usize;
        let action = word(offset + 4)?;
        let length = word(offset + length_offset)? as usize;
        if length == 0 || !length.is_multiple_of(2) {
            return None;
        }
        let data = bytes.get(offset + name_offset..offset + name_offset + length)?;
        let name: Vec<_> = data
            .as_chunks::<2>()
            .0
            .iter()
            .map(|w| u16::from_le_bytes(*w))
            .collect();
        let path = String::from_utf16(&name).ok()?.replace('\\', "/");
        crate::components(&path).ok()?;
        let kind = match action {
            FILE_ACTION_ADDED => ChangeKind::Create,
            FILE_ACTION_REMOVED => ChangeKind::Remove,
            FILE_ACTION_MODIFIED => ChangeKind::Modify,
            FILE_ACTION_RENAMED_OLD_NAME => ChangeKind::RenameOld,
            FILE_ACTION_RENAMED_NEW_NAME => ChangeKind::RenameNew,
            _ => return None,
        };
        result.push(MetadataEvent { path, kind });
        if next == 0 {
            break;
        }
        if next < name_offset + length || !next.is_multiple_of(4) {
            return None;
        }
        offset = offset.checked_add(next)?;
        if offset >= bytes.len() {
            return None;
        }
    }
    Some(result)
}

/// A lost watcher history is recovered as an endpoint only, with explicit provenance.
pub fn recover_snapshot(root: &AllowedRoot, budget: SnapshotBudget) -> Result<MetadataSnapshot> {
    let mut captured = snapshot(root, budget)?;
    if captured.completeness == Completeness::Complete {
        captured.completeness = Completeness::RecoveredByRescan;
    }
    captured.provenance.push(provenance(
        "directory-watcher",
        "history-lost-metadata-rescan",
    ));
    Ok(captured)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_notifications_are_loss_not_negative_evidence() {
        assert!(parse_notifications(&[0; 12], WatcherMode::Standard).is_none());
        assert!(parse_notifications(&[255; 32], WatcherMode::Extended).is_none());
    }
}
