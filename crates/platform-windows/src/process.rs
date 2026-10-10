//! Current-session and helper owner-bound process metadata and explicit-target closing.
//!
//! WM_CLOSE is asynchronous so prompts cannot block the two-second policy timer.
//! S7 remains unverified for real applications: HWND reuse between the last owner
//! check and posting, prompt behavior, child ownership, relaunch and resource release
//! require VM trials. No Restart Manager shutdown is used: its synchronous call has
//! no validated two-second cancellation strategy. Exit is not evidence of logout or
//! released resources. Callers must review each matched identity before closing it.

use crate::{
    native::{error, last_error, Handle},
    PlatformError, Result,
};
use everyout_core_model::ErrorKind;
pub use everyout_core_model::ProcessClosePolicy;
use std::{
    ffi::OsString,
    mem::size_of,
    os::windows::ffi::OsStringExt,
    path::{Path, PathBuf},
    ptr,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER},
    System::{Diagnostics::ToolHelp::*, RemoteDesktop::ProcessIdToSessionId, Threading::*},
    UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE},
};

const GRACE: Duration = Duration::from_secs(2);
const EXIT_WAIT: u32 = 5000;

/// Opaque observed identity: callers cannot forge or edit its PID/creation time.
/// The retained query-only handle pins the observed process object across PID reuse.
pub struct Process {
    handle: Handle,
    pid: u32,
    image: PathBuf,
    session_id: u32,
    creation: u64,
    owner_sid: Option<String>,
}
impl Process {
    pub fn pid(&self) -> u32 {
        self.pid
    }
    pub fn image_path(&self) -> &Path {
        &self.image
    }
    pub fn image_name(&self) -> &std::ffi::OsStr {
        self.image.file_name().expect("validated image")
    }
    pub fn session_id(&self) -> u32 {
        self.session_id
    }
    pub fn creation_ticks(&self) -> u64 {
        self.creation
    }
    /// Exact manifest basenames or exact resolved installation image paths.
    /// Name matches are candidates, not proof of provider ownership or approval.
    /// A supplied path allowlist narrows the name match; wildcards are never expanded.
    pub fn matches(&self, names: &[String], paths: &[PathBuf]) -> bool {
        let same = |a: &std::ffi::OsStr, b: &std::ffi::OsStr| match (a.to_str(), b.to_str()) {
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
            _ => a == b,
        };
        (names.is_empty() && !paths.is_empty()
            || names.iter().any(|n| same(self.image_name(), n.as_ref())))
            && (paths.is_empty()
                || paths
                    .iter()
                    .any(|p| same(self.image.as_os_str(), p.as_os_str())))
    }
}

/// Inaccessible/vanished processes have unknown ownership and are never targets.
/// Diagnostics carry only PID and stable error codes, not paths or usernames.
pub struct ProcessInventory {
    pub processes: Vec<Process>,
    pub unavailable: Vec<(u32, PlatformError)>,
}

fn token_user(process: HANDLE) -> Result<Vec<usize>> {
    let mut raw = ptr::null_mut();
    // SAFETY: live process handle, output token owned by RAII; query-only rights.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last_error());
    }
    let token = Handle(raw);
    let mut needed = 0;
    // SAFETY: initial size query has no output buffer.
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_USER>() as u32 || needed > 65536 {
        return Err(PlatformError::new(ErrorKind::Io));
    }
    let mut buffer = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: aligned, sized allocation contains TOKEN_USER and its embedded SID.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(buffer)
}
fn same_user(handle: HANDLE) -> Result<bool> {
    let target = token_user(handle)?;
    // SAFETY: pseudo handle is borrowed, not wrapped/closed.
    let current = token_user(unsafe { GetCurrentProcess() })?;
    // SAFETY: both aligned TokenUser allocations and embedded SID pointers are live.
    Ok(unsafe {
        EqualSid(
            (*(target.as_ptr().cast::<TOKEN_USER>())).User.Sid,
            (*(current.as_ptr().cast::<TOKEN_USER>())).User.Sid,
        )
    } != 0)
}
fn same_owner(handle: HANDLE, owner: Option<&str>) -> Result<bool> {
    let Some(owner) = owner else {
        return same_user(handle);
    };
    if !crate::accounts::valid_user_sid(owner) {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let target = token_user(handle)?;
    let mut sid = ptr::null_mut();
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW(
            crate::native::wide(owner).as_ptr(),
            &mut sid,
        )
    } == 0
    {
        return Err(last_error());
    }
    let same = unsafe { EqualSid((*(target.as_ptr().cast::<TOKEN_USER>())).User.Sid, sid) } != 0;
    unsafe {
        LocalFree(sid);
    }
    Ok(same)
}
fn session(pid: u32) -> Result<u32> {
    let mut id = 0;
    // SAFETY: writable session output; no process mutation.
    if unsafe { ProcessIdToSessionId(pid, &mut id) } == 0 {
        return Err(last_error());
    }
    Ok(id)
}
fn creation(handle: HANDLE) -> Result<u64> {
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: query-only process handle and correctly sized output fields.
    if unsafe { GetProcessTimes(handle, &mut created, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err(last_error());
    }
    Ok((u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime))
}
pub(crate) fn observer_start_identity() -> Result<(u32, u64)> {
    // The pseudo handle pins this process; PID alone is never an exclusion identity.
    Ok((
        unsafe { GetCurrentProcessId() },
        creation(unsafe { GetCurrentProcess() })?,
    ))
}
fn image(handle: HANDLE) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    // SAFETY: query-only handle and bounded UTF-16 output buffer.
    if unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) } == 0 {
        return Err(last_error());
    }
    let path = PathBuf::from(OsString::from_wide(&buffer[..len as usize]));
    if !path.is_absolute() || path.file_name().is_none() {
        return Err(PlatformError::new(ErrorKind::Io));
    }
    Ok(path)
}
fn open(pid: u32, rights: u32) -> Result<Handle> {
    // SAFETY: no inheritance; rights supplied only by narrow internal call sites.
    let raw = unsafe { OpenProcess(rights, 0, pid) };
    if raw.is_null() {
        Err(last_error())
    } else {
        Ok(Handle(raw))
    }
}

/// Lists metadata without opening process memory. Other sessions/users are excluded.
/// Access-denied ownership remains explicitly unknown in `unavailable`.
pub fn enumerate_current_user() -> Result<ProcessInventory> {
    enumerate(None, &[], None)
}
pub(crate) fn enumerate_current_user_bounded(limit: usize) -> Result<ProcessInventory> {
    enumerate(None, &[], Some(limit))
}
pub(crate) fn observe_current_user(pid: u32) -> Result<Option<Process>> {
    if pid == 0 {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    observe(pid, None, session(unsafe { GetCurrentProcessId() })?)
}
fn observe(pid: u32, owner: Option<&str>, current_session: u32) -> Result<Option<Process>> {
    let target_session = session(pid)?;
    if owner.is_none() && target_session != current_session {
        return Ok(None);
    }
    let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE)?;
    if !same_owner(handle.0, owner)? {
        return Ok(None);
    }
    Ok(Some(Process {
        pid,
        image: image(handle.0)?,
        session_id: target_session,
        creation: creation(handle.0)?,
        handle,
        owner_sid: owner.map(str::to_owned),
    }))
}
/// Narrow candidates before opening ownership handles. Access denial for an
/// unrelated protected program must not block the selected application's scope.
/// Matching names still require owner, session and exact image-path validation.
pub fn enumerate_current_user_matches(names: &[String]) -> Result<ProcessInventory> {
    if names.is_empty() {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    enumerate(None, names, None)
}
/// Exact image plus creation-ordered descendants. Retained phase identities also
/// catch children whose parent has exited. A PID alone never admits an orphan.
pub fn enumerate_bound_tree(
    executable: &Path,
    retained: &[everyout_core_model::observation::ProcessBinding],
) -> Result<ProcessInventory> {
    let name = executable.file_name().and_then(|n| n.to_str())
        .ok_or_else(|| PlatformError::new(ErrorKind::ScopeViolation))?;
    let mut inventory = enumerate_current_user_matches(&[name.into()])?;
    inventory.processes.retain(|p| p.image_path().as_os_str().eq_ignore_ascii_case(executable.as_os_str()));
    if !inventory.unavailable.is_empty() { return Err(PlatformError::new(ErrorKind::Locked)); }
    for id in retained {
        match observe_current_user(id.pid) {
            Ok(Some(p)) if p.creation == id.creation_ticks => {
                if !inventory.processes.iter().any(|other| other.pid == p.pid) { inventory.processes.push(p); }
            }
            Ok(_) => {},
            Err(e) if matches!(e.os_code, Some(ERROR_INVALID_PARAMETER)) => {},
            Err(e) => return Err(e),
        }
    }
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE { return Err(last_error()); }
    let snapshot = Handle(raw);
    let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    let mut links = Vec::new();
    let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    while found != 0 {
        links.push((entry.th32ProcessID, entry.th32ParentProcessID));
        if links.len() > 32_768 { return Err(PlatformError::new(ErrorKind::Unsupported)); }
        found = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    if unsafe { GetLastError() } != ERROR_NO_MORE_FILES { return Err(last_error()); }
    loop {
        let mut added = false;
        for (pid, parent) in &links {
            if inventory.processes.iter().any(|p| p.pid == *pid) { continue; }
            let Some(parent) = inventory.processes.iter().find(|p| p.pid == *parent) else { continue; };
            let parent_start = parent.creation;
            match observe_current_user(*pid) {
                Ok(Some(p)) if p.creation > parent_start => { inventory.processes.push(p); added = true; },
                Ok(None) => return Err(PlatformError::new(ErrorKind::OwnershipConflict)),
                Ok(_) => {}, // older process: reused parent PID, unrelated child
                Err(e) if e.os_code == Some(ERROR_INVALID_PARAMETER) => {},
                Err(e) => return Err(e),
            }
        }
        if !added { break; }
        if inventory.processes.len() > 128 { return Err(PlatformError::new(ErrorKind::Unsupported)); }
    }
    Ok(inventory)
}
/// Helper-only metadata enumeration for one owner across sessions. Revalidation
/// pins SID, session, image and creation time. S6 desktop access is UNVERIFIED.
pub fn enumerate_account(profile: &crate::accounts::AccountProfile) -> Result<ProcessInventory> {
    profile.revalidate(&crate::accounts::NativeProfiles)?;
    enumerate(Some(profile.sid()), &[], None)
}
pub fn enumerate_account_matches(
    profile: &crate::accounts::AccountProfile,
    names: &[String],
) -> Result<ProcessInventory> {
    profile.revalidate(&crate::accounts::NativeProfiles)?;
    enumerate(Some(profile.sid()), names, None)
}
fn enumerate(
    owner: Option<&str>,
    names: &[String],
    limit: Option<usize>,
) -> Result<ProcessInventory> {
    // SAFETY: snapshot requests only process entries, no modules/heaps/threads.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(last_error());
    }
    let snapshot = Handle(raw);
    // SAFETY: current-process ID query has no arguments or side effects.
    let current_session = session(unsafe { GetCurrentProcessId() })?;
    let mut inventory = ProcessInventory {
        processes: Vec::new(),
        unavailable: Vec::new(),
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    // SAFETY: snapshot handle is live; output structure declares its correct size.
    let mut found = unsafe { Process32FirstW(snapshot.0, &mut entry) };
    let mut attempted = 0;
    loop {
        if found == 0 {
            let e = last_error();
            if e.os_code != Some(ERROR_NO_MORE_FILES) {
                return Err(e);
            }
            break;
        }
        let pid = entry.th32ProcessID;
        let length = entry
            .szExeFile
            .iter()
            .position(|c| *c == 0)
            .unwrap_or(entry.szExeFile.len());
        let candidate = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if pid != 0
            && (names.is_empty() || names.iter().any(|n| n.eq_ignore_ascii_case(&candidate)))
        {
            if limit.is_some_and(|limit| attempted >= limit) {
                inventory
                    .unavailable
                    .push((0, PlatformError::new(ErrorKind::Unsupported)));
                break;
            }
            attempted += 1;
            let observed = observe(pid, owner, current_session);
            match observed {
                Ok(Some(p)) => inventory.processes.push(p),
                Ok(None) => {}
                Err(e) => inventory.unavailable.push((pid, e)),
            }
        }
        // SAFETY: same live snapshot and output buffer as above.
        found = unsafe { Process32NextW(snapshot.0, &mut entry) };
    }
    Ok(inventory)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessCloseStatus {
    WouldClose,
    ClosedGracefully,
    Killed,
    StillRunning,
    Failed,
    AccessDenied,
}
#[derive(Debug)]
pub struct ProcessCloseResult {
    pub pid: u32,
    pub status: ProcessCloseStatus,
    pub error: Option<PlatformError>,
    pub windows_requested: usize,
    pub force_after: Option<Duration>,
}
pub struct ProcessCloseReport {
    pub results: Vec<ProcessCloseResult>,
    /// Indices into the caller's explicit selection, including unknown liveness.
    pub remaining: Vec<usize>,
}
fn validate(process: &Process, handle: HANDLE) -> Result<()> {
    // SAFETY: process-ID query only.
    if process.pid == unsafe { GetCurrentProcessId() } {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    if creation(process.handle.0)? != process.creation || creation(handle)? != process.creation
        || image(handle)? != process.image || !same_owner(handle, process.owner_sid.as_deref())?
        || session(process.pid)? != process.session_id
        // SAFETY: current-process ID query only.
        || (process.owner_sid.is_none() && process.session_id != session(unsafe { GetCurrentProcessId() })?)
    {
        return Err(PlatformError::new(ErrorKind::StalePlan));
    }
    Ok(())
}
fn exited(handle: HANDLE, timeout: u32) -> Result<bool> {
    // SAFETY: wait right is held; wait only observes process exit.
    match unsafe { WaitForSingleObject(handle, timeout) } {
        WAIT_OBJECT_0 => Ok(true),
        WAIT_TIMEOUT => Ok(false),
        _ => Err(last_error()),
    }
}
struct Windows {
    pid: u32,
    items: Vec<HWND>,
    overflow: bool,
}
unsafe extern "system" fn collect(hwnd: HWND, parameter: LPARAM) -> i32 {
    // SAFETY: EnumWindows is synchronous with exclusive access to the stack state.
    let state = unsafe { &mut *(parameter as *mut Windows) };
    let mut pid = 0;
    // SAFETY: writable PID output; no window contents are read.
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
    }
    if pid == state.pid {
        if state.items.len() == 1024 {
            state.overflow = true;
            return 0;
        }
        state.items.push(hwnd);
    }
    1
}
fn request(
    process: &Process,
    handle: HANDLE,
    count: &mut usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<Instant> {
    let mut state = Windows {
        pid: process.pid,
        items: Vec::new(),
        overflow: false,
    };
    // SAFETY: synchronous callback receives a live, exclusive state pointer.
    if unsafe { EnumWindows(Some(collect), (&mut state as *mut Windows) as LPARAM) } == 0 {
        return Err(if state.overflow {
            PlatformError::new(ErrorKind::Unsupported)
        } else {
            last_error()
        });
    }
    let mut first_request = None;
    for hwnd in state.items {
        if cancelled() {
            return Err(PlatformError::new(ErrorKind::Cancelled));
        }
        if exited(handle, 0)? {
            break;
        }
        validate(process, handle)?;
        let mut pid = 0;
        // SAFETY: metadata query only; recheck HWND owner immediately before posting.
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut pid);
        }
        if pid != process.pid {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        // SAFETY: exact checked top-level window, pointer-free asynchronous WM_CLOSE.
        if unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) } == 0 {
            let error = last_error();
            // A window may be destroyed after EnumWindows/owner validation, for
            // example when an earlier WM_CLOSE shuts down the same application.
            // Treat only this disappearance as a stale observation; other API
            // failures still block dependent cleanup.
            if error.os_code == Some(ERROR_INVALID_WINDOW_HANDLE) {
                if exited(handle, 0)? {
                    break;
                }
                continue;
            }
            return Err(error);
        }
        first_request.get_or_insert_with(Instant::now);
        *count += 1;
    }
    // UNVERIFIED S6: EnumWindows may expose no windows in a foreign session.
    // As for current-session no-window processes, Ask never escalates; the
    // explicitly approved HardKillAfter2s policy still waits the full interval.
    Ok(first_request.unwrap_or_else(Instant::now))
}
fn close_one(
    process: &Process,
    policy: ProcessClosePolicy,
    dry_run: bool,
    result: &mut ProcessCloseResult,
    cancelled: &dyn Fn() -> bool,
) -> Result<ProcessCloseStatus> {
    if cancelled() {
        return Err(PlatformError::new(ErrorKind::Cancelled));
    }
    // Closing the main process can exit several retained helpers. Observe the
    // original kernel object before reopening a PID that may already be gone.
    if exited(process.handle.0, 0)? {
        return Ok(ProcessCloseStatus::ClosedGracefully);
    }
    let handle = open(
        process.pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
    )?;
    validate(process, handle.0)?;
    if exited(handle.0, 0)? {
        return Ok(ProcessCloseStatus::ClosedGracefully);
    }
    if dry_run {
        return Ok(ProcessCloseStatus::WouldClose);
    }
    let start = request(process, handle.0, &mut result.windows_requested, cancelled)?;
    loop {
        let remaining = GRACE.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            break;
        }
        // Round up: monotonic deadline is also checked after every OS timeout.
        if exited(handle.0, remaining.as_millis().saturating_add(1) as u32)? {
            return Ok(ProcessCloseStatus::ClosedGracefully);
        }
    }
    if exited(handle.0, 0)? {
        return Ok(ProcessCloseStatus::ClosedGracefully);
    }
    if policy == ProcessClosePolicy::Ask {
        return Ok(ProcessCloseStatus::StillRunning);
    }
    if cancelled() {
        return Err(PlatformError::new(ErrorKind::Cancelled));
    }
    // Terminate rights are acquired only after the grace deadline, never for preview/Ask.
    let kill = open(
        process.pid,
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_SYNCHRONIZE,
    )?;
    validate(process, kill.0)?;
    if exited(kill.0, 0)? {
        return Ok(ProcessCloseStatus::ClosedGracefully);
    }
    result.force_after = Some(start.elapsed());
    if cancelled() {
        return Err(PlatformError::new(ErrorKind::Cancelled));
    }
    // SAFETY: exact retained identity, same owner/session, explicit force policy only.
    if unsafe { TerminateProcess(kill.0, 1) } == 0 {
        return Err(last_error());
    }
    if exited(kill.0, EXIT_WAIT)? {
        Ok(ProcessCloseStatus::Killed)
    } else {
        Err(error(WAIT_TIMEOUT))
    }
}

/// Closes only explicit, reviewed inventory identities. Failures never widen selection.
/// Ask observes for two seconds, then returns survivors without terminating them.
/// Each identity has its own grace deadline; batches currently execute sequentially.
/// dry_run performs identity checks only: no messages, sleep, termination or restart.
pub fn close_processes(
    selected: &[&Process],
    policy: ProcessClosePolicy,
    dry_run: bool,
) -> ProcessCloseReport {
    close_processes_with_cancellation(selected, policy, dry_run, &|| false)
}
/// Helper lifetime/pipe cancellation is rechecked before every graceful request
/// and force effect, not merely once before a potentially long process batch.
pub fn close_processes_with_cancellation(
    selected: &[&Process],
    policy: ProcessClosePolicy,
    dry_run: bool,
    cancelled: &dyn Fn() -> bool,
) -> ProcessCloseReport {
    let mut report = ProcessCloseReport {
        results: Vec::new(),
        remaining: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for (index, process) in selected.iter().enumerate() {
        let mut result = ProcessCloseResult {
            pid: process.pid,
            status: ProcessCloseStatus::Failed,
            error: None,
            windows_requested: 0,
            force_after: None,
        };
        let outcome = if seen.insert((process.pid, process.creation)) {
            close_one(process, policy, dry_run, &mut result, cancelled)
        } else {
            Err(PlatformError::new(ErrorKind::ScopeViolation))
        };
        match outcome {
            Ok(status) => result.status = status,
            Err(e) => {
                result.status = if e.kind == ErrorKind::AccessDenied {
                    ProcessCloseStatus::AccessDenied
                } else {
                    ProcessCloseStatus::Failed
                };
                result.error = Some(e);
            }
        }
        if !matches!(
            result.status,
            ProcessCloseStatus::ClosedGracefully | ProcessCloseStatus::Killed
        ) {
            report.remaining.push(index);
        }
        report.results.push(result);
    }
    report
}
