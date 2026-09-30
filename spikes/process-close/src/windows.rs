use everyout_process_close::{Method, Options};
use serde::Serialize;
use std::{ptr, time::Instant};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_MORE_DATA, FILETIME, HANDLE, HWND, LPARAM, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{EqualSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser},
    System::{RemoteDesktop::ProcessIdToSessionId, RestartManager::*, Threading::*},
    UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, PostMessageW, WM_CLOSE},
};
struct Handle(HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Session(u32);
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            RmEndSession(self.0);
        }
    }
}
fn times(handle: HANDLE) -> Result<FILETIME, &'static str> {
    let (mut creation, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    // SAFETY: borrowed process handle and valid output fields.
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        return Err("process time unavailable");
    }
    Ok(creation)
}
fn equal_time(a: FILETIME, b: FILETIME) -> bool {
    a.dwLowDateTime == b.dwLowDateTime && a.dwHighDateTime == b.dwHighDateTime
}
fn token_user(process: HANDLE) -> Result<Vec<usize>, &'static str> {
    let mut raw = ptr::null_mut();
    // SAFETY: valid process handle; token query only.
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut raw) } == 0 {
        return Err("owner unavailable");
    }
    let token = Handle(raw);
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 64 * 1024 {
        return Err("owner size invalid");
    }
    // usize allocation supplies alignment for TOKEN_USER and its embedded SID.
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
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
        return Err("owner query failed");
    }
    Ok(buffer)
}
fn identity(handle: HANDLE, options: &Options, creation: FILETIME) -> Result<(), &'static str> {
    if !equal_time(times(handle)?, creation)
        || unsafe { WaitForSingleObject(handle, 0) } != WAIT_TIMEOUT
    {
        return Err("process exited or identity changed");
    }
    let mut image = [0u16; 32768];
    let mut len = image.len() as u32;
    if unsafe { QueryFullProcessImageNameW(handle, 0, image.as_mut_ptr(), &mut len) } == 0 {
        return Err("image unavailable");
    }
    let image = String::from_utf16(&image[..len as usize]).map_err(|_| "invalid image encoding")?;
    if !image
        .rsplit(['/', '\\'])
        .next()
        .is_some_and(|name| name.eq_ignore_ascii_case(&options.image))
    {
        return Err("image mismatch");
    }
    let (mut target_session, mut current_session) = (0, 0);
    if unsafe { ProcessIdToSessionId(options.pid, &mut target_session) } == 0
        || unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut current_session) } == 0
        || target_session != current_session
    {
        return Err("cross-session or unknown session refused");
    }
    let target = token_user(handle)?;
    let current = token_user(unsafe { GetCurrentProcess() })?;
    // SAFETY: aligned token buffers remain live; TokenUser returns valid SID pointers.
    let same = unsafe {
        EqualSid(
            (*(target.as_ptr().cast::<TOKEN_USER>())).User.Sid,
            (*(current.as_ptr().cast::<TOKEN_USER>())).User.Sid,
        )
    };
    if same == 0 {
        return Err("cross-user process refused");
    }
    Ok(())
}
struct Windows {
    pid: u32,
    items: Vec<HWND>,
    overflow: bool,
}
unsafe extern "system" fn collect(hwnd: HWND, parameter: LPARAM) -> i32 {
    // SAFETY: EnumWindows receives a unique live pointer for this synchronous call.
    let state = unsafe { &mut *(parameter as *mut Windows) };
    let mut pid = 0;
    unsafe {
        GetWindowThreadProcessId(hwnd, &mut pid);
    }
    if pid == state.pid {
        if state.items.len() >= 1024 {
            state.overflow = true;
            return 0;
        }
        state.items.push(hwnd);
    }
    1
}
fn wm_close(
    handle: HANDLE,
    options: &Options,
    creation: FILETIME,
) -> Result<(u32, Instant), &'static str> {
    let mut state = Windows {
        pid: options.pid,
        items: Vec::new(),
        overflow: false,
    };
    if unsafe { EnumWindows(Some(collect), (&mut state as *mut Windows) as LPARAM) } == 0
        || state.overflow
    {
        return Err("window enumeration failed");
    }
    if state.items.is_empty() {
        return Err("no top-level windows");
    }
    let mut sent = 0;
    let mut first_request = None;
    for hwnd in state.items {
        // An earlier posted request may already have closed the pinned process.
        if unsafe { WaitForSingleObject(handle, 0) } == WAIT_OBJECT_0 {
            break;
        }
        identity(handle, options, creation)?;
        let mut pid = 0;
        unsafe {
            GetWindowThreadProcessId(hwnd, &mut pid);
        }
        if pid != options.pid {
            return Err("window owner changed");
        }
        // Asynchronous WM_CLOSE leaves application prompts/cancellation to the app.
        if unsafe { PostMessageW(hwnd, WM_CLOSE, 0, 0) } == 0 {
            return Err("window request failed");
        }
        first_request.get_or_insert_with(Instant::now);
        sent += 1;
    }
    Ok((sent, first_request.unwrap_or_else(Instant::now)))
}
fn restart_manager(
    handle: HANDLE,
    options: &Options,
    creation: FILETIME,
) -> Result<u32, &'static str> {
    let mut session_id = 0;
    let mut key = [0u16; 33];
    if unsafe { RmStartSession(&mut session_id, 0, key.as_mut_ptr()) } != 0 {
        return Err("Restart Manager start failed");
    }
    let session = Session(session_id);
    let unique = RM_UNIQUE_PROCESS {
        dwProcessId: options.pid,
        ProcessStartTime: creation,
    };
    if unsafe { RmRegisterResources(session.0, 0, ptr::null(), 1, &unique, 0, ptr::null()) } != 0 {
        return Err("Restart Manager registration failed");
    }
    let (mut needed, mut count, mut reboot) = (0, 0, 0);
    let status = unsafe {
        RmGetList(
            session.0,
            &mut needed,
            &mut count,
            ptr::null_mut(),
            &mut reboot,
        )
    };
    if ![0, ERROR_MORE_DATA].contains(&status) || needed == 0 || needed > 32 {
        return Err("Restart Manager affected set unavailable");
    }
    let mut list = vec![RM_PROCESS_INFO::default(); needed as usize];
    count = needed;
    if unsafe {
        RmGetList(
            session.0,
            &mut needed,
            &mut count,
            list.as_mut_ptr(),
            &mut reboot,
        )
    } != 0
        || reboot != 0
        || count != 1
    {
        return Err("Restart Manager affected set refused");
    }
    let affected = &list[0];
    if affected.Process.dwProcessId != options.pid
        || !equal_time(affected.Process.ProcessStartTime, creation)
        || affected.strServiceShortName[0] != 0
    {
        return Err("Restart Manager unrelated owner refused");
    }
    identity(handle, options, creation)?;
    // Register only this unique process; no files/services, force flag or automatic restart.
    // This call is synchronous and may exceed the subsequent observation interval.
    Ok(unsafe { RmShutdown(session.0, 0, None) })
}
#[derive(Serialize)]
struct Outcome {
    schema_version: u32,
    pid: u32,
    method: &'static str,
    request_ms: u128,
    elapsed_ms: u128,
    api_status: u32,
    windows_requested: u32,
    escalated: bool,
    escalation_ms: Option<u128>,
    grace_ms_before_force: Option<u128>,
    outcome: &'static str,
    resource_release: &'static str,
}
pub fn close(options: &Options) -> Result<(String, bool), &'static str> {
    if options.pid == unsafe { GetCurrentProcessId() } {
        return Err("self close refused");
    }
    let access = PROCESS_QUERY_LIMITED_INFORMATION
        | PROCESS_SYNCHRONIZE
        | if options.method == Method::Force || options.hard_kill {
            PROCESS_TERMINATE
        } else {
            0
        };
    let raw = unsafe { OpenProcess(access, 0, options.pid) };
    if raw.is_null() {
        return Err("process access denied or absent");
    }
    let handle = Handle(raw);
    let creation = times(handle.0)?;
    identity(handle.0, options, creation)?;
    let start = Instant::now();
    let mut grace_start = start;
    let mut windows_requested = 0;
    let api_status = match options.method {
        Method::WmClose => {
            (windows_requested, grace_start) = wm_close(handle.0, options, creation)?;
            0
        }
        Method::RestartManager => restart_manager(handle.0, options, creation)?,
        Method::Force => {
            identity(handle.0, options, creation)?;
            if unsafe { TerminateProcess(handle.0, 1) } == 0 {
                return Err("termination failed");
            }
            0
        }
    };
    let request_ms = start.elapsed().as_millis();
    let timeout = if options.hard_kill {
        2000u128.saturating_sub(grace_start.elapsed().as_millis()) as u32
    } else {
        5000
    };
    let mut wait = unsafe { WaitForSingleObject(handle.0, timeout) };
    let mut escalated = false;
    let mut escalation_ms = None;
    let mut grace_ms_before_force = None;
    // Check monotonic time too: an OS timeout alone is not evidence of a full grace interval.
    while wait == WAIT_TIMEOUT && options.hard_kill && grace_start.elapsed().as_millis() < 2000 {
        let remaining = 2000 - grace_start.elapsed().as_millis().min(1999);
        wait = unsafe { WaitForSingleObject(handle.0, remaining as u32) };
    }
    if wait == WAIT_TIMEOUT && options.hard_kill {
        identity(handle.0, options, creation)?;
        escalation_ms = Some(start.elapsed().as_millis());
        grace_ms_before_force = Some(grace_start.elapsed().as_millis());
        if unsafe { TerminateProcess(handle.0, 1) } == 0 {
            return Err("escalation failed");
        }
        escalated = true;
        wait = unsafe { WaitForSingleObject(handle.0, 5000) };
    }
    let exited = wait == WAIT_OBJECT_0;
    let outcome = Outcome {
        schema_version: 1,
        pid: options.pid,
        method: match options.method {
            Method::WmClose => "wm-close",
            Method::RestartManager => "restart-manager",
            Method::Force => "force",
        },
        request_ms,
        elapsed_ms: start.elapsed().as_millis(),
        api_status,
        windows_requested,
        escalated,
        escalation_ms,
        grace_ms_before_force,
        outcome: if exited {
            "exited"
        } else if wait == WAIT_TIMEOUT {
            "still_running"
        } else {
            "wait_failed"
        },
        resource_release: "unverified; no wipe permitted",
    };
    Ok((
        serde_json::to_string_pretty(&outcome).map_err(|_| "serialization failed")?,
        exited,
    ))
}
