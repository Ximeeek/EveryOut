//! Official Windows bindings; S6 runtime validation is still pending.
//! Only identity metadata and the fixed helper executable are read here.
use crate::{protocol::*, *};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsStr,
    fs::File,
    io::Read,
    mem::{size_of, zeroed},
    os::windows::ffi::OsStrExt,
    os::windows::fs::OpenOptionsExt,
    path::Path,
    ptr, thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::*,
    System::{Com::*, Pipes::*, Threading::*},
    UI::{Shell::*, WindowsAndMessaging::SW_HIDE},
};

struct Handle(HANDLE);
impl Handle {
    fn new(raw: HANDLE) -> Result<Self, LaunchFailure> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            Err(LaunchFailure::StartFailed)
        } else {
            Ok(Self(raw))
        }
    }
    fn alive(&self) -> bool {
        // SAFETY: owned process handle opened with SYNCHRONIZE, zero-time poll.
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_TIMEOUT }
    }
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: exactly one owner of a valid native handle.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Local(*mut std::ffi::c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: only allocations returned by LocalAlloc-backed APIs.
        unsafe {
            LocalFree(self.0);
        }
    }
}
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
fn open_process(pid: u32) -> Result<Handle, LaunchFailure> {
    // SAFETY: metadata and lifetime access only, no memory or mutation rights.
    Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) })
}
fn token_buffer(
    token: &Handle,
    class: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<usize>, LaunchFailure> {
    let mut needed = 0;
    // SAFETY: required-size query; aligned allocation below.
    unsafe {
        GetTokenInformation(token.0, class, ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 || needed > 65536 {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let mut data = vec![0usize; (needed as usize).div_ceil(size_of::<usize>())];
    // SAFETY: buffer covers requested bytes and has native alignment.
    if unsafe {
        GetTokenInformation(
            token.0,
            class,
            data.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    Ok(data)
}
fn identity(process: &Handle, pid: u32) -> Result<Peer, LaunchFailure> {
    let mut raw = ptr::null_mut();
    // SAFETY: query-only token for the retained process handle.
    if unsafe { OpenProcessToken(process.0, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let token = Handle::new(raw)?;
    let user = token_buffer(&token, TokenUser)?;
    let stats = token_buffer(&token, TokenStatistics)?;
    let session = token_buffer(&token, TokenSessionId)?;
    let mut sid = ptr::null_mut();
    // SAFETY: TokenUser layout and SID allocation remain alive during conversion.
    if unsafe { ConvertSidToStringSidW((*(user.as_ptr().cast::<TOKEN_USER>())).User.Sid, &mut sid) }
        == 0
    {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let allocation = Local(sid.cast());
    let mut length = 0;
    // SAFETY: OS-produced null-terminated SID string.
    while unsafe { *sid.add(length) } != 0 {
        length += 1;
    }
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid, length) })
        .map_err(|_| LaunchFailure::AuthenticationFailed)?;
    drop(allocation);
    // SAFETY: successful token queries returned these fixed layouts.
    let logon = unsafe { (*(stats.as_ptr().cast::<TOKEN_STATISTICS>())).AuthenticationId };
    let session = unsafe { *session.as_ptr().cast::<u32>() };
    Ok(Peer {
        sid,
        logon: (logon.LowPart, logon.HighPart),
        session,
        pid,
    })
}
fn random_nonce() -> Result<String, LaunchFailure> {
    let mut bytes = [0u8; 32];
    // SAFETY: fixed output buffer, Windows system-preferred CSPRNG.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            bytes.as_mut_ptr(),
            32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err(LaunchFailure::StartFailed);
    }
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn pipe_name(nonce: &str) -> Vec<u16> {
    wide(format!(r"\\.\pipe\EveryOut-{nonce}"))
}

fn server(nonce: &str, peer: &Peer) -> Result<Handle, LaunchFailure> {
    // Specific read/write rights omit FILE_CREATE_PIPE_INSTANCE (generic write
    // would grant that alias). BA permits over-the-shoulder administrator consent.
    let sddl = wide(format!(
        "D:P(A;;0x00120183;;;{})(A;;0x00120183;;;BA)",
        peer.sid
    ));
    let mut descriptor = ptr::null_mut();
    // SAFETY: OS SID text, fixed SDDL grammar and out pointer.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(LaunchFailure::StartFailed);
    }
    let allocation = Local(descriptor);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: explicit DACL, one instance, first-instance and remote-client denial.
    let pipe = Handle::new(unsafe {
        CreateNamedPipeW(
            pipe_name(nonce).as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            MAX_FRAME as u32,
            MAX_FRAME as u32,
            0,
            &attributes,
        )
    });
    drop(allocation);
    pipe
}
fn write(pipe: &Handle, frame: &[u8]) -> Result<(), LaunchFailure> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let mut written = 0;
    // SAFETY: nonblocking message pipe, bounded initialized input.
    if unsafe {
        WriteFile(
            pipe.0,
            frame.as_ptr(),
            frame.len() as u32,
            &mut written,
            ptr::null_mut(),
        )
    } == 0
        || written as usize != frame.len()
    {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    Ok(())
}
fn read(pipe: &Handle) -> Result<Option<Vec<u8>>, LaunchFailure> {
    let mut frame = vec![0; MAX_FRAME];
    let mut read = 0;
    // SAFETY: nonblocking pipe with initialized bounded buffer. MORE_DATA is a
    // protocol violation, never joined into an unbounded allocation.
    if unsafe {
        ReadFile(
            pipe.0,
            frame.as_mut_ptr(),
            MAX_FRAME as u32,
            &mut read,
            ptr::null_mut(),
        )
    } == 0
    {
        // SAFETY: capture this call's thread-local error immediately.
        let error = unsafe { GetLastError() };
        if error == ERROR_NO_DATA {
            // Distinguish an empty connected pipe from a lost endpoint.
            if unsafe {
                PeekNamedPipe(
                    pipe.0,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } != 0
            {
                return Ok(None);
            }
        }
        return Err(LaunchFailure::AuthenticationFailed);
    }
    if read == 0 {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    frame.truncate(read as usize);
    Ok(Some(frame))
}
fn pause() {
    thread::sleep(Duration::from_millis(10));
}

/// Authenticated client holds the actual ShellExecute process handle and file
/// locks. The digest must come from reviewed host/distribution code, never UI or IPC.
pub struct Client {
    pipe: Option<Handle>,
    helper: Handle,
    _installation: Vec<File>,
    run: String,
    next: u64,
}
impl Client {
    pub fn request(&mut self, command: Command) -> Result<Response, LaunchFailure> {
        let request = Request {
            version: VERSION,
            run: self.run.clone(),
            sequence: self.next,
            nonce: String::new(),
            command,
        };
        let result = self.exchange(request);
        if result.is_err() {
            self.pipe.take();
        }
        result
    }
    fn exchange(&mut self, request: Request) -> Result<Response, LaunchFailure> {
        let timeout = if matches!(
            request.command,
            Command::Plan { .. } | Command::PlanAccounts { .. } | Command::Execute { .. }
        ) {
            MAX_LIFETIME
        } else {
            IDLE_TIMEOUT
        };
        let frame = encode(&request).map_err(|_| LaunchFailure::AuthenticationFailed)?;
        let pipe = self
            .pipe
            .as_ref()
            .ok_or(LaunchFailure::AuthenticationFailed)?;
        write(pipe, &frame)?;
        let start = Instant::now();
        loop {
            if start.elapsed() >= timeout {
                return Err(LaunchFailure::Timeout);
            }
            if let Some(frame) = read(pipe)? {
                let response: Response = serde_json::from_slice(&frame)
                    .map_err(|_| LaunchFailure::AuthenticationFailed)?;
                if response.version != VERSION || response.sequence != self.next {
                    return Err(LaunchFailure::AuthenticationFailed);
                }
                self.next += 1;
                if response.status == Status::Finished {
                    self.pipe.take();
                }
                return Ok(response);
            }
            if !self.helper.alive() {
                return Err(LaunchFailure::AuthenticationFailed);
            }
            pause();
        }
    }
}

fn lock_installation(path: &Path, expected_digest: &[u8; 32]) -> Result<Vec<File>, LaunchFailure> {
    let mut locks = Vec::new();
    // Lock every ancestor against rename/delete and reject all reparse points.
    for ancestor in path
        .ancestors()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
    {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(ancestor)
            .map_err(|_| LaunchFailure::StartFailed)?;
        use std::os::windows::fs::MetadataExt;
        if file
            .metadata()
            .map_err(|_| LaunchFailure::StartFailed)?
            .file_attributes()
            & FILE_ATTRIBUTE_REPARSE_POINT
            != 0
        {
            return Err(LaunchFailure::StartFailed);
        }
        locks.push(file);
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|_| LaunchFailure::StartFailed)?;
    use std::os::windows::fs::MetadataExt;
    if file
        .metadata()
        .map_err(|_| LaunchFailure::StartFailed)?
        .file_attributes()
        & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
        != 0
    {
        return Err(LaunchFailure::StartFailed);
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 16384];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LaunchFailure::StartFailed)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    if hash.finalize().as_slice() != expected_digest {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    locks.push(file);
    Ok(locks)
}

pub fn launch(
    mode: AccountMode,
    privileged_work_needed: bool,
    expected_helper_digest: [u8; 32],
) -> LaunchOutcome<Client> {
    launch_on_demand(mode, privileged_work_needed, || {
        start(expected_helper_digest)
    })
}
fn start(expected_digest: [u8; 32]) -> Result<Client, LaunchFailure> {
    let current = std::env::current_exe().map_err(|_| LaunchFailure::StartFailed)?;
    let path = current
        .parent()
        .ok_or(LaunchFailure::StartFailed)?
        .join("everyout-elevated-helper.exe");
    let locks = lock_installation(&path, &expected_digest)?;
    let nonce = random_nonce()?;
    // SAFETY: current process ID is metadata, not a privileged operation.
    let parent = unsafe { GetCurrentProcessId() };
    let file = wide(&path);
    let verb = wide("runas");
    let parameters = wide(format!("{parent} {nonce}"));
    // SAFETY: zeroed POD, initialized size/flags and live UTF-16 strings.
    let mut info: SHELLEXECUTEINFOW = unsafe { zeroed() };
    info.cbSize = size_of::<SHELLEXECUTEINFOW>() as u32;
    info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
    info.lpVerb = verb.as_ptr();
    info.lpFile = file.as_ptr();
    info.lpParameters = parameters.as_ptr();
    info.nShow = SW_HIDE;
    struct Apartment;
    impl Drop for Apartment {
        fn drop(&mut self) {
            // SAFETY: balanced successful initialization on the same thread.
            unsafe {
                CoUninitialize();
            }
        }
    }
    // The host should call the synchronous launcher on its own STA worker.
    // Fail closed if a conflicting apartment is already active on this thread.
    if unsafe {
        CoInitializeEx(
            ptr::null(),
            (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
        )
    } < 0
    {
        return Err(LaunchFailure::StartFailed);
    }
    let _apartment = Apartment;
    // SAFETY: fixed absolute binary, no shell/user command fragments.
    if unsafe { ShellExecuteExW(&mut info) } == 0 {
        return Err(if unsafe { GetLastError() } == ERROR_CANCELLED {
            LaunchFailure::UacDeclined
        } else {
            LaunchFailure::StartFailed
        });
    }
    let helper = Handle::new(info.hProcess)?;
    // SAFETY: actual retained launch process handle, not a supplied PID.
    let helper_pid = unsafe { GetProcessId(helper.0) };
    let start = Instant::now();
    let pipe = loop {
        if !helper.alive() {
            return Err(LaunchFailure::StartFailed);
        }
        if start.elapsed() >= IDLE_TIMEOUT {
            return Err(LaunchFailure::Timeout);
        }
        // SAFETY: local fixed nonce-derived pipe name; no generic-write alias.
        let raw = unsafe {
            CreateFileW(
                pipe_name(&nonce).as_ptr(),
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if raw != INVALID_HANDLE_VALUE {
            break Handle::new(raw)?;
        }
        pause();
    };
    let mut server_pid = 0;
    // SAFETY: query the actual connected server endpoint.
    if unsafe { GetNamedPipeServerProcessId(pipe.0, &mut server_pid) } == 0
        || server_pid != helper_pid
    {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
    // SAFETY: owned message pipe, bounded nonblocking mode.
    if unsafe { SetNamedPipeHandleState(pipe.0, &mode, ptr::null(), ptr::null()) } == 0 {
        return Err(LaunchFailure::StartFailed);
    }
    let mut client = Client {
        pipe: Some(pipe),
        helper,
        _installation: locks,
        run: nonce.clone(),
        next: 0,
    };
    let response = client.exchange(Request {
        version: VERSION,
        run: nonce.clone(),
        sequence: 0,
        nonce,
        command: Command::Report,
    })?;
    if response.status != Status::Authenticated {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    Ok(client)
}

pub(super) fn serve() -> Result<(), LaunchFailure> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 2 || !nonce_valid(&args[1]) {
        return Err(LaunchFailure::StartFailed);
    }
    let pid: u32 = args[0].parse().map_err(|_| LaunchFailure::StartFailed)?;
    let parent = open_process(pid)?;
    let peer = identity(&parent, pid)?;
    let nonce = &args[1];
    // Direct unelevated invocation must never masquerade as a helper.
    let current = open_process(unsafe { GetCurrentProcessId() })?;
    let mut raw = ptr::null_mut();
    // SAFETY: current retained process token, query-only access.
    if unsafe { OpenProcessToken(current.0, TOKEN_QUERY, &mut raw) } == 0 {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let token = Handle::new(raw)?;
    let elevation = token_buffer(&token, TokenElevation)?;
    if unsafe { (*(elevation.as_ptr().cast::<TOKEN_ELEVATION>())).TokenIsElevated } == 0 {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    let pipe = server(nonce, &peer)?;
    let start = Instant::now();
    let cancellation_parent = open_process(pid)?;
    let mut cancellation_pipe = ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            pipe.0,
            GetCurrentProcess(),
            &mut cancellation_pipe,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(LaunchFailure::StartFailed);
    }
    let cancellation_pipe = Handle::new(cancellation_pipe)?;
    let cancelled = Box::new(move || {
        !cancellation_parent.alive()
            || start.elapsed() >= MAX_LIFETIME
            || unsafe {
                PeekNamedPipe(
                    cancellation_pipe.0,
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            } == 0
    });
    let mut session = Session::new(peer.clone(), nonce.clone())
        .map_err(|_| LaunchFailure::StartFailed)?
        .with_backend(Box::new(crate::accounts::NativeAccounts::new(cancelled)));
    loop {
        if session.expired(start.elapsed(), parent.alive()) {
            return Ok(());
        }
        // SAFETY: nonblocking connection, no async pointer retained.
        let connected = unsafe { ConnectNamedPipe(pipe.0, ptr::null_mut()) };
        let error = unsafe { GetLastError() };
        // In NOWAIT mode first success can mean merely entering listening state.
        let mut connected_pid = 0;
        if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut connected_pid) } != 0 {
            break;
        }
        if connected == 0
            && error != ERROR_PIPE_LISTENING
            && error != ERROR_NO_DATA
            && error != ERROR_PIPE_CONNECTED
        {
            return Err(LaunchFailure::AuthenticationFailed);
        }
        pause();
    }
    let mut client_pid = 0;
    // SAFETY: endpoint metadata, independently authenticated against retained parent.
    if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut client_pid) } == 0
        || client_pid != pid
        || identity(&parent, pid)? != peer
    {
        return Err(LaunchFailure::AuthenticationFailed);
    }
    loop {
        if session.expired(start.elapsed(), parent.alive()) {
            return Ok(());
        }
        if let Some(frame) = read(&pipe)? {
            let response = session
                .receive(&frame, &peer, start.elapsed(), parent.alive())
                .map_err(|_| LaunchFailure::AuthenticationFailed)?;
            session.completed_at(start.elapsed());
            write(
                &pipe,
                &encode(&response).map_err(|_| LaunchFailure::AuthenticationFailed)?,
            )?;
            if response.status == Status::Finished {
                // Let the client consume the final reply before closing the pipe;
                // its Finish response handler disconnects immediately after read.
                let finish = Instant::now();
                while parent.alive()
                    && finish.elapsed() < IDLE_TIMEOUT
                    && start.elapsed() < MAX_LIFETIME
                {
                    match read(&pipe) {
                        Ok(None) => pause(),
                        _ => break,
                    }
                }
                return Ok(());
            }
        }
        pause();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn binary_pin_and_retained_locks_reject_synthetic_replacement() {
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("helper.exe");
        let content = b"synthetic executable fixture; no account data";
        std::fs::write(&path, content).unwrap();
        let digest: [u8; 32] = Sha256::digest(content).into();
        assert!(matches!(
            lock_installation(&path, &[0; 32]),
            Err(LaunchFailure::AuthenticationFailed)
        ));
        let locks = lock_installation(&path, &digest).unwrap();
        assert!(std::fs::write(&path, b"replacement").is_err());
        assert!(std::fs::rename(&path, fixture.path().join("replacement.exe")).is_err());
        drop(locks);
        std::fs::write(&path, b"replacement").unwrap();
        assert!(matches!(
            lock_installation(&path, &digest),
            Err(LaunchFailure::AuthenticationFailed)
        ));
    }
    #[test]
    fn native_current_mode_never_reaches_binary_or_uac() {
        for (mode, needed) in [
            (AccountMode::Current, true),
            (AccountMode::AllAccounts, false),
        ] {
            assert!(matches!(
                launch(mode, needed, [0; 32]),
                LaunchOutcome::CurrentAccount
            ));
        }
    }
    #[test]
    fn local_named_pipe_authenticates_real_endpoint_without_elevation() {
        // Only the test process token and a random private pipe; no profile I/O/UAC.
        let pid = unsafe { GetCurrentProcessId() };
        let peer = identity(&open_process(pid).unwrap(), pid).unwrap();
        let nonce = random_nonce().unwrap();
        let (ready, wait) = std::sync::mpsc::channel();
        let (done, received) = std::sync::mpsc::channel();
        let server_nonce = nonce.clone();
        let server_peer = peer.clone();
        let helper = thread::spawn(move || {
            let pipe = server(&server_nonce, &server_peer).unwrap();
            ready.send(()).unwrap();
            let mut session = Session::new(server_peer.clone(), server_nonce).unwrap();
            let start = Instant::now();
            loop {
                assert!(start.elapsed() < Duration::from_secs(5));
                unsafe {
                    ConnectNamedPipe(pipe.0, ptr::null_mut());
                }
                let mut client_pid = 0;
                if unsafe { GetNamedPipeClientProcessId(pipe.0, &mut client_pid) } != 0 {
                    assert_eq!(client_pid, pid);
                    break;
                }
                pause();
            }
            loop {
                assert!(start.elapsed() < Duration::from_secs(5));
                if let Some(frame) = read(&pipe).unwrap() {
                    let response = session
                        .receive(&frame, &server_peer, start.elapsed(), true)
                        .unwrap();
                    assert_eq!(response.status, Status::Authenticated);
                    write(&pipe, &encode(&response).unwrap()).unwrap();
                    // Keep the pipe alive until the fake client has read its reply.
                    received.recv_timeout(Duration::from_secs(5)).unwrap();
                    return;
                }
                pause();
            }
        });
        wait.recv_timeout(Duration::from_secs(5)).unwrap();
        let raw = unsafe {
            CreateFileW(
                pipe_name(&nonce).as_ptr(),
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | FILE_WRITE_ATTRIBUTES
                    | READ_CONTROL
                    | SYNCHRONIZE,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        let pipe = Handle::new(raw).unwrap();
        let mut server_pid = 0;
        assert_ne!(
            unsafe { GetNamedPipeServerProcessId(pipe.0, &mut server_pid) },
            0
        );
        assert_eq!(server_pid, pid);
        let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
        assert_ne!(
            unsafe { SetNamedPipeHandleState(pipe.0, &mode, ptr::null(), ptr::null()) },
            0
        );
        write(
            &pipe,
            &encode(&Request {
                version: VERSION,
                sequence: 0,
                run: nonce.clone(),
                nonce,
                command: Command::Report,
            })
            .unwrap(),
        )
        .unwrap();
        let start = Instant::now();
        loop {
            assert!(start.elapsed() < Duration::from_secs(5));
            if let Some(frame) = read(&pipe).unwrap() {
                let response: Response = serde_json::from_slice(&frame).unwrap();
                assert_eq!(response.status, Status::Authenticated);
                break;
            }
            pause();
        }
        done.send(()).unwrap();
        helper.join().unwrap();
    }
}
