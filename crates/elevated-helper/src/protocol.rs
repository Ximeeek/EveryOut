//! Bounded identifiers/statuses only. Peer identity is transport-derived, never JSON.
use everyout_core_model::ProcessClosePolicy;
use everyout_core_model::Support;
use everyout_engine::accounts::AccountConsent;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, time::Duration};
include!(concat!(env!("OUT_DIR"), "/catalog.rs"));
pub const VERSION: u32 = 1;
/// Progress frames belong to the same authenticated request sequence as its final response.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgressFrame {
    pub version: u32,
    pub sequence: u64,
    pub account: String,
    pub progress: everyout_engine::Progress,
}
pub const MAX_FRAME: usize = 8192;
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
pub const MAX_LIFETIME: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub sid: String,
    pub logon: (u32, i32),
    pub session: u32,
    pub pid: u32,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub provider_id: String,
    pub revision: u64,
    pub account_id: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Command {
    EnumerateProfiles,
    Plan {
        selections: Vec<Selection>,
    },
    PlanAccounts {
        selections: Vec<Selection>,
        policy: ProcessClosePolicy,
    },
    Review {
        plan_id: String,
        digest: String,
        accounts: Vec<AccountConsent>,
    },
    ReadReport {
        page: u32,
    },
    Execute {
        plan_id: String,
        dry_run: bool,
    },
    CloseProcesses {
        plan_id: String,
    },
    Report,
    Finish,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u32,
    pub run: String,
    pub sequence: u64,
    pub nonce: String,
    pub command: Command,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    ProfilesReady,
    PlanReady,
    Reviewed,
    ApprovalRequired,
    Completed,
    Authenticated,
    ScopeUnavailable,
    CandidateBlocked,
    StaleRevision,
    UnknownProvider,
    Rejected,
    Finished,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub version: u32,
    pub sequence: u64,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<ReplyData>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyData {
    pub plan_id: Option<String>,
    pub digest: Option<String>,
    pub page: u32,
    pub pages: u32,
    /// A bounded chunk of sanitized report JSON; no SID, absolute path or secrets.
    pub report: String,
}
pub struct BackendReply {
    pub status: Status,
    pub data: Option<ReplyData>,
}
impl BackendReply {
    pub fn status(status: Status) -> Self {
        Self { status, data: None }
    }
}
/// A native helper owns the account/root and plan capabilities; test sessions use
/// a fake backend. Dispatch occurs only after transport and payload validation.
pub trait AccountBackend {
    fn dispatch(
        &mut self,
        command: &Command,
        catalog: &BTreeMap<String, everyout_providers::Manifest>,
        run: &str,
    ) -> BackendReply;
}
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Status> {
    let frame = serde_json::to_vec(value).map_err(|_| Status::Rejected)?;
    if frame.len() > MAX_FRAME {
        return Err(Status::Rejected);
    }
    Ok(frame)
}
pub fn decode(frame: &[u8]) -> Result<Request, Status> {
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err(Status::Rejected);
    }
    serde_json::from_slice(frame).map_err(|_| Status::Rejected)
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub fn nonce_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The helper loads exactly the compile-time catalog through the shared validator.
/// No writable catalog file, manifest payload or root from the client is accepted.
pub struct Session {
    peer: Peer,
    nonce: String,
    run: String,
    next: u64,
    authenticated: bool,
    closed: bool,
    last: Duration,
    catalog: BTreeMap<String, everyout_providers::Manifest>,
    backend: Option<Box<dyn AccountBackend>>,
}
impl Session {
    pub fn new(peer: Peer, nonce: String) -> Result<Self, Status> {
        if !nonce_valid(&nonce) {
            return Err(Status::Rejected);
        }
        let mut catalog = BTreeMap::new();
        for json in BUNDLED {
            let manifest = everyout_providers::load_manifest(json).map_err(|_| Status::Rejected)?;
            if catalog.insert(manifest.id.clone(), manifest).is_some() {
                return Err(Status::Rejected);
            }
        }
        Ok(Self {
            peer,
            run: nonce.clone(),
            nonce,
            next: 0,
            authenticated: false,
            closed: false,
            last: Duration::ZERO,
            catalog,
            backend: None,
        })
    }
    pub fn with_backend(mut self, backend: Box<dyn AccountBackend>) -> Self {
        self.backend = Some(backend);
        self
    }
    /// A long native command is work, not idle time. The absolute lifetime still
    /// applies independently; this method never revives a closed session.
    pub fn completed_at(&mut self, now: Duration) {
        self.last = now;
    }
    pub fn expired(&mut self, now: Duration, parent_alive: bool) -> bool {
        if !parent_alive || now >= MAX_LIFETIME || now.saturating_sub(self.last) >= IDLE_TIMEOUT {
            self.closed = true;
        }
        self.closed
    }
    /// Handshake is sequence zero with Report; nonce is consumed once. Subsequent
    /// requests use the run ID and monotonic sequence, with an empty nonce.
    pub fn receive(
        &mut self,
        frame: &[u8],
        peer: &Peer,
        now: Duration,
        parent_alive: bool,
    ) -> Result<Response, Status> {
        let result = self.accept(frame, peer, now, parent_alive);
        if result.is_err() {
            self.closed = true;
        }
        result
    }
    fn accept(
        &mut self,
        frame: &[u8],
        peer: &Peer,
        now: Duration,
        parent_alive: bool,
    ) -> Result<Response, Status> {
        if self.expired(now, parent_alive) || peer != &self.peer {
            return Err(Status::Rejected);
        }
        let request = decode(frame)?;
        if request.version != VERSION || request.run != self.run || request.sequence != self.next {
            return Err(Status::Rejected);
        }
        let status = if !self.authenticated {
            if request.nonce != self.nonce || !matches!(request.command, Command::Report) {
                return Err(Status::Rejected);
            }
            self.authenticated = true;
            self.nonce.clear();
            Status::Authenticated
        } else {
            if !request.nonce.is_empty() {
                return Err(Status::Rejected);
            }
            validate_command(&request.command)?;
            if !matches!(request.command, Command::Finish) {
                if let Some(backend) = &mut self.backend {
                    let reply = backend.dispatch(&request.command, &self.catalog, &self.run);
                    return Ok(Response {
                        version: VERSION,
                        sequence: self.advance(now),
                        status: reply.status,
                        data: reply.data,
                    });
                }
            }
            match request.command {
                Command::Plan { selections } => {
                    if selections.is_empty() || selections.len() > 64 {
                        return Err(Status::Rejected);
                    }
                    // Validate every identifier before catalog lookup; an unknown
                    // first provider must not hide a later injection payload.
                    if selections.iter().any(|selection| {
                        !identifier(&selection.provider_id) || !identifier(&selection.account_id)
                    }) {
                        return Err(Status::Rejected);
                    }
                    let mut status = Status::ScopeUnavailable;
                    for selection in selections {
                        let Some(manifest) = self.catalog.get(&selection.provider_id) else {
                            status = Status::UnknownProvider;
                            continue;
                        };
                        if status == Status::UnknownProvider {
                            continue;
                        }
                        if selection.revision != manifest.revision {
                            status = Status::StaleRevision;
                        } else if manifest.support != Support::Validated {
                            status = Status::CandidateBlocked;
                        }
                    }
                    // No account/root capabilities exist in phase 27. Thus neither
                    // SafePath nor the engine safety guard can authorize effects.
                    // Never use helper HKCU/known folders as an owner substitute.
                    status
                }
                Command::Execute { plan_id, .. } | Command::CloseProcesses { plan_id } => {
                    if !identifier(&plan_id) {
                        return Err(Status::Rejected);
                    }
                    // No helper-held plan means no mutation or process closing.
                    Status::ScopeUnavailable
                }
                Command::EnumerateProfiles | Command::Report => Status::ScopeUnavailable,
                Command::PlanAccounts { .. }
                | Command::Review { .. }
                | Command::ReadReport { .. } => Status::ScopeUnavailable,
                Command::Finish => {
                    self.closed = true;
                    Status::Finished
                }
            }
        };
        Ok(Response {
            version: VERSION,
            sequence: self.advance(now),
            status,
            data: None,
        })
    }
    fn advance(&mut self, now: Duration) -> u64 {
        let sequence = self.next;
        self.next += 1;
        self.last = now;
        sequence
    }
}
#[allow(clippy::collapsible_match)]
fn validate_command(command: &Command) -> Result<(), Status> {
    match command {
        Command::Plan { selections } | Command::PlanAccounts { selections, .. } => {
            if selections.is_empty()
                || selections.len() > 64
                || selections
                    .iter()
                    .any(|s| !identifier(&s.provider_id) || !identifier(&s.account_id))
            {
                return Err(Status::Rejected);
            }
        }
        Command::Execute { plan_id, .. } | Command::CloseProcesses { plan_id } => {
            if !identifier(plan_id) {
                return Err(Status::Rejected);
            }
        }
        Command::Review {
            plan_id,
            digest,
            accounts,
        } => {
            if !identifier(plan_id)
                || !nonce_valid(digest)
                || accounts.is_empty()
                || accounts.len() > 64
                || accounts.iter().any(|a| {
                    !identifier(&a.account)
                        || a.risks.len() > 32
                        || a.confirmations.len() > 64
                        || a.confirmations.iter().any(|c| !identifier(&c.0))
                })
            {
                return Err(Status::Rejected);
            }
        }
        _ => {}
    }
    Ok(())
}
