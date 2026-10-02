# Elevated helper boundary

Phase 27 adds `crates/elevated-helper` as a library and a separate
`everyout-elevated-helper.exe`. There are no Tauri commands or UI changes.
The host calls `launch(AccountMode, privileged_work_needed, expected_helper_digest)`;
the digest is a trusted release/build pin supplied by native host code, never frontend input
or a digest computed from an untrusted installed binary just before launching it.
Distribution pin provisioning and publisher signing remain release work. The launcher is not
connected to the shipping host in this phase.

## Launch and trust

`Current` and a remembered all-accounts preference without requested work return before any
binary access or native elevation call. Only an on-demand all-accounts request invokes
`ShellExecuteExW` with the fixed sibling executable, `runas`, and a retained process handle.
The launcher rejects a mismatched SHA-256 pin and reparse-point executable/ancestors and keeps
handles open against binary modification and ancestor rename while the client exists.
Hashing reads only this executable, never session files. No network calls are made at runtime.
The returned pipe server PID must match the actual retained launched process.

UAC cancellation maps `ERROR_CANCELLED` to `UacDeclined`; start, authentication and timeout
failures have distinct stable enum values. Each fallback specifies current effective/saved mode
and fresh review. Phase 30 must discard expanded inventory/plans/confirmations, persist this
choice, explain the reason and rescan; the launcher performs no fallback mutation or prompt loop.

## IPC and lifetime

The helper derives the parent's SID, token authentication LUID and session ID from a retained
query/synchronize process handle, not from message fields. It requires an elevated own token.
The named pipe has one first instance, rejects remote clients and uses a protected DACL granting
specific data/attribute/read-control/synchronize rights only to the launcher's SID and built-in
administrators. Generic write is avoided because it also grants pipe-instance creation.
Endpoint PID checks bind the connected client to that exact parent; other logons/sessions/PIDs
cannot authenticate even with the nonce. Administrator authority cannot establish user scope.

A system-CSPRNG 256-bit per-launch nonce derives the private pipe/run name. The initial `Report`
request at sequence zero must match protocol version 1, nonce, run and transport identity.
The nonce is consumed; later requests carry an empty nonce and increasing sequence.
Unknown fields/variants, paths in identifier fields, malformed or oversized messages, duplicate
JSON fields and replay are rejected. The message envelope contains `version`, `run`, `sequence`,
`nonce` and a typed `command` object. Messages are at most 8192 bytes; selections at most 64.
Only enumerate-profiles, plan, execute-with-dry-run, close-processes, report and finish are defined.
Responses contain version, sequence and a fixed status; there is no raw OS output or secret data.

Nonblocking pipe polling bounds idle lifetime to 30 seconds and total lifetime to five minutes.
Parent termination, pipe loss, rejection or finish ends the helper. There is no reconnection or
persistent registration. An unconnected helper also times out; failed launch never leaves it
indefinitely waiting. Completion/cancellation uses `Finish`; dropping the client disconnects IPC.

## Independent safety and phase boundary

The helper embeds the same project catalog at build time and reloads every manifest through
`everyout_providers::load_manifest`. It accepts provider IDs, exact revisions and opaque account
IDs, never manifests, filesystem roots, registry expressions, executables or command lines.
Unknown providers, stale revisions and candidate support are separately reported.

Phase 28 owns OS profile enumeration, account-ID/root associations and unloaded hives.
Until then enumeration reports `scope-unavailable`, no helper-held plan is issued, and execute
(including dry run) and close-processes are blocked. There is no fallback to elevated HKCU or
known folders. Without a validated owner-root capability there is no `SafePath` and no approved
engine operation: the boundary refuses work before either can authorize an effect.
Phase 28 must resolve owners inside the helper, use `SafePath` and the existing engine safety
guard, retain helper-held plans/revisions/approvals, and revalidate them before every effect.
This phase deliberately provides no alternative destructive adapter or caller-supplied resolver.

## Evidence and remaining gates

Automated tests use fake in-process endpoints and a local same-process Windows pipe, without UAC
or real profile access. They verify nonce/SID/logon/session/PID/version/run binding, replay,
unknown fields/commands, injection, stale/candidate catalog rules, missing scopes, idle/absolute
timeouts, parent-loss state, launch preconditions and distinct fallback values.
The local pipe test verifies real endpoint PID APIs and explicit-rights connection.

S6 remains **PENDING USER EXECUTION**. Actual UAC, over-the-shoulder administrator consent,
cross-user ACL denial, executable trust under hostile installation changes and real helper exit
timing require the [manual VM checklist](../testing/vm-guide.md#elevated-helper-and-uac-phase-27).
No experiment here resolves artifact signing, other-account scope or privileged execution gates.
No other-user enumeration/wipe, hive loading or cross-session process closing is implemented.
