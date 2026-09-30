# Permission and account-mode model

Phase 9 target design for EveryOut, based on
[Windows research §5](../research/02-windows-identity-and-multi-account.md#5-optional-multi-account-mode-and-elevated-operation),
[classification rules](04-classification-rules.md#global-account-mode),
[ADR 0002](../adr/0002-retain-tauri-rust-stack.md) and
[ADR 0003](../adr/0003-rust-command-capability-boundary.md).
This adopts the dossier's normal-app plus short-lived helper recommendation; implementation
and runtime enforcement remain future work.

## First run and normal operation

Ask on first run: **Clean only the current Windows account (default), or include other Windows
accounts?** Explain that current mode covers discovered app/browser profiles for the invoking
user; all-accounts mode needs UAC, explicit review of other user scopes and may skip inaccessible
or active profiles. This choice is one global setting, never a provider checkbox.

Launch the main application `asInvoker` without requesting elevation. Current mode never requests
UAC, including after an access-denied result. Keep operations within the invoking user's reviewed
scope. A manually elevated main app is not authority to widen that scope; privileged work still
requires explicit all-accounts mode and its review gates.

Only enabling all-accounts mode permits an on-demand UAC request. Start the helper with `runas`
when privileged discovery/work is needed, before reviewing the expanded inventory. Do not keep
a helper alive between runs or request UAC merely because a remembered preference exists.
A later run in all-accounts mode explains and requests its helper on demand again.
UAC grants system authority, not wipe approval: dry run, target review and additional loss/category
confirmations in [05](05-wipe-sequence.md) still precede mutation.

If UAC is declined, cancel elevated work, switch the effective mode and saved choice to current
account, and tell the user: **Administrator access was declined. Other accounts were not cleaned;
current-account mode is available.** Discard the expanded plan and its confirmations, rescan and
require normal current-scope review before execution. Do not loop UAC prompts. Launch failures
use the same visible fallback, with a sanitized failure reason. No mutation occurs as part of
this fallback itself.

## Helper boundary

The UI continues to use narrow Rust commands and opaque IDs. The helper is a separate fixed
executable for one authorized run, not an elevated React window, generic shell, service,
scheduled task or COM registration. Reuse the engine/provider invariants and validated operations;
the helper does not turn candidate manifests into supported rules.

Adopt the dossier's named-pipe direction: explicit DACL restricted to the launching user/logon
identity and necessary helper access; authenticated endpoints, one-time nonce/handshake and a
small typed request set. Validate caller SID, logon context, run/plan binding and helper identity;
fail closed on mismatches, IPC loss or failed validation. A nonce alone is not authentication.
Exact ACLs, over-the-shoulder administrator consent and executable trust validation remain
`elevated-helper-ipc-validation`, not an assertion that these controls already work.

Requests identify engine-held selections, manifest revisions and bounded account scopes. The
helper independently resolves and revalidates owners and effects from trusted rules; it accepts
no arbitrary path, registry expression, executable or command line. It returns sanitized outcomes
and exits after completion, cancellation or failure. IPC cannot transport secret-store bytes,
credential blobs, raw command output or user-supplied deletion recipes.
This extends the existing command boundary without redesigning the provider contract.

## Eligible profiles and context

Use reviewed OS profile metadata (SID, local path, loaded/special state) to inventory candidate
users. Keep actual SID/root associations in Rust and use neutral UI labels when needed.
All accounts means **eligible detected profiles**, not every account known to a remote service.
Show special/system profiles as excluded and inaccessible profiles as uncovered. V1 skips loaded
other-user profiles, including simultaneous local/RDP sessions, and does not force their logout
or close processes in another user's session. Active invoking-user targets follow [05](05-wipe-sequence.md).

Resolve roots from each selected owner, never the helper administrator's `%USERPROFILE%` or HKCU.
Other-user filesystem access does not authorize that user's Credential Manager, broker or CLI
operations: do not run a current-user API and label its effect as another user's cleanup.
Without a validated per-user operation, report unsupported coverage.

For supported registry targets, only a validated unloaded-hive lifecycle may be used: recheck
loaded state before work, never remount/unload an already-mounted hive, track hives opened by this
run and release only those. If state changes or lifecycle safety cannot be established, skip the
affected action. Do not take ownership, change ACLs or bypass protections to make a wipe succeed.
Exact profile eligibility, root validation and hive cleanup are `other-account-scope-validation`.
The conservative loaded-profile exclusion follows Windows research §5; elevation does not solve
secret access, other-user consent or application ownership.

The Windows sign-in account, WAM/PRT, device join and unsupported broker caches remain protected
in both modes. Additional category confirmation never overrides these exclusions
([Windows research §§1–3](../research/02-windows-identity-and-multi-account.md)).

## OPEN DECISIONS

| Named spike                             | Evidence needed                                                                                                                                       | Until resolved                                                                            |
| --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- |
| `elevated-helper-ipc-validation`        | Named-pipe ACL/endpoint authentication, nonce/run binding, helper trust/lifecycle and different administrator consent identity; Windows §5            | No privileged executable operation                                                        |
| `other-account-scope-validation`        | OS profile enumeration, loaded-state races, per-owner roots, reparse constraints, unloaded-hive lifecycle and per-user API eligibility; Windows §§3–5 | Skip unresolved other-user targets; no cross-session close or borrowed administrator HKCU |
| Existing `metadata-discovery-allowlist` | Exact readable metadata fields and credential-target discovery; [00](00-overview.md#open-decisions)                                                   | No configuration-content or blob-returning discovery exception                            |

These are implementation-blocking validations of the adopted direction. Threat modeling and
test strategy remain Phase 10 work.
