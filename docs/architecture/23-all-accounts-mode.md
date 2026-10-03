# All-accounts mode

Phase 28 extends the on-demand helper with owner-bound account compartments. This
explicitly supersedes Phase 9's policy of skipping every loaded foreign profile.
The Windows sign-in identity, candidate manifests, preservation rules and offline
requirements remain protected. There are no Tauri commands, UI, services or tasks.

## Inventory and owner roots

The helper enumerates local ProfileList records. Local SAM level-20 account IDs
and the local LSA account-domain SID must identify a local user; no remote server
or domain SID lookup is used. System/service, special, stale `.bak`, temporary, nonlocal,
unrecognized nonzero profile-state and unsupported path records are excluded.
Individual metadata failures produce neutral exclusion codes; a failed inventory
API or ambiguous SID/root association prevents planning. Inventory is bounded to
64 eligible profiles. LSA interactive logon-session metadata includes locked and
disconnected logons; HKU presence is a separate mounted-hive observation.

Actual SID/profile associations stay inside Rust. Run-local account IDs are the
only account selectors on IPC. Re-enumeration invalidates the prior plan. Profiles
are revalidated and retained directory handles pin profile roots through review.
AppData, LocalAppData and UserProfile resolve from the selected owner's metadata,
never the consenting administrator's HKCU, known folders or environment variables.
User Shell Folders reads are restricted to `AppData` and `Local AppData`. Only
owner-derived variables are expanded; UNC, device paths, traversal, reparse points,
hard links, redirected out-of-profile folders and unknown variables are refused.
Missing known-folder values use that owner's standard profile-relative locations.
ProfileImagePath containing unresolved variables is an uncovered location.

## Registry lifecycle

A mounted `HKU\SID` hive is borrowed and never independently loaded or unloaded.
If an interactive logon exists without its mounted hive, registry work is blocked.
For an offline profile, recheck logon/HKU state, require an existing regular
`NTUSER.DAT`, retain its attribute-only file handle against replacement, and load
it with RegLoadKeyW under a unique `EveryOut-<run>-<counter>` key. Registry root
capabilities reinterpret manifest HKCU under this owner mount. Exact key/value
deletion uses the existing link-rejecting registry capability; no value data or
hive-file bytes are read by EveryOut.

Backup/restore privileges exist only on short-lived impersonating registry workers.
Prior token privilege state is restored on exit; the main execution thread and
process token never acquire filesystem bypass privileges. No ACL or ownership
changes are attempted.

The scoped hive callback drops all registry handles before cleanup. Success,
operation errors, cancellation, caught panics and detected logon races all attempt
RegUnLoadKeyW, with at most three attempts and a short delay. Failed cleanup reports
the temporary key, attempt count and residual mount separately from operation
results. A residual preview blocks that account's apply until manual recovery and
a new plan. There is no unload of an existing/live SID hive and no automatic
account/profile modification. Forced process crashes cannot guarantee cleanup.

Mounting is infrastructure for an offline account's metadata preview: planning and
dry-run may temporarily mount/unmount HKU but never delete session targets or close
processes. This distinction must be explained by the future host UI before preview.

## Plans, review, sequence and reports

`AccountScope { CurrentUser, AllUsers }` binds the engine-held plan and report.
AllUsers contains independent owner-bound current-account provider compartments;
it does not reinterpret elevated HKCU as the invoking user. Each selected account
gets its own plan, execution/verification results, category sections and issues.
Failed or unsupported providers appear as blocked sections. One account's denial,
stale state, missing consent or failed hive lifecycle never aborts other accounts.

The authenticated protocol retains its original envelope and adds `PlanAccounts`,
`Review` and `ReadReport`. `Plan` defaults to Ask. The helper reloads the bundled
catalog, checks revisions, resolves account capabilities and retains an immutable
preview plus opaque physical file identities. Overlapping physical target scopes
block affected accounts. Review binds the exact plan ID and SHA-256 preview digest
to per-account category, loss and force-close acknowledgments. No paths, executables,
manifests or registry recipes are accepted from IPC.

Dry-run re-observes selected account metadata and file identities. Changes discard
the plan and require fresh review. Apply rebuilds and compares each reviewed
provider plan (only fresh internal snapshot/plan IDs differ), checks retained file
identities after preparing, then uses Engine::for_account and its existing safety
guard. Revalidate owner/logon state and process quiescence before each effect.
The separate Windows/Microsoft + developer-tools confirmation and silent-SSO
warning apply to each selected account. A confirmation cannot promote candidates,
authorize a borrowed administrator credential API or override preservation.

Application, browser and Windows/developer reports stay independent. Every account
report includes `unverified-s6-profile-logon-races-hive-lifecycle-cross-session-close`.
Apply consumes the held plan before replying, so replay requires a fresh plan.
Reports use bounded 2048-byte chunks within the existing 8192-byte IPC frame limit;
pages carry sanitized JSON with opaque account IDs, never raw SIDs or absolute
profile paths. Parent loss, pipe loss and the absolute deadline stop new effects
at engine cancellation gates and still complete in-flight hive cleanup. No rollback
or automatic restart is promised. A disconnected client may not receive the final
residual report; VM recovery must also inspect the owned temporary HKU namespace.

## Process closing

The native process inventory can bind a selected SID across sessions. Retained
process handles, creation times, full image paths, SID and session IDs are checked
again before graceful requests and force termination. Only catalog process names
with independently resolved exact App Paths registrations can enter the helper's
close set; custom/unregistered or ambiguous installations remain blocked. The only
additional registry payload exception is the fixed App Paths executable-location
metadata value, not application session or credential data.

Both policies use the existing asynchronous WM_CLOSE attempt and two-second grace
interval. Ask never escalates; HardKillAfter2s also requires that account's explicit
unsaved-work acknowledgment. EnumWindows does not guarantee another session's
desktop access. If no graceful window is accessible for a foreign session, Ask waits and returns
survivors without escalation. An explicitly reviewed HardKillAfter2s policy waits
the full interval and may terminate the retained surviving process even with zero
window requests, just as for a current-session no-window process. Logged-on account
reports explicitly warn about this unverified graceful-access limitation. Actual
access/termination failures still block dependent cleanup. No desktop injection,
hooks, foreign-memory reads or drivers are used.

## Evidence and remaining limits

S6 remains **PENDING USER EXECUTION**. Fixture tests exercise profile exclusions,
per-SID roots, borrowed live hives, unique offline mounts, cleanup on success/error/
panic/races, unload retries/residuals, native helper sequencing with fake hives,
preview binding, stale files, per-account failures, replay and paged reports.
All filesystem mutations in those tests are confined to generated temporary trees.
No host profile enumeration, RegLoadKey, elevation or real multi-user trial is run.

Real logon/mount races, default/nonzero ProfileList state eligibility, locked/RDP
sessions, hive sharing/privilege behavior, cross-session graceful access, UAC under
a different administrator, cleanup after disconnect/crash and hostile installations
remain UNVERIFIED. Rechecks are not an OS-wide profile lock. Shipping catalog rules
retain their existing candidate/unsupported status; this phase does not validate
session persistence or add another user's Credential Manager/broker/CLI adapter.
The [two-user VM checklist](../testing/vm-guide.md#all-accounts-mode-phase-28)
must record these gaps without promoting them from passing fixture tests.

API contracts: [NetUserEnum](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netuserenum),
[local account-domain metadata](https://learn.microsoft.com/en-us/windows/win32/api/lsalookup/ns-lsalookup-policy_account_domain_info),
[RegLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw),
[RegUnLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regunloadkeyw),
[LSA logon enumeration](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaenumeratelogonsessions).
Reviewed on 2026-10-03; these contracts are documentary evidence, not S6 results.
