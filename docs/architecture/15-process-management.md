# EveryOut current-user process management

Phase 16, 2026-10-01. This adds platform primitives and manifest candidate matching;
the wipe engine, UI confirmations and cross-account closing remain future phases.

## Metadata and selection

`crates/platform-windows/src/process.rs` enumerates process entries with Tool Help,
filters by the invoking session and token user SID, and exposes PID, full image path,
basename, session ID and creation ticks. Other sessions and users are excluded.
Unqueryable processes have unknown ownership and are returned separately as PID/error
diagnostics; they never become close targets. No process memory, window text, command
lines or token credentials are read. TokenUser is used only for owner comparison.

Each opaque Process retains a query-only process handle and creation time. Closing
reopens the selected PID with query/synchronize rights, then verifies creation time,
image, user and session. The earlier handle remains alive to pin the process object.
Self-closing and duplicate selection are refused. Failures report stable core error
kinds and OS codes, without path-bearing error text or privilege escalation.

`PlatformManifest::match_processes` uses loader-validated `identity.process_names`.
The existing schema has no image-path declaration: separately resolved installation
paths can narrow these candidates without extending the manifest schema. Matching
is literal, ASCII case-insensitive, with no wildcard, path expansion or alias lookup.
Non-ASCII spelling must match exactly. Name matches do not establish exclusive owner
or permission to close. The caller reviews and passes an explicit Process selection;
matching never starts closing or selects children, services or shared WebView2 hosts.

## Closing and policy

The core model exposes serializable `ProcessClosePolicy { Ask, HardKillAfter2s }`.
Both request asynchronous WM_CLOSE on the selected process's top-level windows,
rechecking identity and HWND owner before each post. Window enumeration is bounded
to 1,024 matches. Every selected identity has its own monotonic two-second grace
deadline; selections currently run sequentially. A windowless process receives no
message but still gets the observation interval, then follows the selected policy.

Ask never opens terminate rights and returns surviving selection indices for caller
review. HardKillAfter2s obtains terminate rights only after the deadline, revalidates
the exact identity again, terminates only that survivor, and observes actual exit
for up to five seconds. Windows scheduling can delay escalation beyond two seconds;
the timer is a minimum grace interval, not a hard real-time guarantee. The caller
must obtain the unsaved-work acknowledgment and exact process-set approval described
in the wipe sequence before using this policy.

Each result reports WouldClose, ClosedGracefully (observed exit without force),
Killed (observed exit after successful termination), StillRunning, Failed or
AccessDenied, with message count and optional force timing. Remaining indices include
failures with unknown liveness, so dependent mutations stay blocked. Partial results
are retained. Dry run rechecks identity and returns WouldClose without posting,
waiting, termination, restart or filesystem/registry mutation.

WM_CLOSE uses
[PostMessageW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-postmessagew),
which returns without waiting for the application to process the request and respects
UIPI. A denied request is reported without force fallback. Restart Manager shutdown
is intentionally absent because S7 has no validated bounded/cancellable strategy for
its synchronous call. This follows the architecture's WM_CLOSE alternative.

## Unverified S7 behavior and local checks

S7 remains PENDING USER EXECUTION. Actual application prompt/refusal behavior,
HWND reuse between final owner check and posting, child ownership, relaunch and
resource release still need the defined VM trials. Retained process identity does
not make HWND posting atomic. No result establishes released locks, completed wipe
or logout. The future engine must handle relaunch and revalidate resources before
mutation. No automatic restart or Restart Manager forced shutdown is performed.

The Cargo-built integration test executable has a guarded helper entry point that
opens its own window or sleeps. Parent tests spawn it explicitly and clean up only
their own children. Coverage includes cooperative graceful closure, refusal under
Ask, force timing at or after 2,000 ms, dry run with both policies, no-window behavior,
same-image sibling preservation, duplicate refusal and an exited selection. A
read-only provider test verifies manifest names and exact path narrowing against
its own test-process metadata. Local tests do not change S7's VM evidence status.
