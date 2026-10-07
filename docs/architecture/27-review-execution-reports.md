# Review, execution and local reports

The historical checkbox confirmations and report tabs below are superseded by
[the UI redesign](28-ui-redesign.md). Native approval payloads, graceful closure,
fresh review and scoped retry boundaries remain in effect.

Phase 32 completes the desktop flow from the stored Phase 31 selection. Home's
high-confidence defaults remain selected; loss and Windows-category confirmations
are additional review gates. Medium/low confidence discoveries retain their existing
unchecked defaults and unsupported shipping providers remain blocked.

## Metadata-only preview and consent

Review builds a native plan and calls `dry_run`. It renders the three independent
categories, per-account/provider targets, logical relative paths, action counts and
available metadata sizes. No file content, credential names, account SID or absolute
profile root reaches React. Null sizes are explicitly unavailable; directory sizes
are not recursively estimated. Browser identity, synchronization, silent SSO and
unverified scope remain distinct from local target absence.

Each item lists its native affected-data description and an acknowledgment for each
risk kind, or its separate effect confirmation when no risk flag is supplied. The
Windows/Microsoft + developer-tools gate repeats the silent-SSO warning and states
that Windows remains signed in. Force-close policy requires a fresh acknowledgment
of unsaved-work loss and the reviewed process list. Tokens and confirmation IDs are
sent only after every required gate has passed. Rust independently validates them
before any process operation or cleanup.

## Ask and process changes

`close_reviewed` is an additional native command. It accepts the same plan-bound
approval as `execute`, permits only Ask, revalidates the retained preview and requests
graceful closure through the existing process capability. It never deletes session
targets, changes identity/sync configuration or escalates to force termination. A
surviving process remains locked. Current-account and helper plans are consumed after
an accepted close request, including an unsuccessful closure.

Review then scans again and builds a new plan. All confirmations reset, even if only
a process disappeared. The user can close programs manually and retry the check, or
skip provider/account items that depend on the listed blockers. Fresh matching must
resolve exactly one provider in the same opaque account, with the previously selected
profile IDs still present; otherwise the flow stops for a new manual selection.
Skipping is projected from native inventory IDs into the retained report; it does
not claim a cleaned category. Skipping every selected item can finish a report without
scheduling any cleanup.

The existing authenticated helper session may serve successive fresh reviews. Its
account identifiers remain stable for the same owner during that session, including
when enumeration order changes. Each execution still consumes its plan and approvals;
existing helper lifetime/idle bounds, owner revalidation, trust pins and UAC rules are
unchanged. An expired/disconnected helper requires a newly enabled mode and selection.

## Execution, cancellation and retry

The ordered native channel updates category/account stages and completed items.
Review, navigation and duplicate starts are disabled during active work; the native
admission boundary also rejects a second wipe or close request. Cancellation stops
future effects through the existing engine/helper boundary. Received item results
remain visible after a stream failure. Unacknowledged results are explicitly unknown,
and the UI cannot export an older retained report as the failed run's report.

Retry starts a new scan and review limited to failed or locked provider/account items
and their originally selected profile subsets. Successful providers, unrelated
categories and other profiles are not added. Protected stores and unsupported scope
remain blocked regardless of confirmation or retry.

## Reports and export

Reports have separate Applications, Browsers and Windows/Microsoft + developer-tools
tabs, per-account sections, distinct action/verification statuses, skipped choices and
an explicit What remains section. Unrequested categories say Not requested. Browser
reports retain plain-language sync restoration and silent-sign-in warnings; Windows
reports never claim Windows sign-out. Residual account hives require manual recovery.

`export_report` accepts only `json` or `text` and exports the retained native projection,
including all three categories and skipped choices. Rust chooses the destination in
the app configuration directory's `reports` subfolder. The returned relative filename
is safe to display. Atomic, no-clobber file persistence preserves existing exports.
JavaScript cannot supply a path or report payload, and receives no filesystem, shell,
HTTP or opener plugin permission. AppManifest now grants eleven local main-window
application commands; remote content and other windows remain denied.

## Verification

Frontend tests mock all native calls and exercise preview, each approval gate, Ask
closure/recheck/skipping, force policy, streamed progress/cancellation, report isolation,
account coverage, exports, fresh scoped retries and missing-scope refusals. Rust tests
use synthetic confined stores, fake processes and account/hive adapters to establish
that close-only operations preserve files, missing/stale approvals refuse closure,
replay fails, locked results remain explicit, skipped-only runs schedule no mutations,
and native JSON/text exports contain no fixture payloads or absolute account roots.

This does not validate real UAC, cross-session shutdown, vendor artifact closure or
browser identity/sync editing. Their existing unverified catalog and VM gates remain.
