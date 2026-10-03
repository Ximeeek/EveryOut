# Desktop application commands

Phase 29 connects the native EveryOut host to the engine and authenticated helper.
React screens remain outside this phase; `src/api/index.ts` is the typed IPC client.

## Commands and retained capabilities

`scan` returns a fresh inventory ID, opaque instances grouped by category/confidence,
default selection, discovery limitations and account coverage. Heuristics stay unchecked
and cannot become executable providers. Native ownership conflicts also block known
provider selection. Unsupported adapters remain visible as discovery-only coverage.

`build_plan` accepts only the inventory ID and selected instance IDs. It consumes that
inventory and retains immutable engine plans in the native worker. The returned preview
contains three independent category sections, risks, confirmation IDs, logical target
labels, process identities and uncertainty. `dry_run` refreshes metadata without mutation;
changed observations, provider descriptions or close sets reject the old review.

`execute` accepts a plan ID, per-account/per-instance `confirmed_risks`, confirmation IDs,
category tokens issued with that preview and force-close account acknowledgments. Missing
confirmations reject the entire request before scheduling any effect. Engine checks still
independently refuse unsupported candidates, protected data and stale ownership. A plan
is consumed after an accepted execution; a new inventory and review are required to retry.

One dedicated worker owns the borrowed engine/provider capabilities. A host-side atomic
admission boundary permits only one active wipe; scans, planning and settings changes return
`busy` during that wipe. `get_settings`, `get_last_report` and run-bound `cancel` remain usable.
Commands wait on background tasks, never on the webview/UI thread. The last report is retained
in memory for this app lifetime, with no session-store payloads or absolute account paths.

## Progress and cancellation

`execute` uses Tauri 2 `Channel<WipeEvent>` for ordered, typed progress, completed item results,
the final report and stable errors. Current-account progress and item results are emitted
directly by the engine. The helper sends bounded progress frames bound to the authenticated
request version/sequence; its paged final report supplies per-item results after execution.
Progress frames never contain owner SIDs, absolute roots, session content or command output.

Current-account cancellation stops scheduling mutations at engine gates and retains completed
effects in the final report. Cancelling helper work disconnects its authenticated pipe; the
helper observes pipe loss at its existing gates and attempts in-flight hive cleanup. Results
not acknowledged before disconnect remain unknown. The terminal error is `cancelled`, not a
successful cleanup claim; the previous last report is not replaced by invented results.

## Settings and effective account mode

`get_settings`/`set_settings` use JSON in the host-resolved app-config directory. Defaults are
Ask, current account and first run incomplete. Saving writes and syncs a temporary file before
replacing settings. Unknown fields and invalid JSON are rejected. No settings field can supply
paths, executable names, privilege grants, credentials or an expected helper hash.

A saved all-accounts preference does not launch UAC or grant effective authority. The client
must explicitly call `enable_all_accounts_mode` before its all-accounts scan. That command
invalidates old plans before launching a fresh fixed helper. Refusal, authentication failure,
timeout or a missing build pin persists current mode and returns a stable reason plus
`requires_fresh_review`. The client must explain fallback and call `scan` before planning again.
The worker never executes a reduced version of an expanded plan.

Other-account scans use the helper's owner-bound known folders and metadata scanner. Offline
scans can temporarily mount/unmount the selected user's hive using the existing scoped lifecycle.
Scan results expose residual mount metadata for recovery and disable selection for that account.
Installation registrations for foreign users remain incomplete coverage. All S6 limitations,
candidate status and protection gates continue to apply; fixture tests do not validate real UAC.

Current-account process closing uses the same fixed App Paths executable-location metadata
exception as the helper. Active matching names without independently registered exact paths
remain blocked. Reviewed sets use WindowsProcessGate, both close policies and cancellation.
No process image path supplied by JavaScript can authorize closing.

## Build-provided helper trust

Run `pnpm desktop:build` on Windows to build the helper from the checked-out source with the
locked dependencies, compute SHA-256 of that build artifact, embed it in the host through
`EVERYOUT_HELPER_SHA256`, and package the exact binary as a Tauri sidecar. The environment
variable is read by `build.rs`, never at runtime. `-NoBundle` builds the same pinned release
without creating installers. The script restores any previous build environment value.

Ordinary `cargo build` and unpinned development builds retain current-account functionality;
enabling other accounts returns `trust-pin-unavailable` before UAC. Malformed supplied pins
fail compilation. The runtime never derives its expected pin from an installed executable.
The existing launcher compares the installed helper against the embedded pin while retaining
binary/ancestor locks. Publisher signing and manual hostile-installation/UAC trials remain
release/VM work; sign a helper before computing the host pin if a signed artifact is distributed.

## IPC types and permissions

Rust DTOs and shared domain enums implement ts-rs 12 `TS`. `pnpm bindings:generate` writes
the committed `src/api/types.ts`; `pnpm bindings:check` compares the full recursive declarations
without rewriting files. CI runs that check. The DTOs use JSON-compatible numbers, opaque string
IDs and serde's exact enum spellings. The approach is independent of Tauri macros and works with
the locked Tauri 2.12 channel/invoke API. Generated types are excluded from handwritten formatting.

AppManifest registers exactly nine app commands. Configuration enables exactly the `default`
capability for the local `main` window, containing only those command grants. There are no fs,
shell, HTTP, opener or general core-default permissions. Tauri's built-in Channel transport needs
no event-listen/emit grant. Strict CSP is retained. A mock-runtime IPC test verifies local main
access and rejection of another window and remote content using the generated ACL context.
The Windows manifest explicitly retains `asInvoker` and is embedded by the linker for both
the host and test executables, so the ACL mock tests can load Common Controls v6 safely.

References: [Tauri application command permissions](https://docs.rs/tauri-build/2.7.0/tauri_build/struct.AppManifest.html),
[Tauri 2 channels](https://v2.tauri.app/develop/calling-rust/#channels),
[ts-rs declarations and dependencies](https://docs.rs/ts-rs/12.0.1/ts_rs/trait.TS.html).

## Validation

The command-layer tests inject fixture folders, synthetic manifests, process gates and empty
installation inventories. They cover scan/plan/dry-run/apply, preservation, streamed results,
missing confirmations, stale IDs, concurrency, cancellation, defaults, atomic settings replacement
and unpinned fallback. Neither application startup nor real profile/UAC adapters run in tests.
The workspace's existing provider, engine, helper and platform tests continue to check their
independent constraints and the scanned offline hive's bounded cleanup lifecycle.
