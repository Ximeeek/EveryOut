# Local cleanup interface

The redesigned interface supersedes the presentation described in
[25](25-desktop-shell.md), [26](26-home-selection.md) and
[27](27-review-execution-reports.md). Their native contracts and safety boundaries
remain applicable. Rust commands, generated bindings, capabilities and cleanup
behavior are unchanged.

## Overview and selection

Current-account metadata scanning starts when settings load. The first launch uses
the native current-account and Ask defaults without a blocking welcome dialog.
Opening the application never requests administrator access. A remembered all-account
preference requires an explicit Check all Windows accounts action that enables the
helper before scanning. Helper fallback reasons remain visible; the effective mode
is reconciled with native settings.

The main screen has one primary action, Log out locally, and a one-line summary for
apps, browsers and Windows/developer tools. Counts represent selected provider/account
items, including partial profile selections; they do not prove authenticated login.
The sole secondary entry, Customize & settings, contains per-item/profile selection,
account scope, process policy, catalog updates and all existing privacy boundaries.
There are no main-screen tabs.

Only high-confidence, selectable, classified items with `default_selected` start
selected. Uncertain detections stay unchecked. Unsupported scopes remain unavailable.
Saving preferences, catalog operations and a new scan invalidate the old inventory.
The backend retains responsibility for support, ownership and protected-store checks.

## Deliberate confirmation

The primary action builds a plan and runs its metadata-only preview. A permanent-loss
notice summarizes the affected data, Windows sign-in limitations and force-close
risks where applicable. Per-item effects, relative paths, risk descriptions and
processes are available in a disclosure on the same screen.

A continuous 1.2-second mouse, Space or Enter hold confirms the displayed plan. An
ordinary click never executes. Early release, pointer departure/cancellation, Escape,
focus loss, window blur, visibility changes and unmount cancel an incomplete hold.
One complete hold submits the original per-item risk flags and confirmation IDs,
category tokens and, for an existing force-close policy, the reviewed account IDs.
The native validator still rejects stale plans, missing approvals and protected scope.
There is no undo or backup claim.

In Ask mode, open programs replace execution with Hold to close programs. The hold
only requests native graceful closure. A fresh scan, plan and second deliberate hold
are required before deletion. Manual closure can be rechecked; dependent items can
be skipped. Scope matching must resolve exactly one provider/account and retain every
originally selected profile. No automatic force termination is introduced.

## Progress and outcomes

Native progress and item events update the three category summaries. Foreign and
late terminal events are ignored. Stop remaining work sends cancellation for the
active plan; already completed changes remain irreversible.

Results show Done only for verified complete local item results without account,
scan or skipped-scope gaps. Otherwise the heading states how many items need
attention or asks the user to check coverage. Problems appear first with concise
reasons. Locked or failed items have an individual retry action that starts a fresh
plan for that provider/account and the original profile subset, requiring a new hold.
Unknown or blocked effects are never represented as successful removal.

Received results survive stream failure. Unacknowledged items remain unknown and
cannot export an older native report. Skipped choices and residual account hives stay
visible. Detailed effects and native JSON/text exports are behind disclosures. Every
result states that remote sessions remain active and Windows or sync may sign in again.

## Visuals and accessibility

Plain CSS tokens define the near-black surfaces, white text, three grey steps and
small tinted status pills. All custom icons use the same nine-by-nine round-dot SVG
component. The animated progress grid and success mark share that geometry. Geist
and Doto are bundled locally with their OFL licenses; only the selected-item counter
uses Doto. No UI framework or dependency was added.

Native buttons, inputs, select controls and disclosures support keyboard operation.
Focus is visible, route changes focus the heading and changing state headings are
announced. Reduced-motion preferences disable dot animation. Responsive rules fit
the configured 900-by-640 and 640-by-480 logical viewports. At higher scaling, long
reviews and results scroll vertically rather than hiding data or controls.

## Safe browser preview and verification

`pnpm dev` serves `http://127.0.0.1:1420`. Development browser sessions use a separate
mock adapter; native Tauri development sessions and every production build use the
existing IPC adapter. The mock module and preview controls are removed from the
production bundle. The preview explicitly labels simulated data and never reads,
closes or deletes anything on the machine.

Use Customize & settings / Development preview states, or the `?demo=` query:

- `idle`: overview; select Log out locally to review, release early to cancel a hold.
- `scanning`: a persistent metadata scan state.
- `preparing`: select the primary action to freeze the read-only plan preparation.
- `running`: review and hold to freeze category progress; Stop produces a stopped report.
- `partial`: review and hold for two locked failures and individual retry actions.
- `success`: review and hold for verified local results.
- `error`: a sanitized scan error.
- `processes`: open-program handling and a fresh review after gentle closure.
- `empty`: no selected items.

Frontend tests mock the client and cover state transitions, hold interruption,
duplicate prevention, exact approval payloads, Ask/force boundaries, foreign events,
cancellation, scoped retry, profile mismatch, retained results, skipped-only reports,
coverage and settings fallback. Required commands are `pnpm lint`, `pnpm typecheck`,
`pnpm test`, `pnpm format:check`, `pnpm build` and `pnpm bindings:check`.

Browser screenshots and validation use only the mock adapter. Real vendor cleanup,
UAC and Windows/WebView scaling still require the existing synthetic-store/VM workflow.

## Backend limitations

The scan has no authenticated-session count or per-category scan-progress events;
the overview counts selected items and says Checking while scanning. Native failures
expose stable statuses/codes rather than detailed, user-safe failure reasons, so
the interface uses conservative reason text and retains action details for review.
Local absence does not prove remote revocation, lasting sign-out or cleared SSO.
These are product boundaries, not changes requested of the backend in this redesign.
