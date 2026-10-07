# Local cleanup interface

The redesigned interface supersedes the presentation described in
[25](25-desktop-shell.md), [26](26-home-selection.md) and
[27](27-review-execution-reports.md). Their native contracts and safety boundaries
remain applicable. Rust cleanup commands, generated bindings and cleanup behavior
are unchanged. Window configuration and narrowly scoped window/event capabilities
support custom chrome.

## Overview and selection

Current-account metadata scanning starts when settings load. The first launch uses
the native current-account and Ask defaults without a blocking welcome dialog.
Opening the application never requests administrator access. A remembered all-account
preference requires an explicit Check all Windows accounts action that enables the
helper before scanning. Helper fallback reasons remain visible; the effective mode
is reconciled with native settings.

The main screen has one primary action, Log out locally, and three category
checkboxes for apps, browsers and Windows/developer tools. The whole cell toggles
supported items and profiles; Space/Enter activate it and arrow keys move between
enabled cells. Each shows N of M selected from real detections. The live heading
reflects the selection and the primary action is disabled with nothing selected.
Counts represent selected provider/account
items, including partial profile selections; they do not prove authenticated login.
The sole secondary entry, Customize & settings, contains per-item/profile selection,
account scope, process policy, catalog updates and all existing privacy boundaries.
There are no main-screen tabs.

Selectable, classified known providers start selected even at medium confidence,
with all profiles. High-confidence heuristic detections also start selected.
The earlier `default_selected` filter no longer blocks the normal flow.
Lower-confidence heuristic detections stay unchecked until explicitly selected.
Category controls include all classified selectable detections; confidence alone
never disables a category. Unsupported scopes remain unavailable.
Saving preferences and catalog operations invalidate the old inventory. Rescans
retain previous counts and selections with disabled controls, replace the inventory on completion
and compare detected counts independently of selection. Limited coverage links
directly to per-item review.
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
small tinted status pills. All icons use a shared SVG bitmap with integer CSS pixel
geometry: minimum pitch 4 px, minimum dot width/height 2 px, and exact pitch-multiple
extents. Square dots use crisp-edge rasterization at fractional display scaling.
Small window controls use five-by-five glyphs, others nine-by-nine. Icons never
scale through CSS; the primary icon is 36 px with no disc. Geist
and Doto are bundled locally with their OFL licenses; only the selected-item counter
uses Doto. No UI framework or dependency was added.

Native buttons, inputs, select controls and disclosures support keyboard operation.
Focus is visible, route changes focus the heading and changing state headings are
announced. Reduced-motion preferences show final values instantly with the same
transient delta pills. CSS transforms and opacity animate dots and count strips;
visibility changes pause animation and feedback expiration. `src/motion.ts` owns
all scan timings. Even fast failures stay visible for at least 600 ms. The
1.6-second scan shimmer resolves into the idle logo within 650 ms. Rescans light
additional dots for increases, dissolve dots outward for decreases, and pulse once
for unchanged counts. Only delta pills carry status colors. Responsive rules fit
the configured 900-by-640 and 640-by-480 logical viewports. At higher scaling, long
reviews and results scroll vertically rather than hiding data or controls.

During a rescan only the hero glyph and the animated heading change. Metadata,
description, selection counter, category glyphs and primary-action label and color
stay stable. The unchanged-count pill has a neutral surface and border with a
gently pulsing indicator; it fades away with the other delta feedback. Rescans
retain explicitly deselected items and the surviving selected profile subset.

## Safe browser preview and verification

`pnpm dev` serves `http://127.0.0.1:1420`. Development browser sessions use a separate
mock adapter; native Tauri development sessions and every production build use the
existing IPC adapter. The mock module and preview controls are removed from the
production bundle. The preview explicitly labels simulated data and never reads,
closes or deletes anything on the machine.

Use Customize & settings / Development preview states, or the `?demo=` query:

- `idle`: overview; select Log out locally to review, release early to cancel a hold.
- `scanning`: a persistent metadata scan state.
- `rescan`: alternate scans increase Apps, decrease Browsers and leave Windows/dev unchanged.
- `medium`: selectable known providers with medium confidence, matching native detections.
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
the overview counts selected items and animates icons while scanning, keeping
previous counts visible during rescans. Counts estimate the selection and do not
measure authenticated sessions. Native failures
expose stable statuses/codes rather than detailed, user-safe failure reasons, so
the interface uses conservative reason text and retains action details for review.
Local absence does not prove remote revocation, lasting sign-out or cleared SSO.
These are product boundaries, not changes requested of the backend in this redesign.

## Custom window chrome

The native title bar is disabled, shadow and edge resizing stay enabled, and the
header shares the content background. Only the bar owns `data-tauri-drag-region`;
buttons never carry it. Tauri's injected handler handles dragging and double-click
maximize. Controls have 46-by-32 px hit areas, accessible names and keyboard focus.
Restore follows native resize events. Close hover uses the error status color.

The capability adds only minimize, close, toggle-maximize, internal-toggle-maximize,
start-dragging, is-maximized and event listen/unlisten to existing local commands.
Names were checked against the
[Tauri 2 permission reference](https://v2.tauri.app/reference/acl/core-permissions/).
Windows 11's maximize-button Snap Layout flyout is intentionally unavailable.
Alt+F4, edge resizing and Win+Arrow snapping retain native window behavior;
manual validation remains after the interrupted native window check.

Revision 2 browser evidence uses simulated data only and lives in
[`docs/screenshots/ui-r2`](../screenshots/ui-r2). Overview and magnified icon crops
cover device scale factors 1, 1.25 and 1.5. A compact 640-by-480 viewport has no
horizontal overflow. Keyboard selection and transition to review pass at all three
scales. No real cleanup ran.
