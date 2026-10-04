# Home scan and selection

The historical screen layout below is superseded by [the UI redesign](28-ui-redesign.md).
Selection policy and native scope validation remain in effect.

Phase 31 adds Home scan results, independent category controls, profile selection,
Windows account grouping and a shared selection passed to a Review placeholder.
No planning, process closure or cleanup runs from this screen.

## Selection policy

The desktop selection policy supersedes the earlier default-selection presentation
rules in phases 19 and 25: high-confidence selectable detections start selected;
medium and low confidence detections appear in collapsed uncertain sections and
start unchecked. Category masters cover only their category, including its uncertain
entries. Selecting a candidate does not validate support, ownership or cleanup rules.
Unclassified discoveries, inaccessible accounts and discoveries without an engine
provider remain disabled. S8 calibration is still pending; high confidence is not a
measured probability. No detection scoring rule or execution gate changes.

The scan DTO projects this policy in `default_selected`. Internal legacy engine and
scanner defaults are retained for their existing callers; the desktop uses the scan
projection. All three category summaries count selected provider/account instances,
including partially selected instances, rather than individual profile leaves.

## Native contract and scope

Scan items include opaque profile IDs, typed risk flags and loss assessment from the
engine description, fixed metadata signal IDs, unverified status and a browser warning.
Unverified status reflects candidate support or reported unverified limitations in
current mode and catalog evidence status in all-account mode. Browser identity/sync
metadata cannot establish authenticated sign-in or active synchronization. Browsers
therefore retain a restoration warning for unknown state as well as detected artifacts.
The interface never renders raw limitation codes, paths or rejected command payloads.

`SelectionRequest.profiles` optionally narrows individual selected current-account
instances. Omission retains whole-instance compatibility. Native validation rejects
empty, duplicate, foreign or unselected profile scopes before consuming inventory;
the engine independently checks scope and binds exact profiles to the provider plan.
The engine's existing preparation entry point continues to select all profiles.

The elevated helper currently binds one indivisible provider scope per Windows account.
Home expands providers into Windows accounts with independent account checkboxes and
explicit indivisible-scope text. It does not offer profile checkboxes for these scopes.
The elevated bridge rejects profile overrides rather than silently expanding them.
No helper protocol, trust pin, capability or execution authority is broadened.

## State and verification

Scanning is explicit, has a loading state, prevents duplicate calls and sanitizes errors.
Every scan clears previous selection. Saving settings invalidates inventory and review,
including mode changes and helper fallback. Navigation preserves selection in App state.
Review stores the inventory ID, selected instance IDs and exact profile subsets and
navigates to a placeholder; phase 32 will build and display a native plan there.

Native checkboxes implement checked, unchecked and indeterminate states. Details and
summaries expose providers, profiles and Windows account groups to keyboard users.
English copy is centralized in the strings module. No network or filesystem plugin
is added. Frontend tests mock the complete API and cover policy, independence, partial
states, badges, warnings, retries, invalidation and review transfer. Native tests use
temporary synthetic fixture stores to check profile narrowing and hostile scope IDs.

Phase 32 replaces the placeholder with [review, execution and reports](27-review-execution-reports.md).
Returning from review clears the consumed inventory and requires a fresh Home scan.
