# Desktop shell and settings

Phase 30 adds the EveryOut React shell. Home is a placeholder for phase 31;
this phase never scans, plans, closes programs or clears session data. Settings
and About are reachable through keyboard-accessible navigation. The first-run
native modal makes the shell inert until its choice is successfully saved.

All English UI copy lives in `src/strings.ts`. About summarizes all fifteen
boundaries in [08](08-not-doing.md). Its other-account wording follows the
phase 28 supersession documented in [06](06-permission-model.md) and
[23](23-all-accounts-mode.md): loaded accounts are not categorically excluded,
and reviewed cross-session process termination has separate approval gates.
It retains the exclusion of forced cleanup of every profile without repeating
the earlier design's outdated blanket exclusions.

## Settings and administrator access

The UI loads settings through `getSettings` and uses `setSettings` to persist
process policy, account preference and first-run completion. The first-run
question defaults to the current account. Choosing all accounts and submitting
explicitly calls `enableAllAccountsMode` before saving its returned effective
mode. The same sequence applies when Settings changes current to all accounts.
Loading a remembered preference never launches UAC.

Every helper fallback, including declined UAC, reports its stable reason and
saves current-account mode without retrying elevation automatically. No scan
is triggered here; any future execution needs fresh inventory and review.
Failure after helper enablement reloads native settings to reconcile changes
that the helper command may already have persisted. First-run completion is
not assumed after a failed save. Failed initial loading offers an explicit retry.

Force close after two seconds shows the full unsaved-work warning and requires
acknowledgment before changing from Ask. That interaction does not replace the
engine's later per-account and per-plan force-close approval. The existing
Settings DTO has no acknowledgment field; the UI does not add a second store.

## Errors, permissions and validation

Commands use only `src/api`. Notices map known stable errors and helper reasons
to fixed copy; unknown error objects and arbitrary rejected strings are never
rendered. Pending saves disable the form and navigation and reject duplicate
submissions. Native capabilities, Rust sources and generated DTOs are unchanged.

`pnpm test` runs Vitest with React Testing Library and jsdom. The complete API
module is mocked; tests never start native commands, UAC, scans or cleanup.
Tests cover both first-run answers, subsequent launches, all helper fallback
reasons, persistence, force-close acknowledgment, read/write failures, safe error
messages, reconciliation, duplicate submissions and every About limitation.
The jsdom dialog shim covers modal visibility; actual browser top-layer focus
containment and UAC prompts are provided by Windows/WebView and are not proven
by these fixture tests. CI runs the frontend tests alongside existing checks.
