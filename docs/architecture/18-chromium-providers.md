# Declarative execution and Chromium providers

Phase 20 adds `crates/providers/src/executor.rs` and the
[Chromium candidate catalog](../../catalog/browsers/README.md). The canonical project is EveryOut.

## Contract and binding

`ManifestExecutor::load` parses the bundled schema and semantic rules from memory. Trusted Rust
supplies the current-user identity, reviewed installation identity, known-folder resolver and
process coordinator. No UI path override, shell, network interface or content reader is exposed.
One executor binds one filesystem root; multi-root/registry scopes and local API/exception
adapters are explicitly unsupported here. Directory exclusions are not approximated by deleting
the whole directory. File families expand their declared WAL/SHM/journal companions into separate
actions, including absent companions.

`detect` enumerates bounded profile directories and extension IDs with filesystem capabilities.
Profile IDs are opaque; Default and numeric Profile N are supported, with an explicit Opera
root-profile declaration. `describe` projects retained metadata without fresh I/O. `plan` checks
snapshot, owner and selected profiles and fixes every action. Browser targets also pass an exact
artifact-path preservation boundary, independently of their declared family labels. Unresolved
methods, ownership, extensions or preservation conflicts block execution.

`execute` receives the engine-held plan; dry run performs only metadata observations. Apply uses
the engine's guarded local operations and confined platform deletion. `verify` observes each
target and companion without reading bytes; dry-run verification is NotPerformed. `report`
retains partial outcomes, risks and limitations and leaves authentication, identity, sync and SSO
unknown, with remote revocation unsupported. Absence is never proof of logout or key destruction.

`WindowsProcessGate` accepts exact reviewed executable paths in addition to manifest process
names. Preview retains PID/creation-time identities. A changed close set requires a new review;
survivors, unavailable metadata and relaunch block dependent deletion. It uses the platform's
existing current-user/current-session close policies. S7 real-browser behavior remains unverified.
No hook, injection, foreign-memory access, driver or lock bypass is introduced.

Profile discovery and extension directory sets are revalidated before each operation. A newly
added profile or extension invalidates the preview, including a new store that was previously
absent. An expected extension directory may disappear as a result of its own planned deletion.
Underlying platform capabilities refuse path substitution, redirects and hard-link escapes.

## Evidence and tests

The schema gains optional root-profile, per-artifact evidence/confidence, manifest confidence
status and extension-risk policy fields. Existing manifests remain readable. `unverified` status
cannot be promoted to validated support. IDs require Chromium's 32-character a-p grammar, an
explicit source/access date/confidence, supported risk flag and unknown-extension blocking policy.
Only the four reviewed extension/app-setting store names are accepted.

Tests validate every catalog manifest and schema/model parity. The Windows executor tests seed
fresh owned fixture roots for all five layouts and test multi-profile deletion, SQLite sidecars,
dry-run immutability, byte-identical password/history/autofill/configuration/passkey canaries,
distinct Locked failures with partial progress, both extension risk gates, unknown/candidate
blocking, changed snapshots/process prerequisites, added-extension invalidation and misleading
preservation labels. Fixture rules explicitly use synthetic version coverage; shipping manifests
are never promoted by test success. No real browser, account or profile is inspected or closed.

S1-S4 have no recorded results. Shipping artifact closure, DBSC, vendor paths, extension-origin
isolation, PWA discovery and real process behavior remain unverified. Firefox is Phase 21 and
identity/sync handling is Phase 22. No UI, all-accounts mode or non-browser provider is added.
