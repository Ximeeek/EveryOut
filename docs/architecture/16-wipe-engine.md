# Current-account wipe engine

Phase 18 adds `everyout-engine` as a workspace library. It is not wired to Tauri or the desktop
UI. There are no catalog entries, application discovery rules, network operations, elevated
helpers or all-account fallback. Trusted Rust providers supply existing `Provider` methods
and the additional `EngineProvider` hooks; current-user platform capabilities supply
`LocalOperations`. Production integration must use the current-user resolver from Phase 15,
never the fixture feature or arbitrary caller roots.

## Review and execution

`Engine::scan` calls metadata-only detection and pure description for a requested category.
It rejects foreign owners, duplicate instance IDs and mismatched description identities.
Phase 25 leaves low-confidence application candidates unchecked, including known providers.
Other resolved known-provider instances follow Phase 19's selection policy. Explicit `detection_origin` keeps all
heuristic instances unchecked, including high, until S8 passes; missing provenance in old JSON
defaults to heuristic. Selection does not waive supported-scope validation or review gates.
Explicit selections cannot name unknown instances or another category. See
[detection and scope clarifications](17-detection-classification.md).

`Engine::prepare` fixes the inventory, instance/profile selection, manifest revision, owner,
actions, shared effects, risks, process identities and close policy. It checks the logical
target claims and requires every shared owner to be selected within the requested category.
Providers must resolve physical aliases before planning: duplicate logical target claims are
refused, not independently deleted. The engine cannot establish physical identity from opaque
artifact IDs. Final Windows confinement and retained-handle identity remain platform duties.

Preparation runs `Provider::execute(DryRun)` through a metadata-only facade whose `apply`
method refuses all mutations. Preview deletion verification is always `NotPerformed`.
The authoritative preview comes from metadata, not simulated execution success. Neither
closing nor identity/sync hooks run in dry mode. A mutation attempt blocks later execution.

The engine-held `PreparedRun` cannot be deserialized or expanded from UI input. It is consumed
by `apply` and bound to its originating engine. Risk confirmations name an exact instance and
specific flags in that preview. Windows/Microsoft + developer-tools additionally needs a
separate category token from that same preview. Known irreversible loss without named flags,
unknown loss/flags, candidate support, preservation exclusions and unresolved blockers cannot
be confirmed away. Force closing separately requires unsaved-work acknowledgment, with the
chosen policy and exact process set visible in review.

Before closing, the engine compares a fresh plan and description with the retained plan,
rechecks existence/type/size observations and the process preview. Changes require a new scan
and review. `EngineProvider::close` must use only that plan's retained, reviewed process set and
the Phase 16 current-user closing adapter. `revalidate` must establish exit, owner/scope and
absence of relaunch before each operation and through verification. No successful no-op closing
default is provided. Providers with no process dependencies explicitly declare an empty set.
The engine does not discover processes or broaden the selected set.

Live provider execution receives an operation facade restricted to that immutable plan and its
actions. The facade blocks repeated/unplanned mutations and cancellation, and revalidates the
process prerequisite before each mutation. It retains actual adapter outcomes even when the
provider returns different results. Missing operations are skipped with an explicit issue;
invented `Applied` outcomes cannot establish success. Providers must continue scheduling
independent actions after item failures under the existing contract. Independent instances
continue after another instance fails its review or closing gate.

After cleaning, a separately revalidated `identity_sync` hook runs even when a cookie action
failed. Its default declares no applicable operation; browser identity and sync remain unknown.
The hook is reserved for reviewed, local, idempotent operations in later phases. No remote
revocation or concrete sync edit is implemented. Cancellation stops new mutations and the hook,
preserving earlier outcomes and metadata verification.

## Verification and reporting

The engine performs common verification directly through `MetadataAccess`, rather than relying
on provider-returned absence claims. This is a deliberate common scheduling/projection choice:
`Provider::verify` and `Provider::report` remain available for later provider-specific adapters,
but are not used as an authoritative success oracle here. Deletion is verified by absence;
present targets, denied observation and process relaunch produce residual/inaccessible/unknown
results. Non-deletion operations remain unknown under metadata-only verification. No empty
database, operation exit code or zero-byte file is accepted as session absence.

JSON and human-readable reports always contain three independent category sections. Other
categories say `NotRequested`. Reports retain full plans, logical paths, statuses, specific
issues, process effects, risk flags, coverage limitations and succeeded/failed/skipped/locked
counts. Paths are reviewed root-relative labels from trusted providers, an intentional response
to the Phase 18 path-report requirement; raw account names and credential targets are not
introduced. Explanations at the operation boundary use stable codes, never arbitrary OS output.
Only trusted, secret-free provider declarations belong in names, IDs, labels and plan strings.

`CompleteLocalScope` only means that all supported planned deletion targets are absent and
all operation outcomes succeeded/already absent. DBSC key-reference exclusions remain visible;
identity, sync, silent SSO and authentication uncertainty are separate. Missing cookies do not
prove destroyed keys, refresh failure, safe restart, account sign-out or remote revocation.

Each run starts with a fresh inventory. Already-absent artifacts produce no-op outcomes without
creating stores. Under quiescence, the second run reports all targets `AlreadyAbsent`, unchanged
fixture metadata and the same coverage limits. Restored data requires fresh review.

## Validation

`cargo test -p everyout-engine` runs Windows integration tests using Phase 17's generated
`FixtureFolders` and the real guarded file adapter. The test-only provider has no catalog entry.
Cases cover full cookie-family deletion, unchanged dry run, idempotence, a real denied-delete
sharing lock, both independent review gates, specific risk subsets, stale revision/metadata and
process sets, independent instances, cancellation, relaunch, inaccessible verification, forged
provider success, force-close acknowledgment, wrong-engine approval and excluded preservation.
A synthetic content sentinel is written by the harness; the engine never receives its bytes
and neither JSON nor text contains it. Metadata snapshots check unchanged preserved/outside
fixture targets. Process hooks in these tests are controlled spies; Phase 16 separately tests
the Windows closing adapter with owned dummy processes.

Full Windows/AV matrix, read-observation fidelity, hostile race review and real browser DBSC
closure remain open under the existing architecture gates. Synthetic tests establish only
their declared local effects. No host profiles or authentic session payloads are used.
