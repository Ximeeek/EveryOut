# Testing destructive operations in EveryOut

Phase 10 strategy, 2026-09-30. Phase 17 adds the
[synthetic profile harness](../../crates/test-support/README.md) and
[manual VM guide](../testing/vm-guide.md), with guarded Windows adapter tests. Phase 18 adds the
[current-account wipe engine](16-wipe-engine.md) and guarded execution tests. Real providers and
the broader acceptance matrix below remain future work. Passing synthetic
tests does not establish authentication closure or complete destructive-harness validation.

## Evidence and invariant oracle

Use [browser research §§1, 3–7](../research/01-browsers.md) for companion families, DBSC,
mixed-store preservation and restoration; [Windows research §§3, 5–6](../research/02-windows-identity-and-multi-account.md)
for secret-returning APIs, profile/hive/IPC boundaries and anti-cheat constraints; and
[application research §§1–3, 5–6](../research/03-apps-detection-process-av.md) for ownership,
shutdown and security-product uncertainty. Test the existing [contract](01-provider-contract.md),
[manifest rules](02-manifest-spec.md), [sequence](05-wipe-sequence.md) and
[permission model](06-permission-model.md), with adversarial cases from [10](10-threat-model.md).

Required oracles are: only approved effects occur; preservation exclusions win; no secret
content is read, copied, decrypted or transmitted; dry run has no mutation/process effects;
stale approvals cannot widen scope; and partial outcomes are reported honestly. Assert metadata
absence only for supported planned targets. It is never an authenticated-session oracle.

## Synthetic fixtures and containment guard

Generate fake profile trees with expected artifact names, empty files, seeded random bytes,
synthetic sidecars and preservation sentinels. Random bytes stand in for opaque session content;
never capture real profiles, cookies, tokens, wallet seeds, credential dumps or employee accounts.
Fixtures should include Unicode/spaces, long paths, unknown versions, residue, shared roots and
multiple fake user/profile identities. Random payloads cannot validate a real SQLite schema or
browser logout; record that limit rather than inventing valid authentication stores.

For operations needing structure, use synthetic non-secret configuration fields or schema-only
databases created from public formats, with no authentic credential payload. Tests do not grant
permission to implement content reads: the production metadata adapter still never reads payloads.
The `metadata-discovery-allowlist` and `browser-sync-profile-edit` gates remain in force.

Before any destructive integration test, create a unique temporary fixture root, resolve its
absolute physical identity and inject an immutable allowed-root capability into the shared
platform mutation boundary. Root authority comes from the harness, never from a manifest, UI
request or ambient helper environment. Refuse startup if the root is missing, redirected,
ambiguous, a drive root, actual user profile, real AppData, network location or production store.
An environment variable or a filename marker alone is insufficient proof of confinement.

Every mutation, including recursive descendants, retries, registry adapters and helper actions,
must pass the guard. Registry tests use only an exact unique disposable test namespace; hive tests
use only harness-created synthetic hives in a VM, not host user hives. Process tests launch only
harness-owned dummy processes and validate their identity/session; never close a real browser on
the developer host. Existing fake roots must not cause a production API/CLI fallback.

Check root/owner identity and reject reparse traversal at the operation boundary. A sibling such
as `fixture-other` must not pass a prefix check for `fixture`; test ancestor substitution and leaf
replacement too. Unknown alias/race behavior blocks deletion until `destructive-root-confinement`
is resolved. The guard must be exercised through the real destructive adapter, not solely a mock.
Production uses reviewed owner roots under [02](02-manifest-spec.md); a test guard cannot create
an arbitrary-root option in the shipping application.

Place synthetic canaries outside the allowed deletion root and within preserved fixture families.
The harness may compare/hash its own random canaries to prove they remain unchanged; the wipe
code receives no payload reader. Record mutation/read attempts through narrow adapter spies,
and validate actual OS behavior in confined integration/VM cases. Mocks alone cannot prove
absence of unauthorized I/O. Harness confinement and read-observation fidelity remain
`destructive-test-harness-validation`.

## Three test tiers

| Tier        | Environment and scope                                                                                                                                                            | Required cases and evidence                                                                                                                                                                                                                                                                                                                                              |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unit        | Pure model/parser/planner/report tests with fake metadata and spy operation interfaces; no real deletion.                                                                        | Manifest rejection, deny-over-include, ownership conflicts and deduplication, candidate blocking, version coverage, confidence independence, plan/confirmation invalidation, dry-run no-effects, error/partial aggregation and report redaction. Catalog tests cover authenticated bytes, version rules and failure states from [12](12-catalog-update-design.md).       |
| Integration | Real Windows filesystem/registry adapters under the validated fixture guard; synthetic roots and exact test namespaces only. Privileged/profile/IPC cases run in disposable VMs. | Sidecars, directories, preservation canaries, absent targets, denied/locked objects, cancellation and interrupted results; adversarial traversal/reparse/hard-link/race tests; helper identity/replay/disconnect failures; no cross-user scope fallback. Assert attempted and actual effects, stable errors and unchanged out-of-scope fixtures.                         |
| Manual VM   | Disposable Windows 10/11 VMs with snapshots and no host profile access; representative product/channel and security-product versions.                                            | Reviewed plan/loss warnings, current/all-account/UAC cancellation, loaded/RDP-profile exclusions, graceful/approved force-close loss, relaunch, local verification and separate identity/sync/DBSC uncertainty. Validate signed update rejection, interrupted activation, high-water recovery and offline wipe. Retain a sanitized reproducible matrix and observations. |

Automate repeatable VM integration cases where practical; manual observations supplement them.
Do not substitute frontend snapshots or scaffold tests for the destructive adapter tests.
Coverage should follow explicit effects and threats, rather than a target line-coverage percentage.

## VM workflow and failure matrix

Take a clean baseline snapshot before each destructive scenario. Use disposable local Windows
accounts, synthetic profiles and dummy apps/processes. Disable host folder sharing, clipboard
and profile import; never mount personal home/profile trees into the guest. Keep test archives
and snapshots free of real secrets. Restore the baseline after each case, including failed runs,
and verify canaries before teardown. Snapshot/revert belongs to lab infrastructure; EveryOut
itself never backs up secret stores or promises undo under [08](08-not-doing.md).

Run ordinary offline wipe cases with networking disabled. Network-enabled catalog tests use only
test bundles/endpoints, outside an active wipe; then disable networking and confirm the accepted
catalog still works. Failure cases include invalid signature/key, old version, equal version with
different bytes, incompatible parser/app, incomplete download, corrupt local state and crashes at
each activation boundary. They must leave no unverified catalog executable.

For filesystem cases, attempt `..`, absolute/UNC/device paths, sibling-prefix escape, root/parent/
leaf junction or symlink, hard-link alias, preserved ancestor overlap, and deterministic target
substitution after dry run and immediately before deletion. Race tests must force the interleaving
and assert outside canaries survive; repeated stress runs supplement that evidence. Unsupported
filesystems/semantics yield refusal, not a skipped safety assertion counted as passed.

For execution cases, cover zero-effect dry run, already-absent idempotence under quiescence, one
locked companion after another succeeds, cancellation after an applied action, helper disconnect,
security-product denial, process PID reuse/relaunch, and loaded-profile changes. Preserve received
outcomes and label unknown effects; never report a requested deletion or zero exit code as absence.
See [05](05-wipe-sequence.md#failure-handling) and [06](06-permission-model.md).

Real product installs with unused/test-only profiles can establish layout and preservation
behavior. They cannot establish login/DBSC refresh behavior using random bytes. Authentication,
restart and expiry/refresh experiments remain `browser-artifact-closure` future work: any test-site
method must first prove compatibility with never reading, copying, decrypting or transmitting
secrets. Do not introduce real test-account tokens, network login probes or secret snapshots as
an exception. If compliant evidence is unavailable, authentication closure stays unknown.

AV/EDR cases follow `metadata-av-compatibility`: record exact product/policy/version and distinguish
file verdict, behavioral alert and access-policy denial. No security disablement, evasion,
hooks, injection, foreign-memory reads or drivers. A blocked case is an observed limitation,
not a passed cleanup case; sanitized synthetic evidence supports the [false-positive plan](10-threat-model.md#avedr-false-positive-mitigation-plan).

## What a verified catalog entry means

Keep three axes independent: catalog evidence confidence (`high`/`medium`/`low`), manifest support
(`candidate`/`validated`) in [02](02-manifest-spec.md), and runtime detection confidence in
[03](03-heuristic-detection.md). No score means probability of an active login or authorizes deletion.
The following is proposed acceptance policy derived from the dossiers' verified/hypothesis
distinction; thresholds and representative sampling remain `catalog-verification-matrix`.

| Catalog evidence confidence | Meaning and required evidence                                                                                                                                                                         | Execution implication                                                                                                                                                               |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Low                         | Hypothesis, incomplete source leads or uncorroborated layout; missing ownership, effects or compatibility evidence is explicit.                                                                       | Candidate; no executable cleaning scope derived from the weak claim.                                                                                                                |
| Medium                      | Relevant primary-source/pinned implementation evidence plus partial synthetic or VM corroboration; safety/coverage or version matrix remains incomplete.                                              | Keep unresolved rule candidate; medium confidence cannot waive missing safety evidence.                                                                                             |
| High                        | Claim-specific primary evidence and reproducible unit/integration/VM results for the declared revision, effect and OS/product/channel/version tuple, with reviewed preservation and failure behavior. | Eligible for validated support only after every safety gate below passes. A high-confidence path alone, such as the candidate in [02](02-manifest-spec.md), remains non-executable. |

Mark an entry **verified for its declared local scope** only when its exact immutable rule revision
has reviewed provenance, known exclusive/shared ownership, declared effects/risks/exclusions and
explicit compatibility; all three applicable tiers pass; the guard/no-secret/offline invariants
hold; preservation, companions, failure/partial reporting and stale-plan tests pass; and no
blocking spike remains for an executable action. Unsupported operations remain blocked and
excluded from that declared verified scope. A non-applicable tier/case requires a written reason
and review; failure or unknown evidence cannot be relabeled non-applicable.

Store a sanitized evidence record: provider ID/revision, catalog digest/version, exact Windows and
product/channel versions, fixture seed/generator revision, test-code revision, commands/cases,
expected/observed metadata effects, preservation results, limitations, reviewer and date.
No profiles or payloads accompany it. Bind confidence to individual claims so a proven cookie path
does not promote unknown identity, sync, DBSC or remote logout claims. Changed rules/effects or
versions outside the matrix require renewed validation; unknown versions cannot inherit support.
A signature carries the record's identity, not an independent proof that tests passed.

## Checks and OPEN DECISIONS

Current repository checks are documented in [CONTRIBUTING](../../CONTRIBUTING.md#quality-checks):
Rust formatting, Clippy and workspace tests; frozen frontend install, lint, typecheck, formatting
and build; and commit lint. Later destructive test commands must be documented when a harness
exists. No invented command or empty test suite counts as provider verification in this phase.

| Named spike                           | Evidence needed                                                                                                                                                                                      | Until resolved                                                                          |
| ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| `destructive-test-harness-validation` | VM isolation/snapshot procedure, unforgeable fixture-root authority, registry/process/helper containment, actual OS I/O observation and canary checks; existing dossiers do not establish a harness. | No destructive host tests or real-profile fixtures; pure tests and design review only.  |
| `catalog-verification-matrix`         | Representative OS/product/channel/version and preservation matrix, confidence promotion/review rules and evidence invalidation; browser/app dossiers leave completeness unverified.                  | No entry promoted solely from citations, fixture success or a signed `validated` label. |

Reuse `destructive-root-confinement` from [10](10-threat-model.md#open-decisions), catalog spikes
from [12](12-catalog-update-design.md#open-decisions), and existing closure, ownership, process,
permission, sync and AV spikes from [00](00-overview.md#open-decisions),
[05](05-wipe-sequence.md#open-decisions), [06](06-permission-model.md#open-decisions) and
[07](07-sync-and-identity.md#open-decisions). This phase defines acceptance evidence without
claiming those investigations have run.
