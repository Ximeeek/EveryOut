# Updating the EveryOut provider catalog

Phase 10 target design, 2026-09-30. Catalog updates distribute manifests and associated descriptive
metadata independently of application releases. No updater, signature implementation, production
key or catalog service is added here. Executable/application update design and release policy
remain outside this phase.

## Evidence and limits

The catalog consumes [02](02-manifest-spec.md): declarative roots, typed methods, immutable provider
revisions, explicit compatibility, evidence, preservation and risk fields. [00](00-overview.md)
and [ADR 0003](../adr/0003-rust-command-capability-boundary.md) keep plan authority in Rust;
[05](05-wipe-sequence.md) invalidates approval when rule revision/effects change.
[Browser research §§1, 5–7](../research/01-browsers.md) and
[application research §§1–4, 7](../research/03-apps-detection-process-av.md) show why layouts,
ownership, mixed stores and source provenance need versioned review. Application §3 also rules
out an uncredited automatic import of broader Winapp2 deletion expressions.

The dossiers do not establish a catalog signing protocol, rollback storage or atomic activation
mechanism. The signed-bundle direction is a requested architectural requirement; detailed choices
below are acceptance requirements, with named implementation-blocking spikes. They do not claim
that a particular crypto library or update framework has been selected or audited.

## Bundle contents and immutable versions

Use a complete catalog snapshot, with detached signature and a signed envelope binding its
identity and every payload byte. Prefer a bounded, non-executable container whose entries are
identified by provider IDs; never extract attacker-chosen paths into profile or application trees.
Exact encoding/container and limits are `catalog-signature-protocol`.

| Signed field/content                             | Meaning                                                                                                                                                                              |
| ------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Domain/product and channel                       | Explicit EveryOut catalog purpose and approved channel; signatures for another product/purpose are invalid.                                                                          |
| Envelope and manifest format versions            | Separate parser/schema compatibility versions; unknown versions fail closed.                                                                                                         |
| Catalog version                                  | Strictly increasing integer within the embedded trusted channel/key lineage; never ordered by wall-clock date or display string. Integer bounds/overflow behavior must be specified. |
| Minimum/maximum compatible app or engine version | Explicit interpreter compatibility; an incompatible catalog requires an application release instead of a fallback interpretation.                                                    |
| Provider IDs, immutable revisions and manifests  | Unique IDs; every changed declaration has a new revision. Unchanged revision cannot acquire different bytes. Removed providers are visible removals.                                 |
| Payload lengths and cryptographic digests        | Authenticate exact manifest/evidence/changelog membership and bytes, not only a list of filenames.                                                                                   |
| Evidence/validation references and limitations   | Reviewed claim-level evidence identifiers from [11](11-test-strategy.md); no user data or secrets.                                                                                   |
| User-visible changelog                           | Added/changed/removed providers, compatibility, effects, preservation/risk changes and new limitations; authenticated together with rules.                                           |
| Key identifier                                   | Select only a locally embedded trusted key; an ID or public key supplied by the bundle cannot grant itself trust.                                                                    |

Bundles contain manifests, evidence descriptions, changelog and necessary provenance/license
notices only. No Rust/JavaScript/Wasm, DLLs, scripts, SQL, shell strings, plugins, binaries or new
adapter implementations. Fixed method/exception-adapter IDs may reference only already shipped,
reviewed implementations; unsupported IDs are rejected. Catalog data cannot widen compiled safety
policy, add metadata-read exceptions, enable `revoke()` or bypass preservation/confirmation gates.
New code, root kinds or semantics require an application release and architecture review.

## Embedded-key verification and activation

Rust owns fetching/import, verification, compatibility, persistence and activation. The main UI
receives sanitized status/changelog and cannot label bytes trusted. Bundle bytes are project
configuration, distinct from secret-bearing profiles; reading them does not authorize reading
session content under [00](00-overview.md).

1. Outside an active wipe, optionally fetch from the configured catalog endpoint over authenticated
   transport, or import the same signed bundle from a local file. Do not upload inventory, profile
   identities, paths, reports or secrets. Endpoint, redirects, request minimization, proxy behavior
   and opt-in/check scheduling remain `catalog-update-transport`.
2. Stage into a dedicated bounded catalog area, never target profile roots. Enforce byte/count/
   nesting/time limits before expensive parsing; reject oversized, truncated, duplicate or unsafe
   container entries. If compression is adopted, expansion bounds and no links/path extraction are
   mandatory. These defenses need `catalog-signature-protocol` validation.
3. Verify the signature against an embedded trusted public key and a precisely defined signed
   byte representation, including all envelope fields and payload digests. A downloaded key,
   transport certificate, hash alone, filename or UI acknowledgment cannot substitute for this.
   Cryptographic algorithm, canonicalization/domain separation and vetted library are OPEN DECISIONS.
4. Parse strictly; reject duplicate keys/IDs, unknown or ambiguous fields, unsupported formats,
   methods, root kinds and incompatible engine/app ranges. Enforce the ordinary manifest grammar,
   evidence/risk completeness and hard safety constraints, even after a valid signature. Reject
   the whole bundle on invalid membership instead of silently executing a partially parsed update.
5. Check catalog monotonicity, immutable per-provider revisions and persistent anti-rollback state
   below. Do not derive freshness from an untrusted local clock. Signature validity alone is not
   freshness, safe scope or a test-pass attestation.
6. Show installed/proposed versions and the authenticated changelog, including increased effects,
   risks and removed support. Require explicit catalog activation acceptance; this accepts the
   rule set only, never approves a wipe. Treat changelog as inert text, with no executable HTML or
   privileged links. Actual effects still come from validated rules and the normal plan review.
7. Persist verified bytes/digest and high-water state as one crash-consistent activation, then
   expose an immutable active snapshot. `catalog-activation-rollback-state` must prove recovery
   at every boundary before remote activation is implemented. Serialize activations; don't trust
   a writable cache file merely because it was verified earlier.
8. Reverify persisted bytes when loading; bind digest/catalog version/provider revisions to the
   inventory and engine-held plan. Activation invalidates old inventories/plans/approvals. The
   helper verifies the same snapshot identity and rules independently under [06](06-permission-model.md).

Do not activate during scan, dry run, review or execution of a wipe. An active run uses a pinned
accepted snapshot; update acceptance waits until it ends. On an unexpected snapshot mismatch,
block affected work and require rescan/review. No silently substituted rule or helper version.

## Anti-rollback and offline operation

Maintain the highest accepted catalog version and digest for the trusted lineage in local state
separate from downloaded bundles. Seed the initial floor from the embedded bundled catalog.
Reject lower versions; accept an equal version only as identical digest/content for an idempotent
reload. Equal version with different content is invalid. A higher catalog version cannot restore
an older provider revision or reuse a revision with different bytes; retain provider revision
history/tombstones across removals. A corrective rule is published as a new revision in a higher
catalog version, never by downloading an older bundle.

Crash recovery must reconstruct one coherent accepted snapshot and floor, or disable catalog
execution until repaired. After raising the floor, never automatically switch to an older embedded
catalog just because the active cache is corrupt. Before any remote update, the embedded verified
catalog is usable at its initial floor; after an update, only a valid accepted version at/above
the floor is eligible. A staging failure leaves the current accepted snapshot unchanged.

Storage layout, integrity protections, transaction/recovery ordering, concurrency, reinstall/
migration and missing-state handling remain `catalog-activation-rollback-state`. Unexpected
missing/inconsistent state in an existing installation blocks execution; recovery must not
silently reset the floor. A genuinely new install starts at the embedded floor. Distinguishing
fresh install from deliberate complete state erasure is not solved here. Local anti-rollback
cannot guarantee protection against an administrator restoring the entire machine or deleting
all app state; do not claim hardware-backed rollback resistance.

An embedded public key is the initial trust anchor. Do not allow downloaded catalogs to replace
it. Interim recovery from suspected key compromise is to disable catalog updates/affected rules
and require a reviewed application release carrying a new trust anchor and migration floor.
Routine rotation, signed revocation/expiry metadata, thresholds and secure time are
`catalog-key-lifecycle`, not implemented capabilities. Offline clients cannot learn immediate
revocation or prove they hold the latest available catalog; a network attacker can deny/freeze
updates even while signatures and monotonicity are enforced. Show installed version and last
successful check as status, not proof of freshness; offline availability must not imply freshness.

**The wipe never needs network access.** No fetch, freshness probe, telemetry, vendor logout,
server revocation or online signature service occurs in detection, planning, process closing,
execution or verification. Optional update I/O is a separate operation; missing connectivity
does not block a wipe using a locally accepted, compatible catalog. Offline does not override a
known invalid catalog, missing anti-rollback state or ordinary provider safety blocker.
See [05](05-wipe-sequence.md), [08](08-not-doing.md) and Windows research §4.

## Failure behavior

| Failure                                                                            | Required behavior                                                                                                                                                 |
| ---------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Network unavailable, download timeout or user declines activation                  | Keep the accepted local snapshot and its limitations; show update status separately from wipe results. No network retry inside a wipe.                            |
| Invalid signature, untrusted key, malformed bundle or incompatible version         | Reject activation, retain current accepted snapshot, show sanitized reason. No unsigned/manual override or partial acceptance.                                    |
| Lower version, changed bytes at equal version or provider revision reuse/downgrade | Reject; preserve high-water state. Offer a newer signed corrective bundle or compatible app release, never rollback approval.                                     |
| Crash, storage full or permission failure before activation commits                | Recover previous coherent accepted snapshot/floor or block if coherence cannot be established; never infer success from a staged file.                            |
| Active cache corrupted or state missing/inconsistent after activation              | Block affected catalog execution, report invalid/unavailable status and preserve known floor; no automatic older bundled fallback.                                |
| Catalog activation would race a reviewed/active plan                               | Defer activation; if snapshot binding fails, invalidate plan and require new scan/review.                                                                         |
| Suspected signing-key compromise or harmful signed rule                            | Stop accepting affected updates/rules when known; pursue new trusted app release and higher corrective revisions. Offline clients may not yet know of compromise. |

Catalog failure is a catalog status, not a successful wipe or authentication result. Do not modify
session targets while repairing the cache. Diagnostic exports include only app/catalog versions,
bundle digest, rule IDs and stable errors under [01](01-provider-contract.md).

## Review evidence

Signing approval must reference the exact rule diff, evidence/version matrix and preservation/
failure tests defined in [11](11-test-strategy.md). A new signature does not validate a candidate
provider. Preserve source/license provenance; independently authored vendor-evidenced rules are
the interim route. `catalog-source-provenance` must settle any dataset adoption and notices
against application research §3 and [ADR 0001](../adr/0001-license.md); no imported rules or
license-policy changes are introduced here. Maintainer roles and publication policy are later work.

## OPEN DECISIONS

| Named spike                         | Required evidence                                                                                                                                               | Until resolved                                                          |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `catalog-signature-protocol`        | Algorithm/library, signed encoding, embedded-key verification, container bounds and parser ambiguity tests; no signing protocol is established by the dossiers. | No remotely supplied catalog becomes executable.                        |
| `catalog-activation-rollback-state` | Atomic snapshot/floor/revision-history persistence, crash/concurrency recovery, corruption, reinstall/migration and state-reset limits.                         | No updater activation or rollback-resistance claim.                     |
| `catalog-key-lifecycle`             | Key custody, rotation, compromise recovery and possible revocation/expiry/freeze handling consistent with offline wiping.                                       | Embedded trust anchor only; key changes require an application release. |
| `catalog-update-transport`          | Endpoint/redirect trust, privacy of requests, scheduling/consent, offline import and isolation from an active wipe.                                             | No endpoint or automatic update schedule assumed.                       |
| `catalog-source-provenance`         | Rule source attribution, dataset adoption/licensing and traceable review evidence; application §3's Winapp2 caveats.                                            | No bulk third-party rule import or unsupported relicensing.             |

Reuse `artifact-signing-provenance` from [10](10-threat-model.md#open-decisions) and
`catalog-verification-matrix` from [11](11-test-strategy.md#checks-and-open-decisions).
Application code updates, implementation and spike execution are outside this documentation phase.
