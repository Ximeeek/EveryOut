# Updating the EveryOut provider catalog

Phase 10 target design, 2026-09-30. Catalog updates distribute manifests and associated descriptive
metadata independently of application releases. No updater, signature implementation, production
key or catalog service is added here. Executable/application update design and release policy
remain outside this phase.

Phase 33 implements the decisions in [Implementation notes](#implementation-notes). That section
supersedes the implementation-blocking status of the signature, activation and transport spikes
below for this bounded V1 protocol. Key custody and hosting remain maintainer responsibilities.

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
   Phase 33 selects Ed25519, strict verification and an exact-byte signed representation;
   see [Implementation notes](#implementation-notes).
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

The status column records which V1 gates Phase 33 resolves and which decisions remain open.

| Named spike                         | Required evidence                                                                                                                       | Until resolved                                                                                  |
| ----------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| `catalog-signature-protocol`        | Algorithm/library, signed encoding, embedded-key verification, container bounds and parser ambiguity tests.                             | Resolved for the bounded Phase 33 V1 protocol; see Implementation notes.                        |
| `catalog-activation-rollback-state` | Atomic snapshot/floor/revision-history persistence, crash/concurrency recovery, corruption, reinstall/migration and state-reset limits. | V1 acceptance resolved in Phase 33; future app migrations require review.                       |
| `catalog-key-lifecycle`             | Key custody, rotation, compromise recovery and possible revocation/expiry/freeze handling consistent with offline wiping.               | Embedded trust anchor only; key changes require an application release.                         |
| `catalog-update-transport`          | Endpoint/redirect trust, privacy of requests, scheduling/consent, offline import and isolation from an active wipe.                     | Explicit bounded HTTPS checks resolved; hosting, scheduling and offline import remain separate. |
| `catalog-source-provenance`         | Rule source attribution, dataset adoption/licensing and traceable review evidence; application §3's Winapp2 caveats.                    | No bulk third-party rule import or unsupported relicensing.                                     |

Reuse `artifact-signing-provenance` from [10](10-threat-model.md#open-decisions) and
`catalog-verification-matrix` from [11](11-test-strategy.md#checks-and-open-decisions).
Application code updates, implementation and spike execution are outside this documentation phase.

## Implementation notes

Phase 33 separates checking from explicit acceptance, implements the catalog tools and keeps all
update I/O outside cleanup. The crate `crates/catalog-update` owns validation, transport and storage;
the native desktop worker owns acceptance and the lifetime of execution capabilities. The project
name and signature purpose are EveryOut.

### Signed protocol and validation

- Ed25519 uses `ed25519-dalek` 2.2 with `VerifyingKey::verify_strict`; weak embedded keys are rejected.
  See the [library documentation](https://docs.rs/ed25519-dalek/2.2.0/ed25519_dalek/struct.VerifyingKey.html).
  SHA-256 binds each manifest and the accepted payload. Transport TLS is additional protection.
- The non-compressed UTF-8 JSON wrapper has exactly `payload` (a JSON string) and `signature`
  (hexadecimal encoding of 64 detached signature bytes). Signed bytes are the ASCII/UTF-8 prefix
  `EveryOut/catalog/stable/v1` followed by a NUL byte and the exact UTF-8 payload bytes. Verification
  never reserializes the payload. There is no archive extraction or filename interpretation.
- The payload is the strict `Envelope` Rust type: format 1, product EveryOut, stable channel,
  key ID `stable-v1`, unsigned 64-bit nonzero catalog version, inclusive interpreter ABI range
  (currently ABI 1), bounded changelog and ID-sorted entries. Every entry binds ID, revision,
  UTF-8 byte length, SHA-256 and manifest text. All fields are signed. Unknown fields, duplicate
  JSON keys at any level, duplicate IDs and inconsistent membership are rejected.
- Manifests are normalized once by the builder: recursively sort JSON object keys and serialize
  compactly with serde_json, preserving array order and explicit field membership. Repository
  formatting and Windows line endings therefore cannot change an immutable rule revision.
  Signed manifests must already have exactly that representation. Entry hashes authenticate these
  bytes, not a separately reinterpreted rule. A declaration change requires a revision increase.
- Limits: 8 MiB total wire bundle, 256 KiB per input manifest, 256 providers, 64 KiB changelog and
  serde_json's default recursion limit. Unsupported formats/ranges fail closed; the integer version
  never increments locally, so overflow cannot wrap the floor. ABI changes require an app release.
- Every entry passes the existing schema and semantic validator. Fixed API/exception adapter IDs
  may only reference IDs present in the compiled catalog. Existing research candidates retain
  their ordinary non-executable gates; signatures never promote their confidence or support.
  New adapters or code need an application release. Changelog is rendered as inert React text.

### Atomic acceptance and offline behavior

`catalog-v1/accepted.redb` under the host-resolved app configuration directory holds one accepted
record: signed bytes (absent only for the compiled initial catalog), payload digest, high-water
version and latest revision/digest for every seen provider, including removed-provider tombstones.
The dedicated directory is also an initialization marker. An existing directory with missing,
unreadable or inconsistent state blocks cleanup; it does not initialize a fresh floor.

An immediate-durability redb transaction writes the complete next record and commits once.
The database owns the file lock, serializes writes and provides crash recovery. See
[redb durability](https://docs.rs/redb/2.6.4/redb/enum.Durability.html). No separate cache rename or
floor update can succeed independently. Pre-commit failure retains the previous coherent snapshot;
an uncertain commit error blocks execution until reopening/recovery establishes the committed
record. Startup checks the signature again, exact digest/floor and current revision membership.

Lower catalog versions are refused. Equal versions require an identical payload digest. A higher
version cannot lower a provider revision or change its canonical bytes without increasing that
revision. Removing a provider preserves its latest revision/digest. Reintroducing its older
revision is rejected. Signing a rollback does not authorize it.

The compiled catalog starts at `BUNDLED_VERSION = 1`. Rejected downloads, malformed manifests and
failed staging keep the accepted catalog; the fallback is the bundled catalog only while it is
the accepted initial snapshot. After accepting a newer version, damaged state blocks cleanup
instead of silently returning to the older bundled rules. Complete deliberate state erasure or
whole-machine rollback cannot be distinguished from a fresh installation. A process with write
access can also deliberately restore the entire accepted database, including its floor/history;
the database checksum is not authentication against that local attacker. No hardware-backed or
administrator-proof rollback protection is claimed. Updating the bundled floor/catalog or key lineage in a later app
release requires a reviewed migration; incompatible state currently blocks rather than guessing.

The native worker serializes checking/acceptance with scan and execution. Acceptance is rejected
while an inventory/review is held; Settings/check explicitly discards that review first. On
acceptance the previous session and elevated connection are dropped and all borrowed providers
are reconstructed from the new immutable snapshot before processing another request. This pins
an inventory, plan, approval and run to one snapshot lifetime. Old opaque IDs cannot authorize
work in the replacement session. No fetch, storage repair or update retry happens inside a wipe.
Native text/JSON report exports retain the run's catalog version and payload digest alongside the
existing per-provider revision data, so a later activation cannot relabel an earlier result.

The current elevated helper independently interprets its compiled catalog. If accepted manifest
membership or bytes differ, all-accounts mode is blocked with `helper-unavailable` until a reviewed
compatible helper/app release; it never executes the helper's older rules against a new preview.
Catalog-only changes to version/changelog with identical manifests retain helper compatibility.
Current-account cleanup uses the accepted updated manifests and ordinary safety gates.

### Transport and user consent

Settings exposes `Check for catalog updates`, an authenticated proposal and a separate `Accept
catalog update` action bound to the verified proposal digest. No automatic scheduling or network
access is enabled in the frontend; only two narrowly scoped native command permissions are added.
The UI shows installed/proposed versions, inert changelog and sanitized failures; it does not
present check time as proof of freshness. It explains that checking discards the prior scan.

The build embeds one public key and one exact HTTPS endpoint via `EVERYOUT_CATALOG_PUBLIC_KEY`
(64 hex characters) and `EVERYOUT_CATALOG_URL`. Both must be supplied together. Without them the
app uses its compiled catalog and checking returns `catalog-unconfigured`; no fabricated production
key or service is shipped. The URL cannot contain credentials, query or fragment. Rust makes one
bounded GET with a 10-second connection timeout and 30-second overall timeout, no redirects,
cookies, automatic decompression or system proxies. No inventory, account ID, paths, reports or
request body are uploaded. The server inevitably sees connection/request metadata. Controlled
proxy support, offline file import and update scheduling are not implemented.

### Maintainer steps

1. Establish signing custody outside this repository: generate an Ed25519 key with reviewed key
   tooling/ceremony, retain the raw 32-byte signing seed in restricted offline storage and export
   the raw 32-byte public key. Do not reuse an application-signing key. Key generation, hosting
   infrastructure and executable signing are outside this phase. Never commit the signing seed.
2. Review all changed declarations, increment changed provider revisions and prepare a UTF-8
   changelog describing additions/removals, compatibility, effects, preservation, loss risks and
   limitations. Candidate support remains candidate until its own evidence gates are satisfied.
3. Run `cargo run -p xtask -- catalog-validate`, `cargo run -p xtask -- catalog-table`, and the normal
   Rust/frontend checks. Commit the resulting `docs/catalog/CATALOG.md` with the manifest changes.
   CI validates all manifests and fails if that deterministic table is stale. The generated file
   is excluded from Prettier because the generator owns its exact formatting.
4. Build payload configuration outside the checkout:
   `cargo run -p xtask -- catalog-bundle VERSION CHANGELOG_PATH PAYLOAD_PATH`.
   VERSION must exceed the bundled floor and every previously published catalog version.
5. Sign with `cargo run -p xtask -- catalog-sign PAYLOAD_PATH BUNDLE_PATH PRIVATE_KEY_PATH`, or omit
   the last argument and set `EVERYOUT_CATALOG_PRIVATE_KEY_PATH` to the external seed file path.
   The tool rejects private key files resolving inside the checkout, bounds the read, zeroizes
   seed buffers, validates the signed result and never prints key material. The environment
   variable contains a path, not the private key. Use a restricted workstation and file ACLs.
6. Independently verify `cargo run -p xtask -- catalog-verify BUNDLE_PATH PUBLIC_KEY_PATH` against
   the same public key embedded in the client. Retain previous manifests/revisions and signing
   review evidence; the stateless verifier does not know clients' accepted revision histories.
7. Host only the complete signed bundle at a stable, direct HTTPS endpoint, with no redirects or
   authentication requirement. Publish atomically on the hosting side. Build a reviewed app with
   the public-key hex and exact URL in the two build variables above. Never download a trust key
   from that endpoint. Test with a disposable catalog state before distributing the app.
8. A compromised key requires a reviewed application release with a new trust anchor and explicit
   migration floor. Rotation, remote revocation, expiry and freeze detection are still open.
   Never advise deleting accepted state or approving an older bundle as recovery.

### Verification evidence and remaining boundaries

Local fixtures and throw-away keys cover valid/invalid signatures, wrong/weak keys, tampering,
duplicate keys/IDs, malformed manifests, unsupported adapters/formats, traversal, bounds, older
versions, equal-version mutations, revision reuse/downgrade and tombstones. Store tests reopen
after aborted writes and after child processes terminate immediately before/after commit, verify
that the coherent old/new floor is recovered, and block corrupt persisted signatures or missing
state. Tests make no network requests. UI tests prove no automatic check, separate acceptance,
inert changelog rendering and visible unconfigured-build status. Table equality is tested and
checked independently in CI.

These tests resolve the V1 signature/activation/transport implementation gates for the protocol
above, not physical power-loss certification on every filesystem, key custody or newest-version
proof. Storage/OS permission failures remain visible. Source/licensing review is unchanged; no
external deletion dataset is imported. Publishing infrastructure, executable signing, reproducible
builds and release workflow remain phases 34–35 or separate maintainer work.
