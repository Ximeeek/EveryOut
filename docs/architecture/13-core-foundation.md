# EveryOut core foundation

Phase 14 introduces two libraries in the existing root Cargo workspace:

- `crates/core-model` / `everyout-core-model`: IDs, metadata observations, provider
  descriptions, risks, selections, plans, partial outcomes, verification and reports.
  The object-safe `Provider` trait uses the six methods from the architecture contract.
- `crates/providers` / `everyout-providers`: serde manifest declarations and a pure
  `load_manifest(&str)` JSON loader. It checks the embedded JSON Schema first and
  then checks Windows path grammar, references, category identity, ownership,
  method compatibility, preservation declarations and support gates.

`src-tauri` remains a workspace member. The four existing spike executables remain
excluded. Platform adapters, the engine and the elevated helper are reserved for
later phases; no empty implementations or new Tauri commands are introduced.

## Choices where the design left details open

The provider contract is synchronous, with borrowed narrow metadata/operation
interfaces. These are declarations only; no system access is implemented. Execution
uses `ExecutionMode::DryRun` or `Apply`. Verification receives the reviewed plan in
its context, preserving the sketch's method signature. `Provider::revoke()` has a
failing default whose message is `not supported in V1`; it exposes no transport,
request payload or remote operation.

A `ProposedPlan` is serializable. `ValidatedPlan` is not deserializable and has a pure
review constructor checking support, blockers, preservation and confirmations.
Its name does not establish runtime ownership or containment: the future engine
must resolve logical artifact IDs, bind snapshots/revisions/owners, revalidate
metadata and enforce cancellation and account scope before applying any action.
The `PlanResult::Ready` payload is boxed to keep blocked results small. Aggregate
statuses are declarations; aggregation and wipe sequencing remain future engine work.

The initial parser accepts JSON, matching the JSON Schema; the design's YAML example
remains illustrative. The schema is generated from the serde model with schemars
and checked for drift by a test. To regenerate it from the repository root:

```powershell
cargo run -p everyout-providers --example manifest-schema | Set-Content -Encoding utf8 catalog/schema/provider-manifest.schema.json
pnpm exec prettier --write catalog/schema/provider-manifest.schema.json
```

The initial known-folder allowlist contains only `local-app-data` and
`roaming-app-data`. A registry root must explicitly name `current-user` and an exact
relative key under `Software`; future platform code must bind that hive to the
selected owner. No ambient environment expansion, machine hive, custom root or
absolute path is accepted. This is a conservative implementation choice, not an
approval of every target below those roots. Lexical validation cannot prove runtime
containment or detect reparse points; those checks belong to the platform boundary.
Profile discovery accepts literal single components or one nonrecursive `*` inside
a named pattern, such as `Profile *`. A bare `*`, recursive wildcard, traversal or
unreviewed metadata adapter is rejected. Registry value paths are exact nonempty
relative names; the unnamed/default value is not supported in this initial grammar.
File companions are limited to the documented `-wal`, `-shm` and `-journal` suffixes.

Application and special-category manifests require `installation_id` or `package_id`;
browsers require a matching `browser_id` and profile discovery. Process names alone
never satisfy identity. These field spellings and category checks make the prose
requirements concrete. `artifact_family`, method `effects`, risk `reason` and
confidence `version_coverage` supplement the worked candidate's fields. Candidates
may retain incomplete evidence and explicit unknown loss, but cannot be reviewed
for execution. Validated declarations require explicit effects, version coverage,
resolved spikes and loss assessment. Declared preserved-family conflicts and
protected browser-loss flags block validated support; confirmation is not a waiver.
Fixed API/exception IDs can be described in candidates, but no IDs are approved for
validated execution in this phase. Review of actual adapters remains future work.

Reports keep the three category sections, opaque user/profile IDs, partial action
results, stable issue codes, risks and independent authentication/identity/sync/SSO
uncertainty. They contain no concrete root paths or credential targets. Code and
limitation strings are intended for stable reviewed vocabulary, never OS messages.
Public domain types are not a substitute for future engine validation or report
projection; no report exporter is implemented here.

## Verification boundary

The example at `crates/providers/tests/fixtures/provider.json` describes only an
invented browser and cannot execute. Tests parse in-memory synthetic JSON and
round-trip domain values. They do not resolve paths, scan profiles, enumerate
accounts, read session contents or mutate system state. Tests cover schema drift,
required fields, forbidden path forms, unknown roots/methods, broken references,
category requirements, method/target mismatches, unresolved validation gates,
confirmation review and the reserved revocation default.
