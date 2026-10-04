# EveryOut documentation

This directory contains project decision records and contributor-facing design documentation.

## Index

- [Reproducible builds and verification](oss/reproducible-builds.md): build controls, unsigned
  checkpoints, signing boundaries and independent release verification.
- [Code signing policy](oss/code-signing.md): Poland eligibility, Foundation conditions,
  SmartScreen evidence, alternatives and maintainer actions.
- [Antivirus/EDR false positives](oss/false-positives.md): safe reports, evidence, vendor
  submissions and post-release tracking.
- [Release process](oss/release-process.md): maintainer gates for versions, changelogs, CI,
  signatures, checksums, publishing and monitoring.
- [ADR 0005: Code signing](adr/0005-code-signing.md): proposed signing choice and acceptance gates.

These release documents define proposed gates; provider acceptance and full bit reproducibility
are unverified, and release workflow implementation remains Phase 35 work. [HYPOTHESIS]

- [Gaming launcher catalog](catalog/apps-gaming.md): seven candidate manifests, exact Steam
  cleanup names, manual logout evidence, loss risks and synthetic fixture limits.

- [Architecture Decision Records](adr/README.md): process and index for durable project decisions.
- [ADR 0001: License](adr/0001-license.md): rationale for the GNU GPL version 3 or later.
- [Architecture overview](architecture/00-overview.md): components, proposed Cargo workspace,
  metadata-only data flow and the central open-decision register.
- [Provider contract](architecture/01-provider-contract.md): six methods, partial results,
  verification limits and the unimplemented V1 `revoke()` reservation.
- [Manifest specification](architecture/02-manifest-spec.md): declarative fields, candidate example,
  cleaning vocabulary, risk flags and catalog table columns.
- [Heuristic detection](architecture/03-heuristic-detection.md): bounded discovery, independent
  signals, provisional confidence scoring and unchecked lower-confidence candidates.
- [Classification rules](architecture/04-classification-rules.md): app/browser/shared identity
  ownership, overlap, global account mode and selection/confirmation defaults.
- [Wipe sequence](architecture/05-wipe-sequence.md): review gates, process closing, partial errors,
  metadata verification, category reports and conditional idempotence.
- [Permission model](architecture/06-permission-model.md): first-run account choice, on-demand
  elevated helper, UAC fallback and conservative other-user eligibility.
- [Elevated helper](architecture/22-elevated-helper.md): authenticated on-demand transport,
  executable pinning, bounded lifetime and current-account UAC fallback.
- [All-accounts mode](architecture/23-all-accounts-mode.md): SID-bound roots, offline hive cleanup,
  per-account review/execution/reports and unverified multi-user VM behavior.
- [Sync and identity](architecture/07-sync-and-identity.md): closed-profile editing direction,
  restoration warnings, preservation blockers and the unimplemented policy alternative.
- [What V1 will not do](architecture/08-not-doing.md): explicit local-only scope and limitations.
- [V2 extension points](architecture/09-v2-extension-points.md): roadmap-only triggers, reserved
  provider revocation and possible recovery, each subject to a named feasibility spike.
- [Threat model](architecture/10-threat-model.md): abuse and target scenarios, destructive-path
  confinement, catalog/helper trust boundaries and the AV/EDR false-positive mitigation plan.
- [Test strategy](architecture/11-test-strategy.md): confined synthetic fixtures, snapshot VMs,
  three test tiers and claim-specific catalog verification/confidence requirements.
- [Windows VM testing guide](testing/vm-guide.md): disposable test accounts, per-case checkpoints,
  synthetic harness commands, spike tools, sanitized evidence and restoration.
- [Synthetic test support](../crates/test-support/README.md): five fake profile layouts,
  injected fixture roots and metadata-only removal/preservation/idempotence assertions.
- [Catalog update design](architecture/12-catalog-update-design.md): signed manifest-only bundles,
  embedded trust, anti-rollback, changelog review and offline wipe independence.
- [Core foundation](architecture/13-core-foundation.md): implemented workspace libraries,
  provider types, manifest validation and the boundary with future system operations.
- [Windows platform foundation](architecture/14-platform-windows.md): object-bound filesystem
  and registry primitives, confined fixture evidence and remaining verification gates.
- [Current-account wipe engine](architecture/16-wipe-engine.md): immutable dry-run review,
  category/risk confirmations, process prerequisites, partial outcomes and metadata reports.
- [Detection and classification](architecture/17-detection-classification.md): bounded registry,
  shortcut/package inventory, manifest probes, unverified heuristic scoring, physical ownership
  overlaps and unchecked heuristic selection until S8 passes.
- [Chromium providers](architecture/18-chromium-providers.md): declarative execution, five candidate
  browser manifests, extension loss gates, fixture verification and unverified shipping coverage.
- [Firefox provider](architecture/19-firefox-provider.md): bounded profiles.ini path discovery,
  Gecko artifacts, extension risk gates, preservation fixtures and unverified S4 coverage.
- [Browser identity metadata](architecture/20-browser-identity-metadata.md): six-browser shallow
  signals, restoration warnings and explicit unsupported identity/sync mutations.
- [ADR 0004: Windows bindings](adr/0004-windows-metadata-and-deletion-bindings.md): official
  metadata/deletion bindings and their operating limits.
- [ADR 0002: Retain Tauri and Rust](adr/0002-retain-tauri-rust-stack.md): stack rationale.
- [ADR 0003: Rust command boundary](adr/0003-rust-command-capability-boundary.md): verified Tauri 2
  capabilities/scopes and critical-operation placement.
- [Browser session research](research/01-browsers.md): Windows browser artifacts, identity, sync,
  encryption, extension risks, and detection evidence.
- [Windows identity and multi-account research](research/02-windows-identity-and-multi-account.md):
  Windows account state, developer credentials, and elevated profile handling.
- [Application detection, process closing, and AV/EDR research](research/03-apps-detection-process-av.md):
  Embedded web runtimes, package/PWA ownership, discovery and licensing, prior art, shutdown risks,
  security-product interaction, and initial catalog candidates.

- [Review, execution and reports](architecture/27-review-execution-reports.md): metadata preview,
  confirmation gates, Ask closure, scoped retry and native JSON/text export.

Contributor workflow and security reporting are documented in the root
[CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).

Phase 26's [Windows/Microsoft and developer-tool catalog](catalog/windows-dev.md) records
blocked research scopes, offline refusal reasons and the evidence needed before local execution.
