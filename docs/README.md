# EveryOut documentation

This directory contains project decision records and contributor-facing design documentation.

## Index

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
- [Sync and identity](architecture/07-sync-and-identity.md): closed-profile editing direction,
  restoration warnings, preservation blockers and the unimplemented policy alternative.
- [What V1 will not do](architecture/08-not-doing.md): explicit local-only scope and limitations.
- [V2 extension points](architecture/09-v2-extension-points.md): roadmap-only triggers, reserved
  provider revocation and possible recovery, each subject to a named feasibility spike.
- [Threat model](architecture/10-threat-model.md): abuse and target scenarios, destructive-path
  confinement, catalog/helper trust boundaries and the AV/EDR false-positive mitigation plan.
- [Test strategy](architecture/11-test-strategy.md): confined synthetic fixtures, snapshot VMs,
  three test tiers and claim-specific catalog verification/confidence requirements.
- [Catalog update design](architecture/12-catalog-update-design.md): signed manifest-only bundles,
  embedded trust, anti-rollback, changelog review and offline wipe independence.
- [Core foundation](architecture/13-core-foundation.md): implemented workspace libraries,
  provider types, manifest validation and the boundary with future system operations.
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

Contributor workflow and security reporting are documented in the root
[CONTRIBUTING.md](../CONTRIBUTING.md) and [SECURITY.md](../SECURITY.md).
