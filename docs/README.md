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
