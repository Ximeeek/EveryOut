# Changelog

All notable changes to EveryOut will be documented here.

This file follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). No published release is claimed below.
The 0.x public contract remains unstable.

## [Unreleased]

### Added

- Windows Tauri desktop shell with React/TypeScript views and persisted preferences.
- Metadata discovery, scoped selection, reviewed plans, dry runs and explicit risk confirmation.
- Local wipe engine with confinement, process-close coordination, cancellation and detailed
  blocked, skipped, partial and completed outcomes.
- Current-account mode and explicitly enabled all-accounts mode with an authenticated,
  on-demand elevated helper and final-binary trust pin.
- Manifest catalogs for browser, application and Windows/Microsoft + developer-tools scopes,
  with confidence, permanent-loss warnings and unresolved candidates blocked.
- Native report export without secret contents.
- Ed25519 catalog updates, rollback protection, atomic acceptance and maintainer catalog tools.
- OSS signing, verification, reproducibility, security and false-positive policies.
- Tag-triggered draft-only MSI release workflow with locked dependencies, SHA-256 checksums,
  build provenance, unsigned checkpoints and advisory two-build comparisons.
- Conditional helper-first SignPath integration, disabled until maintainer onboarding is complete.

### Security

- Local clearing never reads, copies, decrypts or transmits secrets; wiping stays offline.
- No hooking, injection, foreign-memory reads or drivers; no anti-cheat certification is claimed.
- Deletion has no backup/undo and can permanently destroy local-only data. Local clearing
  does not guarantee server-side logout or prevent silent SSO re-login.
