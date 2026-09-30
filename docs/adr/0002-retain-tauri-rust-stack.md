# ADR 0002: Retain Tauri 2.x with a Rust system layer

- Status: Accepted
- Date: 2026-09-30

## Context

EveryOut already has a Tauri 2.x host and React/TypeScript frontend in `src-tauri` and `src`.
The research describes session persistence across browser profiles, embedded runtimes, packages,
registry targets and Windows identity interfaces. It requires metadata-only discovery and local
operations without secret reads, memory inspection, hooking, injection or drivers.
See browser dossier §§1, 5, 7, Windows dossier §§3, 5–6 and application dossier §§1–3, 6.

None of the three dossiers establishes a clearly better desktop/system stack or benchmarks
framework overhead. Embedded Chromium/WebView2 storage research concerns target applications;
it is not evidence that EveryOut must use their runtimes for cleaning.

## Decision

Keep Tauri 2.x and React/TypeScript for the desktop shell and Rust for the system layer.
Adopt the component/crate split in [the overview](../architecture/00-overview.md), with an
independent core model, Windows platform adapters, engine and manifest-based providers.
System behavior is reachable only through narrow Rust commands, as decided by ADR 0003.
Reserve a separate helper executable boundary without deciding its privilege/UAC mechanics here.

This is an accepted Phase 8 architecture choice under the requested keep-stack baseline.
It does not claim comparative speed, binary size or stronger anti-cheat compatibility.

## Consequences

Retaining the scaffold avoids a migration unsupported by research. OS behavior stays testable
outside the UI, and common Rust types can describe partial effects without transporting secrets.
Windows-specific adapters still need review; a language/framework choice does not establish safe
deletion or complete logout. Tauri's host permissions do not make arbitrary Rust I/O safe.

A native .NET/WinUI shell would replace the frontend and bridge without resolving undocumented
session stores. Electron would introduce another desktop runtime without evidence of a superior
Windows operations layer. Neither migration is justified by these dossiers. This is a scope and
evidence judgment, not a performance comparison or rejection of those stacks in general.

OPEN DECISIONS: `app-session-scope` and `metadata-discovery-allowlist` must validate actual system
operations; `tauri-command-acl-validation` must validate the locked bridge configuration.
See [the register](../architecture/00-overview.md#open-decisions). No stack migration spike is
needed absent evidence of a blocking stack limitation.

## References

- [Browser session research](../research/01-browsers.md)
- [Windows identity and multi-account research](../research/02-windows-identity-and-multi-account.md)
- [Application detection and safety research](../research/03-apps-detection-process-av.md)
- [ADR 0003: Rust command and capability boundary](0003-rust-command-capability-boundary.md)
