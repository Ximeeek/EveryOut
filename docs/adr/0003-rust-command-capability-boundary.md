# ADR 0003: Keep critical operations behind scoped Rust commands

- Status: Accepted
- Date: 2026-09-30

## Context

Providers need bounded metadata discovery and local mutation, while the frontend needs only
descriptions, selection and progress. Browser dossier §7 and application dossier §§1, 6 reject
secret-content inspection as a discovery shortcut. Windows dossier §3 shows why even a normal
credential enumeration API can violate that boundary.

Official Tauri 2 documentation was checked on 2026-09-30:

- [Capabilities](https://v2.tauri.app/security/capabilities/): grants bind to windows/webviews;
  overlapping capabilities merge permissions. Capability-directory files are enabled by default
  unless explicitly selected in configuration. Registered application commands are available to
  all app windows/webviews by default; `AppManifest::commands` enables command permission control.
- [Permissions](https://v2.tauri.app/security/permissions/): permissions allow/deny commands and
  associate scopes; capability references grant them to a window/webview.
- [Command scopes](https://v2.tauri.app/security/scope/): deny supersedes allow; application-defined
  scope enforcement belongs in the Rust command implementation.

These controls constrain frontend IPC; they do not automatically constrain arbitrary Rust I/O.
The current placeholder has an empty capability and no custom invoke handler. Its configuration
is a baseline, not an implemented security policy for future commands.

## Decision

All critical filesystem/registry deletion, credential operations, ownership decisions and process
operations run in Rust through the engine/platform boundary. JavaScript receives no fs, SQL,
shell, process or credential plugin permissions for wiping. Noncritical plugins require a
separate narrow purpose and grant; they cannot become an alternate system-operation path.

Use explicit app command permission registration through `AppManifest::commands`, with narrowly
named permissions granted only to the intended local main window. Explicitly enumerate enabled
capabilities, avoid wildcard window grants and review unions. Do not enable remote-content IPC.
The main window cannot delegate authority by creating a differently labeled privileged window.

Commands accept opaque inventory/instance/plan IDs and bounded selection options. Rust resolves
targets from an engine-held plan, checks owner and scope, rejects stale/conflicting plans and
requires the plan's confirmations before mutation. No command accepts arbitrary deletion paths,
registry expressions, executables or shell strings. Scope checks apply to both normal and dry-run
paths; reports return sanitized DTOs.

This decides the bridge placement and Tauri capability model. It does not settle OS permission,
UAC/helper IPC design, the wipe sequence, threat model or test strategy.

## Consequences

A single Rust boundary centralizes provider invariants and prevents frontend plugins from
bypassing plan review. Missing plugin grants alone are insufficient: app-command ACL registration
and command-side scope checks are both required. Incorrect Rust checks remain a risk that Tauri
capabilities cannot repair. More UI functionality requires explicit permissions rather than a
generic shell/filesystem grant.

OPEN DECISION: `tauri-command-acl-validation` must confirm permission generation and effective
command/scoping behavior against the locked Tauri version before implementing this bridge.
See [the register](../architecture/00-overview.md#open-decisions). The design is accepted; runtime
enforcement is unimplemented and unverified in this documentation phase.

## References

- Official Tauri 2 capability, permission and scope pages linked above; accessed 2026-09-30.
- [Browser session research, §7](../research/01-browsers.md#7-detection-signals-and-explicit-read-exceptions)
- [Windows identity research, §3](../research/02-windows-identity-and-multi-account.md#3-credential-target-enumeration-without-reading-secrets)
- [Application detection and safety research](../research/03-apps-detection-process-av.md)
- [Provider contract](../architecture/01-provider-contract.md)
