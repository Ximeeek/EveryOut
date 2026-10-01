# ADR 0004: Use official Windows bindings for object-bound platform operations

- Status: Accepted
- Date: 2026-10-01

## Context

Phase 14 deliberately implemented pure model and manifest logic without selecting an OS
binding. Phase 15 needs current-user known folders, bounded metadata, registry presence and
deletion. Lexical validation alone cannot establish the confinement required by the
[threat model](../architecture/10-threat-model.md).

## Decision

Use Microsoft's `windows-sys` 0.61.2 bindings. This version is already present in the workspace
lockfile and existing filesystem/registry spikes. Keep unsafe calls private to
`everyout-platform-windows`, with owned RAII handles, checked buffers and safety explanations.
Providers depend on this narrow platform library; the platform depends only on core model,
not providers, Tauri or the engine.

Use `SHGetKnownFolderPath` for the current user's Local/Roaming AppData, with no token override,
environment expansion or folder creation. Keep the Phase 14 root allowlist. `%APPDATA%` and
`%LOCALAPPDATA%` describe these known-folder locations, but are not interpolated from environment
strings. `%USERPROFILE%`, arbitrary user roots, redirected roots and other-user access remain
unsupported.

Open filesystem components relative to a checked directory handle using user-mode `NtCreateFile`
with `FILE_OPEN`, `FILE_OPEN_REPARSE_POINT` and `OBJ_DONT_REPARSE`. `RootDirectory` supplies the
object context and `OBJ_DONT_REPARSE` refuses name reparsing, as documented in
[OBJECT_ATTRIBUTES](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes).
File handles request attributes and, when applying deletion, `DELETE`; they never request file
content access. Directory enumeration rights are requested only with `FILE_DIRECTORY_FILE`.
See [the create/open contract](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile).
Delete the checked object through
[SetFileInformationByHandle](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfileinformationbyhandle),
not a reopened absolute path. No POSIX deletion, attribute override or protection bypass is used.

Registry operations bind the current process user's HKCU using `RegOpenCurrentUser` and open
single components with `REG_OPTION_OPEN_LINK`. Enumerate value names/types with **both data
arguments null**, rejecting `REG_LINK` without retrieving its target. Remove exact values by
name on a held key. Delete checked key objects through the user-mode `NtDeleteKey` binding;
[Microsoft documents that user-mode callers use this name](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey).
The `Wdk` namespace supplies these official ntdll declarations; no driver, kernel-mode execution,
hooking, injection or process-memory inspection is introduced.

## Consequences

The adapter supports only fixed local NTFS volumes and the current user's registry 64-bit view.
Unknown filesystems, remote/device namespaces, all reparse tags, multiple hard links, short-name
aliases, unsupported path forms and resource-limit violations fail closed. Capabilities retain
ancestor handles without delete sharing; checked deletion objects also refuse write sharing.
Existing conflicting handles may therefore cause a `Locked` result.

The optional `test-fixtures` feature creates its own fresh temporary root and cannot adopt an
existing arbitrary path. Development tests enable it; normal shipping builds do not. Tests
never receive a production-resolver fallback.

This decision selects bindings and a confinement mechanism, not full production approval.
The evidence and remaining `destructive-root-confinement` gate are recorded in
[the Phase 15 platform record](../architecture/14-platform-windows.md). Engine-held approvals,
ownership, exclusions, shared-family planning, process handling and other-user/helper work
remain separate phases.
