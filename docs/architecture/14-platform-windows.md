# EveryOut Windows platform foundation

Phase 15 implementation and verification record, 2026-10-01. The phase implementation and its
required local checks completed successfully. The broader `destructive-root-confinement` review
remains open; local tests do not establish every Windows version or filesystem/filter-driver case.

## Capabilities and operations

`crates/platform-windows` adds a workspace library using
[ADR 0004](../adr/0004-windows-metadata-and-deletion-bindings.md). Its public Windows API includes:

- `RootResolver` and `CurrentUserFolders`: fixed current-user Local/Roaming AppData known folders.
- `AllowedRoot::from_manifest`: validated relative configuration below an OS/harness root,
  represented by retained directory handles; no public absolute-root constructor.
- `AllowedRoot::path` and `SafePath`: strict relative Windows grammar, ancestor/leaf identity
  snapshots and operation-time validation. Empty/dot/traversal components, rooted/UNC/device
  paths, ADS, wildcards, environment variables, reserved names, trailing spaces/dots and
  short-name aliases are refused. Forward separators are normalized into literal components.
- `probe`, `exists`, `is_directory`, `size` and `modified`: presence, type, recursive logical
  file size and last-write time only. Recursive metadata fails on inaccessible or redirected
  descendants rather than silently reporting an incomplete size.
- `delete_file` and `delete_tree`: mandatory `dry_run`, checked type, postorder tree deletion,
  complete bounded preflight and at most two 10 ms retries on the same deletion handle.
  Missing targets report `AlreadyAbsent`; dry runs report `WouldApply` without disposition calls.
- `RegistryRoot`: current-user `Software` subroots with exact key/value target allowlists;
  key/value presence, value deletion and tree deletion. No HKLM/other-user hive, default-value
  target, wildcard, root deletion, registry payload API or link traversal is exposed.
- `PlatformError`: core error kind and OS code, without path-bearing OS messages. Sharing,
  lock and mapped-file errors map to `Locked`; errors after mutation carry an applied count.

Trees are limited to 10,000 objects and 64 levels. Filesystem size addition is checked for
overflow. Directory enumeration returns names/attributes; ordinary files never receive
`FILE_READ_DATA`. No function reads session-file bytes, registry payloads or network data.

Filesystem roots and ancestors remain open without delete sharing. Relative native opens cannot
reopen a substituted absolute pathname. Root/ancestor/leaf reparse attributes and file link counts
are checked; deletion uses the held target object. Deletion preflight pins every collected child
before applying any effect, so a known unsafe descendant blocks the whole preflight. New children
after enumeration can still make directory deletion fail; retries never enumerate broader targets.
Completed effects cannot be undone, so the caller must retain partial results.

SafePath captures identity before later use. Different ancestor/leaf identities or targets newly
created after an absent observation are rejected as `StalePlan`. Reparse/type substitutions can
instead fail the earlier scope/native-open checks; disappearance remains idempotent absence.
This is not the future engine's snapshot, owner or approval validation.

## Manifest boundary

`crates/providers/src/platform.rs` adds an immutable `PlatformManifest` built only through the
existing schema/semantic loader. It binds declared artifact IDs, matching literal/bounded profile
names and typed root bases to narrow wrappers. Registry wrappers receive only the declared exact
target. Candidates can probe/dry-run but cannot apply. Directory methods with exclusions are
refused until the future engine can resolve them safely; no broader deletion fallback occurs.

These wrappers perform individual target primitives, not the six-method provider lifecycle or
family execution. The engine must still plan companions, preservation families, exclusions,
shared ownership, selection/confirmation, cancellation and verification. No production catalog,
Tauri command, engine, process operation or elevated helper is added in this phase.

## Harness and observed checks

`FixtureFolders`, behind the optional `test-fixtures` feature, creates and owns a unique new
temporary directory. It validates/pins that physical root and does not accept an existing
path or fall back to real AppData. Filesystem canaries and junction destinations stay within
this owned fixture but outside the selected target subtree. Tests use invented opaque bytes
only. The harness content-open oracle requests a read handle to its own synthetic file and
asserts that Windows denies the open; it never reads bytes.

Registry fixtures create unique volatile subkeys under exactly
`HKCU\Software\SessionWipeTest\everyout-...`. Teardown removes only the namespace created by
that test; it neither clears the shared parent nor adopts an existing key. Adapter reads are
restricted to key/value names and types. Both an ordinary key containing a synthetic `REG_LINK`
value and a real registry symbolic-link key test refusal without retrieving the target. The
harness addresses its synthetic sibling using key-name metadata and removes the link object
directly before teardown. Broader adversarial registry-link/race coverage remains unverified.

Filesystem integration cases cover Unicode/spaces, recursive size/time, dry runs, real deletion,
absence, traversal, prefix escapes, hard-link aliases, root/parent/leaf/recursive junctions,
unchanged canaries, locked/content-unreadable files, stale leaf/parent replacement, newly appeared
targets and immutable roots. A deterministic private-adapter test attempts substitution after
the target open and before disposition. A handle-lifetime regression checks that released probes
do not block later directory renames.

The first file-symlink run returned OS error 1314 (`ERROR_PRIVILEGE_NOT_HELD`) while creating its
synthetic link. After the user enabled Windows Developer Mode, the unchanged test passed in the
same workspace. Microsoft documents the privilege requirement and
[Developer Mode behavior](https://blogs.windows.com/windowsdeveloper/2016/12/02/symlinks-windows-10/).

```powershell
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Development dependencies enable the fixture feature for tests automatically. A normal
`cargo build --workspace` does not enable it. Frontend and commit checks remain those in
[CONTRIBUTING](../../CONTRIBUTING.md#quality-checks).

Observed on Windows 11 Home 10.0.26200, 64-bit:

| Check                                                         | Result                                                                           |
| ------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| `cargo build --workspace`                                     | Passed                                                                           |
| `cargo clippy --workspace --all-targets -- -D warnings`       | Passed                                                                           |
| `cargo fmt --all -- --check`                                  | Passed                                                                           |
| `cargo test --workspace`                                      | All 29 tests passed, including the symlink case after Developer Mode was enabled |
| Production-source payload/network API search                  | No prohibited API found; content-denied probe test passed                        |
| Registry integration cases                                    | All 3 passed, including real link refusal and unique-key cleanup                 |
| Frozen frontend install, lint, typecheck, format check, build | Passed                                                                           |
| Phase commit, commit lint and push                            | Passed; commit `0f5cad0` is on `origin/feat/core-foundation`                     |

No tests are ignored or filtered. The phase commit pushed after the checks is `0f5cad0`; its
parent is the Phase 14 core-foundation commit.

## Gate status

`destructive-root-confinement` remains **open**. Local fixture evidence does not establish every
Windows 10/11 version, filesystem/filter-driver interaction, adversarial alias/identity-reuse
case or reparse conversion interleaving. The real symlink case passed on this host after Developer
Mode was enabled. No production provider or live profile is approved by these tests.
The separate engine/catalog/VM/harness gates in [10](10-threat-model.md) and
[11](11-test-strategy.md) remain unchanged. This implementation provides a reviewable bounded
adapter and local evidence, not a claim that all earlier open decisions have been resolved.
