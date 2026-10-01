# EveryOut synthetic test support

Development-only workspace library, `publish = false`. Production packages must not depend on
this crate or enable the platform's `test-fixtures` feature. The desktop dependency graph does
not include it. `cargo build --workspace` builds this lab library too, but does not ship it.

`FixtureTree::empty()` owns a fresh temporary directory. `FixtureTree::profiles(seed)` generates
the layout below, with reproducible opaque bytes and invented `profiles.ini` text. There is no
existing-root constructor, profile import, environment override, network access or payload reader.
The seed is reproducibility metadata, not cryptographic randomness. These are fake stores, not
valid databases, extension manifests, login records or authentication evidence.

| Family   | Relative layout and preservation sentinels                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Chromium | `LocalAppData/Chromium/User Data/{Default,Profile 1}/`: `Network/Cookies` (64 bytes), `Cookies-wal` (16), `Cookies-shm` (8), `Local Storage/leveldb/000001.log` (32), `Session Storage/000001.log` (24), `IndexedDB/lab.indexeddb.leveldb/000001.log` (40), `Service Worker/Database/000001.log` (20), `Extensions/synthetic/1.0/manifest.json` (12), `Local Extension Settings/synthetic/000001.log` (28), `Bookmarks` (13), `History` (17). |
| Firefox  | `RoamingAppData/Firefox/profiles.ini` contains only the invented relative profile configuration; `Profiles/lab.default/` contains `cookies.sqlite` (64), `cookies.sqlite-wal` (16), `cookies.sqlite-shm` (8), `storage/default/lab/opaque` (32), and preserved `places.sqlite` (19).                                                                                                                                                          |
| Electron | `RoamingAppData/Electron Lab/`: `Network/Cookies` (64), `Local Storage/leveldb/000001.log` (32), `Session Storage/000001.log` (24), `IndexedDB/lab/opaque` (40), preserved `drafts/preserved` (21).                                                                                                                                                                                                                                           |
| Steam    | `LocalAppData/Steam/`: `config/loginusers.vdf` (32), `ssfn0000000001` (24), preserved `steamapps/preserved` (23). This synthetic AppData location is a lab convention, not an installation discovery rule.                                                                                                                                                                                                                                    |
| Store    | `LocalAppData/Packages/EveryOutLab_synthetic/LocalState/`: `session` (32) and `preserved` (27).                                                                                                                                                                                                                                                                                                                                               |

Additional trees: `LocalAppData/unknown version żółć/residue` (11), `outside-allowed/canary` (29),
and an empty `empty/` directory. Parent directories are generated implicitly. No real application
IDs, accounts or secrets are used. Layout tests compare every generated relative path and size.

`FixtureFolders::profiles(seed)` in the platform's test feature wraps the owned tree and pins
distinct Local/Roaming AppData roots through the existing Windows guard. `FixtureFolders::create()`
retains the original empty-root behavior for focused adversarial tests. Neither adopts an ambient
path or falls back to OS profile resolution. All deletion uses `AllowedRoot`/`SafePath`; snapshot
observation is not a deletion authorization mechanism. The platform retains ancestor identities,
rejects reparse and hard-link traversal, and validates mutation through held handles.

`snapshot()` records a sorted map of relative paths and sizes only. Directories have a trailing
`/` and size zero. It rejects redirected descendants, non-Unicode names and special objects,
and bounds traversal to 64 levels and approximately 10,000 entries. Use only a quiescent owned
tree: observation is not atomic, does not validate hostile ancestor replacement, and cannot
detect equal-size payload changes or prove secret-read absence. No timestamps, hashes, absolute
roots or payloads are recorded.

Snapshot assertions check selected removals, exact remaining metadata, and an unchanged second
run. Negative tests exercise surviving targets, resized canaries, additions and non-idempotence.
Platform tests use these assertions for dry runs, cookie-family deletion, all five profile kinds,
external temporary canaries, sibling-prefix escape and recursive junction refusal. Existing
registry tests retain exact volatile namespaces and process tests retain owned dummy subprocesses;
filesystem fixtures do not grant registry or process authority.

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo tree -p everyout --edges normal,build
```

Windows integration tests require local NTFS and Developer Mode or symlink privilege. Failure to
create a required adversarial fixture is a test failure. CI runs the new workspace tests through
its existing commands. Manual trials follow the [VM guide](../../docs/testing/vm-guide.md).
The broader `destructive-test-harness-validation` and `destructive-root-confinement` gates remain
open for the full Windows/filesystem/filter-driver matrix, race review and read-observation fidelity.
