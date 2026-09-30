# EveryOut tree snapshot lab tool

Independent Rust CLI for disposable, quiescent VM trees. It is not a wipe tool and performs no
deletion, browser discovery, account operations or network I/O. Its own `[workspace]` keeps it
outside the root application's workspace and release bundle. Build dependencies may require
network access at build time; the compiled executable does not.

```powershell
cargo build --locked --manifest-path spikes/tree-snapshot/Cargo.toml
cargo test --locked --manifest-path spikes/tree-snapshot/Cargo.toml
cargo fmt --manifest-path spikes/tree-snapshot/Cargo.toml -- --check
cargo clippy --locked --manifest-path spikes/tree-snapshot/Cargo.toml --all-targets -- -D warnings
```

Inside the VM, use a copied executable and an evidence directory **outside** every captured root:

```powershell
$tool = 'C:\Lab\Tools\everyout-tree-snapshot.exe'
$root = 'C:\Lab\Profiles\Case01'
$evidence = 'C:\Lab\Evidence\Case01'
New-Item -ItemType Directory -Path $evidence -Force | Out-Null
$before = & $tool capture $root
if ($LASTEXITCODE -ne 0) { throw 'Before capture failed' }
$before | Set-Content -LiteralPath "$evidence\before.json" -Encoding utf8NoBOM
# Perform only the exact, separately reviewed VM operation; this tool never wipes.
$after = & $tool capture $root
if ($LASTEXITCODE -ne 0) { throw 'After capture failed' }
$after | Set-Content -LiteralPath "$evidence\after.json" -Encoding utf8NoBOM
$diff = & $tool diff "$evidence\before.json" "$evidence\after.json"
if ($LASTEXITCODE -ne 0) { throw 'Diff failed' }
$diff | Set-Content -LiteralPath "$evidence\diff.json" -Encoding utf8NoBOM
```

Use PowerShell 7 for `utf8NoBOM`; on Windows PowerShell 5.1 write the captured string with
`[IO.File]::WriteAllText(path, text, [Text.UTF8Encoding]::new($false))` instead. Do not redirect
straight into the target tree or treat an empty output after a failure as a valid snapshot.
Exit 0 means valid complete output; exit 1 means failure (including invalid arguments).
A diff with changes still exits 0. Errors use sanitized categories rather than raw paths.

Schema version 1 contains `entries`: `path`, `size`, `modified_ns`, `created_ns` only. Paths are
relative UTF-8 strings with `/` separators; a trailing `/` identifies a directory, whose size is
zero. Times are signed decimal nanoseconds since the Unix epoch, or `null` if unsupported.
Entries and diff groups sort by relative path; a changed entry includes before/after metadata.
Access time is intentionally omitted. There are no absolute roots, contents, hashes, account
labels, registry values or authentication conclusions. Snapshot documents themselves must be
read in diff mode; `capture` never opens payloads. Diff accepts only explicit `.json` inputs,
at most 64 MiB each, with the supported schema and unique relative paths. It never resolves their
entry paths against a live filesystem. Do not supply a browser JSON file to diff.

Capture rejects symlinks, Windows junctions and all other reparse points (including root
ancestors), special files, parent traversal, non-Unicode paths, depth above 256 and more than
one million entries. Windows accepts local drive paths only, excluding UNC/device paths and mapped
network drives.
Permission, enumeration and missing-file errors abort output rather than silently omitting entries.
An inaccessible timestamp is explicitly `null`, not zero. Hard links are observed by path;
their alias/ownership relationships are not inferred.

The tree must remain closed and unchanged throughout capture. Path checks are not an atomic,
handle-bound containment mechanism: concurrent replacement can invalidate the observation.
Do not run against adversarial/live trees, network-mapped drives, personal profiles, cloud
placeholders or host browsers. The tool is not the production confinement adapter.
Metadata can miss changes of equal size with unchanged timestamps and cannot prove content
preservation, token invalidity or logout. Recreated paths prove recreation only, not whether
sync, SSO, browser initialization or another source caused it. Local relative names can reveal
origins/extension IDs; sanitize those names before publishing evidence.

Tests use uniquely created synthetic temporary trees only. The Windows sharing test holds a
synthetic file with sharing denied, confirms a content open fails, then successfully captures its
metadata. A source audit supplements this OS test; neither alone proves all future versions
cannot read content. Other tests cover Unicode, nesting, empty/missing roots, metadata diffs,
schema validation and exclusion of the synthetic payload from serialized output.
