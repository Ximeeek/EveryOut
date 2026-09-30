# EveryOut heuristic scan lab tool

Separate read-only Rust CLI for disposable quiescent Windows 10/11 VMs. Its own `[workspace]`
and ignored target directory exclude it from the application workspace and release build.
No inventory was executed on the development machine; VM measurements belong to [S8](../../docs/spikes/S8-heuristic-confidence-calibration.md).

```powershell
cargo build --locked --manifest-path spikes/heuristic-scan/Cargo.toml
cargo test --locked --manifest-path spikes/heuristic-scan/Cargo.toml
cargo fmt --manifest-path spikes/heuristic-scan/Cargo.toml -- --check
cargo clippy --locked --manifest-path spikes/heuristic-scan/Cargo.toml --all-targets -- -D warnings
# Disposable VM only, as the intended test user:
& 'C:\Lab\Tools\everyout-heuristic-scan.exe' scan-lab
```

`scan-lab` is a lab acknowledgment, not VM detection. Exit 0 emits JSON schema version 1;
exit 1 emits a sanitized error with no report for a top-level failure. stdout is its only report
destination. Keep any evidence outside AppData. There is no network I/O, elevation, process close,
registry mutation, file mutation, payload reader, hashing or secret inspection.

## Inventory and signals

Official `windows-sys` bindings enumerate Uninstall and App Paths subkey names in both HKCU/HKLM
32/64-bit views, with enumeration rights only. View aliases are deduplicated; different sources
are not guessed to be the same install. JSON exports opaque registration IDs, sources and state,
never raw registry names/values. Names remain briefly in memory. Registration-only inventory is
not proof of an existing installation; registry values including executable/InstallLocation paths
remain unread while the architecture's metadata exception is unresolved.

Official `windows` bindings initialize WinRT and call PackageManager's
`FindPackagesByUserSecurityId` (the Rust projection of
[FindPackagesForUser](https://learn.microsoft.com/en-us/uwp/api/windows.management.deployment.packagemanager.findpackagesforuser),
accessed 2026-09-30) with an empty SID, selecting the calling user. Framework/resource packages
and listed OS brokers/runtime packages are excluded. OS package family and InstalledLocation
metadata map registered containers to one package; installation existence must be corroborated
by metadata before identity/ownership points are awarded. No manifest/settings file is opened.
Installation state is `existing`, `residue` when the location is absent, or `unknown` when it cannot
be safely observed. A missing candidate data root never earns identity/ownership points.
Package API failure aborts output; no all-users or administrator fallback.

One direct-child enumeration per `%APPDATA%` and `%LOCALAPPDATA%` discovers possible roots.
Packages are inspected only by registered PFN under `%LOCALAPPDATA%/Packages`, never by an
unbounded container walk. EveryOut, Microsoft, Packages, Temp, CrashDumps, Windows, Application
Data and EdgeWebView direct roots plus known broker/runtime PFN prefixes are excluded. The broad
Microsoft exclusion intentionally sacrifices coverage; it does not prove all remaining packages
are safe session owners. At most 10,000 entries per enumeration, with fixed layout probes only.

Layouts (indexed 0–7): root, User Data/Default, EBWebView/Default, LocalCache, LocalState,
RoamingState, LocalCache/Roaming and LocalCache/Local. No arbitrary child names, partitions,
other browser profiles, recursive sizes or executable-adjacent custom roots are searched.
Fixed storage observations: Cookies, Network/Cookies, Local Storage, Session Storage, IndexedDB,
Local State. Cookies locations count as one artifact; at least three distinct artifacts including
Cookies or IndexedDB fire the storage family. Network alone is conservatively insufficient.
Only metadata existence/type and logical regular-file size are observed; directory size is null,
not a recursive byte total. Runtime probes are resources/app.asar and resources/app in an
independently identified existing package installation. No generic EBWebView/Local State/name
match awards identity, ownership or runtime points; CEF packaging rules remain unreviewed.

The architecture's weights and gates are implemented without changing thresholds. Each family
fires once. JSON contains points, confidence and fired signals per candidate plus observations
and limitations; suppressed candidates are included for calibration, not presented as detected
apps. All candidates have `actionable: false`, including high identity confidence. Generic roots
usually remain suppressed because registry value reads and root ownership inference are blocked.
High is not a probability, authentication assertion or executable wipe plan.

Opaque candidate/registration IDs omit root names and user paths; they are stable only for an
unchanged sorted inventory. S8's private mapping must use separately reviewed OS/UI metadata;
do not export it. Missing paths are absent; denied/type-mismatched/redirected observations are
unknown, never clean-machine evidence. Registry incomplete coverage is explicit; top-level
AppData/package errors abort. Non-fixed/network/device paths and reparse ancestors/entries are
rejected. Path checks are not atomic handle-bound confinement: use only unchanged lab trees.

Tests use synthetic temporary trees only, including a Windows file held with sharing denied:
the oracle confirms payload opening fails while storage metadata still succeeds. Scoring gates,
cookie deduplication, package-install corroboration, missing/relative paths, junctions and a
source audit cover read-only boundaries. No test runs the live inventory or accesses credentials.
