# Metadata-only detection and classification

Phase 19 adds the workspace library `everyout-detection`. It is not connected to Tauri,
commands or the UI, contains no real catalog entries, and does not supply cleaning plans.
The spike remains excluded from the workspace and shipped dependency graph. All tests inject
fresh Phase 17 fixture roots and synthetic inventory; none calls the live OS inventory.

## Phase 19 scope clarification

Phase 25 leaves low-confidence application candidates unchecked in both scanner and engine,
including known-provider detections. Typed unresolved desktop roots are reported as incomplete
coverage without filesystem probing. Other resolved known-provider detections retain the
Phase 19 selection policy.
Selection expresses intent; unsupported scope and all existing engine review gates still block
execution. All heuristic results, including high confidence, remain in a separate unchecked
candidate group until S8 passes. The weights 4/2/2/3 and high/medium/low gates are unverified
architecture policy, not measured probabilities. Synthetic tests do not pass S8.

Every detection with a resolved owner has exactly one category. Unknown/conflicting owners
remain unclassified, unchecked and non-executable. Classification follows the physical session
owner, not WebView2 rendering, Microsoft names, Store packaging or shortcut names. A reviewed
browser-wrapper alias is applied only when the observed physical store matches an existing
browser detection; otherwise it remains unresolved. SSO relationships do not change app/browser
ownership. Shared identity and developer-tool categories require explicit manifest semantics.

`ProviderInstance.detection_origin` distinguishes known providers from heuristic instances.
Old JSON without provenance defaults to heuristic. Phase 18's default selection now uses this
field rather than high confidence plus validated support. Detection provenance comes from trusted
Rust providers, never from a UI selection. The engine's scope, review, confirmations and operation
validation remain enforced. The engine also refuses missing owner identifiers and instance-level
ownership-conflict issues at scan time. Unclassified candidates have no executable
`ProviderInstance` or cleaning plan.

## Inventory and exact remaining exceptions

`InstalledInventory::collect_current_user` enumerates Uninstall and App Paths subkey names in
HKCU/HKLM 32/64-bit views, including the WOW6432Node view. It merges view aliases within the same
hive/source, preserving provenance. Different sources/hives are not guessed to be the same install.
Registration names are not asserted to be human-readable application names or existing installs.
No registry value is read. Fixed current-user/common Start Menu Programs roots provide one bounded
directory-entry enumeration: direct shortcut filenames only, no shortcut loading, target resolution
or arguments. Nested program groups are reported as unobserved.

The current-user WinRT package API supplies package identity, publisher and installation location.
Only its reviewed OS-supplied installation location can be observed through the existing guarded
local NTFS capability. Raw locations are not retained in inventory/report DTOs. Framework/resource
packages and excluded brokers/runtimes do not become candidates. Failure, residue and unknown
installation metadata do not earn identity/ownership points. Enumeration errors remain explicit.

The original full inventory requirement remains incomplete in these exact areas:

| Required element                                                                   | Current output                                                                              | Exception needed before expanding coverage                                                                                                |
| ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| Installed app display names, installation locations and publisher from Uninstall   | Subkey names and presence only; remaining fields unknown                                    | Explicit allowlist for `DisplayName`, `InstallLocation` and `Publisher` string values, including hive/view and safe output handling       |
| Installation/executable paths from App Paths                                       | Subkey names and presence only                                                              | Explicit allowlist for the default executable-path value and, if required, `Path`; no arbitrary value reads                               |
| Start Menu app identity, install root and browser/PWA mapping                      | Direct shortcut filenames only                                                              | Reviewed shortcut target metadata exception; arguments require a separate explicit exception and must not expose secret-bearing arguments |
| Browser/custom profile, portable-install and executable-adjacent WebView2 mappings | Reviewed manifest patterns and fixed layouts only                                           | Approved exact-root/ownership metadata source; profile configuration and whole-drive searching stay blocked                               |
| Generic provider registry session-target observations                              | Only an exact HKCU Uninstall/App Paths inventory registration can corroborate a root signal | Separate reviewed key-presence scope beyond the installation inventory; credential-like values remain forbidden                           |

No exception above is granted by this phase. Missing evidence is incomplete coverage, not proof
that a machine is clean or an installation absent. The live inventory was not run on the host.

## Discovery boundaries and scoring

The scanner uses current-user `RootResolver` capabilities, with one direct-child AppData
enumeration and eight fixed layouts. Registered package PFNs map exact package containers; the
Packages directory is never enumerated to invent package owners. Generic root names and multiple
registry views never create independent identity signals. Storage needs three distinct artifacts,
including Cookies or IndexedDB; the two cookie locations count once. Generic runtime evidence is
accepted only from an independently identified existing package install. Uncorroborated generic
storage clusters are suppressed because they supply only one family.

Manifest detection accepts loader-validated configuration supplied from memory. It probes only
declared roots/artifacts and exact or reviewed wildcard profile patterns, with existence/type and
regular-file sizes. Inventory registration can corroborate the same manifest identity; name matches
alone cannot establish an install/root owner. Missing/type-mismatched/denied observations remain
absent or unknown with coverage limitations. Reports contain stable signal IDs, confidence, fired
families, metadata observations and limitations, never payload bytes or absolute user paths.

`SafePath::probe_shallow` does not enumerate directory descendants or calculate directory size.
The existing recursive `probe` remains available to earlier phases, but discovery never calls it.
AppData and Programs enumeration is bounded to 10,000 entries per root; package/registry enumeration
has the same bound. Redirected discovery entries are omitted with explicit coverage.
The scan additionally retains at most 1,000 detections, bounding handle use and pairwise overlap
resolution; reaching the limit is explicit incomplete coverage. Existing
mutation enumeration still refuses reparse entries. All fixed-path observations retain guarded
ancestor handles and reject reparse, hard-link, network/device and out-of-root traversal.

Physical volume/file identities and ancestor chains resolve exact and ancestor/descendant overlaps.
Exact aliases for the same resolved owner merge into one item; conflicting owners or broader/narrower
stores become unclassified candidates. Scope expansion and shared-store deletion are never authorized
by discovery. The engine still owns reviewed action deduplication and inclusion/confirmation gates.
Cancellation stops subsequent discovery; native bounded inventory API calls do not guarantee immediate
interruption. Missing coverage and incomplete scans remain visible. Run-local opaque candidate IDs are
not persistent cross-inventory identifiers.

## Validation and open gates

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
pnpm lint
pnpm typecheck
pnpm format:check
pnpm build
```

Tests cover all five Phase 17 profile families, high/medium heuristic fixtures, low conflicting
ownership candidates, a false-positive corpus, PWA aliases, independent WebView2/Store apps, shared
UDF conflicts, explicit shared-identity classification, physical ancestor overlaps, cancellation,
registry-name-only corroboration, sharing-denied payloads, and junction refusal without descendant
enumeration. Engine tests cover every category/confidence/support/provenance combination; core tests
cover conservative legacy provenance. Metadata snapshots prove quiescent fixture preservation.

S8 calibration, metadata discovery exceptions, PWA/shared-UDF ownership validation, hostile race
review and Windows/AV matrix gates remain open. Fixture tests establish only the stated synthetic
behavior; there is no measured detector false-positive rate, authentication proof, automatic
shortcut/PWA identification or validated real-provider cleaning scope.
