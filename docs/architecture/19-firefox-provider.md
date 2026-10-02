# Firefox provider

Phase 21 adds the [Firefox candidate manifest](../../catalog/browsers/firefox.json) to EveryOut
and extends the [Phase 20 executor](18-chromium-providers.md). Firefox uses Gecko paths and a
reviewed configuration adapter, rather than Chromium directory patterns. Identity and Sync
operations remain reserved for Phase 22. S4 has no recorded execution results.

## Narrow configuration decision

`profiles.metadata_adapter: firefox-profiles-ini` is the sole approved content exception for
Firefox discovery. The semantic validator restricts it to the Firefox browser identity and the
single current-user Roaming AppData `Mozilla/Firefox` root. Directory patterns and root-profile
fallback cannot be combined with the adapter. Other adapter IDs remain unsupported. The existing
JSON schema already expresses `metadata_adapter`; its version and structure do not change.

The platform's fixed `firefox_profiles_ini` entry point opens only `profiles.ini`, relative to the
retained root capability. It uses a synchronous read handle, denies concurrent writes/deletion,
rejects reparse points and multiple hard links, and bounds input to 64 KiB of UTF-8. No arbitrary
filename or content-reading capability is exposed. Windows errors retain the existing stable
Locked/AccessDenied/ScopeViolation classification without printing configuration contents.

The Rust adapter retains only `Path` and `IsRelative` from numeric `ProfileN` sections, including
the default profile and additional profiles; names, default-selection flags and Install sections
are not retained. It refuses duplicate sections/fields, missing or invalid location fields,
empty profile sets and more than 100 entries. Relative paths use the platform's Windows path
checks. Absolute local-drive paths are accepted only beneath the retained Firefox root and are
converted back into capability-relative paths. UNC/device paths, traversal, ADS, redirects,
missing/non-directory profiles and overlapping profile roots block discovery. Duplicate paths
are deduplicated by physical directory identity, including case aliases. Unlisted directories never become profiles by guessing.

Profiles relocated outside the approved root remain unsupported, even when listed in the INI.
A configuration path cannot grant authority over another owner's folder. Local AppData caches
are not adopted as independent roots in this phase. Both limits are explicit in the manifest.
The adapter reparses location fields before every operation; a changed profile set invalidates
review. It does not retain or persist the full INI contents.

## Artifact and preservation boundary

The manifest enumerates cookies and SQLite WAL/SHM/journal families, quota/migration databases,
legacy DOM/IndexedDB stores, `storage/`, service-worker registration, the main sessionstore file
and the complete sessionstore-backups directory. Removing `storage/` covers Local Storage,
IndexedDB, Cache API and container/partition origin attributes, including the LS archive inside
that directory. Non-SQLite session/worker files have no invented SQLite companions. Session
backups include upgrade/fallback files without content reads or build-dependent wildcards.

An independent Firefox path allowlist rejects mislabeled logins/key/history/autofill/passkey
and configuration targets. `logins.json`, key databases, `places.sqlite` and its sidecars,
`formhistory.sqlite`, autofill/passkey stores, `cert9.db`, `signedInUser.json`, `prefs.js`, `user.js`,
`weave/`, `containers.json`, `permissions.sqlite` and `parent.lock` remain outside deletion.
Container definitions stay intact; their cookies and site-origin data are covered by the reviewed
whole-store targets. Password-manager extension data may itself contain passkeys, vaults or
recovery material and carries separate loss risk; shipping isolation is unresolved.

`ProcessGate` and the engine retain Phase 20's reviewed installation/current-user closure and
relaunch checks. A locked artifact yields Locked with partial progress where applicable. No
lockfile removal, lock bypass, process hooking, injection, foreign-memory access, drivers or
provider network calls are introduced. Dry run never closes processes or mutates targets.

## Extension risks and opaque stores

Firefox policy accepts only `browser-extension-data` and bounded Gecko GUID/email-style IDs.
The initial known-risk list has Bitwarden, Authenticator and MetaMask IDs with upstream manifest
sources, checked on 2026-10-02. This establishes product/ID association, not release coverage or
safe recovery. Presence in the legacy ID-addressed store adds vault/2FA or wallet/key-material
flags and the same provider confirmation plus instance-bound engine risk acknowledgment as
Phase 20. Unknown/unverified extension identities block execution.

Modern extension IndexedDB storage uses opaque `moz-extension` origins inside quota persistence
roots. Those origins cannot be matched to product IDs without reading prohibited mixed prefs
or extension payloads. Their presence adds unknown risk and blocks the scope. Mixed
`storage-sync-v2.sqlite`/`storage-sync.sqlite` and their sidecars are likewise observed only by
metadata, preserved and blocking; no row-level mapping or deletion is attempted. A newly added
origin, legacy extension store or sync database invalidates review. No retained quota-directory
handle prevents the engine from deleting an otherwise approved synthetic storage family.

## Validation and content-read audit

`crates/providers/tests/firefox.rs` creates fresh owned fixture roots only. It tests three
profiles (default, additional relative path with spaces, additional absolute in-root Unicode path),
container/partition storage and service-worker/session artifacts, multi-profile deletion,
dry-run metadata immutability, byte-identical preservation canaries, locked cookie companions,
both independent extension confirmations, unknown/opaque/sync blockers, changed profile and
extension sets, process failure, path escapes, INI hard links and mislabeled protected targets.
Secret/mixed canaries are held with sharing that denies content readers during execution.
No real browser, profile, account or process is touched. Parser tests cover malformed and bounded
input; the platform source audit permits only the fixed INI reader and keeps other content/network
APIs forbidden. Catalog tests exercise vendor-scoped adapter/extension validation and schema parity.

The content-read audit uses `rg -n 'ReadFile|FILE_READ_DATA|read_to_string|fs::read|File::open'
crates/providers/src crates/platform-windows/src`. In the Firefox execution path the sole read is
`native::firefox_profiles_ini`, called by `AllowedRoot::firefox_profiles_ini`, then
`firefox::discover`/`locations`. Generic metadata/deletion opens always pass `profile_config:
false`; no other file receives content rights. Bundled manifest JSON is configuration supplied
from memory. Fixture tests may read their own synthetic canaries for preservation assertions.

Shipping Firefox stays candidate with per-artifact `unverified` confidence and unresolved S4/
extension-preservation blockers. Fixture-only validated manifests cannot promote shipping
support. Durable website logout, restart restoration, browser identity/Sync, opaque extension
isolation, relocated profiles and version-specific residuals remain unverified or unsupported.
Metadata absence is never authentication proof or remote revocation.
