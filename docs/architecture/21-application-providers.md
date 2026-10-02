# Generic application providers

Phase 23 adds `application` to the manifest schema: `electron-cef`, `webview2`, or `store`.
These are typed modes of `ApplicationProvider` / the shared `ManifestExecutor`, retaining the
engine's snapshot review, process gate, dry-run, confirmations, metadata verification and
handle-confined deletion. No application module reads file contents or decrypts payloads.

## Ownership and storage boundaries

The caller supplies a reviewed installation, current user and process gate. A framework cluster
or process name alone cannot establish ownership. This phase does not add package enumeration,
real product support, broker cleanup or an all-accounts mode.

Each executor binds one root. Electron/CEF uses a single app directory under selected-user
Roaming or Local AppData. WebView2 uses an explicitly configured `<app>/EBWebView` root with
exact profile patterns, such as `Default`. This example layout is not a universal WebView2
default. Shared UDFs, executable-adjacent UDFs and custom external CEF roots are unsupported.
Additional roots and persistent partitions require separately reviewed manifests and ownership
scopes; there is no recursive partition guessing or whole-profile deletion.

The fixed embedded-storage vocabulary includes `Cookies`, `Network/Cookies` and their declared
SQLite companions, `LocalStorage`, `SessionStorage`, `Local Storage`, `Session Storage`,
`IndexedDB`, `Service Worker` and `WebStorage`. `Network` itself is never cleared wholesale.
Local storage can contain offline documents, drafts and preferences; real manifests must declare
their known loss effects and obtain the engine's risk confirmation. Unknown effects block execution.

Store roots must be Local AppData `Packages/<PackageFamilyName>` and exactly match
`identity.package_id`. The package family name has a name and 13-character publisher ID, not a
versioned package full name or display name. Only declared storage families beneath `LocalState`,
`LocalCache` or `RoamingState` are allowed, including an explicitly reviewed `Session` directory.
`Session` is a synthetic example convention, not a Windows-defined session path. Whole
`LocalState`, package roots, `Settings`, documents and broker containers are not generic targets.

## Encryption and preservation

`Local State` remains in place. The application dossier describes shared encryption-key metadata
and explicitly leaves safe key invalidation unresolved. Removing a key could damage preserved
passwords or unrelated encrypted data. The fixed target vocabulary rejects this filename even
when a manifest mislabels its artifact family. `encryption-key-metadata` preservation is required.
DPAPI/safeStorage containers can be deleted only as declared session families; their format and
payload are irrelevant to detection and deletion. No `Local State`, SQLite or LevelDB parsing,
decryption, backup, credential APIs, foreign memory access or network operations are introduced.

## Browser-installed PWAs

The classifier resolves a PWA wrapper to its canonical browser owner and `BrowserProfile` claim.
Browser ownership takes precedence when all claims agree on the owner; conflicting owners remain
unclassified. An independent package identity cannot override browser ownership. Manifest loading
rejects application/browser identity and ownership conflicts, and application execution requires
the typed app scope. Browser profile origin targets therefore clean PWA sessions once through the
browser provider, with browser preview/report sections and no independent PWA deletion root.
No live PWA database enumeration or origin-specific isolated wipe is claimed here.

## Fixture verification and audit

The three `catalog/apps/example-*.json` entries are candidate-only synthetic examples; they cannot
execute as shipped. Tests promote only in-memory copies with synthetic coverage and known effects.
`applications.rs` verifies Electron/CEF, WebView2 and MSIX deletion, SQLite companions, untouched
preservation paths, mutation-free preview, candidate blocking, locked-file partial progress and
PWA execution/reporting through the browser profile. `policy.rs` verifies PWA ownership precedence.

A session placeholder held with read sharing denied still permits metadata-only discovery. One
test denies deletion and expects a lock result; another permits deletion and verifies absence
after the fixture handle closes. Windows can retain a delete-pending file until that close, so
the normal verification may report partial progress while it remains observable. All handles
and files belong to generated fixtures; no real user profiles or application accounts are touched.

Audit `crates/providers/src/application.rs` for content reads, copying, decoding, DPAPI or crypto
calls. The application path in `executor.rs` uses `probe_shallow`, `discovery_children`,
`delete_file` and `delete_tree`. Firefox's previously reviewed `profiles.ini` exception remains
browser-only and cannot be selected by an application manifest.

Evidence and limitations follow [application research](../research/03-apps-detection-process-av.md)
and [classification policy](04-classification-rules.md). No upstream path claim is promoted to
shipping-version logout coverage by these fixtures.
