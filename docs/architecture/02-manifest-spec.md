# Declarative provider manifest specification

## Purpose and evidence

New application/browser support is expressed in a manifest interpreted by the shared provider.
Rust code is reserved for reviewed exceptions referenced by stable adapter IDs; manifests cannot
contain scripts, arbitrary commands, SQL or executable expressions. The exact parser and schema
will be implemented later; YAML below is a human-readable proposed format only.

[Application research §§1, 3–4](../research/03-apps-detection-process-av.md) supports declarative
discovery and shows why general-cleaner deletion rules cannot be reused as session rules.
[Browser research §§1, 5–7](../research/01-browsers.md) establishes companions, mixed stores and
preservation risks. [Windows research §§1–4](../research/02-windows-identity-and-multi-account.md)
distinguishes supported local operations from remote revocation and broker state.

## Fields and interpretation

| Field                        | Required semantics                                                                                                                                                          |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `format_version`             | Integer version; unknown versions rejected                                                                                                                                  |
| `id`, `revision`, `name`     | Stable lowercase provider ID, immutable rule revision, display name                                                                                                         |
| `category`                   | Exactly `application`, `browser`, or `windows-microsoft-and-dev-tools`; classification precedence follows 04                                                                |
| `support`                    | `candidate` or `validated`; candidate manifests describe research but cannot execute                                                                                        |
| `compatibility`              | Explicit OS/product/channel/version coverage; unknown version coverage must not inherit validated status                                                                    |
| `identity`                   | Exact install/package/browser identities and process names as corroboration; names alone are insufficient                                                                   |
| `detection`                  | Named metadata signals, root IDs, independent evidence families and ownership requirement                                                                                   |
| `roots`                      | Root ID, approved known-folder base, relative path, user/profile scope and owner; registry roots require exact hive/key scope                                               |
| `profiles`                   | Bounded directory pattern or reviewed OS metadata adapter; no config-content parsing without a separate decision                                                            |
| `session_locations`          | Stable artifact ID, root/profile reference, relative path, kind, existence/size evidence, ownership and method ID                                                           |
| `cleaning_methods`           | Typed method IDs with complete effects and blockers; supported methods described below                                                                                      |
| `preserve`                   | Exact excluded artifact families and shared-store/key dependencies; deny takes precedence over include                                                                      |
| `true_logout`                | `available`, `unavailable`, or `unknown`; surface (`local-app`, `browser-identity`, `remote`), supported mechanism and evidence; availability does not imply V1 eligibility |
| `risks`                      | Explicit known loss flags, affected data, reason, evidence, `unknown` coverage and required confirmations                                                                   |
| `confidence`                 | Evidence quality `high`, `medium`, `low`, with rationale and version coverage; separate from runtime detection score                                                        |
| `evidence`                   | Dossier anchors, primary source URL/revision, access date and verified/hypothesis status per claim                                                                          |
| `limitations`, `open_spikes` | Unverified closure, shared ownership or preservation conflicts and named blocking spikes                                                                                    |

An omitted risk assessment is invalid, not equivalent to no risk. Risk flags include
`local-only-documents`, `drafts-or-offline-messages`, `settings-or-profiles`, `wallet-or-key-material`,
`vault-or-2fa-recovery`, `saved-passwords-passkeys-autofill-history`, `shared-store` and `unknown`.
Each records the data that could be permanently lost. Password/history/key-store conflicts are
hard blockers under browser preservation requirements; a warning is not a waiver.
Other known supported loss effects require additional confirmation while leaving selection intact.

## Location grammar and methods

Root expansion uses the selected owner's known folders, never the elevated process's ambient
environment. Relative paths cannot contain `..`, drive prefixes or UNC roots. Profiles may use
bounded single-component patterns; recursive drive-wide globs and traversal through reparse points
are forbidden. Exact registry key/value-name presence may be observed without fetching payloads.
User-supplied root overrides require a later reviewed discovery decision and cannot be injected
into an existing executable plan.

Typed method vocabulary:

- `delete-file-family`: delete an enumerated artifact and declared SQLite companions such as
  `-wal`, `-shm`, `-journal`; companion completeness needs product evidence.
- `delete-directory-family`: delete a reviewed storage family within its owner root, with all
  effects and exclusions declared; never infer that a whole profile is session-only.
- `delete-registry-target`: exact reviewed key/value target deletion, no content reads or broad
  hive clearing; requires evidence that it is unrelated to Windows sign-in identity.
- `local-api-operation`: fixed, reviewed Windows operation ID; inventory cannot use APIs that
  return credential blobs. Unsupported target discovery remains blocked.
- `exception-adapter`: fixed reviewed Rust adapter ID with the same contract and constraints.

No generic subprocess method is defined. A vendor local-logout CLI can be considered only through
a reviewed adapter proving offline behavior and secret-free invocation/output; documented
server-revoking commands are ineligible for V1. An unavailable method never falls back to a broader
delete. Overlap resolution occurs before a plan becomes executable.

## Worked candidate manifest

This Chrome example illustrates a **partial cookie-family candidate**, not a complete browser
wipe recipe. The path is supported by browser dossier §1 (C1); shipping-version closure and
sidecar behavior still require validation. Other artifact groups, browser identity and DBSC
remain uncovered. It stays non-executable despite high confidence in that specific path claim.

```yaml
format_version: 1
id: chrome
revision: 1
name: Google Chrome
category: browser
support: candidate
compatibility:
  os: [windows-10, windows-11]
  channel: stable
  product_versions: unvalidated
identity:
  browser_id: chrome
  process_names: [chrome.exe]
detection:
  require_exclusive_owner: true
  signals:
    - { id: root-present, root: user-data, family: ownership, observe: exists }
    - {
        id: cookies-present,
        artifact: network-cookies,
        family: storage,
        observe: exists-and-size,
      }
roots:
  - id: user-data
    base: local-app-data
    relative: 'Google\Chrome\User Data'
    scope: os-user
    owner: chrome
profiles:
  root: user-data
  directory_patterns: [Default, "Profile *"]
session_locations:
  - id: network-cookies
    root: user-data
    scope: profile
    relative: 'Network\Cookies'
    kind: file
    observe: exists-and-size
    ownership: browser-profile
    method: remove-cookie-family
cleaning_methods:
  - id: remove-cookie-family
    kind: delete-file-family
    companions: ["-wal", "-shm", "-journal"]
    blockers: [candidate-support, unvalidated-version-closure]
preserve:
  artifact_families:
    [password-stores, web-data, history, passkeys, encryption-key-metadata]
true_logout:
  availability: unknown
  surface: browser-identity
  mechanism: none-validated-for-v1
  evidence: [browser-identity]
risks:
  flags: [shared-store, unknown]
  affected_data: [site-cookie-preferences, cross-origin-sign-in-state]
  permanent_data_loss: unknown
  confirmations: [review-unknown-effects]
  evidence: [browser-c1]
confidence:
  level: high
  rationale: upstream-path-evidence-only-not-logout-coverage
evidence:
  - id: browser-c1
    dossier: "../research/01-browsers.md#chromium-artifact-inventory"
    source: "https://chromium.googlesource.com/chromium/src/+/HEAD/chrome/browser/net/profile_network_context_service.cc"
    accessed: "2026-09-30"
    status: verified-path
  - id: browser-identity
    dossier: "../research/01-browsers.md#3-browser-identity-synchronization-and-restoration"
    status: hypothesis-offline-closure
limitations:
  [cookie-family-only, no-authentication-proof, identity-and-dbsc-uncovered]
open_spikes: [browser-artifact-closure]
```

The example's two detection signals do not authorize a generic high-confidence heuristic match;
curated path evidence and runtime detection confidence are independent. Profile enumeration and
ownership must still meet the discovery contract.

## Catalog table format

Every catalog row uses exactly these six columns, with evidence links in the relevant cells:

| Name                               | Where the session lives                                                                   | Cleaning method                                               | True logout available?                                              | Risk of permanent data loss and which                                                                       | Confidence of the information                                                                           |
| ---------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Google Chrome (candidate, partial) | Per-profile `Network/Cookies`; additional browser stores omitted here; browser dossier §1 | Candidate file-family removal; not executable until validated | Unknown for V1 browser identity; local absence is not remote revoke | Unknown closure; cookies also hold site preferences; shared profile effects; mixed preserved stores blocked | High for upstream C1 path, unknown for shipping-release logout completeness; `browser-artifact-closure` |

The catalog's confidence concerns evidence, not probability of an active login. `True logout`
must state scope and distinguish manual vendor support, local invalidation, and server revocation.
A blank cell is invalid; unknown is explicit. This phase defines the table, not a supported-app list.

## OPEN DECISIONS

The [central register](00-overview.md#open-decisions) names `browser-artifact-closure`,
`app-session-scope`, `metadata-discovery-allowlist` and `extension-preservation-boundary`.
Until resolved, candidate manifests and unresolved operations remain non-executable. Catalog
distribution, updates and imported-dataset licensing adoption are reserved for Phase 10.
