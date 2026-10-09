# EveryOut

EveryOut is a Windows 10/11 desktop application for reviewing and clearing supported local
application and browser session data. It uses Tauri 2, Rust and React/TypeScript. Local clearing
does not guarantee logout on servers, other devices or retained Windows/browser identities.

**Status: V1 implementation, pre-alpha validation.** The review flow, engine, providers and
catalog tooling exist. Many real-product catalog entries remain candidates or blocked until
version-specific disposable-VM checks establish safe ownership, coverage and preservation.
An entry in the catalog is not a promise that its cleanup can execute.

**Permanent data loss warning:** deletion cannot be undone through EveryOut. Session-related
storage can also contain drafts, offline documents, settings, wallet or recovery data. Force
closing programs can lose unsaved work. Read the proposed effects and risks before confirming;
unsupported or unresolved scopes remain blocked. EveryOut provides no backup or undo.

## Safety principle

EveryOut does not decrypt credentials, inspect cookie/token rows, or export or transmit session
contents. General discovery is metadata-only. One compiled, version-pinned Spotify adapter reads
the fixed `prefs` file into private, zeroized buffers to remove four saved-login fields while
preserving other bytes; credential values are briefly present in memory and never returned to
the UI or reports. See [ADR 0006](docs/adr/0006-fixed-saved-login-adapters.md).
Wiping stays local and offline. Optional catalog downloads are separate, user-requested network operations and
require a configured public verification key and HTTPS URL.

The implementation uses reviewed file/registry and Windows operations with **no hooking,
injection, foreign-memory reads or drivers**. This is the anti-cheat compatibility boundary,
not certification or a guarantee against anti-cheat, antivirus or EDR warnings.

## Features and categories

- Metadata scans, explicit target/profile selection, reviewed plans and dry runs before deletion.
- Risk acknowledgements, reviewed process closing, cancellation and blocked/partial outcomes.
- Current-account mode by default; an on-demand elevated helper for explicitly enabled
  all-accounts mode, with fresh review and inaccessible/special scopes skipped.
- Native report export and persisted preferences; reports do not export secret contents.
- Manifest-based browser, application and Windows/Microsoft + developer-tools categories.
  These are independent scopes; the last category does not authorize unsupported Windows
  identity-store deletion.
- Signed catalog update verification, rollback resistance and atomic acceptance when public
  trust inputs are configured. Authenticode signing and catalog signing are separate.

See the [catalog table](docs/catalog/CATALOG.md) for locations, methods, confidence, blockers
and permanent-loss implications, and the [VM validation guide](docs/testing/vm-guide.md).

## Development cleanup diagnostics

Debug desktop builds write bounded JSON Lines diagnostics to
`%APPDATA%/io.github.ximeeek.session-wipe/dev-logs/cleanup.jsonl` and the development terminal.
The terminal prints the resolved location at startup. The file resets at 4 MiB.
Release builds do not create or write these logs.

Entries describe command errors, adapter failures, preview blockers, process counts, cleanup
stages, local operation methods/outcomes and verification results. No session file contents,
tokens, account identities or profile paths are recorded. A completed command is not a successful
logout: check each item's action outcomes and verification, and its authentication limitations.
Spotify desktop 1.2.98.301 has a reviewed saved-login adapter for the pinned executable;
other builds and Store installations remain blocked. The complete `prefs` file is preserved.
Browser development previews use simulated data and never remove local files.

## Install and verify

Use only maintainer-published assets from [EveryOut releases](https://github.com/Ximeeek/EveryOut/releases).
Drafts are review material, not published releases. The release pipeline builds a Windows x64 MSI;
Windows 10/11 x64 and the separately installed Microsoft Edge WebView2 Runtime are required.
The MSI deliberately does not download or bundle WebView2.

1. Download `EveryOut-x64.msi`, `SHA256SUMS.txt`, `build-inputs.json` and `reproducibility.json`
   from the same release. Confirm its source tag/commit and linked CI run.
2. Compare the exact filename and SHA-256 in `SHA256SUMS.txt`:

   ```powershell
   Get-FileHash -LiteralPath .\EveryOut-x64.msi -Algorithm SHA256
   Get-AuthenticodeSignature -LiteralPath .\EveryOut-x64.msi | Format-List
   ```

3. Check the release's signing status. Unsigned prereleases are explicitly marked **unsigned**;
   do not assume signing provider approval. For signed builds require a valid signature,
   the declared publisher, trusted chain and timestamp. Verify the installed `everyout.exe`
   and `everyout-elevated-helper.exe` too; their hashes/signatures are in `build-inputs.json`.
   With Windows SDK SignTool: `signtool verify /pa /all /v <file>`.
4. Only after verification, open the MSI. Review selections, candidate/blocked targets and
   risks in the app before any cleanup.

Checksums share the download channel's trust and do not independently authenticate the
publisher. Signing does not guarantee immediate SmartScreen reputation; device policy can
block unsigned downloads. Do not disable protection to run a build. Follow the
[verification and reproducibility procedure](docs/oss/reproducible-builds.md),
[code signing policy](docs/oss/code-signing.md) and
[false-positive handling](docs/oss/false-positives.md).

## What this app will NOT do

The following boundary statement is copied from
[the V1 exclusions](docs/architecture/08-not-doing.md), with relative links rebased for this README.

<!-- v1-exclusions:start -->

### What EveryOut will not do in V1

EveryOut V1 means **local session clearing**, not guaranteed global logout. This is a target
scope statement, not a claim that providers are implemented. The boundaries below follow the
[Phase 8 overview](docs/architecture/00-overview.md), [provider contract](docs/architecture/01-provider-contract.md),
[manifest preservation rules](docs/architecture/02-manifest-spec.md) and the cited research dossiers.

| Exclusion or limitation                                    | Consequence and evidence                                                                                                                                                                                                                                   |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No server-side session invalidation                        | No remote token revocation, `revoke()` call, remote Sync reset or logout of other devices. Copied tokens and remote sessions may remain usable. The wipe stays offline; browser §§3–4, Windows §4 and provider contract                                    |
| No Windows account sign-out                                | No Windows logout, sign-in identity removal, PRT clearing, WAM/broker-cache purge or device/work-account disconnect. Instructions for a separate user/organization action may be shown; Windows §§1–2                                                      |
| No general secret inspection or transmission               | No credential inventory, cookie/token row inspection, browser key extraction or database authentication queries. The fixed Spotify exception is documented in [ADR 0006](docs/adr/0006-fixed-saved-login-adapters.md); values remain private and zeroized. |
| No undo or backup of a wipe                                | Applied deletion is irreversible through EveryOut; no profile snapshots, secret-store copies or rollback after partial failure. Warn about local-only losses before approval; provider contract and browser §6                                             |
| No protection against silent SSO re-login                  | Windows identity, retained browser identity or another authentication source can create fresh sessions. Results describe local effects at verification time; Windows §2 and browser §3                                                                     |
| No clearing saved passwords, autofill, history or passkeys | These are not session scope. A mixed store that cannot be isolated without secret reads stays blocked, even with extra confirmation; browser §§1, 4–5 and manifest rules                                                                                   |
| No universal application/browser coverage                  | Framework signatures do not prove auth paths; relocated profiles, vendor stores, partitions, DBSC keys and extension state can remain unresolved. Unsupported candidates are visible gaps, not executable rules; browser §§1, 4, 7 and applications §§1–3  |
| No safe-loss guarantee for extensions or web storage       | Session-related storage may contain drafts, offline documents, vaults, wallet/recovery data and settings. Known supported losses need extra confirmation; unknown preservation conflicts block execution; browser §6 and applications §§1, 7               |
| No forced cleanup of every Windows profile                 | All-accounts mode still skips inaccessible/special profiles and loaded other-user scopes, and cannot assume administrator HKCU means another user. No cross-session process killing; Windows §5 and [06](docs/architecture/06-permission-model.md)         |
| No automatic privilege or protection bypass                | Current mode does not request UAC on errors. No ACL takeover, AV/EDR disablement or protected-process bypass; Windows §§5–6, applications §6 and [06](docs/architecture/06-permission-model.md)                                                            |
| No hooking, injection, foreign-memory reads or drivers     | File/registry and reviewed OS operations remain the boundary. Anti-cheat compatibility is not certification or an immunity guarantee; Windows §6 and applications §6                                                                                       |
| No automatic restart or authenticated verification         | Metadata absence is not remote logout, destroyed TPM keys or proof of failed refresh. No browser restart/network login probe in the wipe; browser §4 and [05](docs/architecture/05-wipe-sequence.md)                                                       |
| No guarantee that hard kill preserves work                 | Graceful close can wait for user interaction; force close can destroy unsaved work in other programs. Two seconds is a chosen policy, not a Windows safety guarantee; applications §5                                                                      |
| No machine-wide browser policy changes                     | The adopted profile-edit direction stays subject to secret-free validation; policy alternative is documented only. Existing policy or sync may recreate state; browser §§3, 7 and [07](docs/architecture/07-sync-and-identity.md)                          |
| No global hotkey or shutdown-triggered wipe                | These are V2 roadmap items, not an alternate V1 authorization path; [09](docs/architecture/09-v2-extension-points.md)                                                                                                                                      |

App cleanup, browser cleanup and Windows/Microsoft + developer-tools cleanup are independent
report scopes. None implies another, and the special category does not authorize deletion of
unsupported Windows identity stores. See [classification rules](docs/architecture/04-classification-rules.md).

### Evidence and OPEN DECISIONS

- [Browser dossier](docs/research/01-browsers.md): §§1–7 for mixed stores, identity, sync, DBSC,
  extension loss and read exceptions.
- [Windows dossier](docs/research/02-windows-identity-and-multi-account.md): §§1–6 for sign-in
  protection, SSO, secret-returning APIs, local/remote CLI differences and multi-account limits.
- [Application dossier](docs/research/03-apps-detection-process-av.md): §§1–3, 5–7 for runtime
  ownership, closing risks, security-product uncertainty and application scope.

Unresolved coverage uses existing `browser-artifact-closure`, `app-session-scope`,
`extension-preservation-boundary`, `metadata-discovery-allowlist`, `metadata-av-compatibility`
and `pwa-shared-store-ownership` spikes in [00](docs/architecture/00-overview.md#open-decisions), plus the
permission/closing/sync spikes in [05](docs/architecture/05-wipe-sequence.md#open-decisions),
[06](docs/architecture/06-permission-model.md#open-decisions) and [07](docs/architecture/07-sync-and-identity.md#open-decisions).
An open decision does not relax a V1 exclusion. No new investigation is needed to treat the
explicitly excluded features as out of scope.
<!-- v1-exclusions:end -->

## Development and project policies

See [CONTRIBUTING.md](CONTRIBUTING.md) for prerequisites, contributions and quality gates,
[the documentation index](docs/README.md), [ROADMAP.md](ROADMAP.md), [CHANGELOG.md](CHANGELOG.md)
and [the release process](docs/oss/release-process.md). Use synthetic fixtures and disposable
VMs; do not submit real profile or session data.

Report vulnerabilities privately under [SECURITY.md](SECURITY.md). For suspected antivirus/EDR
false positives follow [the reporting procedure](docs/oss/false-positives.md).

EveryOut is licensed under **GNU GPL v3.0 or later**. See [LICENSE](LICENSE).
