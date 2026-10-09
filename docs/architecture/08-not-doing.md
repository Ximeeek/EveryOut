# What EveryOut will not do in V1

EveryOut V1 means **local session clearing**, not guaranteed global logout. This is a target
scope statement, not a claim that providers are implemented. The boundaries below follow the
[Phase 8 overview](00-overview.md), [provider contract](01-provider-contract.md),
[manifest preservation rules](02-manifest-spec.md) and the cited research dossiers.

| Exclusion or limitation                                    | Consequence and evidence                                                                                                                                                                                                                                  |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| No server-side session invalidation                        | No remote token revocation, `revoke()` call, remote Sync reset or logout of other devices. Copied tokens and remote sessions may remain usable. The wipe stays offline; browser §§3–4, Windows §4 and provider contract                                   |
| No Windows account sign-out                                | No Windows logout, sign-in identity removal, PRT clearing, WAM/broker-cache purge or device/work-account disconnect. Instructions for a separate user/organization action may be shown; Windows §§1–2                                                     |
| No general secret inspection or transmission               | No credential inventory, cookie/token row inspection, browser key extraction or database authentication queries. The fixed Spotify exception is documented in [ADR 0006](../adr/0006-fixed-saved-login-adapters.md); values remain private and zeroized.  |
| No undo or backup of a wipe                                | Applied deletion is irreversible through EveryOut; no profile snapshots, secret-store copies or rollback after partial failure. Warn about local-only losses before approval; provider contract and browser §6                                            |
| No protection against silent SSO re-login                  | Windows identity, retained browser identity or another authentication source can create fresh sessions. Results describe local effects at verification time; Windows §2 and browser §3                                                                    |
| No clearing saved passwords, autofill, history or passkeys | These are not session scope. A mixed store that cannot be isolated without secret reads stays blocked, even with extra confirmation; browser §§1, 4–5 and manifest rules                                                                                  |
| No universal application/browser coverage                  | Framework signatures do not prove auth paths; relocated profiles, vendor stores, partitions, DBSC keys and extension state can remain unresolved. Unsupported candidates are visible gaps, not executable rules; browser §§1, 4, 7 and applications §§1–3 |
| No safe-loss guarantee for extensions or web storage       | Session-related storage may contain drafts, offline documents, vaults, wallet/recovery data and settings. Known supported losses need extra confirmation; unknown preservation conflicts block execution; browser §6 and applications §§1, 7              |
| No forced cleanup of every Windows profile                 | All-accounts mode still skips inaccessible/special profiles and loaded other-user scopes, and cannot assume administrator HKCU means another user. No cross-session process killing; Windows §5 and [06](06-permission-model.md)                          |
| No automatic privilege or protection bypass                | Current mode does not request UAC on errors. No ACL takeover, AV/EDR disablement or protected-process bypass; Windows §§5–6, applications §6 and [06](06-permission-model.md)                                                                             |
| No hooking, injection, foreign-memory reads or drivers     | File/registry and reviewed OS operations remain the boundary. Anti-cheat compatibility is not certification or an immunity guarantee; Windows §6 and applications §6                                                                                      |
| No automatic restart or authenticated verification         | Metadata absence is not remote logout, destroyed TPM keys or proof of failed refresh. No browser restart/network login probe in the wipe; browser §4 and [05](05-wipe-sequence.md)                                                                        |
| No guarantee that hard kill preserves work                 | Graceful close can wait for user interaction; force close can destroy unsaved work in other programs. Two seconds is a chosen policy, not a Windows safety guarantee; applications §5                                                                     |
| No machine-wide browser policy changes                     | The adopted profile-edit direction stays subject to secret-free validation; policy alternative is documented only. Existing policy or sync may recreate state; browser §§3, 7 and [07](07-sync-and-identity.md)                                           |
| No global hotkey or shutdown-triggered wipe                | These are V2 roadmap items, not an alternate V1 authorization path; [09](09-v2-extension-points.md)                                                                                                                                                       |

App cleanup, browser cleanup and Windows/Microsoft + developer-tools cleanup are independent
report scopes. None implies another, and the special category does not authorize deletion of
unsupported Windows identity stores. See [classification rules](04-classification-rules.md).

## Evidence and OPEN DECISIONS

- [Browser dossier](../research/01-browsers.md): §§1–7 for mixed stores, identity, sync, DBSC,
  extension loss and read exceptions.
- [Windows dossier](../research/02-windows-identity-and-multi-account.md): §§1–6 for sign-in
  protection, SSO, secret-returning APIs, local/remote CLI differences and multi-account limits.
- [Application dossier](../research/03-apps-detection-process-av.md): §§1–3, 5–7 for runtime
  ownership, closing risks, security-product uncertainty and application scope.

Unresolved coverage uses existing `browser-artifact-closure`, `app-session-scope`,
`extension-preservation-boundary`, `metadata-discovery-allowlist`, `metadata-av-compatibility`
and `pwa-shared-store-ownership` spikes in [00](00-overview.md#open-decisions), plus the
permission/closing/sync spikes in [05](05-wipe-sequence.md#open-decisions),
[06](06-permission-model.md#open-decisions) and [07](07-sync-and-identity.md#open-decisions).
An open decision does not relax a V1 exclusion. No new investigation is needed to treat the
explicitly excluded features as out of scope.
