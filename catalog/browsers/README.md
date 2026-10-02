# EveryOut browser catalog

Phase 20 provides five Chromium **candidate** manifests; Phase 21 adds Firefox. Every artifact carries evidence references and
`confidence: unverified`; the manifest confidence has `status: unverified`. Upstream path evidence
does not establish shipping-version coverage. S1-S4 remain pending, so these manifests cannot
authorize a live wipe. The executor is exercised with separately validated synthetic rules.

| Name                            | Where the session lives                                                                                                                                                                                                              | Cleaning method                                                                        | True logout available?                                    | Risk of permanent data loss and which                                                                                       | Confidence of the information                                               |
| ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------- | --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| [Google Chrome](chrome.json)    | Local AppData `Google/Chrome/User Data`, `Default`, numeric `Profile N`; [layout evidence](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md)                                                              | Candidate cookie/SQLite families, origin-storage directories and session restore files | Unknown; browser identity and sync reserved for Phase 22  | Offline documents, extension vaults/2FA/wallets, session restore; unknown mixed stores block execution                      | Unverified shipping coverage; per-artifact evidence in manifest             |
| [Microsoft Edge](edge.json)     | Local AppData `Microsoft/Edge/User Data`; [vendor layout](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)                                                                                    | Same candidate artifact families                                                       | Unknown; vendor identity and SSO uncovered                | Same known risks; Edge identity stores preserved                                                                            | Unverified shipping coverage; S4 pending                                    |
| [Brave](brave.json)             | Candidate Local AppData `BraveSoftware/Brave-Browser/User Data`; [vendor deletion guidance](https://support.brave.com/hc/en-us/articles/4413256282765-How-do-I-delete-my-data-in-Brave)                                              | Same candidate artifact families                                                       | Unknown; Sync and Wallet state uncovered                  | Origin documents and extension wallets/vaults; vendor Wallet and Rewards state preserved                                    | Unverified root spelling and shipping coverage                              |
| [Opera](opera.json)             | Candidate Roaming AppData `Opera Software/Opera Stable`; root-profile plus `Default` and numeric `Profile N`; [vendor profile guidance](https://help.opera.com/en/latest/crashes-and-issues/)                                        | Same candidate artifact families, including legacy session files                       | Unknown; Sync and vendor identity preserved               | Offline documents, vaults/2FA/wallets, session restore; GX and other channels unsupported                                   | Unverified root and multi-profile layouts                                   |
| [Vivaldi](vivaldi.json)         | Local AppData `Vivaldi/User Data`; [vendor profile guidance](https://help.vivaldi.com/desktop/install-update/full-reset-of-vivaldi/)                                                                                                 | Same candidate artifact families                                                       | Unknown; Sync and vendor saved-session variants uncovered | Origin documents and extension wallets/vaults; mixed configuration preserved                                                | Unverified shipping and standalone layouts                                  |
| [Mozilla Firefox](firefox.json) | Roaming AppData `Mozilla/Firefox`; paths from profiles.ini; cookies, quota/DOM stores, service workers and session backups; [Mozilla profile guidance](https://support.mozilla.org/en-US/kb/profiles-where-firefox-stores-user-data) | Candidate SQLite families, site-origin storage and session restore removal             | Unknown; Mozilla account and Sync reserved for Phase 22   | Offline site data, container-partitioned sessions, extension vault/2FA/wallet data; opaque extension stores block execution | Unverified shipping coverage; S4 pending, per-artifact evidence in manifest |

## Preservation and incomplete coverage

`Login Data`, account password stores, `Web Data`, autofill, history, passkeys, mixed Preferences,
Secure Preferences, AccountPreferences and root Local State are outside the target allowlist.
Deletion of encryption-key metadata is forbidden. `Network/Device Bound Sessions` and its SQLite
companions are candidate DBSC targets; database absence cannot prove key destruction or refresh
failure. Legacy/alternate DBSC partitions, browser identity/sync, vendor wallet state,
internal Extension State/Rules/Scripts/Managed Extension Settings and ambiguous generic Storage or
notification/cache families remain uncovered and preserved. See the
[artifact inventory and preservation boundary](../../docs/research/01-browsers.md).

PWAs use the selected browser profile's origin storage and browser category. They do not gain
independent wipe actions. No shortcut/configuration payload or account contents are read.
Relocated, portable, custom and non-stable-channel roots require separate reviewed rules.

## Extension risk lookup

The three Chrome Web Store IDs below were checked against their official listings on 2026-10-02.
The lookup is an initial known-risk list, not an exhaustive extension catalog. A verified listing
establishes the ID/product association only; it does not validate storage isolation, recoverability
or logout. Alternative store IDs remain unknown unless separately recorded.

- [Bitwarden Password Manager](https://chromewebstore.google.com/detail/bitwarden-password-manage/nngceckbapebfimnlniiiahkandclblb): `nngceckbapebfimnlniiiahkandclblb`, vault/passkey cache risk.
- [Authenticator](https://chromewebstore.google.com/detail/authenticator/bhghoamapcdpbohphigoooaddinpkbai): `bhghoamapcdpbohphigoooaddinpkbai`, 2FA recovery risk.
- [MetaMask](https://chromewebstore.google.com/detail/metamask/nkbihfbeogaeaoehlefnkodbefgpgknn): `nkbihfbeogaeaoehlefnkodbefgpgknn`, wallet/key-material risk.

Presence in bounded local/sync extension or app-setting directories adds the corresponding risk
flags and an `extension-permanent-data-loss` confirmation. The engine also requires its separate
instance-bound risk acknowledgment. Unknown extension data blocks the profile scope; it cannot
be treated as harmless by accepting a warning. Shared origin-storage isolation remains unverified
and all shipping candidates retain their blockers.

## Firefox discovery and extension boundary

Firefox uses only Path/IsRelative fields in `profiles.ini`; relative and absolute paths must stay
beneath the approved current-user Firefox root. Unlisted or externally relocated profiles are
not adopted. Logins/key databases, history, autofill, passkeys, mixed prefs, Mozilla identity,
Sync, container definitions, permissions and the profile lockfile are preserved. Cookies and
site storage include container/partition contexts without reading container or cookie contents.
See the [Phase 21 contract and content-read audit](../../docs/architecture/19-firefox-provider.md).

The following upstream manifests establish Firefox IDs, checked on 2026-10-02. Sources are
linked directly because their filenames do not contain the Gecko ID. As with Chromium, these
are product associations only; shipping storage isolation remains unverified.

- [Bitwarden Password Manager](https://raw.githubusercontent.com/bitwarden/clients/main/apps/browser/src/manifest.json): `{446900e4-71c2-419f-a6a7-df9c091e268b}`, vault/passkey-cache risk.
- [Authenticator](https://raw.githubusercontent.com/Authenticator-Extension/Authenticator/dev/manifests/manifest-firefox.json): `authenticator@mymindstorm`, 2FA recovery risk.
- [MetaMask](https://raw.githubusercontent.com/MetaMask/metamask-extension/main/app/manifest/v2/firefox.json): `webextension@metamask.io`, wallet/key-material risk.

Legacy `browser-extension-data/<id>/` directories trigger the same risk acknowledgments as
Phase 20. Unknown IDs, opaque `moz-extension` IndexedDB origins and mixed extension Sync
databases block execution; prefs.js/UUID maps and extension payloads are never read. The Sync
stores stay preserved, and no installed-extension inference authorizes opaque-origin deletion.
