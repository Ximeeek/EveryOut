# EveryOut Chromium catalog

Phase 20 provides five **candidate** manifests. Every artifact carries evidence references and
`confidence: unverified`; the manifest confidence has `status: unverified`. Upstream path evidence
does not establish shipping-version coverage. S1-S4 remain pending, so these manifests cannot
authorize a live wipe. The executor is exercised with separately validated synthetic rules.

| Name                         | Where the session lives                                                                                                                                                                       | Cleaning method                                                                        | True logout available?                                    | Risk of permanent data loss and which                                                                  | Confidence of the information                                   |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| [Google Chrome](chrome.json) | Local AppData `Google/Chrome/User Data`, `Default`, numeric `Profile N`; [layout evidence](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/user_data_dir.md)                       | Candidate cookie/SQLite families, origin-storage directories and session restore files | Unknown; browser identity and sync reserved for Phase 22  | Offline documents, extension vaults/2FA/wallets, session restore; unknown mixed stores block execution | Unverified shipping coverage; per-artifact evidence in manifest |
| [Microsoft Edge](edge.json)  | Local AppData `Microsoft/Edge/User Data`; [vendor layout](https://learn.microsoft.com/en-us/deployedge/edge-learnmore-create-user-directory-vars)                                             | Same candidate artifact families                                                       | Unknown; vendor identity and SSO uncovered                | Same known risks; Edge identity stores preserved                                                       | Unverified shipping coverage; S4 pending                        |
| [Brave](brave.json)          | Candidate Local AppData `BraveSoftware/Brave-Browser/User Data`; [vendor deletion guidance](https://support.brave.com/hc/en-us/articles/4413256282765-How-do-I-delete-my-data-in-Brave)       | Same candidate artifact families                                                       | Unknown; Sync and Wallet state uncovered                  | Origin documents and extension wallets/vaults; vendor Wallet and Rewards state preserved               | Unverified root spelling and shipping coverage                  |
| [Opera](opera.json)          | Candidate Roaming AppData `Opera Software/Opera Stable`; root-profile plus `Default` and numeric `Profile N`; [vendor profile guidance](https://help.opera.com/en/latest/crashes-and-issues/) | Same candidate artifact families, including legacy session files                       | Unknown; Sync and vendor identity preserved               | Offline documents, vaults/2FA/wallets, session restore; GX and other channels unsupported              | Unverified root and multi-profile layouts                       |
| [Vivaldi](vivaldi.json)      | Local AppData `Vivaldi/User Data`; [vendor profile guidance](https://help.vivaldi.com/desktop/install-update/full-reset-of-vivaldi/)                                                          | Same candidate artifact families                                                       | Unknown; Sync and vendor saved-session variants uncovered | Origin documents and extension wallets/vaults; mixed configuration preserved                           | Unverified shipping and standalone layouts                      |

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
