# EveryOut desktop application catalog

Phase 25 research, accessed 2026-10-03. All 17 entries are **candidate / low / unverified** for
local session removal. Verified vendor data paths are distinguished from unverified session
coverage. No shipping-version Windows 10/11 logout or preservation matrix has been run.
No reviewed offline, secret-free invocation of official logout was established for any entry;
manual logout availability does not authorize automated invocation. Wipes never use the network.

Paths use the selected owner's Roaming/Local AppData, not the process environment. An
`unresolved` root and artifact are typed research markers, **not paths**: no binder can resolve
them, and they cannot become validated. Unknown is never a reason to delete a broader store.

| Name              | Where the session lives                                                                                                                                                                  | Cleaning method                                             | True logout available?                                                                                                                                                          | Risk of permanent data loss and which                                                                                                   | Confidence of the information                                 |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| Discord           | Roaming `discord` / `Local Storage` ([source](https://support.discord.com/hc/en-us/articles/115004307527--Windows-Corrupt-Installation))                                                 | Candidate exact directory deletion; blocked until validated | Yes, manual [vendor guidance](https://support.discord.com/hc/en-us/articles/209572128-How-do-I-log-out); scriptability unknown                                                  | Discord drafts and local preferences; complete effects unknown                                                                          | Low / unverified for cleanup; specific vendor claims in notes |
| Spotify           | Roaming `Spotify` / `prefs` ([source](https://support.spotify.com/us/article/how-to-log-out/))                                                                                           | Candidate exact file deletion; blocked until validated      | Yes, manual [vendor guidance](https://support.spotify.com/us/article/how-to-log-out/); scriptability unknown                                                                    | Remembered accounts and mixed preferences; offline download effects unknown                                                             | Low / unverified for cleanup; specific vendor claims in notes |
| Slack             | Roaming `Slack` / `Local Storage` ([source](https://slack.com/help/articles/212475728-Deploy-Slack-for-Windows))                                                                         | Candidate exact directory deletion; blocked until validated | Yes, manual [vendor guidance](https://slack.com/help/articles/214613347-Sign-out-of-Slack); scriptability unknown                                                               | Local workspace preferences and possibly unsent drafts; complete effects unknown                                                        | Low / unverified for cleanup; specific vendor claims in notes |
| Microsoft Teams   | Local `Packages/MSTeams_8wekyb3d8bbwe` / `LocalCache/Microsoft/MSTeams` ([source](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-administration/clear-teams-cache)) | Candidate exact directory deletion; blocked until validated | Yes, manual [vendor guidance](https://support.microsoft.com/en-US/teams/troubleshooting/sign-out-or-remove-an-account-from-microsoft-teams); scriptability unknown              | Personalization, diagnostic logs and potentially local drafts; complete effects unknown                                                 | Low / unverified for cleanup; specific vendor claims in notes |
| Telegram Desktop  | Roaming `Telegram Desktop` / `tdata` ([source](https://github.com/telegramdesktop/tdesktop/blob/dev/Telegram/SourceFiles/platform/win/specific_win.cpp))                                 | Candidate exact directory deletion; blocked until validated | Yes, manual [vendor guidance](https://telegram.org/faq); scriptability unknown                                                                                                  | Local cache, settings and device authorization; cloud messages retained; unsynced data effects unknown                                  | Low / unverified for cleanup; specific vendor claims in notes |
| WhatsApp Desktop  | Unknown exact session files; see notes below ([source](https://faq.whatsapp.com/378279804439436/))                                                                                       | Blocked; no deletion scope                                  | Yes, manual [vendor guidance](https://faq.whatsapp.com/834124628020911/); scriptability unknown                                                                                 | Potential device-only messages, media, drafts and linked-device state; exact loss unknown                                               | Low / unverified for cleanup; specific vendor claims in notes |
| Signal Desktop    | Roaming `Signal` / `sql`, `attachments.noindex` ([source](https://support.signal.org/hc/en-us/articles/9045714156314-Can-t-Open-Signal))                                                 | Candidate exact directory deletion; blocked until validated | Unknown suitable desktop logout; no reviewed adapter ([source](https://support.signal.org/hc/en-us/articles/360007059752-Backup-and-Restore-Messages))                          | Desktop-only message history, attachments and identity keys; phone history does not guarantee restoration of desktop-only data          | Low / unverified for cleanup; specific vendor claims in notes |
| Thunderbird       | Roaming `Thunderbird` / `Profiles` ([source](https://support.mozilla.org/en-US/kb/profiles-where-thunderbird-stores-user-data))                                                          | Mixed profile reset rejected by password-preservation gate  | Unknown suitable desktop logout; no reviewed adapter ([source](https://support.mozilla.org/en-US/kb/profiles-where-thunderbird-stores-user-data))                               | Local Folders, POP mail, unsent drafts, address books, saved passwords and settings                                                     | Low / unverified for cleanup; specific vendor claims in notes |
| Microsoft Outlook | Unknown exact session files; see notes below ([source](https://support.microsoft.com/en-us/outlook/find-and-transfer-outlook-data-files-from-one-computer-to-another))                   | Blocked; no deletion scope                                  | Unknown suitable desktop logout; no reviewed adapter ([source](https://support.microsoft.com/en-us/office/account-management/sign-out-of-office))                               | Potential local PST/POP mail, unsent drafts, contacts and cached data; session-store loss unknown                                       | Low / unverified for cleanup; specific vendor claims in notes |
| Proton VPN        | Unknown exact session files; see notes below ([source](https://github.com/ProtonVPN/win-app/blob/master/README.md))                                                                      | Blocked; no deletion scope                                  | Yes, manual [vendor guidance](https://protonvpn.com/support/protonvpn-windows-vpn-application); scriptability unknown                                                           | Potential preferences, profiles and cached authentication; exact loss unknown                                                           | Low / unverified for cleanup; specific vendor claims in notes |
| NordVPN           | Unknown exact session files; see notes below ([source](https://support.nordvpn.com/hc/en-us/articles/37815095197969-I-keep-getting-logged-out-on-Windows))                               | Blocked; no deletion scope                                  | Unknown suitable desktop logout; no reviewed adapter ([source](https://support.nordvpn.com/hc/en-us/articles/19472023025169-How-to-install-and-use-the-NordVPN-app-on-Windows)) | Potential preferences, profiles and cached authentication; exact loss unknown                                                           | Low / unverified for cleanup; specific vendor claims in notes |
| Ente Auth         | Roaming `Ente Technologies, Inc` / `Ente Auth` ([source](https://ente.com/help/auth/troubleshooting/offline-codes-unavailable))                                                          | Candidate exact directory deletion; blocked until validated | Unknown suitable desktop logout; no reviewed adapter ([source](https://ente.com/help/auth/features/offline-mode))                                                               | Offline-only TOTP seeds, local vault secure-storage keys and backups stored inside app data; no server recovery for offline codes       | Low / unverified for cleanup; specific vendor claims in notes |
| WinAuth (legacy)  | Roaming `WinAuth` / `winauth.xml` ([source](https://github.com/winauth/winauth/issues/327))                                                                                              | Candidate exact file deletion; blocked until validated      | No server session; close/lock is not erasure ([source](https://github.com/winauth/winauth/blob/master/WinAuth/WinAuthHelper.cs))                                                | Local authenticator secrets, recovery material and account-bound encrypted configuration; loss may prevent access to protected accounts | Low / unverified for cleanup; specific vendor claims in notes |
| Exodus            | Roaming `Exodus` / `exodus.wallet` ([source](https://www.exodus.com/support/en/articles/8598708-how-do-i-rescue-an-overwritten-wallet))                                                  | Candidate exact directory deletion; blocked until validated | No server session; close/lock is not erasure ([source](https://www.exodus.com/support/en/articles/8598644-how-do-i-delete-my-wallet-and-start-over))                            | Private keys, wallet seed and wallet access; funds may become permanently inaccessible without external recovery material               | Low / unverified for cleanup; specific vendor claims in notes |
| Electrum          | Roaming `Electrum` / `wallets` ([source](https://electrum.readthedocs.io/en/latest/faq.html))                                                                                            | Candidate exact directory deletion; blocked until validated | No server session; close/lock is not erasure ([source](https://electrum.readthedocs.io/en/latest/faq.html))                                                                     | Wallet seeds, imported private keys and wallet metadata; imported keys and local labels may not be restored by a deterministic seed     | Low / unverified for cleanup; specific vendor claims in notes |
| Bitwarden         | Roaming `Bitwarden` / `data.json` ([source](https://bitwarden.com/help/configure-clients-selfhost/))                                                                                     | Candidate exact file deletion; blocked until validated      | Yes, manual [vendor guidance](https://bitwarden.com/help/vault-timeout/); scriptability unknown                                                                                 | Encrypted local vault cache, unsynced changes, settings and possibly device-trust keys; reapproval and two-step login may be required   | Low / unverified for cleanup; specific vendor claims in notes |
| 1Password         | Unknown exact session files; see notes below ([source](https://support.1password.com/settings-security/))                                                                                | Blocked; no deletion scope                                  | Yes, manual [vendor guidance](https://support.1password.com/sign-out/); scriptability unknown                                                                                   | Local vault cache, unsynced items and trusted-device authorization; loss may require another authorized device or recovery process      | Low / unverified for cleanup; specific vendor claims in notes |

## discord

Vendor confirms root only; Local Storage session role is an unverified framework inference.

## spotify

Roaming Spotify/prefs is an unverified candidate; vendor logout does not verify the path or removal effect. Store builds excluded.

## slack

Standard-install root and Local Storage session role unverified; Store package storage and persistent partitions excluded.

## microsoft-teams

Vendor cache repair path is verified as cache only. It does not prove logout; Windows WAM, Office identity and classic Teams excluded.

## telegram-desktop

tdata under standard desktop root is an unverified Windows session scope; portable/custom workdir and Store builds excluded. Telegram Desktop does not provide Secret Chats.

## whatsapp-desktop

Current native desktop package and session files unknown. No Electron legacy path or package-family guess is used.

## signal-desktop

Vendor confirms Roaming Signal root; sql and attachments.noindex are unverified child targets. History and session cannot be safely separated without content reads. Relinking may transfer phone history, not prove recovery of all desktop data. config/key metadata excluded; scope incomplete.

## thunderbird

Profiles is vendor documented mixed data, not session-only. Credential/profile separation unknown; password preservation is a hard blocker even with loss approval. Custom profile locations excluded.

## outlook

Classic/new Outlook differ; Office sign-out is not proof of mail-session logout. PST/OST files are mail stores, not deletion targets. Windows/Office shared identity excluded.

## proton-vpn

Documented Local ProtonVPN/Logs is diagnostics, not a session store. Exact session persistence unknown. No service, driver, network reset or Linux CLI invocation.

## nordvpn

Official Reset app guidance is not a reviewed offline logout API. Exact session store and scriptable logout unknown. Shared service ownership unresolved; no drivers, service state or network reset touched.

## ente-auth

Vendor documents Windows data directory. Whole app data contains vault and protected keys; session cannot be safely separated. Synced accounts and offline-only mode cannot be distinguished through metadata. Legacy Documents stores excluded.

## winauth

Archived local authenticator, not a server login. Vendor owner confirms default data root; source names winauth.xml. Whole file deletion destroys authenticators; portable/custom files excluded.

## exodus

Vendor confirms Windows root and exodus.wallet directory. A local wallet is not a server session. Keys cannot be separated from wallet access; Backups and other app files excluded, so no complete erasure is claimed.

## electrum

Official FAQ documents default Windows data directory and wallets. Closing/locking a wallet does not remove keys. Entire default wallets family is destructive; portable, custom, hardware and external wallet files excluded.

## bitwarden

Vendor documents standard Windows root and mixed data.json settings file. Exact authentication closure unverified. Offline cache is not guaranteed server-synced; session/trust/vault separation unknown. Store, portable and overridden app-data paths excluded.

## onepassword

Vendor documents Roaming 1Password/settings/settings.json only; preferences are not a proven session store. Exact vault/session cleanup paths unknown. Account removal, lock and device unlink have different effects; no CLI adapter is adopted.

## Risk and fixture contract

All entries require their own `review-<provider-id>-permanent-loss` confirmation. Known local-only
loss is explicit for Signal, authenticators, wallets and vaults; remaining risk coverage stays
unknown rather than claiming that drafts or offline data cannot be lost. Wallet balances on the
blockchain are not deleted, but losing the only private keys can permanently remove access.
No backup, seed, authenticator or synchronization status is read or checked by EveryOut.

The fixed `desktop-client` mode accepts only the listed provider/root/artifact tuples; it does
not widen the Electron/CEF/Store modes. Unknown locations have no filesystem capability. Whole
Thunderbird Profiles removal is research only and cannot pass the saved-password preservation
gate even with every confirmation. There is no safe session/data separation established for
Signal history, authenticator vaults or wallet files. The Ente subtree includes its secure-storage
keys; the key-preservation label applies only to unlisted stores, not files inside that target.
Exodus backups and external wallet/authenticator files are preserved and may retain access;
these partial rules do not promise comprehensive erasure or logout.

Low-confidence application candidates start unchecked even when resolved by a known provider.
Explicit selection still cannot waive candidate support, unknown effects, process ownership,
version or preservation blockers. Verification status of individual path claims is recorded in
the notes; every session artifact remains unverified because scope/closure has not been tested.

`crates/providers/tests/desktop.rs` validates all entries and adversarial scope/risk changes.
Windows fixture tests cover actual declared candidate paths without mutation, explicit selection,
synthetic reviewed deletion for resolvable scopes, preservation and engine risk approvals.
Unknown roots never bind; Thunderbird stays blocked. Separate synthetic Electron storage carriers
exercise each category's loss contract (including mail and VPN) without inventing product paths.
They use the catalog risk flags but do not verify product logout. Tests touch only generated
FixtureFolders and opaque invented bytes; no real apps, accounts, process identities or secrets.
