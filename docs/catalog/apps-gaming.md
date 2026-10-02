# EveryOut gaming launcher catalog

Phase 24 research, accessed 2026-10-02. All seven entries are **candidate / unverified** for
session removal. Source-confirmed paths and manual sign-out are separate from complete logout.
No shipping-version Windows 10/11 authentication, restart or preservation matrix has been run.
Scriptability of official logout is **unknown for all entries**: no reviewed offline, secret-free
CLI was established. Deletion does not revoke server sessions. Unknown does not mean no loss.

Paths use the selected user's Local/Roaming AppData. `{Steam}` denotes an exclusively owned
installation capability, not an AppData path. Its production discovery remains blocked.
The [pinned implementation inventory](https://github.com/TCNOco/TcNo-Acc-Switcher/blob/148ed80a303d56b691e22d54992031916eddede7/Platforms.json)
provides filename leads only; its content parsing, backups and broad cleanup are not adopted.

| Name                | Where the session lives                                                                                                                                                                                                                                                  | Cleaning method                                                                               | True logout available?                                                                                                                                                                                                                      | Risk of permanent data loss and which                                                                                                | Confidence of the information                                                    |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------- |
| Steam               | Candidate `{Steam}/config/loginusers.vdf`, `config/config.vdf`, top-level `ssfn*`; HKCU `Software/Valve/Steam`: `AutoLoginUser`, `RememberPassword` ([rule documentation](https://github.com/TCNOco/TcNo-Acc-Switcher/wiki/Platform-Steam)). Other stores unknown.       | Exact files and registry values; bounded ssfn file enumeration. Installation binding blocked. | Manual sign-out described by the rule documentation; scriptability unknown.                                                                                                                                                                 | Remembered accounts, mixed preferences, machine trust; offline access may require online reauthentication. Complete effects unknown. | Unverified overall; documented rule names do not verify shipping-version logout. |
| Epic Games Launcher | Candidate Local `EpicGamesLauncher/Saved/Config/WindowsEditor/GameUserSettings.ini`; vendor-confirmed `Saved/webcache`, `webcache_4147`, `webcache_4430` ([cache guide](https://www.epicgames.com/help/c-32735058/c-36403860/a20673770?lang=en-US)). Full scope unknown. | Candidate mixed INI file and three exact cache directories.                                   | Yes, manual [Sign Out](https://www.epicgames.com/help/en-US/c-Category_EpicGamesStore/c-EpicGamesStore_LauncherSupport/how-do-i-log-out-of-the-epic-game-launcher-a000085831?lang=en-US); scriptability unknown.                            | Local launcher and web preferences; offline data and complete effects unknown.                                                       | Unverified session rule; verified cache paths only.                              |
| Battle.net          | Candidate Roaming `Battle.net/Battle.net.config`; implementation inventories saved account names. Token location unknown.                                                                                                                                                | Candidate whole config deletion; no JSON editing.                                             | Manual logout mentioned by [Blizzard](https://us.support.blizzard.com/en-us/article/000032798); scriptability unknown.                                                                                                                      | Account-name history, mixed preferences; offline effects unknown.                                                                    | Unverified; account names are not authentication proof.                          |
| Riot Client         | Candidate Local `Riot Games/Riot Client/Data/Cookies`, `Data/Sessions`; full scope unknown.                                                                                                                                                                              | Candidate two exact directories.                                                              | Unknown in official-source review; [support lead](https://support-leagueoflegends.riotgames.com/hc/en-us/articles/360042286854-Unexpected-Error-With-Login-Session-How-to-Fix) inaccessible. Scriptability unknown.                         | Remembered authentication, cookie preferences; other session and offline effects unknown.                                            | Unverified implementation leads.                                                 |
| EA app              | Local `Electronic Arts/EA Desktop` is an implementation lead; `CEF/BrowserCache/EADesktop/Cookies` is an **inferred, unverified filename** under the CEF cache lead. Full scope unknown.                                                                                 | Candidate exact cookie file; no guessed companions or whole-directory reset.                  | Yes, manual logout documented by [EA](https://help.ea.com/en/articles/orders-and-rewards/ea-app-find-missing-games/). [App Recovery](https://help.ea.com/en/articles/technical-issues/clear-cache/) is cache repair. Scriptability unknown. | Cookie preferences if the file exists; offline entitlement and other effects unknown.                                                | Unverified, including exact cookie path.                                         |
| Ubisoft Connect     | Candidate Local `Ubisoft Game Launcher/ConnectSecureStorage.dat`, `user.dat`; other stores unknown.                                                                                                                                                                      | Candidate two exact files.                                                                    | Manual logout precedes [vendor cache repair](https://www.ubisoft.com/en-gb/help/connectivity-and-performance/article/emptying-the-cache-of-ubisoft-connect-pc/000061966); scriptability unknown.                                            | Remembered authentication, potentially mixed preferences; offline effects unknown.                                                   | Unverified session files; cache guide does not verify their effects.             |
| GOG Galaxy          | Candidate Local `GOG.com/Galaxy/Configuration/config.json`, HKCU `Software/GOG.com/Galaxy/refreshToken`. ProgramData and integrations uncovered.                                                                                                                         | Exact file/value deletion; multi-root engine execution blocked.                               | Manual logout acknowledged by [GOG requirements](https://docs.gog.com/quality-assurance/); scriptability unknown.                                                                                                                           | Local configuration, remembered authentication; integration and offline client effects unknown.                                      | Unverified, partial scope.                                                       |

## Steam

The exception removes only the two VDF files, regular top-level names beginning with `ssfn`
(case-insensitive Windows matching), and the two registry values. It preserves `userdata`,
`steamapps`, saves, `libraryfolders.vdf`, `SteamPath`, `LastGameNameUsed`, `PseudoUUID` and all
other keys/files. Whole `config/config.vdf` removal can lose non-synced preferences; editing
individual fields would require forbidden content reads.

[Valve's Guard guidance](https://help.steampowered.com/en/faqs/view/4C93-64EF-517B-3329)
describes remembered device authorization. The ssfn rule is from the implementation documentation,
not that Valve page. Removing legacy trust can require a new Guard challenge; modern-client
effects remain unverified. It does not remove the mobile authenticator.
[Valve's offline guide](https://help.steampowered.com/en/faqs/view/0E18-319B-E34B-B2C8)
is the vendor lead for cached-login dependence; exact cleanup effects need versioned evidence.

`steam::SteamCleanup` accepts only existing confined filesystem/registry capabilities and a
reviewed process gate. Preview does not mutate or close processes. Execution refuses candidates,
requires loss confirmation, detects changed ssfn inventories, checks process closure before each
mutation and retains individual outcomes for partial failures. It reads no payloads and resolves
no live installation. Only the `Ask` process policy is supported; forced shutdown requires a
separate engine approval. `reviewed-installation` is a research-only slot, not a filesystem authority:
it cannot become validated and neither generic executor nor platform binder resolves it.
Production integration stays blocked by `steam-installation-ownership`, shared-user installation
ownership and `gaming-session-closure`.

## Epic-games-launcher

Vendor cache repair does not establish logout. The mixed INI is an unverified session claim.
Unreal Engine registry identifiers and Epic Online Services are excluded. New cache suffixes need
new evidence; no wildcard fallback is used.

## Battle-net

Saved names may remain separate from authentication. No Local AppData, ProgramData, Agent or game
directory fallback is used. Whole config deletion is a hypothesis with mixed settings loss.

## Riot-client

Private settings, Config, game directories and Vanguard are excluded. No anti-cheat processes,
services or files are touched. The inaccessible official logout source stays unverified.

## Ea-app

The cookie filename is an inference. Broad directory-copying rules from the implementation are
not adopted. ProgramData and user INI stores remain uncovered. No recovery command or service
process is invoked. No unproven SQLite companions are declared.

## Ubisoft-connect

The two filenames are implementation leads. Preserve `settings.yaml`, installation caches and
savegames. Vendor cache-reset instructions are separate from session removal.

## Gog-galaxy

Shared ProgramData web storage, databases and integration credentials may retain sessions; they
are excluded pending ownership/preservation evidence. Preserve DRM-free game files and saves.
GOG's game requirement does not prove that offline Galaxy features survive cleanup. Delete only
the named `refreshToken` value, never its parent key or unrelated values.

## Fixture evidence and limits

`crates/providers/tests/gaming.rs` covers every manifest, risk declarations, restricted scopes,
dry runs, candidate refusal, synthetic deletion and preservation. Steam additionally covers exact
names, stale inventory, process failure, loss confirmation, denied payload read sharing and
partial deletion. Registry fixtures use a unique generated `Software/EveryOutTest` namespace,
never vendor keys. No real launcher or account is touched.

Fixture success establishes metadata effects only. Synthetic in-memory coverage does not promote
shipped manifests. Single-root AppData execution uses the existing engine risk/snapshot contract;
Steam and GOG production multi-root engine integration remains blocked. All entries still require
versioned Windows 10/11 VM evidence before verified status.
