# Application detection, process closing, and AV/EDR on Windows

Research dossier for EveryOut, Phase 7. Evidence access date: 2026-09-30.
Scope: application discovery and classification, prior art, shutdown risks, security-product
interaction, and initial catalog candidates. No code, destructive experiments, or architecture
decision. Browser artifacts and Windows identity remain in the Phase 5 and 6 dossiers.

Evidence convention: `[VERIFIED: <url>, accessed <date>]` supports only the adjacent factual
claim. `[HYPOTHESIS]` marks an inference, proposal, or unresolved claim. Upstream source code
establishes that implementation at the cited revision, not behavior in every shipping product.
Candidate support links are research entry points, not proof of session locations or wipe support.

## 1. Electron, CEF, and WebView2 applications

### Storage and encryption boundaries

Electron's Windows `appData` path is `%APPDATA%`; `userData` defaults to that directory plus the
application name. `sessionData` defaults to `userData` and contains Chromium-generated session
data, including cookies, local storage, network state, and caches. Applications can override these
paths. [VERIFIED: https://www.electronjs.org/docs/latest/api/app, accessed 2026-09-30]

Electron supports persistent partitions using `persist:` and in-memory partitions otherwise;
`session.storagePath` exposes a persistent session's path. Consequently, one default directory is
not a complete inventory of all partitions. [VERIFIED: https://www.electronjs.org/docs/latest/api/session, accessed 2026-09-30] [HYPOTHESIS]

Chromium upstream names `Cookies`, `Local State`, and `Network`; DOM-storage code selects
`Local Storage\leveldb` and `Session Storage` for LevelDB, with distinct `LocalStorage` and
`SessionStorage` SQLite paths. Its partitioned-storage constants name `IndexedDB` and `WebStorage`.
[VERIFIED: https://raw.githubusercontent.com/chromium/chromium/main/chrome/common/chrome_constants.h, accessed 2026-09-30]
[VERIFIED: https://raw.githubusercontent.com/chromium/chromium/main/components/services/storage/dom_storage/dom_storage_database.cc, accessed 2026-09-30]
[VERIFIED: https://raw.githubusercontent.com/chromium/chromium/main/components/services/storage/public/cpp/constants.cc, accessed 2026-09-30]

An illustrative search root is `%APPDATA%\<app>`, with `Local Storage`, `Cookies`,
`Session Storage`, `IndexedDB`, and `Network` as candidate names; `Network\Cookies` and
partition-specific subdirectories also need consideration. Treat these as layout heuristics,
not a universal contract, an authentication inventory, or permission to delete entire directories.
Local storage may mix authentication with drafts, preferences, or offline content. [HYPOTHESIS]

CEF's versioned 120.1 reference permits configurable `cache_path` and `root_cache_path`, and an
empty cache path uses in-memory storage. Session-cookie persistence is separately configurable.
CEF therefore does not establish `%APPDATA%\<app>` as a universal default. [VERIFIED: https://cef-builds.spotifycdn.com/docs/120.1/structcef__settings__t.html, accessed 2026-09-30]

WebView2's user data folder (UDF) holds cookies, DOM storage, databases, and cached resources.
For non-UWP hosts, the documented default is `<executable-name>.WebView2` beside the executable;
hosts can configure a different UDF and share it between controls. [VERIFIED: https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder, accessed 2026-09-30]

Microsoft documents `EBWebView\Crashpad\reports` beneath an app UDF. Its presence is a useful
WebView2 signal, but crash data is not authentication evidence. [VERIFIED: https://learn.microsoft.com/en-us/deployedge/webview2-security-tools, accessed 2026-09-30] [HYPOTHESIS]

Electron documents Windows DPAPI protection for the synchronous `safeStorage` API: protection
against other users does not imply isolation from applications running as the same user.
Its async API has separate documented providers/semantics, so record the Electron version and API
before assigning a protection model. [VERIFIED: https://www.electronjs.org/docs/latest/api/safe-storage, accessed 2026-09-30]

DPAPI normally ties decryption to the same logon credentials and machine; the machine-scope flag
allows any user on that machine to decrypt. This is a protection mechanism, not a logout API.
[VERIFIED: https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata, accessed 2026-09-30] [HYPOTHESIS]

At Chromium revision `25a5bc7242a972e00204085eca1bc300b9861102`, OSCrypt stores a DPAPI-protected,
Base64-encoded key in local-state preferences under `os_crypt.encrypted_key` and uses it for
AES-GCM encryption. This explains a possible role of `Local State`; it does not establish the
key format or enabled encryption backend of all current Electron/CEF/WebView2 releases.
[VERIFIED: https://chromium.googlesource.com/chromium/src/+/25a5bc7242a972e00204085eca1bc300b9861102/components/os_crypt/sync/os_crypt_win.cc, accessed 2026-09-30] [HYPOTHESIS]

Do not parse `Local State`, decrypt `safeStorage` payloads, inspect SQLite/LevelDB contents, or
remove shared encryption metadata as a generic logout shortcut. Whether removing a key would
invalidate sessions without damaging unrelated encrypted data is unresolved. [HYPOTHESIS]

### Detection signals and safe observations

Here, “safe” means a proposed observation that avoids reading session contents; it does not mean
an AV exemption, proof of ownership, or a deletion approval. Restrict discovery to installation
metadata and known candidate roots, with no traversal through reparse points. [HYPOTHESIS]

| Signal                                                                                            | Evidence and limits                                                                                                                                                                                                                                           | Proposed observation                                                                                      |
| ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `resources\app.asar` or `resources\app`                                                           | Electron documents both Windows packaging layouts. [VERIFIED: https://www.electronjs.org/docs/latest/tutorial/application-distribution, accessed 2026-09-30] An archive alone cannot identify session paths or prove the app is still installed. [HYPOTHESIS] | Existence and file size only; do not unpack or execute it. [HYPOTHESIS]                                   |
| Co-occurring `Local Storage`, `Session Storage`, `IndexedDB`, `Network`, `Cookies`, `Local State` | Candidate Chromium-family cluster; names can be shared by browsers, test fixtures, and abandoned profiles. [HYPOTHESIS]                                                                                                                                       | Existence/type and file-size metadata only; do not open databases or JSON. [HYPOTHESIS]                   |
| `EBWebView` beneath an identified host UDF                                                        | Microsoft documents an `EBWebView` descendant. [VERIFIED: https://learn.microsoft.com/en-us/deployedge/webview2-security-tools, accessed 2026-09-30] Host ownership still needs corroboration. [HYPOTHESIS]                                                   | Directory existence only; no crash-report contents. [HYPOTHESIS]                                          |
| `libcef.dll`, `WebView2Loader.dll`, or runtime processes                                          | Candidate framework hints; shared runtimes and optional embedding can mislead. [HYPOTHESIS]                                                                                                                                                                   | Known installation-file existence/size; no foreign-process memory access. [HYPOTHESIS]                    |
| Uninstall/App Paths/package identity plus framework cluster                                       | Candidate corroboration linking an installation to a data owner. Display names alone are insufficient. [HYPOTHESIS]                                                                                                                                           | Read selected installation metadata, not credentials or arbitrary command strings into logs. [HYPOTHESIS] |

**Expected false-positive rate: unknown, not a defensible numeric percentage.** No representative
benchmark was established in this research. A single generic folder is expected to be weak;
independent installation identity plus a framework cluster is expected to be stronger, but that
ranking is unmeasured. A framework match also does not prove an authenticated session exists.
[HYPOTHESIS]

Later evaluation should label installed browsers, packaged and unpackaged apps, portable apps,
unused profiles, fixtures, shared runtimes, and unrelated same-name directories. Report precision,
recall, and FP/(FP+TN) with sample counts by framework; do not call the fraction of wrong positive
matches the false-positive rate. Unknown roots should remain non-actionable. [HYPOTHESIS]

## 2. Store/MSIX applications and browser-installed PWAs

Packaged per-user data uses `%LOCALAPPDATA%\Packages\<PackageFamilyName>`; documented children
include `LocalState`, `LocalCache`, `RoamingState`, and `Settings`. `LocalState` is persistent local
app data, not a dedicated session store. [VERIFIED: https://github.com/microsoftdocs/msix-docs/blob/main/msix-src/desktop/managing-your-msix-reset-and-repair.md, accessed 2026-09-30]

Enumerate registered packages with `Get-AppxPackage` for the current user, or the corresponding
package-management APIs in a later implementation. Other-user enumeration requires administrator
permissions. Retain PFN and installation identity, and distinguish application packages from
framework/resource dependencies rather than treating every package as a logout target.
[VERIFIED: https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage, accessed 2026-09-30] [HYPOTHESIS]

Chromium's desktop PWA coordinator belongs to a `Profile`; its web-app database, icons, and most
preferences are profile-associated. Chrome documents `chrome://web-app-internals` for inspecting
web-app state. [VERIFIED: https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/web_applications/README.md, accessed 2026-09-30]

Edge exposes installed apps through `edge://apps`, including websites installed as apps.
[VERIFIED: https://blogs.windows.com/msedgedev/2022/05/18/find-and-manage-your-installed-apps-and-sites/, accessed 2026-09-30]

For a future inventory, correlate browser app listings, Start Menu shortcut target/arguments,
browser identity, profile, and app ID. A `--app-id` or `--app` launch argument is a candidate hint,
not sufficient evidence alone. Automated enumeration from a live browser's internal database is
not a verified public Windows API and must not read session secrets. [HYPOTHESIS]

Proposed mutually exclusive ownership rule, for later validation rather than an ADR:
[HYPOTHESIS]

1. Browser-owned profile data, including browser-installed PWAs and their aliases, is **browser**.
   Assign its PWA display entry to that owner rather than creating an independent wipe root.
   Browser ownership takes precedence over an Uninstall entry or package/shortcut wrapper.
   [HYPOTHESIS]
2. A separately identified native/Electron/CEF/WebView2 host with its own data root, or an
   independently registered app package with its own app-data container, is **application**.
   Use `(user, PFN)` or `(user, installation identity, data root)` for deduplication. [HYPOTHESIS]
3. Do not make a binary guess when identity or root ownership conflicts. Mark the discovery
   unresolved and exclude it from the actionable catalog until evidence assigns exactly one
   owner. Package-only browser PWAs and shared UDFs need explicit validation. [HYPOTHESIS]

This rule gives each accepted target one category without claiming all discovered objects are
classifiable. Browser PWA authentication and tab authentication may overlap by origin; separate
sign-out completeness remains unverified. [HYPOTHESIS]

## 3. Installed-application sources and Winapp2 licensing

### Windows discovery sources

| Source                   | Verified capability                                                                                                                                                                                                                                                                                            | Proposed use and blind spots                                                                                                                                                                                                                                  |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Uninstall registry       | Windows Installer documents `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall` values such as DisplayName, Publisher, InstallLocation, and UninstallString. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key, accessed 2026-09-30]                                | Also inspect the corresponding HKCU key for per-user registrations; not every installer supplies it or a usable InstallLocation. Stale entries and portable apps need corroboration. Never execute UninstallString for discovery. [HYPOTHESIS]                |
| 32/64-bit registry views | Microsoft documents `KEY_WOW64_32KEY` and `KEY_WOW64_64KEY` for alternate views and warns against direct access to reserved `Wow6432Node` paths. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view, accessed 2026-09-30]                               | Inspect both applicable Uninstall views under HKLM and HKCU; recognize the familiar `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` representation, but avoid assuming every key is redirected. Deduplicate view aliases. [HYPOTHESIS] |
| App Paths                | HKCU/HKLM `Software\Microsoft\Windows\CurrentVersion\App Paths\<exe>` registers executable paths and optional search-path additions. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/shell/app-registration, accessed 2026-09-30]                                                                   | Corroborate executables; this is not an exhaustive installed-app or session-root database. [HYPOTHESIS]                                                                                                                                                       |
| Start Menu shortcuts     | Known folders include per-user/common Programs; Shell links expose target, working directory, and arguments. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid, accessed 2026-09-30] [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/shell/links, accessed 2026-09-30] | Read shortcut metadata without launching targets; reject document/help links and distinguish PWA aliases. Do not resolve remote targets or retain arbitrary arguments. Missing shortcuts and duplicates remain possible. [HYPOTHESIS]                         |
| Store/MSIX packages      | `Get-AppxPackage` lists installed packages for a user profile. [VERIFIED: https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage, accessed 2026-09-30]                                                                                                                                       | Join package identity to metadata-only container checks; a leftover directory is not proof of registration. [HYPOTHESIS]                                                                                                                                      |

### Winapp2: usefulness and exact obligations

The retrieved Winapp2.ini header identifies version `260915` and **4,068 entries**, superseding
the brief's approximate “3.7k+”. These are cleaning entries, not 4,068 distinct applications.
[VERIFIED: https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini, accessed 2026-09-30] [HYPOTHESIS]

Winapp2 is a declarative cleaning dataset. `Detect` checks registry keys and `DetectFile` checks
paths/files; any matching detection key displays an entry. Deletion uses `FileKey`/`RegKey`, with
separate exclusions and warnings. [VERIFIED: https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/CONTRIBUTING.md, accessed 2026-09-30]

Use detection expressions as attributed research leads, never automatically import deletion
expressions into a session catalog. The retrieved file includes password/autofill and broader
cleanup rules, so its target set exceeds this phase's purpose. [VERIFIED: https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini, accessed 2026-09-30] [HYPOTHESIS]

The repository license is CC BY-SA 4.0. For redistributed material, section 3(a) requires retention
of supplied creator/designated attribution, copyright, license and warranty-disclaimer notices,
and a source link where reasonably practicable; indicate modifications and retain previous
modification indications; include the license text or link. Attribution may be reasonable for
the medium and must be removed on the licensor's request where reasonably practicable.
[VERIFIED: https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/License.md, accessed 2026-09-30]

For shared adaptations, section 3(b) requires CC BY-SA with the same elements at version 4.0 or
later, or a designated compatible license, plus its text/link. Do not add restrictions or effective
technological measures that prevent exercising granted rights. Section 4 covers substantial
database extraction/reuse and can treat a new database incorporating a substantial portion as
adapted material. The license does not grant patents/trademarks or imply endorsement.
[VERIFIED: https://creativecommons.org/licenses/by-sa/4.0/legalcode.en, accessed 2026-09-30]

Creative Commons designates **GPLv3** as compatible with BY-SA 4.0, in one direction only.
[VERIFIED: https://creativecommons.org/compatible-licenses/, accessed 2026-09-30] Its explanation
limits this route to GPL version 3, recommends it for content inseparably adapted into software,
and describes a proxy mechanism for future-version compatibility. It does not authorize a blanket
GPL “or later” grant for imported material. [VERIFIED: https://wiki.creativecommons.org/wiki/ShareAlike_compatibility%3A_GPLv3, accessed 2026-09-30]

Project comparison: [ADR 0001](../adr/0001-license.md) selects GPL-3.0-or-later. **Usable**, as a
separately attributed CC BY-SA 4.0 dataset alongside GPL project code, retaining its own license
and meeting the above redistribution/adaptation duties. This is the proposed conservative route,
not an adoption decision. **Not usable** as an uncredited import labeled solely
GPL-3.0-or-later. An inseparable adaptation can use the GPLv3 compatibility route only with
version-specific notices and applicable GPL source obligations; resolve future-version rights
before claiming unrestricted “or later” coverage for that combined work. [HYPOTHESIS]

Alternatives: Windows registration/package metadata and independently authored rules verified
from vendor documentation; request an explicit additional license from Winapp2 contributors;
evaluate BleachBit CleanerML separately with file-level license review. CleanerML supports XML
cleaners and a running-process guard, but its capabilities do not establish the license of each
third-party rule. [VERIFIED: https://docs.bleachbit.org/cml/cleanerml/, accessed 2026-09-30] [HYPOTHESIS]

## 4. Prior-art comparison

“Gaps” below compare documented behavior with a proposed EveryOut requirement; they are not
claims of experimentally demonstrated defects or an exhaustive security review. [HYPOTHESIS]

| Project               | What it does well: primary evidence                                                                                                                                                                                                                                                                               | Gap for this task and proposed EveryOut difference                                                                                                                                                                                                                                                                                                                                                                  |
| --------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| TcNo Account Switcher | Documents account switching by storing/swapping files and registry values, configurable platforms, and support across game launchers and Discord. [VERIFIED: https://raw.githubusercontent.com/TCNOco/TcNo-Acc-Switcher/master/README.md, accessed 2026-09-30]                                                    | Retaining reusable account state for switching does not meet the proposed delete-only boundary. Learn from platform-specific evidence, but do not copy credential backup/restoration workflows. [HYPOTHESIS]                                                                                                                                                                                                        |
| AutoLogout (TagSteel) | Documents manual/idle/app-close/Windows-sign-out triggers, user-level operation, action logs, and browser cleanup; acknowledges lack of guaranteed remote revocation and a Dashlane-preservation trade-off. [VERIFIED: https://raw.githubusercontent.com/TagSteel/AutoLogout/main/README.md, accessed 2026-09-30] | Source targets process image names with `taskkill /IM /T`, adds `/F` after a failed first call and one-second sleep, and logs successful initial requests without a subsequent exit check. [VERIFIED: https://raw.githubusercontent.com/TagSteel/AutoLogout/main/auto_logout/system_utils.py, accessed 2026-09-30] Prefer verified ownership, actual exit status, and separately approved force close. [HYPOTHESIS] |
| BleachBit             | Documents preview, configurable cleaners, Winapp2 integration, and operations on files, registry, JSON, and SQLite. [VERIFIED: https://www.bleachbit.org/features, accessed 2026-09-30]                                                                                                                           | General cleanup and database editing are broader than session removal without reading secrets. Preserve preview/reporting ideas; require independently validated session scope and explicitly show incomplete logout. [HYPOTHESIS]                                                                                                                                                                                  |
| CCleaner              | Documents configurable cookie deletion and a Cookies to Keep list; deleting cookies can affect logins and other stored site data. [VERIFIED: https://support.ccleaner.com/articles/en_US/Master_Article/select-cookies-to-clean-with-ccleaner-for-windows, accessed 2026-09-30]                                   | Retained login cookies conflict with an unconditional logout expectation; cookie cleanup alone does not prove app/session closure. Make exclusions explicit and distinguish intended local sign-out from complete remote revocation. [HYPOTHESIS]                                                                                                                                                                   |

## 5. Process closing and unsaved work

Restart Manager accepts explicit filenames, process identities, and services through
`RmRegisterResources`; `RmGetList` returns applications/services using registered resources.
It is a way to discover resource users, not proof that all returned processes belong to the
selected application. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources, accessed 2026-09-30] [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist, accessed 2026-09-30] [HYPOTHESIS]

`RmShutdown` supports forced shutdown and a restart-registration restriction. Microsoft documents
forced unresponsive-app shutdown within 30 seconds and service shutdown after 20 seconds;
**two seconds is not its documented timeout**. Restart registration does not prove unsaved work
will survive. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmshutdown, accessed 2026-09-30] [HYPOTHESIS]

`WM_CLOSE` tells a window/application it should terminate; the application can prompt the user
before closing, and default handling destroys the window. A sent message is not confirmation that
the process exited or its helper processes released files. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-close, accessed 2026-09-30] [HYPOTHESIS]

`TerminateProcess` unconditionally terminates process threads, requests pending-I/O cancellation,
can compromise DLL-maintained global state, and is asynchronous when invoked on another process.
Use an exit wait to establish completion. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess, accessed 2026-09-30]

A hard kill after two seconds can cut off a save prompt or lengthy flush and lose unsaved work,
interrupt mail composition/uploads, or leave application data inconsistent. Killing every process
using a shared resource or matching an image name can affect other programs and accounts. There is
no verified universal two-second interval that makes this safe. [HYPOTHESIS]

Proposed safety criteria: close only selected, identity-checked targets in the authorized user
session; request graceful closure; allow time for user interaction; show processes that remain;
skip locked data rather than reporting success. Require separate, informed force-close consent,
then verify actual exit and recheck ownership before any later deletion. Keep unrelated processes
and services out of the default close set. These are research recommendations, not an implemented
shutdown policy. [HYPOTHESIS]

## 6. AV/EDR detection and concrete mitigations

### Published detection examples and their limits

Sigma's Windows security hunting rule `4b60e527-ec73-4b47-8cb3-f02ad927ca65` selects event 4663,
file objects with AccessMask `0x1`, and Chromium paths containing `Default\Login Data`,
`User Data\Local State`, or `Default\Network\Cookies`. It requires File System auditing plus
object read/list auditing, has broad process-path filters, is marked `test`, and calls for heavy
baselining. It is not a universal “any touch triggers AV” rule. [VERIFIED: https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules-threat-hunting/windows/builtin/security/win_security_file_access_browser_credential.yml, accessed 2026-09-30]

Sigma's related Windows file-access rule `91cb43db-302a-47e3-b3c8-7ede481e27bf` requires the
Microsoft-Windows-Kernel-File ETW provider, includes `Login Data` and `Local State`, and explicitly
lists antivirus, backup, search software, and installations outside `C:` as false-positive sources.
[VERIFIED: https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules-threat-hunting/windows/file/file_access/file_access_win_browsers_credential.yml, accessed 2026-09-30]

Elastic's “Suspicious Web Browser Sensitive File Access” example selects file-open activity from
untrusted/unsigned processes or `osascript`, including `Cookies` and `Login Data`, but is explicitly
**macOS**. It is useful comparative evidence, not a Windows rule. [VERIFIED: https://elastic.github.io/detection-rules-explorer/rules/20457e4f-d1de-4b92-ae69-142e27a4342a, accessed 2026-09-30]

A first-person Norton Community report describes a Browser Data Protection alert/block against
`MsMpEng.exe` accessing Firefox cookies. This verifies that the report was published, not its
diagnosis or a reproducible product rule. No primary product specification for the exact Norton
trigger was established here; current release behavior and metadata-only/delete access remain
unverified. [VERIFIED: https://community.norton.com/t/should-i-unblock-msmpeng-exe-and-if-so-how/354392, accessed 2026-09-30] [HYPOTHESIS]

Reading/decrypting/copying secrets and deleting files have different access patterns. Metadata-only
discovery may avoid read-based rules, but there is no evidence that all AV/EDR products exempt
existence/size queries or deletion. Do not emulate browser identity, bypass hooks, or disable
protection to make a wipe succeed. [HYPOTHESIS]

### Mitigation and reporting candidates

- **Code signing:** Microsoft says consistent signing with a trusted-root certificate helps identify
  software publishers, but offers no developer preapproval/false-positive-prevention program.
  Signing cannot be represented as guaranteed behavioral-detection immunity.
  [VERIFIED: https://learn.microsoft.com/en-us/defender-xdr/developer-faq, accessed 2026-09-30] [HYPOTHESIS]
- **Transparency:** publish readable target descriptions and versioned rules; show the local-only
  purpose, executable publisher, intended effects, exclusions, and irreversible consequences.
  This is a user-trust measure, not a verified reduction in detection rates. [HYPOTHESIS]
- **Dry-run:** enumerate known-target existence and file-size metadata, with no opening of secret
  databases, no process closure, and no writes/deletes. Unknown or conflicting ownership should
  be visibly non-actionable. [HYPOTHESIS]
- **Detailed report:** record target IDs, rules, aggregate counts/bytes, close outcomes, skips,
  access-denied errors, and incomplete results. Redact user paths and arbitrary arguments; exclude
  cookies, tokens, decrypted data, database rows, crash dumps, and session-store backups.
  [HYPOTHESIS]
- **Minimal privileges:** use the current user's access; do not request elevation solely to defeat
  a security-product block. Never read/copy/decrypt session secrets and keep wiping offline.
  Validate these boundaries against actual implementation in later phases. [HYPOTHESIS]
- **Microsoft false positives:** submit the affected executable as a software developer, wait for
  the determination, then use the developer contact form if disputing it. Supply the clean release
  binary, hash/version/signature, detection name, and a synthetic reproduction rather than user
  profiles. [VERIFIED: https://learn.microsoft.com/en-us/defender-xdr/developer-faq, accessed 2026-09-30] [HYPOTHESIS]
- **Vendor false positives:** Norton documents a sample/URL review process for false positives and
  false negatives. Use each affected vendor's official equivalent and include the precise alert
  type; a file-verdict submission may not resolve Browser Data Protection policy blocks.
  [VERIFIED: https://support.norton.com/sp/en/us/home/current/solutions/kb20090410134005EN, accessed 2026-09-30] [HYPOTHESIS]

## 7. Initial application catalog candidates

Names, proposed categories, and source leads only. Inclusion does not claim support, installed
presence, a session path, or safe wipe behavior. All category/priority choices below are proposals;
even for opened support pages, the links establish only a starting point. [HYPOTHESIS]

| Candidate names                                                                          | Proposed category                                            | Initial source pointers                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------------------------------------------------------------------------- | ------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Steam; Epic Games Launcher; Battle.net; Riot Client; EA app; Ubisoft Connect; GOG Galaxy | Game launchers [HYPOTHESIS]                                  | [TcNo platform overview](https://raw.githubusercontent.com/TCNOco/TcNo-Acc-Switcher/master/README.md) lists these platforms or their legacy names. [VERIFIED: https://raw.githubusercontent.com/TCNOco/TcNo-Acc-Switcher/master/README.md, accessed 2026-09-30] [Steam Support](https://help.steampowered.com/en/), [Epic help](https://www.epicgames.com/help/), [Riot support](https://support.riotgames.com/en-us/riot/), [EA help](https://help.ea.com/), [GOG support](https://support.gog.com/hc/en-us) are leads; Blizzard and Ubisoft help require access follow-up. [HYPOTHESIS] |
| Discord                                                                                  | Community/messaging [HYPOTHESIS]                             | [Discord support](https://support.discord.com/hc/en-us). [VERIFIED: https://support.discord.com/hc/en-us, accessed 2026-09-30]                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Spotify                                                                                  | Media [HYPOTHESIS]                                           | [Spotify support](https://support.spotify.com/). [VERIFIED: https://support.spotify.com/, accessed 2026-09-30]                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| Slack; Microsoft Teams                                                                   | Workplace communication [HYPOTHESIS]                         | [Slack sign-out](https://slack.com/help/articles/214613347-Sign-out-of-Slack); [Teams help](https://support.microsoft.com/en-us/teams/). [VERIFIED: https://slack.com/help/articles/214613347-Sign-out-of-Slack, accessed 2026-09-30] [VERIFIED: https://support.microsoft.com/en-us/teams/, accessed 2026-09-30]                                                                                                                                                                                                                                                                         |
| Signal Desktop; Telegram Desktop; WhatsApp                                               | Messengers [HYPOTHESIS]                                      | [Signal support](https://support.signal.org/hc/en-us); [Telegram FAQ](https://telegram.org/faq); [WhatsApp help](https://faq.whatsapp.com/) requires rendered-content follow-up. [VERIFIED: https://support.signal.org/hc/en-us, accessed 2026-09-30] [VERIFIED: https://telegram.org/faq, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                                              |
| Thunderbird; Outlook                                                                     | Mail clients [HYPOTHESIS]                                    | [Thunderbird help](https://support.mozilla.org/en-US/products/thunderbird); Microsoft Outlook documentation remains a follow-up lead. [VERIFIED: https://support.mozilla.org/en-US/products/thunderbird, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                                                                                                                                |
| Proton VPN; NordVPN; Mullvad                                                             | VPN clients [HYPOTHESIS]                                     | [Proton VPN support](https://protonvpn.com/support); NordVPN/Mullvad official client documentation remains a follow-up lead. [VERIFIED: https://protonvpn.com/support, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                                                                                                                                                                  |
| Authy Desktop (legacy); 2FAS browser companion                                           | 2FA/recovery-sensitive candidates [HYPOTHESIS]               | [Twilio Authy Desktop EOL](https://www.twilio.com/en-us/changelog/end-of-life--eol--of-twilio-authy-desktop-apps) documents retirement; current 2FAS platform/support documentation remains a follow-up lead. [VERIFIED: https://www.twilio.com/en-us/changelog/end-of-life--eol--of-twilio-authy-desktop-apps, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                         |
| Exodus; Electrum; Ledger Live; MetaMask extension                                        | Crypto wallets/recovery-sensitive candidates [HYPOTHESIS]    | [Exodus support](https://www.exodus.com/support); official Electrum, Ledger, and MetaMask documentation remains a follow-up lead. [VERIFIED: https://www.exodus.com/support, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                                                                                                                                                            |
| Bitwarden; 1Password; KeePass; Dashlane                                                  | Password managers/recovery-sensitive candidates [HYPOTHESIS] | [Bitwarden help](https://bitwarden.com/help/); [1Password support](https://support.1password.com/); official KeePass/Dashlane documentation remains a follow-up lead. [VERIFIED: https://bitwarden.com/help/, accessed 2026-09-30] [VERIFIED: https://support.1password.com/, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                                                           |

## Open questions

- Measure heuristic precision/recall and false-positive rate on a representative labeled corpus;
  validate portable installs, leftover data, name collisions, custom paths, and shared UDFs.
  [HYPOTHESIS]
- Establish version-specific storage/encryption behavior and whether secrets coexist with drafts,
  offline messages, wallet keys, 2FA seeds, or vault data before authorizing any catalog rule.
  [HYPOTHESIS]
- Validate PWA enumeration without secret reads, Store wrappers, origin overlap, and exclusive
  ownership/deduplication across app/browser listings. [HYPOTHESIS]
- Confirm Winapp2's desired packaging and notices; review derivative-database scope and future-GPL
  rights before importing anything. No Winapp2 content is vendored in this phase. [HYPOTHESIS]
- Establish target-specific close behavior, user cancellation, PID reuse, helper ownership, and
  safe handling of locks; no universal two-second cutoff is justified. [HYPOTHESIS]
- Reproduce AV/EDR behavior using synthetic profiles across identified product versions, including
  existence/size queries, delete access, and exact Norton Browser Data Protection alerts; obtain
  vendor clarification rather than treating community reports as product specifications.
  [HYPOTHESIS]
- Complete unresolved candidate support links and later per-app research; inclusion is not a
  promise that local deletion is either effective or safe. [HYPOTHESIS]

## Sources

All verification-tagged URLs below were accessed on 2026-09-30. Support portals are catalog entry
points only; the Norton Community report is firsthand anecdotal evidence, not official product
documentation. Versioned CEF and pinned Chromium evidence retain the limitations stated above.

- [www.electronjs.org: app](https://www.electronjs.org/docs/latest/api/app) — accessed 2026-09-30.
- [Chromium: filename constants](https://raw.githubusercontent.com/chromium/chromium/main/chrome/common/chrome_constants.h) — accessed 2026-09-30.
- [Chromium: DOM storage database paths](https://raw.githubusercontent.com/chromium/chromium/main/components/services/storage/dom_storage/dom_storage_database.cc) — accessed 2026-09-30.
- [Chromium: partitioned storage constants](https://raw.githubusercontent.com/chromium/chromium/main/components/services/storage/public/cpp/constants.cc) — accessed 2026-09-30.
- [www.electronjs.org: session](https://www.electronjs.org/docs/latest/api/session) — accessed 2026-09-30.
- [cef-builds.spotifycdn.com: structcef__settings__t.html](https://cef-builds.spotifycdn.com/docs/120.1/structcef__settings__t.html) — accessed 2026-09-30.
- [learn.microsoft.com: user-data-folder](https://learn.microsoft.com/en-us/microsoft-edge/webview2/concepts/user-data-folder) — accessed 2026-09-30.
- [learn.microsoft.com: webview2-security-tools](https://learn.microsoft.com/en-us/deployedge/webview2-security-tools) — accessed 2026-09-30.
- [www.electronjs.org: safe-storage](https://www.electronjs.org/docs/latest/api/safe-storage) — accessed 2026-09-30.
- [learn.microsoft.com: nf-dpapi-cryptprotectdata](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata) — accessed 2026-09-30.
- [chromium.googlesource.com: os_crypt_win.cc](https://chromium.googlesource.com/chromium/src/+/25a5bc7242a972e00204085eca1bc300b9861102/components/os_crypt/sync/os_crypt_win.cc) — accessed 2026-09-30.
- [www.electronjs.org: application-distribution](https://www.electronjs.org/docs/latest/tutorial/application-distribution) — accessed 2026-09-30.
- [github.com: managing-your-msix-reset-and-repair.md](https://github.com/microsoftdocs/msix-docs/blob/main/msix-src/desktop/managing-your-msix-reset-and-repair.md) — accessed 2026-09-30.
- [learn.microsoft.com: get-appxpackage](https://learn.microsoft.com/en-us/powershell/module/appx/get-appxpackage) — accessed 2026-09-30.
- [Chromium: desktop web apps](https://raw.githubusercontent.com/chromium/chromium/main/chrome/browser/web_applications/README.md) — accessed 2026-09-30.
- [blogs.windows.com: find-and-manage-your-installed-apps-and-sites](https://blogs.windows.com/msedgedev/2022/05/18/find-and-manage-your-installed-apps-and-sites/) — accessed 2026-09-30.
- [learn.microsoft.com: uninstall-registry-key](https://learn.microsoft.com/en-us/windows/win32/msi/uninstall-registry-key) — accessed 2026-09-30.
- [learn.microsoft.com: accessing-an-alternate-registry-view](https://learn.microsoft.com/en-us/windows/win32/winprog64/accessing-an-alternate-registry-view) — accessed 2026-09-30.
- [learn.microsoft.com: app-registration](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration) — accessed 2026-09-30.
- [learn.microsoft.com: knownfolderid](https://learn.microsoft.com/en-us/windows/win32/shell/knownfolderid) — accessed 2026-09-30.
- [learn.microsoft.com: links](https://learn.microsoft.com/en-us/windows/win32/shell/links) — accessed 2026-09-30.
- [raw.githubusercontent.com: Winapp2.ini](https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/Winapp2.ini) — accessed 2026-09-30.
- [raw.githubusercontent.com: CONTRIBUTING.md](https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/CONTRIBUTING.md) — accessed 2026-09-30.
- [raw.githubusercontent.com: License.md](https://raw.githubusercontent.com/MoscaDotTo/Winapp2/master/License.md) — accessed 2026-09-30.
- [creativecommons.org: legalcode.en](https://creativecommons.org/licenses/by-sa/4.0/legalcode.en) — accessed 2026-09-30.
- [creativecommons.org: compatible-licenses](https://creativecommons.org/compatible-licenses/) — accessed 2026-09-30.
- [wiki.creativecommons.org: ShareAlike_compatibility:_GPLv3](https://wiki.creativecommons.org/wiki/ShareAlike_compatibility%3A_GPLv3) — accessed 2026-09-30.
- [docs.bleachbit.org: cleanerml](https://docs.bleachbit.org/cml/cleanerml/) — accessed 2026-09-30.
- [TcNo Account Switcher: overview](https://raw.githubusercontent.com/TCNOco/TcNo-Acc-Switcher/master/README.md) — accessed 2026-09-30.
- [AutoLogout: overview](https://raw.githubusercontent.com/TagSteel/AutoLogout/main/README.md) — accessed 2026-09-30.
- [raw.githubusercontent.com: system_utils.py](https://raw.githubusercontent.com/TagSteel/AutoLogout/main/auto_logout/system_utils.py) — accessed 2026-09-30.
- [www.bleachbit.org: features](https://www.bleachbit.org/features) — accessed 2026-09-30.
- [support.ccleaner.com: select-cookies-to-clean-with-ccleaner-for-windows](https://support.ccleaner.com/articles/en_US/Master_Article/select-cookies-to-clean-with-ccleaner-for-windows) — accessed 2026-09-30.
- [learn.microsoft.com: nf-restartmanager-rmregisterresources](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources) — accessed 2026-09-30.
- [learn.microsoft.com: nf-restartmanager-rmgetlist](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmgetlist) — accessed 2026-09-30.
- [learn.microsoft.com: nf-restartmanager-rmshutdown](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmshutdown) — accessed 2026-09-30.
- [learn.microsoft.com: wm-close](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-close) — accessed 2026-09-30.
- [learn.microsoft.com: nf-processthreadsapi-terminateprocess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess) — accessed 2026-09-30.
- [raw.githubusercontent.com: win_security_file_access_browser_credential.yml](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules-threat-hunting/windows/builtin/security/win_security_file_access_browser_credential.yml) — accessed 2026-09-30.
- [raw.githubusercontent.com: file_access_win_browsers_credential.yml](https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules-threat-hunting/windows/file/file_access/file_access_win_browsers_credential.yml) — accessed 2026-09-30.
- [Elastic: suspicious browser file access on macOS](https://elastic.github.io/detection-rules-explorer/rules/20457e4f-d1de-4b92-ae69-142e27a4342a) — accessed 2026-09-30.
- [Norton Community: firsthand Browser Data Protection report](https://community.norton.com/t/should-i-unblock-msmpeng-exe-and-if-so-how/354392) — accessed 2026-09-30.
- [learn.microsoft.com: developer-faq](https://learn.microsoft.com/en-us/defender-xdr/developer-faq) — accessed 2026-09-30.
- [support.norton.com: kb20090410134005EN](https://support.norton.com/sp/en/us/home/current/solutions/kb20090410134005EN) — accessed 2026-09-30.
- [support.discord.com: en-us](https://support.discord.com/hc/en-us) — accessed 2026-09-30.
- [support.spotify.com: support portal](https://support.spotify.com/) — accessed 2026-09-30.
- [slack.com: 214613347-Sign-out-of-Slack](https://slack.com/help/articles/214613347-Sign-out-of-Slack) — accessed 2026-09-30.
- [support.microsoft.com: teams](https://support.microsoft.com/en-us/teams/) — accessed 2026-09-30.
- [support.signal.org: en-us](https://support.signal.org/hc/en-us) — accessed 2026-09-30.
- [telegram.org: faq](https://telegram.org/faq) — accessed 2026-09-30.
- [support.mozilla.org: thunderbird](https://support.mozilla.org/en-US/products/thunderbird) — accessed 2026-09-30.
- [protonvpn.com: support](https://protonvpn.com/support) — accessed 2026-09-30.
- [www.twilio.com: end-of-life--eol--of-twilio-authy-desktop-apps](https://www.twilio.com/en-us/changelog/end-of-life--eol--of-twilio-authy-desktop-apps) — accessed 2026-09-30.
- [www.exodus.com: support](https://www.exodus.com/support) — accessed 2026-09-30.
- [bitwarden.com: help](https://bitwarden.com/help/) — accessed 2026-09-30.
- [support.1password.com: support portal](https://support.1password.com/) — accessed 2026-09-30.
