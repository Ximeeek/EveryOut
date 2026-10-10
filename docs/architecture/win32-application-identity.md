# Win32 application identity in EveryOut

P1 identifies an executable and corroborates candidate storage. It does not discover tokens,
establish authentication closure, or construct a generic destructive provider. MSIX identity is
optional. An independently bound portable executable can have Exact application identity while
storage ownership and authentication remain Unknown.

## Shared native resolver

`everyout-platform-windows::win32_identity` is the common implementation for inventory,
App Paths account/process gates, executable physical bindings, static PE metadata, Authenticode,
shortcut targets, runtime process identities, and product-record binding. `InstalledInventory`
owns a native `Rc<Win32Snapshot>`; `IdentityFolders` supplies this same snapshot to providers.
The current-account scan collects discovery before provider inventory so both consume the same
physical storage observations. A new scan replaces the snapshot; no UI-supplied identity data is
accepted. Other-account scanning retains its explicit incomplete-inventory coverage boundary.

Registry enumeration covers HKCU/HKLM and both 32/64-bit views. App Paths reads only the EXE
subkey name and default executable path. Uninstall reads only `DisplayName`, `Publisher`,
`InstallLocation`, `DisplayIcon`, and `DisplayVersion`. Registry symbolic links are rejected.
Commands, arguments, UninstallString, QuietUninstallString, ModifyPath, InstallSource, and arbitrary
values are not queried or executed. DisplayIcon's optional numeric icon suffix is a path hint;
environment expansions, relative paths and argument strings do not become executable paths.

Current/common Start Menu traversal is bounded to 2,048 entries and six nested directory levels.
Local shell links use `IPersistFile::Load` and `IShellLinkW::GetPath`, without `Resolve`, arguments,
working directories or execution. Unsafe/missing targets remain coverage gaps. Executable
collection is bounded to 512 physical applications and 512 process metadata queries, with explicit
coverage when a limit is reached. Registry provenance distinguishes the hive and registry view.

Static metadata includes the PE executable header, ProductName, CompanyName, FileDescription,
ProductVersion, FileVersion, and OriginalFilename. Authenticode uses WinVerifyTrust without UI
or online retrieval and records Valid/Unsigned/Invalid/Unknown, signer display identity, and
signing-certificate SHA-256 when available. Offline trust verification is not a fresh online
revocation check. Missing signatures do not exclude portable or open-source executables.
Publisher compatibility is corroboration, never application equality or storage authority.
Conflicting verified publisher/PE/installation metadata degrades identity to Unknown.

## Evidence hierarchy and physical safety

| State        | Evidence                                                                                                                                                                                                                                                       |
| ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Exact        | A concrete selected or observed executable, valid PE header and revalidated physical binding, with no detected metadata conflict. Registry/shortcut observations add independent same-file provenance. This also permits portable images without registration. |
| Corroborated | A checked executable registered through App Paths or a shortcut, with no concrete selection/process observation.                                                                                                                                               |
| Weak         | Only a checked Uninstall executable hint; display names or publishers without a target cannot resolve an executable at all.                                                                                                                                    |
| Unknown      | No usable executable binding, stale physical identity, or conflicting metadata.                                                                                                                                                                                |

There is no numerical identity score. Names choose among already resolved candidates; they cannot
create physical identity or Exact evidence. Multiple unrelated files with the same name remain
ambiguous. Catalogs without process names can select a unique PE product-name/EXE-stem candidate,
but that textual selection is not an ownership or authentication proof.

`ExecutableBinding` distinguishes lexical path, checked canonical path, and opaque volume/file
identity. It uses the existing AllowedRoot/SafePath/handle-relative no-reparse implementation;
it does not introduce another path validator. Ancestors stay retained. Read-only image pins protect
metadata collection and are then released so discovery does not prevent application updates.
Revalidation checks the original physical file, size and modification time; stale metadata fails
closed. Process gates retain image pins for the reviewed operation. Attribute-only handles do not
enforce delete-sharing exclusion. Shortcut target reads also retain a read-only link pin.
Paths, physical identity and process PID/creation time are rechecked before process operations.
Symlinks, junctions, reparse substitution, hard-link aliases, and unsafe roots fail closed.
Executable hashing is bounded to 256 MiB and reads only the pinned executable, never storage.

## Candidate storage and Restart Manager

Candidates come from existing AppData/framework discovery, catalog artifacts, safe product-name
folders, and adjacent `<exe>.WebView2` directories. Installation catalog slots are metadata
candidates only. Electron/CEF/WebView2/Squirrel marker existence adds framework hints without
reading app.asar, database, cookie or token contents. Custom userData/sessionData/UDF roots can
remain undiscovered; no whole-drive scan or Teach Mode is introduced.

Restart Manager has a scan-wide budget of eight candidate observations, four existing regular
files per observation, and 32 registered resources. Representative hints include LOCK,
leveldb/LOCK, Network/Cookies, state.db and already cataloged concrete state files. Directories
are rejected as resources. It performs only RmStartSession, RmRegisterResources, RmGetList and
RmEndSession: no shutdown, restart, force or process-memory access. Owner lists are bounded to
64 entries with one bounded buffer retry. Failures, inaccessible resources and exhausted budgets
are explicit coverage gaps.

Representative files use the existing handle-relative validator and read-only pins that allow
writers but exclude deletion. No resource payload is read. The observer itself can appear because
of those pins, so only its exact PID **and creation time** are excluded. All other owners must
match a fresh current-user observation of that specific PID, its creation time and executable
physical file. Resource observation does not re-enumerate unrelated processes.
Unknown owners, reused PIDs, unrelated executables or conflicting roots cannot strengthen ownership.
Similar names, publishers and implicit child-process assumptions do not establish a relation.

Application identity, a candidate layout, exact runtime file use and no ownership conflict can
produce Corroborated storage. Name or framework hints alone leave Unknown. Every candidate has
its own physical observation; proof for one root is not transferred to another. Physical overlap,
unrelated users of the same root, and browser-profile stores produce SharedConflict. Display
labels survive ownership conflicts, so a recognized application is still visible in the UI.
Exclusive remains restricted to existing system-container/compiled-adapter evidence.

## P0 and product-record integration

Spotify's saved-login adapter remains unchanged. Its historical user-observed result and fixed
provider-adapter evidence are explicitly distinct from `product-validation-record`. Its existing
Validated scope is not a newly performed Product Validation or a newly created formal record.
Pinned-build, four-field, preservation and format tests remain mandatory.

`Win32Application::bind_validation` consumes independently collected executable/PE/signature
metadata and a trusted native caller's separately observed application/channel/layout/artifact
context. Expected record fields are never substituted for unknown executable observations.
Required executable hashes are computed from the pinned image; requested publisher/certificate
identity requires a verified signature. Missing product/version data or mismatched identity,
hash, channel, version, layout or families yields Stale and the decision blocker
`product-version-revalidation-required`. There is no UI import, automatic record admission or
generic operation created from a record. A channel/layout that has not been independently
attributed must not be supplied as the expected record's value.

## Representative fixture traces

These are synthetic safety/correlation fixtures, not product authentication trials.

| Case                                                                        | Identity                  | Ownership                             | Authentication          | Action                               |
| --------------------------------------------------------------------------- | ------------------------- | ------------------------------------- | ----------------------- | ------------------------------------ |
| Discord before P1                                                           | Weak                      | Unknown                               | FrameworkHint           | Blocked                              |
| Discord with same-file App Paths/shortcut/process and candidate runtime use | Exact                     | Corroborated                          | FrameworkHint           | Blocked                              |
| Unknown ObscureChat/Slack executable and named Electron-layout candidate    | Exact                     | Corroborated with fixture runtime use | Unknown                 | Blocked; no provider                 |
| Steam image and existing catalog installation state-file candidates         | Exact                     | Corroborated with fixture runtime use | Unknown                 | Blocked; file contents uninterpreted |
| Selected portable WebView2 host and adjacent UDF                            | Exact                     | Corroborated with fixture runtime use | Unknown                 | Blocked; no provider                 |
| Two unrelated executables using a synthetic shared root                     | Exact per executable      | SharedConflict                        | Unknown                 | Blocked                              |
| Registered MSIX fixture                                                     | Existing package identity | Existing container rules              | Existing framework hint | Blocked without auth validation      |

Discord's Local Storage scope, support, preservation and version-applicability evidence remain
unchanged. Improved identity/ownership does not remove its authentication, preservation, version,
support or unknown-loss blockers. Spotify retains its separate reviewed local adapter semantics.

The safety suite covers convergence, display-name/publisher insufficiency, same-name folder
insufficiency, runtime/auth separation, PID reuse, image pinning and symlink refusal, portable
identity, Discord gates, record mismatches and shared roots. Owned volatile registry and generated
local-shortcut fixtures exercise the actual metadata readers. No installed target products are
required in CI. The complete existing Spotify security suite also runs.

Additional regressions cover replacement and in-place updates after discovery, mandatory PID/start
identity, missing proof for another provider root, and conflicts that must survive later corroboration.

## Changed files

- Platform integration: `crates/platform-windows/Cargo.toml`,
  `crates/platform-windows/src/lib.rs`, `crates/platform-windows/src/resolver.rs`,
  `crates/platform-windows/src/accounts/windows.rs`, `crates/platform-windows/src/inventory.rs`,
  `crates/platform-windows/src/filesystem.rs`, `crates/platform-windows/src/native.rs`,
  `crates/platform-windows/src/process.rs`.
- Shared resolver: `crates/platform-windows/src/win32_identity.rs`,
  `crates/platform-windows/src/win32_identity/registration.rs`,
  `crates/platform-windows/src/win32_identity/metadata.rs`,
  `crates/platform-windows/src/win32_identity/runtime.rs`.
- Discovery: `crates/detection/src/lib.rs`, `crates/detection/src/scanner.rs`.
- Provider integration: `crates/providers/src/evidence.rs`, `crates/providers/src/executor.rs`.
- Native wiring: `src-tauri/src/native.rs`, `src-tauri/src/bridge.rs`,
  `crates/elevated-helper/src/accounts.rs`.
- Tests: `crates/platform-windows/tests/win32_identity.rs`,
  `crates/detection/tests/win32.rs`, `crates/detection/tests/fixtures.rs`.
- Documentation: `docs/architecture/win32-application-identity.md`,
  `docs/architecture/scope-evidence-decision-trace.md`,
  `docs/architecture/17-detection-classification.md`.

## Deferred to P2 or later

Teach Mode, login/logout differential observation, filesystem watchers, ETW, token/LevelDB/cookie
parsing, Local State decryption, credential enumeration, auth-scope minimization, generic automatic
reset/destructive Win32 providers, expanded Discord scopes and bulk external cleanup imports are
not implemented. Actual versioned product-closure/preservation trials remain separate work.

Native API references: [App registration](https://learn.microsoft.com/en-us/windows/win32/shell/app-registration),
[WinVerifyTrust](https://learn.microsoft.com/en-us/windows/win32/api/wintrust/nf-wintrust-winverifytrust),
[IShellLinkW::GetPath](https://learn.microsoft.com/en-us/windows/win32/api/shobjidl_core/nf-shobjidl_core-ishelllinkw-getpath),
and [RmRegisterResources](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources).
