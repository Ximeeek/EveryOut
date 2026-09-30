# EveryOut identity probe lab tool

Independent read-only Rust CLI for disposable Windows 10/11 test VMs. Its own Cargo workspace and
local target ignore keep it outside the shipped app. No probe inventory was run on the development
machine. Tests use synthetic metadata; no credential creation, deletion or account login occurs.

```powershell
cargo build --locked --manifest-path spikes/identity-probe/Cargo.toml
cargo test --locked --manifest-path spikes/identity-probe/Cargo.toml
cargo fmt --manifest-path spikes/identity-probe/Cargo.toml -- --check
cargo clippy --locked --manifest-path spikes/identity-probe/Cargo.toml --all-targets -- -D warnings
# Inside the disposable VM only, under the intended test user:
& 'C:\Lab\Tools\everyout-identity-probe.exe' inspect-lab
```

`inspect-lab` is an explicit lab guard, not VM detection. Exit 0 produces schema-version-1 JSON;
exit 1 produces a sanitized category and no report for a top-level error. Directory/profile field
failures remain explicit states in valid output; success is not complete supported cleanup coverage.
No automatic elevation, impersonation, network access, hive mounting or process closing occurs.

## Credential target discovery

Follow [research §3](../../docs/research/02-windows-identity-and-multi-account.md): execute the
absolute system-directory `cmdkey.exe` with the fixed `/list` argument, no shell, PATH lookup or
user-supplied command. [Microsoft documents this metadata list and non-display of stored passwords](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/cmdkey)
(accessed 2026-09-30). The CLI does not call CredEnumerateW/CredRead or obtain credential blobs;
there is no blob-returning API exception and therefore no blob zeroing. The Windows utility's
internal implementation is outside this crate's audit; metadata output does not prove how the
utility itself accesses the store internally.

The localized utility output (including usernames) exists briefly in process memory and is never
printed, logged or saved by the probe. stdout/stderr are captured; only selected target fields are
serialized. English `Target` and Polish `Obiekt docelowy` labels and synthetic fixtures are supported;
OEM decoding uses GetOEMCP/MultiByteToWideChar. Those layout/encoding assumptions require actual
version/locale VM validation; other layouts fail rather than falling back to a secret-bearing API.
The utility has no stable structured-output contract. It runs synchronously without a timeout;
output size is checked after collection at 4 MiB, not an allocation bound. Unsupported/hung cases
block evidence; this is a lab utility, not a production discovery adapter.

Case-insensitive candidate substrings: `MicrosoftAccount:`, `WindowsLive:`, `MicrosoftOffice`,
`MSTeams`, `OneDrive`, `ADAL:`, `MSAL:`, `SSO_POP_`. This heuristic is neither exhaustive nor proof of
app ownership. Results are sorted/deduplicated; usernames/type/persistence fields are omitted.
Target names themselves can contain email addresses and identifiers. Keep raw JSON local in the
VM; replace names with neutral labels before sharing or committing evidence. The scope is the
process user only: running elevated as a different administrator changes that scope, not B's store.

## Filesystem and profiles

The three candidate directories are under the process user's `%LOCALAPPDATA%\Microsoft\`:
TokenBroker, IdentityCache, OneAuth. Location is a research hypothesis, not an exhaustive Windows
broker inventory. Only symlink metadata/read_dir are used; payloads are never opened, hashed,
copied or decrypted. Sum logical file lengths (not allocated disk bytes); emit store label, state,
bytes and file count, never child names. Reject redirected ancestors/reparse entries, non-fixed
or non-drive local roots, more than 100,000 entries and depth above 128. Partial sums are discarded;
missing-or-changed/access-denied/unsafe-or-incomplete states have null size, not zero.
Quiescent controlled lab trees are required: checks are not atomic handle-bound confinement and
concurrent replacement can invalidate them. Equal size is not content preservation or logout.

Official `windows-sys` bindings open the native 64-bit
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` with KEY_READ, enumerate subkey
names and query only ProfileImagePath (REG_SZ/REG_EXPAND_SZ). REG_EXPAND_SZ is printed literally,
never expanded with the helper administrator's environment. No profile payload folders are scanned.
Each corresponding HKU key is opened read-only: success means `loaded_observed`, not-found means
`unloaded_observed`, other errors mean `unknown`. Handles are owned and closed on all Rust return
paths. Profile SID/path are private local evidence; sanitize both before export.

ProfileList can contain special/system, stale and backup entries; it is a candidate inventory, not
validated user eligibility or a session lock. The CLI does not query WMI/session state and does not
prove that an absent hive can safely be loaded. S6 requires independent OS/session comparison and
race testing. It never opens NTUSER.DAT or registry secret values and makes no sign-in changes.

## Audit and tests

The crate has no filesystem/registry/credential mutations, secret API calls or payload readers.
Its only output is JSON/stdout plus sanitized stderr. Build artifacts are ignored. Tests cover
candidate filtering, username omission, Unicode Polish/English fixtures, deduplication, unknown
layouts/empty targets, encoding and metadata failure states. Metadata fixture tests live outside
the executable code and create/remove only unique synthetic temporary folders. They do not run
cmdkey or enumerate this machine's accounts. VM results remain PENDING USER EXECUTION in S5/S6.
