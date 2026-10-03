# EveryOut reproducible builds and release verification

## Meaning and current limit

A reproducible build produces identical bytes from the same source, build instructions and
defined environment. Similar functionality, matching versions and a valid signature alone do not
prove bit reproducibility.
[VERIFIED: https://reproducible-builds.org/docs/definition/, accessed 2026-10-03]

EveryOut has Rust 1.98.1 and pnpm 11.19.0 pins and committed Cargo/frontend lockfiles. The
[release workflow](../../.github/workflows/release.yml) also selects exact Node/MSVC/SDK inputs
from [release-tools.json](../../scripts/release-tools.json), verifies the pinned WiX archive and
records the hosted image and tool binary identities. `windows-latest` is not an immutable image.
The workflow compares two fresh target directories on one runner and the release checkpoints;
this is an advisory measurement, not independent reproduction.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/rust-toolchain.toml, accessed 2026-10-03]
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/package.json, accessed 2026-10-03]
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/.github/workflows/ci.yml, accessed 2026-10-03]
[HYPOTHESIS]

Treat unsigned frontend assets and unsigned PE build checkpoints as reproducibility candidates.
Do not advertise installers, PDBs or full signed releases as bit reproducible until independent
comparisons establish each claim. `reproducibility.json` publishes measured results and differences,
or explicitly records that the comparison was unavailable. Every mismatch remains a failed byte
comparison. Publication review must investigate unexplained unsigned PE/frontend differences.
[HYPOTHESIS]

## Required build controls

The following are release requirements; undocumented environmental defaults must not become
implicit release inputs. [HYPOTHESIS]

1. Build an exact commit from a clean checkout. Record tag, full commit SHA, submodule state if
   applicable, Cargo.lock/pnpm-lock.yaml hashes and generated catalog/binding verification.
2. Use the committed Rust version and target `x86_64-pc-windows-msvc`; pin exact Node patch and
   pnpm versions, Windows image, MSVC compiler/linker and Windows SDK versions. Record Tauri CLI,
   bundler, WiX/NSIS and WebView2 installer inputs, including downloaded bytes and hashes.
3. Install with `pnpm install --frozen-lockfile`; build Rust with `--locked` at **every** invocation,
   including the host through Tauri. Cargo's flag forbids lockfile resolution changes, and pnpm's
   flag refuses an out-of-date lockfile. Neither fixes all operating-system/toolchain inputs.
   [VERIFIED: https://doc.rust-lang.org/cargo/commands/cargo-build.html, accessed 2026-10-03]
   [VERIFIED: https://pnpm.io/cli/install, accessed 2026-10-03]
4. Record features, profile, target, environment, overlay configuration and public trust inputs.
   Never publish private signing credentials. Record `EVERYOUT_CATALOG_PUBLIC_KEY` and
   `EVERYOUT_CATALOG_URL`, or explicitly record both absent; record the exact helper hash.
   These variables affect generated host inputs.
   [VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/src-tauri/build.rs, accessed 2026-10-03]
5. Remap checkout and dependency-cache roots using stable aliases with rustc
   `--remap-path-prefix=FROM=TO`, for example via `RUSTFLAGS`. Rust documents that other external
   tools can still embed paths. Record mappings and check PDB/resource/bundler output separately;
   do not assume this covers MSVC, frontend sourcemaps or build-script string literals.
   [VERIFIED: https://doc.rust-lang.org/rustc/command-line-arguments.html, accessed 2026-10-03]
6. Derive `SOURCE_DATE_EPOCH` from the tagged commit and normalize staged file/archive timestamps
   only with tools that support it. The specification defines an epoch input for cooperating
   tools; it does not force every tool to honor it. Pin locale/timezone and investigate generated
   identifiers, PE metadata, archive ordering and installer timestamps in two clean builds.
   [VERIFIED: https://reproducible-builds.org/docs/source-date-epoch/, accessed 2026-10-03]
   [HYPOTHESIS]

Tauri builds MSI installers with WiX and setup executables with NSIS. The pinned toolchain and
installer inputs must be recorded separately; a Rust lockfile is not their complete provenance.
[VERIFIED: https://v2.tauri.app/distribute/windows-installer/, accessed 2026-10-03]

## Signing boundary and differences that must be explained

Authenticode timestamping uses a timestamp authority's signed time. Repeating timestamped
signing at another time is not a procedure for reproducing identical signature bytes.
[VERIFIED: https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures, accessed 2026-10-03]

An independent builder cannot recreate the publisher's signature without its private signing
authority. Compare the pre-sign build checkpoints and verify published signatures separately;
do not equate certificate validation with source equivalence. Exact signed-file reproduction
would require retaining and reusing the original signing result, not independently re-signing.
[HYPOTHESIS]

The host embeds a SHA-256 pin of the complete helper file. If the helper is signed/timestamped
first, that signed helper becomes an explicit host input. For a host comparison, use the release's
exact final helper hash; independently compare the unsigned helper checkpoint as a separate step.
Freshly signing a rebuilt helper can change its hash and therefore the host as well.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/src-tauri/build.rs, accessed 2026-10-03]
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/scripts/build-desktop.ps1, accessed 2026-10-03]
[HYPOTHESIS]

Tauri's bundle-type patching can change host bytes after compilation. Its changelog documents
`--no-binary-patching` to preserve an already-signed binary, at the cost of per-bundle updater
selection. Record whether patching was skipped or publish separate pre-sign checkpoints for the
final MSI/NSIS host variants; compare the correct variant, not the last overwritten build file.
[VERIFIED: https://tauri.app/release/tauri-bundler/all-versions/, accessed 2026-10-03]
[HYPOTHESIS]

Whether unsigned PE files, PDBs and installers are bit reproducible with the chosen Windows
tools is **unverified**. Do not claim Windows builds inherently cannot be deterministic. Report
each unexplained difference as a failed comparison rather than silently stripping metadata until
hashes match. WebView2 download mode and evolving remote payloads also require explicit inputs.
[HYPOTHESIS]

Local Phase 35 validation on 2026-10-03 built and extracted unsigned MSI packages successfully.
The two fresh target directories and reference comparison matched the three frontend files,
but reported differences in the unsigned helper, host, two PDBs and MSI. The unsigned EXE COFF
timestamps differed; that is an observed input to the mismatch, not proof that all remaining
bytes are equivalent. The comparison script includes PE machine/timestamp metadata alongside
the full-file hashes and never strips fields to manufacture a match. Signed CI and independent
reproduction remain unverified. See the
[Microsoft PE/COFF format](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).

## Third-party verification procedure

Require the release to provide `SHA256SUMS.txt`, corresponding source/tag/commit, CI run and job
identities, build-input manifest, exact commands, unsigned checkpoints and signing metadata.
These are Phase 35 deliverables; missing evidence means the associated claim is unverified.
[HYPOTHESIS]

1. Obtain artifacts from the project's release page; compare the tag's full source SHA with the
   published CI checkout SHA. Review build scripts, catalog and dependencies before executing.
2. In PowerShell, hash every downloaded asset and compare each value and filename with the
   published checksum file. `Get-FileHash` supports SHA-256 file hashing.
   [VERIFIED: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.6, accessed 2026-10-03]

   ```powershell
   Get-FileHash -LiteralPath .\EveryOut-setup.exe -Algorithm SHA256
   Get-AuthenticodeSignature -LiteralPath .\EveryOut-setup.exe | Format-List
   ```

3. For signed assets, require a valid signature, the release-declared publisher, trusted chain
   and timestamp; inspect the application and helper too. With Windows SDK SignTool, use
   `signtool verify /pa /all /v <file>`. PowerShell exposes signer and timestamp information;
   SignTool supports Authenticode-policy verification.
   [VERIFIED: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.6, accessed 2026-10-03]
   [VERIFIED: https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe, accessed 2026-10-03]
4. Rebuild in a disposable Windows environment matching the input manifest, without personal
   browser data. As a local unsigned baseline, run the existing build script after frozen install:

   ```powershell
   pnpm install --frozen-lockfile
   ./scripts/check-release.ps1
   . ./scripts/release-environment.ps1 -Local
   ./scripts/build-release.ps1 -WorkDir target/release-local
   ```

   Use a fresh WorkDir. The release script locks helper and host builds, preserves unsigned
   checkpoints, packages MSI without host patching and verifies extracted host/helper bytes.
   WebView2 is a separate prerequisite, with no downloaded or bundled runtime input. The ordinary
   `scripts/build-desktop.ps1` remains an unsigned developer baseline, not the release verifier.
   For a signed release, extract the exact helper from `final-binaries.zip` and pass its absolute
   path with `-ReferenceHelper` when rebuilding an unsigned host. This preserves the released
   helper pin while independently compiling the unsigned helper checkpoint. See the actual
   [stage commands and two-build procedure](release-process.md#local-verification-without-tags-or-releases).

5. Compare SHA-256 values of unsigned checkpoints and frontend files against the manifest.
   Preserve mismatch details with tool versions, paths and flags; compare PE sections/resources
   and installer contents if full files differ. Never label a content-only comparison as bit
   reproduction. If no unsigned checkpoint exists, restrict the result to download-integrity and
   signature/provenance verification. [HYPOTHESIS]

Checksums hosted beside downloads share that channel's trust. A compromised channel can replace
both; use independent source/CI evidence and publisher verification where available. Neither a
matching checksum nor reproducibility proves the program's behavior is safe. [HYPOTHESIS]
