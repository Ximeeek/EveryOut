# EveryOut release process

This document matches [the draft release workflow](../../.github/workflows/release.yml).
Only a push of a `v*` tag triggers it; there is no manual-dispatch, branch-push or pull-request
release trigger. Do not create a tag merely to test the pipeline. Publication is a separate,
manual maintainer action, outside the workflow.

## Prepare the release

1. Review the changelog, supported versions, dependency/component licenses, destructive-data
   warnings and unresolved provider/VM gates. Catalog candidates are not validated support.
2. Select a SemVer version and synchronize `package.json`, `src-tauri/tauri.conf.json`,
   `src-tauri/Cargo.toml`, workspace versions, lockfiles and executable metadata. The workflow
   rejects a tag that does not match the root, workspace and host versions. Under 0.x the
   public contract is unstable; document breaking changes and use prerelease identifiers where
   appropriate. MSI product versions are numeric; retain the full source/tag version in provenance.
3. Review [signing policy](code-signing.md) and [ADR 0005](../adr/0005-code-signing.md).
   Signing is disabled by default. An unsigned draft is always marked as a prerelease and its
   title, notes and manifest explicitly say `unsigned`, even for a numeric version tag.
4. Verify the committed [release tool pins](../../scripts/release-tools.json). The workflow
   selects Rust 1.98.1, Node 24.18.1, pnpm 11.19.0, Windows x64 MSVC toolset directory
   14.44.35207 and SDK 10.0.26100.0. `windows-latest` must resolve to `ImageOS=win25`.
   Missing pins/image changes stop the build rather than silently selecting another compiler.
   The hosted image is not immutable; exact image/tool binary versions and hashes are recorded
   and still require review. Tauri CLI 2.12.0 is installed from the frozen lockfile.
5. Configure optional repository variables `EVERYOUT_CATALOG_PUBLIC_KEY` (64 hex characters)
   and `EVERYOUT_CATALOG_URL` (HTTPS) together, or leave both absent. They are public host inputs.
   Private catalog signing keys never belong in this workflow or repository.
6. Run the local checks below and validate in a disposable Windows VM. Have the maintainer
   review the exact source commit before creating an annotated `v<version>` tag. Never move
   published tags. Only the maintainer creates tags and publishes releases.

## Configure signing only after onboarding

Until provider acceptance, leave repository variable `SIGNPATH_ENABLED` absent or `false`.
The build uses `release-unsigned`, skips all three signing requests and needs no signing secrets.
No certificate application, purchase or identity submission is performed by the workflow.

After approval, create/protect the GitHub environment `release-signing` with a required human
reviewer and restricted release-tag deployment rules. Store `SIGNPATH_API_TOKEN` as its environment
secret, with only submitter access. Enable manual approval in the SignPath signing policy too.
The environment gate precedes the entire signed build; each SignPath request waits for approval
and completion, up to 3,600 seconds. Only then set these **repository variables**:

| Variable                           | Required value when signing is enabled                                      |
| ---------------------------------- | --------------------------------------------------------------------------- |
| `SIGNPATH_ENABLED`                 | Exactly `true`, set last after all onboarding gates                         |
| `SIGNPATH_ORGANIZATION_ID`         | Assigned organization ID                                                    |
| `SIGNPATH_PROJECT_SLUG`            | Approved EveryOut project slug                                              |
| `SIGNPATH_SIGNING_POLICY_SLUG`     | Policy enforcing authorized manual approval and timestamping                |
| `SIGNPATH_HELPER_CONFIGURATION`    | ZIP artifact configuration for exactly `everyout-elevated-helper.exe`       |
| `SIGNPATH_HOST_CONFIGURATION`      | ZIP artifact configuration for exactly `everyout.exe`                       |
| `SIGNPATH_INSTALLER_CONFIGURATION` | ZIP artifact configuration for exactly `EveryOut-x64.msi`                   |
| `SIGNPATH_CERTIFICATE_SUBJECT`     | Exact approved certificate subject, including distinguished-name formatting |

Upload actions use ZIP archives. Configure `<zip-file>` roots with the exact root member above,
not blanket signing of dependencies or WiX libraries. Enforce product/version metadata, source
origin, approved workflows/tags, named roles and manual approval in SignPath. Install its GitHub
App, grant repository access and satisfy the Foundation's GitHub-hosted build requirements.
The workflow validates configuration presence and final signatures, but cannot establish
provider acceptance or enforce externally configured human roles by itself.
See [official GitHub integration](https://docs.signpath.io/trusted-build-systems/github).

No signed failure falls back to unsigned. A failed request, missing input, wrong publisher,
invalid signature or absent timestamp stops the build. ADR 0005 remains Proposed until
onboarding and end-to-end validation provide evidence for acceptance. Signed CI has not been
run as part of this phase; public signing must not be claimed yet.

## What the workflow does

All jobs run on GitHub-hosted `windows-latest`. Default permission is `contents: read`.
The build adds `actions: read` for signing provenance. Only the final draft job receives
`contents: write`; it also reads workflow artifacts. Checkout does not persist credentials.
Concurrent runs of the same tag serialize, and existing releases are never overwritten.

1. **Validate and check.** Install pinned tools, select the exact MSVC/SDK environment and
   validate tag/public trust/signing inputs. Install frontend dependencies with
   `pnpm install --frozen-lockfile`. Run locked Rust build/test/clippy, formatting, catalog
   validation/table checks, bindings checks, frontend lint/typecheck/test/format/build and
   release-script regression checks. Rust installation does not change lockfiles.
2. **Helper first.** Compile the unsigned helper with `cargo build --locked --release --target
x86_64-pc-windows-msvc -p everyout-elevated-helper`. Retain the unsigned checkpoint and upload
   the signing input. If enabled, obtain and verify the signed helper before calculating its
   final SHA-256. The final bytes become the host input and bundled sidecar.
3. **Host second.** Supply `EVERYOUT_HELPER_SHA256`, record public catalog inputs and the overlay,
   then run `pnpm tauri build --ci --target x86_64-pc-windows-msvc --no-bundle --config <overlay>
-- --locked`. Retain the unsigned host, helper, frontend and PDB checkpoints. Sign/verify
   the host when enabled.
4. **Package third.** Bundle **MSI only** with `pnpm tauri bundle --ci --target
x86_64-pc-windows-msvc --bundles msi --no-sign --no-binary-patching --config <overlay>`.
   The overlay selects `webviewInstallMode.type=skip`: WebView2 must already be installed,
   and there is no downloaded or proprietary bundled WebView2 payload. MSI uses WiX 3.14.1;
   the pinned archive URL/SHA-256 are in `release-tools.json`, verified before packaging,
   and cached files must match. This path avoids NSIS-generated uninstaller signing concerns.
   No application updater depends on per-bundle-type patching. The host hash must stay unchanged.
5. **Verify final contents.** Sign/verify the MSI when enabled. Administratively extract it with
   `msiexec /a` without installing or running the app. Require exact host/helper hashes and
   the expected helper pin; for signed builds verify all three signatures, declared subject,
   timestamp certificate and `signtool verify /pa /all /v`. Publish the exact final binaries
   as verification material. Installed behavior still needs a disposable-VM check.
6. **Compare two fresh builds.** A separate job builds into two fresh target directories,
   reusing the release's final helper bytes/hash as an explicit host input. Compare unsigned
   checkpoints with each other and with the release checkpoints, including missing files.
   `reproducibility.json` records every hash, mismatch and limitation. MSI/PDB comparisons are
   excluded from bit-reproducibility claims; unexplained PE/frontend mismatches remain failed
   byte comparisons. A build failure produces `comparison-unavailable`; job setup failures
   are recorded by the draft job. Comparisons are advisory and never publish a release.
7. **Checksums and draft.** Collect `EveryOut-x64.msi`, `LICENSE`, `build-inputs.json`,
   `unsigned-checkpoints.zip`, `final-binaries.zip` and `reproducibility.json`. Generate
   `SHA256SUMS.txt` last, covering every asset except itself. Use GitHub CLI to create a
   **draft** with `--verify-tag --draft`; reject any existing release for the tag. No workflow
   step publishes the draft, creates a tag or replaces release assets.

The manifest records source/tag/run/attempt/job, locks, tool/image identities, compiler/linker
hashes, flags, path remapping, commit-derived `SOURCE_DATE_EPOCH`, locale/timezone, overlay,
public trust inputs, unsigned/final inventories, WiX inputs, signing request IDs and signature
metadata. It contains no signing tokens or private keys. SOURCE_DATE_EPOCH and remapping alone
do not guarantee determinism. Read [reproducible builds](reproducible-builds.md).

## Local verification without tags or releases

Use a clean synthetic/disposable Windows environment with the pinned tools and WebView2.
From the repository root:

```powershell
pnpm install --frozen-lockfile
./scripts/check-release.ps1
./scripts/validate-release.ps1 -Tag v0.1.0
. ./scripts/release-environment.ps1 -Local
./scripts/build-release.ps1 -WorkDir target/release-local
```

Replace `v0.1.0` with the source version. Choose a fresh WorkDir on every full build; the
script refuses existing checkpoints. `-Local` skips only the hosted-image identity check,
not Rust/Node/pnpm or MSVC/SDK pins. All outputs remain under ignored `target/`.
The build compiles/packages/verifies binaries but does not execute a wipe or install the app.

For two-build comparison, keep an existing build as the reference and run:

```powershell
$helper = (Resolve-Path target/release-local/final/everyout-elevated-helper.exe).Path
./scripts/build-release.ps1 -WorkDir target/repro-one -ReferenceHelper $helper
./scripts/build-release.ps1 -WorkDir target/repro-two -ReferenceHelper $helper
./scripts/compare-release.ps1 -First target/repro-one/checkpoints -Second target/repro-two/checkpoints -Reference target/release-local/checkpoints -Output target/reproducibility-local.json
```

A released signed helper is an explicit input for an unsigned host rebuild. Do not sign a
fresh helper and substitute its new hash when comparing the published host. Compare unsigned
helper checkpoints independently. Run commitlint for the actual release-preparation range:
`pnpm commitlint --from <base> --to <head>`. Check the workflow with a locally installed
[actionlint](https://github.com/rhysd/actionlint) and inspect SHA pins and permissions.
Do not invoke `create-release-draft.ps1` locally; it is the CI write step.

## Maintainer publication gates

Before manually publishing the draft:

- Review source/CI provenance, all checksum entries, changelog, destructive-data warnings,
  supported Windows/architecture scope, candidate blockers and [license](../../LICENSE) notices.
- Review comparison results. Matching bytes on one runner are not independent reproduction.
  Investigate unexplained unsigned helper/host/frontend differences. Known installer/PDB or
  timestamped-signature differences do not automatically establish a bug or reproducibility.
  If comparison is unavailable, retain that limitation; do not advertise reproduction.
- For signed builds verify the actual approved subject/class, trusted chain and timestamp,
  installed app/helper and MSI signatures, and helper-pin integrity. Complete the Foundation's
  attribution, privacy, role and component-license requirements before public signed distribution.
- Install/uninstall and exercise the exact final assets in disposable Windows 10/11 VMs with
  synthetic data and the documented WebView2 prerequisite. Check blocked/partial outcomes.
- Confirm whether signing and comparison are proven, not assumed. Only the named maintainer
  publishes. After publication, download again and recheck final checksums/signatures.
- Monitor [false positives](false-positives.md) and [security reports](../../SECURITY.md).
  Withdraw unsafe assets with an advisory and issue a new version/tag; never silently replace
  bytes or ask users to disable security protection.

Catalog publication follows the separate
[catalog ceremony](../architecture/12-catalog-update-design.md#maintainer-steps).
Its Ed25519 custody/signature does not replace Authenticode signing.

## Official source verification

Action tags were resolved from their official repositories to these full commit SHAs on
2026-10-03. Updates must repeat that verification and review the action's inputs/runtime.

| Action                                          | Version and official commit                                                                                                     |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `actions/checkout`                              | [v6.1.0, d23441a](https://github.com/actions/checkout/tree/d23441a48e516b6c34aea4fa41551a30e30af803)                            |
| `pnpm/action-setup`                             | [v6.1.0, ea17c68](https://github.com/pnpm/action-setup/tree/ea17c68df8912ef543352723c149a84f56e3d413)                           |
| `actions/setup-node`                            | [v7.0.0, 8207627](https://github.com/actions/setup-node/tree/820762786026740c76f36085b0efc47a31fe5020)                          |
| `actions/upload-artifact`                       | [v7.0.1, 043fb46](https://github.com/actions/upload-artifact/tree/043fb46d1a93c77aae656e7c1c64a875d1fc6a0a)                     |
| `actions/download-artifact`                     | [v8.0.1, 3e5f45b](https://github.com/actions/download-artifact/tree/3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c)                   |
| `signpath/github-action-submit-signing-request` | [v3.0, f6d0478](https://github.com/signpath/github-action-submit-signing-request/tree/f6d04783b4569d051e0c80105fe66e82819d0092) |

Tauri's [Windows installer documentation](https://v2.tauri.app/distribute/windows-installer/),
[CLI reference](https://v2.tauri.app/reference/cli/),
[bundler changelog](https://tauri.app/release/tauri-bundler/all-versions/) and the installed
2.12.0 CLI `build --help` / `bundle --help` establish MSI, `skip`, runner argument forwarding
and `--no-binary-patching`. The pinned CLI's
[WiX source constants](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.12.0/crates/tauri-bundler/src/bundle/windows/msi/mod.rs)
match the archive pin. The [official runner image inventory](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md)
is supporting environment evidence, not an immutable image guarantee. The
[Node distribution checksum manifest](https://nodejs.org/dist/v24.18.1/SHASUMS256.txt)
confirms the exact Node release.
