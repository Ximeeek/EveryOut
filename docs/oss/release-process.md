# EveryOut release process

This checklist defines the proposed maintainer release gates. Automation belongs to Phase 35;
do not infer that this document creates a tag-triggered release workflow. The current CI runs
quality checks on pull requests and pushes to main, without a release job.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/.github/workflows/ci.yml, accessed 2026-10-03]

All numbered actions below are project policy requirements. Future pipeline implementation,
provider approval and successful reproducibility comparisons remain unverified. [HYPOTHESIS]

## 1. Select and review a version

- Review changes, dependencies, licenses, catalog effects, known destructive-data risks and
  unresolved VM gates. Keep candidate providers described as candidates; never claim universal
  logout or remote session revocation from local fixture results.
- Apply SemVer: breaking public-contract changes require a major version after 1.0; compatible
  features increment minor; compatible fixes increment patch. Under 0.x, document the unstable
  contract explicitly, use minor increments for breaking changes, and prerelease identifiers
  such as `0.1.0-alpha.1`. SemVer defines 0.y.z as initial development and prereleases as lower
  precedence than the associated normal version.
  [VERIFIED: https://semver.org/spec/v2.0.0.html, accessed 2026-10-03]
- Synchronize `package.json`, the host package version in `src-tauri/Cargo.toml`,
  `Cargo.toml` workspace version, `src-tauri/tauri.conf.json`, relevant lockfile records and
  executable product/file metadata. They currently declare 0.1.0 independently; check inherited
  crate versions and helper metadata too.
  [VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/package.json, accessed 2026-10-03]
  [VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/Cargo.toml, accessed 2026-10-03]
  [VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/src-tauri/Cargo.toml, accessed 2026-10-03]
  [VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/src-tauri/tauri.conf.json, accessed 2026-10-03]

## 2. Prepare changelog and release inputs

- Draft a versioned changelog from Conventional Commits since the previous tag, then review it
  manually. `feat` and `fix` identify features/fixes; a `BREAKING CHANGE` footer or `!` marks a
  breaking change. Include migrations, data-loss risks, unsupported coverage, signing status
  and outstanding false positives; do not infer safety from a commit type.
  [VERIFIED: https://www.conventionalcommits.org/en/v1.0.0/, accessed 2026-10-03]
- Choose signing under [the code signing policy](code-signing.md); confirm provider approval,
  named approver, key custody and publisher subject. Record catalog public key/URL or their
  absence. Keep Authenticode and catalog keys separate and outside the checkout.
- Record the exact build environment, target, features, installer modes, overlays and tool
  versions under [reproducible builds](reproducible-builds.md). Publish source and license notices
  corresponding to every shipped executable and component.

## 3. Run all quality gates before tagging

Run from a clean checkout; require every command to succeed and inspect unintended tracked
changes. Use the actual release commit range for commitlint. `pnpm format:check` covers Markdown
as well as frontend files; catalog table formatting belongs to its generator.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/package.json, accessed 2026-10-03]
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/.prettierignore, accessed 2026-10-03]

```powershell
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo run --locked -p xtask -- catalog-validate
cargo run --locked -p xtask -- catalog-table --check
pnpm install --frozen-lockfile
pnpm bindings:check
pnpm lint
pnpm typecheck
pnpm test
pnpm format:check
pnpm build
pnpm commitlint --from <previous-release-commit> --to <release-commit>
```

Also build the Windows application/installers and perform the documented disposable-VM checks
for supported behavior, installation/uninstallation, helper pinning and blocked/partial outcomes.
Gate signed publishing on Phase 35's helper-first signing path. The current
`pnpm desktop:build` script is an unsigned developer build and does not lock the host invocation.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/scripts/build-desktop.ps1, accessed 2026-10-03]

## 4. Commit, tag and build in CI

- Have the maintainer review the release preparation commit, then create an annotated
  `v<version>` tag pointing to that exact commit; prefer a verifiable tag signature if the
  maintainer has an established key. Do not move or reuse published tags.
- Trigger Phase 35's release CI and verify its checkout SHA, successful quality jobs and complete
  build inputs. Until that workflow exists, this is a release gate requiring implementation,
  not a command that the present CI already supports.
- Build from public source on GitHub-hosted agents when using Foundation signing. Save the
  unsigned helper checkpoint and frontend assets. Manually approve helper signing, then calculate
  the final helper SHA-256 and compile the host with it. Save the unsigned host checkpoint, sign
  the host, package the exact host/helper and sign the installers.
  [VERIFIED: https://docs.signpath.io/trusted-build-systems/github, accessed 2026-10-03]
- Enforce product/version metadata, timestamp signatures and preserve provenance for both
  unsigned checkpoints and signed outputs. Do not rebuild or modify the helper after pinning it.
  Stop if the pipeline cannot establish this relationship.
- Handle Tauri's bundle-type patching before final host signing, or explicitly use its supported
  `--no-binary-patching` preservation path after assessing per-format updater consequences. Capture
  any per-format unsigned host checkpoints and verify extracted MSI/NSIS executables and generated
  uninstallers. A successful installer signature alone is insufficient.
  [VERIFIED: https://tauri.app/release/tauri-bundler/all-versions/, accessed 2026-10-03]
  [HYPOTHESIS]

## 5. Verify signatures, checksums and release evidence

- Verify each signed app/helper/installer with `signtool verify /pa /all /v <file>` and check
  publisher, chain and timestamp against the approved signing identity.
  [VERIFIED: https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe, accessed 2026-10-03]
- In a disposable VM, verify the installed helper's hash equals the host build pin and test
  packaging without personal session data. Retest the exact signed bytes, not a fresh build.
- Generate `SHA256SUMS.txt` **after all signing and final packaging**, with one filename/hash
  per asset, including verification materials. Publish SHA-256 separately for unsigned checkpoints
  in the build-input manifest. Hashing supports comparison of file contents against known values.
  [VERIFIED: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.6, accessed 2026-10-03]
- Perform two clean builds where feasible; publish artifact-specific comparisons and known
  differences. Supply the source SHA/tag, CI links, tool/image versions, commands, public trust
  inputs, final helper pin, signing metadata and unsigned checkpoints. Do not claim complete bit
  reproducibility if any relevant comparison is missing or unexplained.
- If unsigned, say **unsigned** prominently and document possible SmartScreen/managed-device
  blocks using the code signing policy. Never publish a false publisher/signing claim.

## 6. Publish and verify the public release

- Prepare a draft GitHub release for the reviewed tag. Attach final installers, checksums,
  corresponding source access, license notices and verification/provenance material.
- Review changelog, supported Windows/architecture scope, irreversible risks, signing status,
  known limitations and report links. Publish only after the named maintainer approves it.
- Download the published assets and recheck hashes/signatures against the retained outputs;
  record that verification with the release evidence. Preserve old release assets and tags.

## 7. Monitor after publication

- Watch the [false-positive report queue](https://github.com/Ximeeek/EveryOut/issues?q=is%3Aissue%20label%3A%22false%20positive%22)
  and follow [vendor submission and triage](false-positives.md). Record exact hash/product/verdict
  evidence and retest after definition updates; do not promise a vendor response deadline.
- Investigate unexpected behavior or tampering privately under [SECURITY.md](../../SECURITY.md).
  If necessary, withdraw affected assets with a visible advisory and issue a new version/tag.
  Never silently replace bytes or advise users to disable protection.

If separately publishing a catalog update, follow the existing
[catalog ceremony](../architecture/12-catalog-update-design.md#maintainer-steps),
including monotonically increasing catalog/provider revisions and independent signature
verification. Catalog signing does not replace executable signing.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/docs/architecture/12-catalog-update-design.md, accessed 2026-10-03]
