# ADR 0005: Prefer conditional Foundation signing for public releases

- Status: Proposed
- Date: 2026-10-03

## Context

EveryOut needs an affordable signing path for a solo maintainer based in Poland. Microsoft's
Public Trust individual route currently supports only USA/Canada residents; EU availability
applies to organizations. A Polish individual's organizational/DBA acceptance is not established.
[VERIFIED: https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart, accessed 2026-10-03] [HYPOTHESIS]

SignPath Foundation offers free OSS signing, but approval depends on project eligibility,
verifiable builds and its own reputation assessment. The certificate is held in the Foundation's
name. EveryOut approval and the brief's specific OV classification are unconfirmed.
[VERIFIED: https://signpath.org/, accessed 2026-10-03]
[VERIFIED: https://signpath.org/terms, accessed 2026-10-03] [HYPOTHESIS]

EV certificates no longer grant instant SmartScreen reputation; Microsoft dates the behavior
change to 2024. Certificate selection cannot promise warning-free downloads.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/distribution-feature-status, accessed 2026-10-03]

## Proposed decision

Prefer SignPath Foundation after the maintainer confirms eligibility, solo roles, component
licenses and certificate details. Permit a clearly marked unsigned prerelease with checksums,
source and CI evidence pending approval; consider Certum after refusal. Do not buy EV solely for
SmartScreen reputation. Keep executable signing and catalog Ed25519 custody separate.
[HYPOTHESIS]

Require manual release approval and helper-first signing: sign helper, hash final helper bytes,
compile host with that pin, sign host, package those binaries and sign installers. Retain unsigned
checkpoints, build provenance and final checksums. The current script hashes an unsigned helper
and supplies that digest to the host; Phase 35 must implement a signed path before using it.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/scripts/build-desktop.ps1, accessed 2026-10-03]
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/src-tauri/build.rs, accessed 2026-10-03]
[HYPOTHESIS]

## Consequences and acceptance gates

Require packaging to preserve the final signed host, or sign each final patched host variant
before inclusion. Verify installed and extracted executables, not just installer signatures;
record the chosen patching/signing stages in build provenance. [HYPOTHESIS]

Foundation signing requires verifiable GitHub workflow artifacts and GitHub-hosted agents for
all preceding OSS jobs. Release approval, MFA, metadata and public policy requirements are detailed
in the [code signing policy](../oss/code-signing.md).
[VERIFIED: https://docs.signpath.io/trusted-build-systems/github, accessed 2026-10-03]
[VERIFIED: https://signpath.org/terms, accessed 2026-10-03]

The proposed approach trades provider review and potential refusal for reduced signing cost.
Unsigned prereleases carry user trust and execution-policy limitations; checksums alone do not
authenticate the publisher. Signed outputs and unsigned checkpoints need separate verification,
including the signed helper as a host input. Full bit reproducibility remains unverified.
[HYPOTHESIS]

Move to Accepted only after the maintainer records provider acceptance or an explicitly chosen
alternative, actual certificate subject/class, named roles, custody, approved pipeline and
successful app/helper/installer verification. No application or purchase is authorized by this
ADR. Follow [the maintainer steps](../oss/code-signing.md#recommendation-and-actions-the-maintainer-must-perform)
and [release checklist](../oss/release-process.md). [HYPOTHESIS]
