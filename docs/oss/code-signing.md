# EveryOut code signing policy

Research checked on 2026-10-03. This is a proposed policy; provider acceptance and account setup
remain maintainer actions. Do not describe EveryOut as signed until a release has passed signature
verification. [HYPOTHESIS]

## Azure Artifact Signing: Poland and individual eligibility

Artifact Signing is the current name of Microsoft's formerly Trusted Signing service.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03]

Public Trust is available to organizations in the USA, Canada, EU and UK, and also Australia,
New Zealand, Japan, South Korea, Singapore, Switzerland, Norway and Israel. Individual developers
must be located in the USA or Canada. Consequently, **a Poland-based individual does not qualify
for Public Trust through the individual route**; organizational availability does not extend that
route to Polish residents. Private Trust has different geographic restrictions and is not the
public distribution option recommended here.
[VERIFIED: https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart, accessed 2026-10-03]

An organization/DBA application requires a legal business identity, business identifier, owned
website/domain, business address and identity validation. Whether a particular Polish sole
proprietorship qualifies must be confirmed by Microsoft; no acceptance is assumed.
[VERIFIED: https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart, accessed 2026-10-03] [HYPOTHESIS]

The service requires a paid Azure subscription, excluding free, trial and sponsored subscriptions.
Do not open a paid account solely to test an unsupported individual application.
[VERIFIED: https://learn.microsoft.com/en-us/azure/artifact-signing/faq, accessed 2026-10-03]

## SignPath Foundation: free OSS signing, conditional acceptance

SignPath Foundation offers free OSS signing with HSM-held keys. The certificate identifies
SignPath Foundation, rather than the individual maintainer.
[VERIFIED: https://signpath.org/, accessed 2026-10-03]
[VERIFIED: https://signpath.org/terms, accessed 2026-10-03]

The brief's specific claim of a free **OV** certificate is unconfirmed: the Foundation pages
reviewed do not promise that classification. Obtain the current certificate type and publisher
subject from the Foundation before describing them to users. Acceptance of EveryOut, including
its destructive session-cleanup purpose and a solo maintainer's role arrangement, remains pending.
[HYPOTHESIS]

The published conditions require:

- An OSI-approved license for all components, no commercial dual licensing, no proprietary
  components except permitted System Libraries, active maintenance, an existing release and
  documented functionality.
- No malware/PUA or security-circumvention features; privacy protection, warnings for system
  changes and uninstall support.
- Repository ownership, signing only the team's own binaries, MFA for repository and SignPath
  access, contributor review, defined authors/reviewers/approvers and manual release approval.
- A visible “Code signing policy”, service attribution, named roles and privacy disclosures.
- Enforced product name/version metadata, verifiable source builds and cooperation with
  investigations. Acceptance is discretionary; service/certificates can be withdrawn.

[VERIFIED: https://signpath.org/terms, accessed 2026-10-03]

For GitHub integration, SignPath verifies workflow origin and requires uploaded workflow artifacts;
all jobs leading to an OSS signing request must run on GitHub-hosted agents. Plan public source
and public CI provenance, rather than uploading a locally built executable.
[VERIFIED: https://docs.signpath.io/trusted-build-systems/github, accessed 2026-10-03]

EveryOut declares GPL-3.0-or-later. This alone does not establish whole-package license compliance
or Foundation approval; review dependencies, bundled components and WebView2 packaging before
applying. [VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/Cargo.toml, accessed 2026-10-03] [HYPOTHESIS]

## SmartScreen and alternatives

Microsoft dates removal of EV's instant SmartScreen reputation to **2024**. Reputation now depends
on file hash and publisher signals; neither OV nor EV guarantees an immediate bypass. Do not
purchase EV solely for that historical benefit.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/distribution-feature-status, accessed 2026-10-03]

Reputation builds organically. A signed new file can still show an unrecognized-app prompt;
consistent signing can carry publisher reputation, while unsigned new versions rebuild it.
Microsoft provides no exact threshold. Do not promise a clearance date or installation count.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03]

| Option                           | Assessment                                                                                                                                                                                                                                                                                                                                                                                                 |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Certum Standard / Open Source    | Certum lists individual/company Standard certificates and an Open Source offering. Request written confirmation of Polish individual eligibility, identity documents, key custody, total cost and CI support before purchase. [VERIFIED: https://www.certum.eu/en/code-signing-certificates/, accessed 2026-10-03] [HYPOTHESIS]                                                                            |
| Microsoft Store                  | Microsoft describes Store distribution as exempt from SmartScreen download warnings. EveryOut's Store acceptance, packaging and helper compatibility are unverified and require a separate evaluation. [VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03] [HYPOTHESIS]                                                              |
| Self-signed certificate          | Microsoft documents the same SmartScreen behavior as unsigned distribution; it is not a public trust substitute. [VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03]                                                                                                                                                                 |
| Unsigned prerelease with SHA-256 | Permit only with explicit unsigned status, source/CI provenance and checksums. Hash agreement checks bytes against the published value; it does not establish publisher identity or protect against replacement of both file and checksum. [VERIFIED: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.6, accessed 2026-10-03] [HYPOTHESIS] |

Unsigned downloads can show “Windows protected your PC”; enterprise policy can prevent execution.
Windows 11 Smart App Control can block unsigned files without positive reputation. Signed files
may still prompt. Tell users to verify provenance or wait for a trusted release, and never instruct
them to disable protection or create an exclusion.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03]

## Release signing requirements

Require separate custody for Authenticode credentials and the catalog Ed25519 key. Sign the
helper first, hash its final bytes, compile the host with that hash, sign the host, package those
exact binaries, then sign the installers. Publish final hashes and verify the installed helper
against the embedded pin. Preserve unsigned build checkpoints for independent verification.
These are release requirements for Phase 35, not an implemented signing pipeline. [HYPOTHESIS]

Tauri can patch the host with bundle-type information during packaging, invalidating an existing
signature. Its `--no-binary-patching` option preserves an already-signed host, with a trade-off for
per-format updater selection. Phase 35 must either preserve that host explicitly or capture and
sign each final patched host before packaging; verify the binaries extracted from both MSI and
NSIS, including generated uninstallers where applicable.
[VERIFIED: https://tauri.app/release/tauri-bundler/all-versions/, accessed 2026-10-03]
[HYPOTHESIS]

The current [desktop build script](../../scripts/build-desktop.ps1) hashes an unsigned helper
before compiling the host and does not sign artifacts. Signing that helper afterward changes
the bytes pinned by the host; the signed release path must implement the order above before use.
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/scripts/build-desktop.ps1, accessed 2026-10-03]
[VERIFIED: https://github.com/Ximeeek/EveryOut/blob/a739ca4/src-tauri/build.rs, accessed 2026-10-03]
[HYPOTHESIS]

## Recommendation and actions the maintainer must perform

**Prefer SignPath Foundation after eligibility review. Use a clearly marked unsigned prerelease
with verification material while approval is pending; consider Certum if rejected. Keep
[ADR 0005](../adr/0005-code-signing.md) Proposed until the provider and signing process are proven.**
This is a project recommendation, not a guarantee of acceptance or warning-free downloads.
[HYPOTHESIS]

1. Review the Foundation terms against all shipped components, deletion behavior, warnings,
   uninstall support and actual network features. Publish a truthful privacy policy; distinguish
   user-requested catalog downloads from offline wiping.
2. Enable MFA, name the real author/reviewer/approver, and ask the Foundation whether the solo
   role arrangement and project maturity satisfy its requirements. Prepare public source,
   release/download links, license inventory and public CI evidence.
3. Apply personally through [the Foundation application page](https://signpath.org/apply). Ask
   explicitly about EveryOut eligibility, certificate class/subject and required metadata.
4. If accepted, configure repository access, signing roles, approval policy and artifact metadata;
   add “Free code signing provided by SignPath.io, certificate by SignPath Foundation” only when
   actually provided, and link the real service/provider pages. Authorize each release personally.
5. Have Phase 35 implement and verify helper-first signing, locked builds, timestamping,
   provenance and final checksum publication before claiming signed distribution.
6. If refused, request a Certum eligibility/cost/custody quote personally. Reconsider Azure only
   with a genuinely eligible organizational identity or a documented eligibility expansion.
7. Record the provider's decision and validation evidence, then update the ADR status and release
   notes. No certificate application, purchase or identity submission is performed by this phase.

The numbered items are proposed maintainer obligations. [HYPOTHESIS]
