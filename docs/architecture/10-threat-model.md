# EveryOut threat model

Phase 10 target design, 2026-09-30. These are security requirements and validation gates,
not implemented controls or a security certification. This document consumes the existing
[provider contract](01-provider-contract.md), [manifest grammar](02-manifest-spec.md),
[wipe sequence](05-wipe-sequence.md) and [permission model](06-permission-model.md).

## Evidence, assets and boundaries

[Browser research §§1–7](../research/01-browsers.md) establishes mixed stores, preservation
conflicts, restoration and the limits of metadata verification. [Windows research §§1–6](../research/02-windows-identity-and-multi-account.md)
establishes protected sign-in/broker state, secret-returning APIs and the helper/IPC direction.
[Application research §§1–6](../research/03-apps-detection-process-av.md) establishes ambiguous
ownership, dataset provenance, process-closing loss and uncertain AV/EDR behavior.

Assets are the user's unrelated files and protected browser data; selected local session state;
Windows sign-in identity; other users' profiles; engine-held plans and approvals; catalog integrity;
helper authority; and accurate, sanitized reports. General discovery accepts metadata only.
The fixed Spotify exception in [ADR 0006](../adr/0006-fixed-saved-login-adapters.md) temporarily
reads bounded saved-login configuration in private, zeroized memory. No general credential
inventory, decryption, cookie/token row inspection, secret persistence or transmission is allowed.
No hooking, injection, foreign-process memory reads or drivers are allowed
([overview](00-overview.md), [V1 exclusions](08-not-doing.md)).

Trust boundaries are: React to Rust commands; untrusted observations to engine-owned plans;
manifest bytes to the interpreter; local paths to physical filesystem objects; unelevated host
to elevated helper; and network/download cache to an accepted catalog. Catalog signatures
authenticate origin, not safe effects. Helper privilege and UAC do not replace target review.
See [ADR 0003](../adr/0003-rust-command-capability-boundary.md) and [06](06-permission-model.md).

Assume malformed downloads, hostile manifests, compromised distribution infrastructure and local
processes able to change selected directories. Also consider a malicious authorized operator,
compromised UI, dependency or signing key. An administrator or attacker controlling the installed
binary and OS can defeat application controls; this design cannot promise protection against that
adversary. These are conservative modeling assumptions, not incidents established by the dossiers.

## Threat, asset, mitigation and residual risk

The table applies dossier constraints to adversarial scenarios. New mechanisms unsupported by
the dossiers remain OPEN DECISIONS below; until validated, affected operations stay blocked.

| Threat                                                                                         | Asset                                               | Mitigation                                                                                                                                                                                                                                                                                                                                                       | Residual risk                                                                                                                                                                             |
| ---------------------------------------------------------------------------------------------- | --------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Abuse: operator clears session traces to cover activity or destroy evidence                    | Local evidence and other people's data              | Explicit destructive-purpose/loss disclosure, dry run, selected scope and plan-bound approval; no stealth, unattended V1 trigger, arbitrary-path cleaning, log clearing or secure-erasure feature. Existing controls: [05](05-wipe-sequence.md), [08](08-not-doing.md).                                                                                          | Legitimate session deletion inherently removes some evidence. Intent cannot be inferred from metadata; an authorized operator or modified build can still misuse it.                      |
| Abuse: operator uses elevation against another user's active profile                           | Other-user files, unsaved work and Windows identity | Apply [06](06-permission-model.md): show eligible scopes, skip loaded/special/inaccessible other profiles, no cross-session closing; UAC is not per-profile consent. Protect sign-in, PRT and broker stores in both modes.                                                                                                                                       | OS administrator authority is broader than EveryOut. The app cannot establish the operator's legal entitlement to every selected profile.                                                 |
| Catalog tampering in cache or bundled files, including a forged `validated` label              | Approved target/effect set                          | Verify catalog signature at load and activation; pin accepted bundle digest and rule revisions to plans. Apply local schema, supported-method, ownership and preservation checks even to signed rules; no unsigned override. [02](02-manifest-spec.md), [12](12-catalog-update-design.md).                                                                       | A compromised signing key or erroneous signed rule can authenticate harmful declarations. Independent review and scoped tests remain necessary.                                           |
| Malicious manifest uses traversal, absolute/UNC/device paths, broad globs or parser ambiguity  | Files outside approved owner roots                  | Enforce [02](02-manifest-spec.md) root grammar and deny precedence; reject unknown fields/methods, duplicate identities and ambiguous encodings. Resolve owner roots in Rust; UI/catalog cannot supply arbitrary deletion paths. Exact Windows grammar/parser validation is `destructive-root-confinement`.                                                      | Windows aliases/normalization and parser differences can defeat naive checks. Lexical prefix matching is insufficient; unknown resolution blocks mutation.                                |
| Symlink, junction, other reparse point or hard-link alias redirects deletion                   | Unrelated files and protected stores                | No reparse traversal in discovery or deletion, including root and parent components. Revalidate physical owner/target identity and conflicts; unresolved aliases block actions. Existing constraints: [03](03-heuristic-detection.md), [04](04-classification-rules.md), [06](06-permission-model.md); implementation blocked on `destructive-root-confinement`. | Rejecting visible links once does not establish race safety. Hard-link semantics and filesystem support need validation; custom redirected profiles may remain unsupported.               |
| TOCTOU: target/ancestor changes after scan, dry run or final check                             | Reviewed plan and deletion scope                    | Revalidate at mutation boundary and use an object-bound approach that cannot reopen a substituted path. Changed identity, owner, root or effects invalidate the action and approval; never retry with a broader target. `destructive-root-confinement` must prove race resistance.                                                                               | Repeated path checks alone leave a race window. If the platform cannot establish confinement, refuse the affected operation.                                                              |
| Compromised frontend sends arbitrary targets or replays approvals                              | Plan authority and session scope                    | Opaque IDs, explicit command ACLs and Rust-side checks per ADR 0003; reject stale/cross-run plans, unapproved effects and unknown commands. No fs/shell plugin route. `tauri-command-acl-validation` verifies enforcement.                                                                                                                                       | Host/engine bugs or compromised trusted native code can bypass the boundary.                                                                                                              |
| Update channel substitutes, truncates, replays or freezes catalog data                         | Catalog freshness and integrity                     | Embedded-key signature verification, signed version/digest/compatibility/changelog, persistent high-water mark and fail-closed activation per [12](12-catalog-update-design.md). Transport security is additional protection; wipe has no network dependency.                                                                                                    | Offline clients cannot prove newest available version. State reset, key compromise and freeze detection remain explicit limitations.                                                      |
| Application/helper binary or executable update is replaced                                     | Trusted engine and elevated authority               | Treat application distribution as a separate code trust boundary; validate installed helper identity and fixed launch target under [06](06-permission-model.md). Plan consistent publisher signing; catalog channel never delivers executable code.                                                                                                              | Catalog signing does not secure application updates. Executable update protocol/release policy is outside this phase; helper trust stays blocked on its existing spike.                   |
| Helper IPC spoofing, pipe squatting, replay or confused-deputy request                         | Elevated authority, other-user scope                | Explicit pipe DACL and endpoint validation, one-time nonce plus run/plan/revision binding, typed bounded requests and independent helper target resolution per [06](06-permission-model.md). Reject arbitrary paths/commands and mismatched identities.                                                                                                          | Nonce alone is insufficient. Different-admin UAC, same-user attackers, lifecycle and endpoint checks require `elevated-helper-ipc-validation`; no privileged execution before validation. |
| Dependency/build/signing compromise or unsafe imported rules                                   | Application and catalog supply chain                | Review pinned dependency/lockfile changes, build inputs and rule provenance; retain license/evidence metadata and test every changed executable rule. Signing approval must follow review; no automatic Winapp2 deletion import. Application research §§3–4 and [12](12-catalog-update-design.md).                                                               | Pins and signatures can preserve a compromised artifact. Signing custody/provenance process needs a named spike and later release policy.                                                 |
| Secret leakage through diagnostics, exports, subprocess output or backups                      | User privacy and session secrets                    | Narrow metadata interfaces; no blob-returning inventory, content readers, dumps or session backups. Export opaque IDs, stable errors and aggregate outcomes per [01](01-provider-contract.md), [05](05-wipe-sequence.md). Synthetic reproductions only.                                                                                                          | Metadata can still reveal installed applications or timing; user-chosen report sharing requires minimization.                                                                             |
| Incorrect owner, shared store, DBSC omission or misleading success claim                       | Protected data and truthful results                 | Block unknown ownership/mixed preserved stores; deduplicate effects and disclose incomplete identity/DBSC/sync coverage. Use existing partial-result and metadata-only verification semantics. Browser §§1, 3–6, [04](04-classification-rules.md), [07](07-sync-and-identity.md).                                                                                | Fresh SSO, restoration and surviving remote sessions remain possible after complete supported local scope.                                                                                |
| AV/EDR blocks metadata/deletion or classifies the app as credential theft/destructive software | Availability, publisher trust and honest reporting  | Apply the plan below: consistent signing, public readable rules, dry run, sanitized detailed reports and minimal privileges. Preserve blocked/partial results; never disable protection or request exclusions as a fallback. Application research §6.                                                                                                            | No guaranteed immunity, compatibility or measured detection reduction; protected-device policy may intentionally prevent cleanup.                                                         |

## Reasonable abuse mitigation

EveryOut is a local, user-reviewed session clearing tool. Preserve the approved V1 scope; never add
an evidence-shredding mode, audit-log deletion, concealment, remote triggering or security-product
evasion. Explain irreversible local-only losses and the absence of remote revocation before
execution. Dry run and accurate reporting make effects reviewable; they cannot determine intent.
This policy follows the local-only and loss boundaries in [05](05-wipe-sequence.md) and
[08](08-not-doing.md); abuse deterrence effectiveness is unmeasured.

Do not create a mandatory external audit trail, transmit inventory or retain secret evidence to
police misuse. These would add privacy/network exposure and conflict with the existing contract.
Sanitized local reports are user information, not tamper-proof forensic evidence. A hostile
operator can remove them or modify open-source code. `abuse-mitigation-review` must assess whether
disclosures and trigger restrictions are sufficient without expanding collection or wipe scope.

## AV/EDR false-positive mitigation plan

The basis is [application research §6](../research/03-apps-detection-process-av.md#6-avedr-detection-and-concrete-mitigations).
Read-oriented detection examples do not prove metadata/delete exemption; the Norton community
report does not establish a current product rule. Keep `metadata-av-compatibility` open.

1. Plan consistent trusted publisher signing for application/helper artifacts. Keep catalog
   signing separate. Signing identifies a publisher; it does not guarantee vendor approval.
   Certificate choice, custody and artifact verification remain `artifact-signing-provenance`.
2. Publish source and versioned, understandable rule effects, exclusions and limitations. Link
   installed app/catalog versions in diagnostics. Transparency is inspectability, not immunity.
3. Provide metadata-only dry run: no process closing, secret reads, deletion, registry mutation,
   configuration edits or logout calls. Show blocked ownership and unsupported coverage.
4. Report reviewed rule IDs/revisions, planned and applied effects, close outcomes, skips,
   verification and sanitized error codes. Never attach cookies, profiles, tokens, raw paths,
   credential targets, dumps or captured arbitrary command output to an incident.
5. Keep the main app unelevated and helper optional/action-scoped under [06](06-permission-model.md).
   A security-product block stays visible; no protection bypass, exclusion request or escalation
   solely to overcome it. Anti-cheat constraints apply to diagnostics and tests too.
6. Reproduce alerts with synthetic profiles in snapshot VMs, recording Windows/app/catalog and
   security-product versions, alert class, binary hash/signature and sanitized reproduction steps.
   Distinguish malware verdicts from intentional access-policy blocks; follow [11](11-test-strategy.md).
7. For confirmed suspected false positives, a maintainer can submit the clean executable and
   synthetic reproduction through Microsoft's developer sample review process and the affected
   vendor's official equivalent, as cited in application §6. Record determination and dispute
   through the documented developer channel if needed. No automated upload or user-data submission
   is designed here; later release policy owns the procedure and vendor endpoint revalidation.

## OPEN DECISIONS

| Named spike                    | Required evidence                                                                                                                                                                                                                                        | Until resolved                                                                                |
| ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `destructive-root-confinement` | Exact Windows path grammar, normalization/aliases, root/ancestor/leaf reparse checks, hard links, object identity and race-resistant mutation, with adversarial fixtures; basis: [02](02-manifest-spec.md), [03](03-heuristic-detection.md), Windows §5. | No destructive adapter whose confinement is unproven; string checks alone are insufficient.   |
| `abuse-mitigation-review`      | Review misuse scenarios and understandable disclosures against the V1 scope and privacy constraints; no efficacy evidence in the dossiers.                                                                                                               | Existing review gates and exclusions only; no new evidence collection or concealment feature. |
| `artifact-signing-provenance`  | Publisher signing, helper binary trust, signing-key custody and reviewed build/catalog provenance; application §§3, 6 do not settle implementation.                                                                                                      | Do not claim signed releases or trusted helper enforcement; privileged work remains blocked.  |

Existing `elevated-helper-ipc-validation`, `other-account-scope-validation`,
`tauri-command-acl-validation` and `metadata-av-compatibility` retain their gates in
[00](00-overview.md#open-decisions) and [06](06-permission-model.md#open-decisions).
Catalog-specific spikes are in [12](12-catalog-update-design.md#open-decisions). Tests in
[11](11-test-strategy.md) must turn these requirements into evidence before implementation claims.
