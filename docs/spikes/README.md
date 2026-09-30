# EveryOut feasibility spike register

Phase 11, definitions only. No VM experiment or authentication result has been produced.
S1–S4 have `Status: PENDING USER EXECUTION` in their procedures. S5–S8 receive their detailed
procedures in the next two phases of this branch; no S5–S8 procedure files are introduced here.
The [metadata snapshot tool](../../spikes/tree-snapshot/README.md) is a separate lab executable,
excluded from the application's Cargo workspace and release build.

| ID                                     | Question                                                                                                                   | Why it matters                                                                      | Method                                                                                                                                                         | Acceptance criteria                                                                                                                                         | Status                        | Blocking phases / deliverables                                                                               |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------ |
| [S1](S1-chrome-sync-sso.md)            | After a Chrome wipe with sync and Windows SSO enabled, can identity/access reappear silently or data return?               | Local absence can give misleading logout expectations.                              | Controlled VM matrix with independent sync/SSO controls, offline before/after metadata and gated restart/reconnect observation.                                | Reproducible per-version separation of deletion, recreation, sync configuration, identity and SSO; no secret I/O or unsupported durable-logout claim.       | defined in this phase         | Browser provider execution and verification; browser result/warning UI; any claim of durable browser logout. |
| [S2](S2-sync-edits-vs-policy.md)       | Can each browser disable sync by secret-free closed-profile edits, and how does policy differ?                             | Mixed configuration and policy precedence can block the V1 direction.               | Six-browser versioned matrix, synthetic field edits, idempotence/preservation checks and isolated VM policy controls.                                          | Exact compliant fields/method or explicit unsupported outcome per browser; effective scope/precedence and restart evidence; policies remain outside V1.     | defined in this phase         | Browser identity/sync adapters and effective-disable reporting; manifest validation for such actions.        |
| [S3](S3-dbsc-wipe-verification.md)     | What does DBSC require beyond cookie removal, and what can verification prove?                                             | Surviving session records or key references may undermine closure.                  | Versioned metadata inventory and cookie-only/full-candidate/control VM arms; gated restart/expiry/refresh evidence.                                            | Documented DBSC applicability, owned artifact companions and preservation boundaries; distinguish metadata absence from refresh/authentication uncertainty. | defined in this phase         | DBSC-capable browser providers, artifact closure and verification/result claims.                             |
| [S4](S4-firefox-edge-identity-sync.md) | How do Firefox and Edge identity, sync and Windows SSO differ from Chrome?                                                 | Chromium assumptions miss Firefox account/session restore and Edge vendor identity. | Vendor-specific repeats of S1/S2, Firefox containers/restore and Edge account/policy variants.                                                                 | Independent versioned identity/sync/website/SSO observations; preserved mixed stores; unsupported vendor surfaces remain unknown.                           | defined in this phase         | Firefox/Edge provider execution, identity/sync handling and browser reports.                                 |
| S5                                     | Can selected Microsoft account state be removed locally without harming Windows sign-in or allowing misleading SSO claims? | WAM/PRT/device identity is not ordinary app state.                                  | Later VM procedure using supported scoped interfaces and test identities, with sign-in preservation and silent re-login controls.                              | Exact supported scope or refusal; Windows sign-in/device identity preserved; no token/blob reads and explicit re-login limits.                              | defined in later spike phases | Windows/Microsoft account providers and SSO guidance; broader logout claims.                                 |
| S6                                     | Which other-user profiles are eligible, and can NTUSER.DAT load/unload and process close respect other sessions?           | Elevated ambient identity, loaded hives and RDP races can target the wrong user.    | Later disposable multi-user VM procedure with synthetic hives, loaded/unloaded/session races, access-denied and lifecycle checks.                              | Owner-bound access, deterministic exclusions, successful unload on all exit paths, no cross-session close or authority fallback.                            | defined in later spike phases | All-accounts mode, elevated helper/profile-hive operations and related permissions.                          |
| S7                                     | How do Restart Manager, graceful close and hard kill affect locks, cancellation and data loss?                             | Process name/PID alone and forced shutdown are unsafe.                              | Later VM comparison using owned dummy processes first, then reviewed test-only apps, including cancellation/relaunch/PID reuse.                                | Identity revalidation, bounded ownership and observed lock release; consent/cancellation and loss differences recorded; no unauthorized forced close.       | defined in later spike phases | Process coordinator and destructive execution sequencing.                                                    |
| S8                                     | What is the false-positive rate of heuristic detection?                                                                    | Provisional scores cannot justify destructive targeting.                            | Later labeled synthetic/test-installation corpus including residue, collisions, portable/shared/relocated layouts; measure confusion matrix by signal/version. | Defined sampling/labels, false positives and negatives with denominators, reviewed thresholds and uncertainty; detection alone never authorizes a wipe.     | defined in later spike phases | Heuristic detection calibration/preselection and catalog confidence promotion.                               |

Only Phases 11–13 are numbered by this task. Future implementation-phase numbers are not supplied;
the blocking column names their deliverables rather than inventing a roadmap. Defining a spike
does not unblock implementation. A negative finding can resolve feasibility only by explicitly
retaining unsupported scope; it cannot be counted as validated logout support.

## Relationship to architecture decisions

S1/S3/S4 inform `browser-artifact-closure`; S2/S4 inform `browser-sync-profile-edit` and
`browser-sync-policy-interaction`; all require `metadata-discovery-allowlist` for any proposed
content exception. S5 concerns `app-session-scope` and Windows identity restrictions; S6 concerns
`other-account-scope-validation` and `elevated-helper-ipc-validation`; S7 concerns
`process-close-coordination`; S8 concerns `heuristic-confidence-calibration`.
See [architecture overview](../architecture/00-overview.md#open-decisions),
[wipe sequence](../architecture/05-wipe-sequence.md#open-decisions),
[permissions](../architecture/06-permission-model.md#open-decisions),
[sync/identity](../architecture/07-sync-and-identity.md#open-decisions) and
[test strategy](../architecture/11-test-strategy.md#checks-and-open-decisions).

This register covers all eight requested phase-series spikes. Other named architecture decisions
(including containment, test-harness, preservation, catalog/signing, AV and V2 decisions) remain
open in their existing registers; S1–S8 do not silently resolve or supersede them.

## Common lab rules and evidence gates

Use disposable Windows 10/11 VMs, clean VM snapshots and **test accounts only, never real accounts**.
Disable host shares, clipboard, browser import and profile mounting. Build/copy the tool before
isolating networking. Keep evidence outside every captured tree; take separate captures for
each approved user-data/profile/local-storage root, so root-level state is not missed. Use
anonymous case/root labels. Close all lab browser processes gracefully and confirm exit before
every capture/mutation; do not kill host processes. A running/locked/redirected tree invalidates
the case. Restore the clean VM baseline between arms and after failures.

The VM baseline must contain no credentials/session tokens; synthetic metadata fixtures are
permitted. Do not take post-login VM snapshots, export whole profiles or copy secret-bearing
configuration. The task requests test-account sync/SSO scenarios, but
[architecture test strategy](../architecture/11-test-strategy.md#vm-workflow-and-failure-matrix)
explicitly excludes real test-account tokens, network login probes and secret snapshots.
Record this conflict here and in S1/S3/S4: authentication arms remain gated on a reviewed lab
method compatible with that boundary. Their numbered steps describe required future
observations, not permission to log in, create/export tokens or probe a service now. Without
that method, record `NOT RUN — METHOD BLOCKED`, keep authentication unknown and retain the
document status. Offline layout/fixture work cannot substitute for those observations.

There is no browser wipe engine in the current scaffold. Before any manual VM deletion, the user
must record an exact versioned target/companion list, exclusive ownership and exclusions derived
from [browser research](../research/01-browsers.md) and
[manifest preservation rules](../architecture/02-manifest-spec.md). Unreviewed targets remain
blocked. Whole-profile deletion, whole mixed Web Data/Preferences/Local State rewrites, Firefox
password-key deletion, policy writes in EveryOut, TPM-wide key removal and Windows identity/cache
clearing are forbidden substitutes. Do not read, hash, dump, decrypt, back up or transmit session
files. The tool's only content reads are its own metadata JSON in diff mode.

Use [the tool workflow](../../spikes/tree-snapshot/README.md) for `before`, immediate offline
`after`, and post-restart `restart` captures per root. Compare before→after and after→restart;
keep each stage independent. Repeat each executable arm three times from a clean baseline and
include a no-wipe control. Set observation windows before running, record elapsed times,
errors and exclusions. A recreated file is not proof of sync restoration or successful login.
Preservation needs separately approved synthetic canaries/UI observations; unchanged metadata
alone cannot establish byte-for-byte preservation. No remote revocation or durable logout claim.

Results use `NOT RUN`, `PASS`, `FAIL`, `INCONCLUSIVE`, `UNSUPPORTED` or `NOT APPLICABLE` (with reason)
per criterion; only supplied, reproducible evidence can change the pending status. Export sanitized
case/version/rule metadata, never usernames, emails, raw origins, tokens, complete policy dumps or
profiles. No hooking, injection, foreign memory reads, drivers or security-product bypass.
