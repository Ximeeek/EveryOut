# S5 — Microsoft account state and silent reauthentication

Status: PENDING USER EXECUTION

## Hypothesis and protected scope

Removing an explicitly selected app credential may leave broker/app identity capable of silent
reauthentication. TokenBroker, IdentityCache and OneAuth absence or recreation cannot prove logout.
A matching credential target is a candidate, not ownership evidence or permission to remove it.
This spike informs `app-session-scope` and `metadata-discovery-allowlist`, without resolving them.
See [Windows dossier §§1–3](../research/02-windows-identity-and-multi-account.md),
[identity architecture](../architecture/07-sync-and-identity.md) and
[permission model](../architecture/06-permission-model.md).

The Windows sign-in account is never touched, including a Microsoft Windows sign-in account.
WAM, PRT, device join, enrollment, Windows Hello, passwords and TPM keys remain protected.
Direct cache deletion is unsupported: no reviewed public deletion contract is recorded for these
three directories. A negative/unsupported result is acceptable; a blanket cache wipe is not.

## Prerequisites and execution gates

Use disposable Windows 10/11 VMs, isolated from host shares, clipboard and real accounts, with
[a clean token-free baseline and common lab rules](README.md#common-lab-rules-and-evidence-gates).
Use a local Windows test user plus a separate test Microsoft app account; add a separate arm
where the Windows sign-in identity is a test Microsoft account and is strictly preserved.
Record exact OS/app/browser builds, region, July 2026-or-later updates where applicable, account
category, existing policy, sync/SSO settings and prior consent using neutral labels only.
Office version/licensing and unmanaged/managed differences must be recorded separately.

The architecture test strategy excludes real test-account tokens/network login probes.
Authentication arms therefore require a reviewed compatible lab method; without it record
`NOT RUN — METHOD BLOCKED`. Do not create authenticated VM snapshots, export caches, inspect
secret files or use offline synthetic fixtures as evidence of successful authentication.
No wipe engine exists. Any future manual credential removal needs a versioned exact target,
app-only ownership proof and Windows-sign-in exclusion; unresolved targets remain blocked.
Procedures below are future user-executed VM work, not operations performed in this phase.

## Matrix

| Arm | Scoped action/control                                              | Required observations                                                                                                                             |
| --- | ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| C0  | No-change control                                                  | Baseline app/browser identity, prompts, metadata drift and SSO behavior.                                                                          |
| C1  | Selected app-only Credential Manager entry, if ownership validated | Target absence versus Office/browser/app identity; unrelated targets and Windows sign-in preserved.                                               |
| C2  | Supported Office/app sign-out UI, separately approved control      | UI account removal, restart state and whether broker-assisted identity returns.                                                                   |
| C3  | TokenBroker, IdentityCache, OneAuth                                | Metadata-only inventory; direct deletion refused as unsupported. Supported app UI effects observed without attributing a cache deletion contract. |
| C4  | Browser sync/SSO enabled versus disabled                           | Edge, Chrome and Firefox observed independently; controls follow S1/S4 and version applicability.                                                 |
| C5  | Test Microsoft Windows sign-in identity                            | Same eligible app-only actions; sign-in identity and device/account configuration unchanged.                                                      |

Secondary work/school disconnect is a separate user decision, outside EveryOut's automated wipe.
Do not substitute disconnect, `dsregcmd /leave`, global Credential Manager clearing or broker reset
for an unsupported arm. Entra evidence cannot be generalized to personal Microsoft accounts.

## Numbered VM procedure

1. Record the matrix, control arms, reviewed method revision, ownership/exclusion list and
   observation windows (for example 120 seconds offline and 300 seconds reconnected). Mark blocked
   arms before setup. Repeat each executable arm three times from the clean baseline.
2. Record Windows sign-in account category and join/enrollment/Hello configuration through UI
   as booleans/categories, without account names or raw diagnostic dumps. Establish test app
   account/SSO only if the authentication gate permits it. Record consent state independently.
3. Disconnect networking, close the owned test apps/browsers gracefully and verify exit.
   Run [identity-probe](../../spikes/identity-probe/README.md) inside the VM under that test user;
   retain output locally and sanitize target names/SIDs/paths before sharing. Record directory
   access/size states separately; unreadable or redirected state is unknown, never empty.
4. Restore baseline per arm. For C1, use Credential Manager UI to remove only the independently
   reviewed app target. Record refusal if its ownership/sign-in relationship cannot be established.
   For C2, use the approved app sign-out UI. For C3, record `UNSUPPORTED` for direct deletion and
   use only metadata observations or a separately approved supported UI control. Never open blobs.
5. While apps remain closed/offline, repeat metadata inventory. Compare selected target presence,
   unrelated synthetic canaries and aggregate store states. Do not infer token invalidity from
   disappearance, unchanged size or a target-name match.
6. Restart Office and each eligible browser offline, separately. Do not type credentials, accept
   new consent or select an account. Record app identity, browser identity, sync, displayed prompts
   and local access separately. Close again and record metadata recreation.
7. Only where the reviewed authentication method permits it, reconnect and observe the fixed
   window without fresh interaction. Record silent app sign-in, website access, sync restoration,
   consent prompt or unknown independently. Otherwise leave online observations blocked.
8. Compare no-change, SSO-off and sync-off controls. Recreation alone cannot establish its source.
   Record error/lock/version/policy differences and any need for manual user instructions.
9. Verify Windows sign-in identity/settings remain unchanged; where permitted by the method,
   confirm normal test-user Windows sign-in after reboot. If it cannot be checked, preservation
   remains inconclusive. Restore the token-free baseline and fill the result template.

## Acceptance criteria

- A1: exact selected credential scope is supported and independently owner-bound, or explicitly
  unsupported; no Microsoft-pattern match alone authorizes deletion.
- A2: Windows sign-in, WAM/PRT/device/Hello/TPM state remain protected in every executable arm.
- A3: TokenBroker/IdentityCache/OneAuth have separate existence/size/access observations and an
  explicit unsupported direct-wipe outcome unless a future reviewed contract is established.
- A4: Office and browser identity, sync, website access and silent SSO are reported independently,
  with versions, windows, controls and three repetitions; blocked authentication stays unknown.
- A5: no secret reads/copies/decryption/transmission, account snapshots or broad cleanup; no
  remote revocation/global/durable logout claim. Unsupported scope yields honest user guidance.

## Results template — unexecuted

Case label / repetition: NOT RUN
OS build / region / update / app-browser version: NOT RUN
Method revision / authentication gate / blocked reason: NOT RUN
Windows sign-in category / app account category / policy / prior consent: NOT RUN
Arm / target-rule revision / ownership proof / exclusions: NOT RUN
Before / immediate offline after / offline restart / reconnect observations: NOT RUN
TokenBroker / IdentityCache / OneAuth states and logical bytes: NOT RUN
Office identity / browser identity / sync / website access / SSO prompts: NOT RUN
Windows sign-in and protected-state preservation / control comparison: NOT RUN
Observation windows / elapsed time / error categories / sanitation: NOT RUN
A1–A5 individually: NOT RUN (PASS / FAIL / INCONCLUSIVE / UNSUPPORTED / NOT APPLICABLE + reason)
Decision / remaining coverage / user guidance / evidence labels: NOT RUN

No experiment has been executed. Status remains PENDING USER EXECUTION.

## Local tool verification — 2026-09-30 (not spike execution)

The `identity-probe` crate test suite passed (10 tests) on the development PC. Tests covered synthetic parsers and temporary metadata fixtures; the `inspect-lab` inventory was not run, and no live registry, profile, identity store, account, or credential inventory was accessed. S5 remains PENDING USER EXECUTION.
