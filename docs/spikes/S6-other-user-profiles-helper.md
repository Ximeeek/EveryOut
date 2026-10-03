# S6 — Other-user profile scope and elevated helper feasibility

Status: PENDING USER EXECUTION

Policy update: [Phase 28](../architecture/23-all-accounts-mode.md) supersedes the original
loaded-profile exclusion with reviewed per-account helper compartments. The procedure below
records the historical hypothesis; its exclusion/rejection expectations must be evaluated against
the Phase 28 VM checklist when testing the new policy. No results have been supplied or inferred.

## Hypothesis and boundaries

Elevation may permit metadata access to another profile but does not authorize its credentials,
active-session process closure or hive mutation. ProfileList is a candidate inventory, not a
supported eligibility API. Compare it with Win32_UserProfile loaded/special metadata and session
observations before deriving scope. HKU presence is a point-in-time observation, not a lock.
See [Windows research §5](../research/02-windows-identity-and-multi-account.md),
[permissions](../architecture/06-permission-model.md) and
[test strategy](../architecture/11-test-strategy.md).

This spike informs `other-account-scope-validation` and `elevated-helper-ipc-validation`.
V1 skips loaded other-user profiles and never closes another user's session processes.
Cross-session closure below is an isolated dummy-process feasibility experiment, not a change
to that policy. No production helper, engine or session-closing implementation is added here.

## Lab prerequisites and gates

Disposable Windows 10/11 VM with two local test users A/B, synthetic payload-free app fixtures and
clean token-free snapshots. Test ordinary A, B signed out, B locked/disconnected but logged on,
and A/B simultaneously logged on (fast user switching; RDP only where supported).
Use [common lab rules](README.md#common-lab-rules-and-evidence-gates), no host profiles/shares.
A separate local test administrator may supply over-the-shoulder UAC consent; it must not become
A's scope. Record unsupported session configurations with reasons.

Identity-probe only reads metadata; it cannot mount hives, elevate, establish IPC or close apps.
Use a separately reviewed lab harness for hive/helper/dummy-process experiments. If none exists,
record `NOT RUN — HARNESS BLOCKED`, retain this status and do not claim validation from the CLI.
Only synthetic local test hives are eligible: no real account data, secrets or authenticated
profile snapshots. Loading/unloading a hive is not strictly read-only and is never done on the host.

## Numbered VM procedure

1. Set case labels, OS/build/architecture, helper/harness revision, exact A/B owner mappings,
   fixture roots and expected exclusions. Repeat each executable arm three times from baseline.
2. With B signed out, inventory ProfileList under A and repeat under the test administrator.
   Compare SID/root associations against Win32_UserProfile SID/local path/Loaded/Special and
   session state. Check missing paths, stale/.bak records, system/special profiles and inaccessible
   roots. Do not label every registry entry an eligible local user.
3. Read metadata for B's selected synthetic folder before/after elevation. Open only dummy fixture
   contents if a reviewed lab test specifically requires it; never open identity/session stores.
   Test denied access, junctions/reparse roots and redirected/UNC paths. Refuse redirection or
   ambiguous ownership; do not take ownership, change ACLs or enable backup bypass for folders.
4. For a verified signed-out synthetic B profile, prepare a unique temporary HKU key associated
   with this run. Confirm both HKU\\B-SID and the temporary key are absent immediately before
   mounting. Verify the exact owner-bound local NTUSER.DAT and session state again; stop on races.
5. Through the reviewed harness call RegLoadKeyW under that temporary key. Microsoft documents
   both SeRestorePrivilege and SeBackupPrivilege requirements; enable them only around this
   isolated mount/unmount test, restoring the prior token state afterwards. Read only a declared
   synthetic canary value, never secret-bearing real hive contents. No registry edits are needed.
6. Release every opened subkey/handle before RegUnLoadKeyW. Unload only a mount that this run
   successfully created. Verify temporary-key absence on success, cancellation, failed reads and
   caught errors. Test duplicate-key refusal, insufficient privilege, held-handle unload failure,
   IPC loss and helper exit. Report unload failure as incomplete cleanup and retain ownership
   metadata for controlled VM recovery; never unload a user's live SID hive. A forced process crash
   cannot guarantee finally/Drop cleanup: document this limitation and any required recovery.
7. Repeat inventory with B active, locked, disconnected and both users logged on. Confirm loaded
   B is skipped in the proposed V1 flow. Test B signing in/out between discovery and action;
   invalidated plans must abort/skip. HKU polling alone cannot prove safe exclusive mounting.
8. In an isolated arm, B explicitly starts a disposable lab dummy app with no unsaved data.
   Bind its PID, creation time, executable identity, owner SID and session ID in the harness.
   From elevated A, observe graceful-close feasibility and any desktop/session restrictions;
   record access denied, relaunch, PID reuse and unresponsive cases. If separately reviewed,
   compare force termination only for this dummy app and record its loss consequences. Never use
   foreign memory reads/hooks/injection or close Office/browser/system/security processes.
   Feasibility does not authorize V1 cross-session closing; confirm V1 request rejection.
9. Exercise the proposed normal asInvoker + runas helper flow using the reviewed harness: current
   mode does not request UAC; all-accounts mode requests one short-lived helper only on demand.
   Validate launcher SID/logon identity, helper binary trust, explicit named-pipe DACL, endpoint
   authentication, one-time nonce and run/plan binding. Reject arbitrary paths/commands, replay,
   other-session clients, mismatched identities and IPC loss before any privileged action.
10. Decline UAC and separately test launch failure. Verify elevated work never runs, expanded
    inventory/confirmations are discarded, effective and saved mode return to current account,
    current scope is rescanned/reviewed and no prompt loop or automatic mutation occurs.
    With a different administrator consenting, verify roots/HKCU still bind to A/B rather than
    that administrator. Helper exits after completion, cancellation or failure; later runs request
    fresh on-demand consent and never reuse ambient elevated authority.
11. Compare the alternatives below on documented lifetime, installation/cleanup and scope
    properties. Do not install services/tasks/COM registrations just to fill the comparison.
    Runtime claims require a separately approved harness and otherwise remain untested.
12. Restore baseline, check mount/process cleanup and complete every result row with evidence or
    blocker. No S7 shutdown coordinator implementation or active-account support is introduced.

## Design comparison

| Design                        | Reason for comparison                                                          | Required outcome                                                                                                  |
| ----------------------------- | ------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Normal app + on-demand helper | Adopted design: asInvoker UI, runas for one authorized run, bounded typed IPC. | Scope/identity/UAC fallback/lifecycle demonstrated or blocked; IPC validation remains open until evidence exists. |
| Windows service               | Persistent privilege, installation and longer IPC/lifecycle exposure.          | Document trade-offs; not adopted for one-shot V1.                                                                 |
| Scheduled task                | Persistent registration, run-level and interactive identity complexity.        | Document cleanup/scope trade-offs; no UAC bypass or fallback installation.                                        |
| COM elevation moniker         | Narrow interface possible, but HKLM registration and deployment constraints.   | Document installation/trust costs; not silently substituted.                                                      |

Design direction follows the research; the comparison supplies evidence rather than selecting a
new architecture. UAC grants system authority, not per-user consent or wipe approval.

## Acceptance criteria

- A1: ProfileList candidates are compared to OS/session metadata; special/stale/loaded/denied/
  redirected entries are excluded or uncovered, never silently treated as eligible.
- A2: admin consent never changes selected owner roots to helper HKCU/environment; no ACL changes,
  secret-store access, ownership takeover or credential API borrowed for another user.
- A3: synthetic unloaded-hive mount ownership is tracked; handles close before unload; success,
  cancellation and errors verify cleanup. Unload/crash/race gaps are explicitly reported and block
  production support; already-loaded hives are never independently mounted/unloaded.
- A4: simultaneous/locked/disconnected sessions remain loaded exclusions. Dummy cross-session
  experiments record actual close behavior while V1 rejects such requests.
- A5: helper authentication, typed scope, replay/mismatch rejection and bounded lifetime pass or
  remain explicitly blocked. UAC decline/launch failure produce visible current-mode fallback,
  fresh review, no mutation and no repeated prompt.
- A6: all four research alternatives are compared, with observed versus documentary conclusions
  separated; no unsupported privileged operation is promoted to product support.

## Results template — unexecuted

Case / repetition / OS-build / session configuration / harness revision: NOT RUN
A/B neutral labels / admin-consent identity relation / candidate mappings: NOT RUN
ProfileList vs Win32_UserProfile vs session/HKU observations: NOT RUN
Folder access ordinary/elevated / owner validation / exclusions / race cases: NOT RUN
Synthetic hive mount / privileges / temporary-key ownership / handle release: NOT RUN
Unload normal/cancel/error/held-handle/crash / recovery requirement: NOT RUN
Dummy PID-owner-session-binding / graceful/forced outcome / V1 rejection: NOT RUN
IPC DACL/endpoint/trust/nonce/plan checks / mismatch/replay/IPC-loss cases: NOT RUN
UAC declined/launch failure / saved-effective mode / rescan-review / helper exit: NOT RUN
Alternative comparison / observed evidence versus documentary inference: NOT RUN
A1–A6 individually: NOT RUN (PASS / FAIL / INCONCLUSIVE / UNSUPPORTED / NOT APPLICABLE + reason)
Sanitized evidence labels / remaining blockers / architecture implications: NOT RUN

No VM experiment has been executed. Status remains PENDING USER EXECUTION.

## API references checked on 2026-09-30

[RegLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkeyw)
and [RegUnLoadKeyW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regunloadkeyw)
provide the mount/unmount contracts; they do not resolve EveryOut's ownership or session races.

## Local tool verification — 2026-09-30 (not spike execution)

The `identity-probe` crate test suite passed (10 tests) on the development PC using synthetic parser and metadata fixtures. No live ProfileList/HKU inventory, other-user access, hive mount, elevation, helper IPC, or cross-session process trial was run. The reviewed lab harness remains unavailable; those arms remain blocked and S6 remains PENDING USER EXECUTION.
