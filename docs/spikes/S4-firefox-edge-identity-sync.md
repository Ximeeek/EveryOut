# S4 — Firefox and Edge identity/sync equivalents

Status: PENDING USER EXECUTION

## Hypothesis and decision

Firefox Sync disconnect can leave Mozilla identity, session restore can recreate cookies, and
Edge identity/Windows SSO may persist independently of local website storage. Chrome methods
cannot be inherited without vendor evidence. These are version-specific hypotheses informed by
[browser dossier §§3, 5](../research/01-browsers.md),
[Windows SSO dossier §2](../research/02-windows-identity-and-multi-account.md) and
[architecture §07](../architecture/07-sync-and-identity.md).

## Prerequisites and blockers

Disposable Windows 10/11 VM with clean token-free snapshot, test accounts only (never real
accounts), copied tool, [common lab rules](README.md#common-lab-rules-and-evidence-gates) and
vendor-specific reviewed target/exclusion lists. Record Firefox roaming/local profile roots and
Edge user-data/profile roots without parsing account files or profiles.ini. Use explicit lab paths
from controlled setup; relocated discovery remains an open decision.
Preserve Firefox password/key/passkey/history stores and Edge mixed Web Data/autofill stores.
Never read signedInUser.json, browser token caches, PRT/WAM state or mixed Preferences.

Account/SSO/reconnect experiments inherit S1's conflict with the architecture's ban on real
test-account tokens/network probes. They require a compatible reviewed method; otherwise record
`NOT RUN — METHOD BLOCKED` and unknown authentication. Do not snapshot authenticated profiles.

## Vendor matrix

| Vendor  | Required arms and controls                                                                                                                                    | Distinct observations                                                                                                    |
| ------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Firefox | Sync on/off, separate Mozilla sign-out control if compliant, Windows SSO on/off where supported; session-restore on/off, containers, roaming and local roots. | Sync disconnected versus Mozilla identity; restored cookies/session backups; container-scoped coverage versus fresh SSO. |
| Edge    | Sync on/off, SSO on/off, unmanaged versus existing managed policy, lab Microsoft-account versus Entra profiles where eligible.                                | Browser identity, cloud sync, roaming, automatic Windows sign-in/consent and website access; account-type policy limits. |

Use [S1](S1-chrome-sync-sso.md) for control logic and
[S2](S2-sync-edits-vs-policy.md) for eligible field edits/policy comparisons. A browser UI
sign-out is only a separately gated lab control, not the offline EveryOut implementation.
Firefox's [disconnect guide](https://support.mozilla.org/en-US/kb/disable-firefox-sync) and Edge's
[SyncDisabled applicability](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/SyncDisabled)
were checked on 2026-09-30; they do not establish secret-free file-edit support.

## Numbered manual procedure

1. Record OS build/region/updates, exact vendor build/channel, root labels and method revisions.
   Enumerate matrix arms, no-wipe controls, windows and eligibility; block unsupported account/
   SSO/field-edit surfaces rather than silently reducing coverage.
2. Restore the clean VM baseline per arm. Establish only the approved lab setup and dummy
   preservation/sync canaries. Record browser identity, sync and Windows SSO configuration
   independently via neutral UI; do not collect account names or diagnostics.
3. Disconnect networking and close every owned browser process gracefully. Capture `before.json`
   per approved root using the tool workflow; capture both Firefox roaming and local trees and
   Edge root-level state. Capture/lock errors invalidate the arm.
4. Apply only reviewed vendor-specific local artifact removal and an independently eligible S2
   sync edit. Firefox cookie companions, sessionstore backups, containers/partitions and separate
   account artifacts require explicit coverage; Edge vendor identity stores remain unknown where
   no compliant inventory exists. Do not delete whole profiles or password/key/mixed stores.
5. Capture `after.json` while closed/offline and diff before→after per root. Record target/companion
   absence, preserved families and unsupported identity scope separately.
6. Restart offline without accepting sign-in prompts. Observe Firefox Sync/Mozilla account state
   and session restore; observe Edge browser identity/sync/Windows sign-in prompts. Close,
   capture `restart-offline.json` and diff after→restart; metadata is not a live-login oracle.
7. If a compatible lab method permits it, observe automatic behavior for the declared reconnect
   window without supplying credentials or approving fresh consent. Separate dummy sync data
   return, vendor identity, website access and Windows SSO. Otherwise keep those observations
   unknown; no network login probe is authorized here.
8. Disconnect, close, capture `restart-reconnected.json` and compare to after/offline restart.
   Compare no-wipe, SSO-off and Sync-off controls; do not attribute recreation without supporting
   evidence. Repeat each executable arm three times from the baseline.
9. In a separately restored policy arm, follow S2's manual lab policy comparisons, including
   unselected profile/user effects and Edge account applicability. Policy writes remain outside V1.
10. Restore baseline and complete both vendor result rows with failures/blockers. Record any
    contradiction as a spike note; do not change the adopted architecture in this phase.

## Acceptance criteria

- Both vendors have explicit build/root/configuration matrices, repeat/control evidence or named blockers.
- Firefox roaming/local/container/restore and identity-key conflicts, and Edge vendor/root/policy/SSO
  uncertainty are explicitly covered; no generic Chromium rule or cookie-only logout assumption.
- Sync disable, vendor sign-out, website access and Windows SSO are distinct findings; prompts or
  consent are not silent re-login. Effective policy is not inferred from key existence.
- Supported local effects and preservation have independent evidence; mixed/unknown ownership stays blocked.
- Authenticated/reconnect claims remain unknown until compliant execution evidence exists, with no
  remote revocation or durable global logout claim.

## Results template (one row set per vendor/case/repeat)

| Field                                                                   | Value   |
| ----------------------------------------------------------------------- | ------- |
| Date / reviewer / approved method / case / repeat                       | NOT RUN |
| Vendor build/channel / OS / region-updates / anonymous root labels      | NOT RUN |
| Account type / sync / SSO / policy / restore-container configuration    | NOT RUN |
| Exact target-companion revision / exclusions / S2 edit eligibility      | NOT RUN |
| Before / after / restart / reconnect evidence IDs and exit codes        | NOT RUN |
| Local effects / preservation / no-wipe and sync-SSO-off controls        | NOT RUN |
| Vendor identity / sync state / website access / Windows SSO and prompts | UNKNOWN |
| Recreated metadata / restoration cause and independent support          | UNKNOWN |
| Per-criterion verdict / failures / blockers / architecture notes        | NOT RUN |
| Supported scope / warning text / outstanding vendor decisions           | UNKNOWN |
