# S2 — Closed-profile sync edits versus browser policy

Status: PENDING USER EXECUTION

## Hypothesis and decision

A fixed, idempotent edit of an exact non-secret field might disable local sync in some versions;
mixed storage, integrity checks and existing policy may make it impossible. Policy may offer a
different effective scope without signing out browser identity. These are feasibility questions,
not supported implementations. [Architecture §07](../architecture/07-sync-and-identity.md) adopts
closed-profile edits as the V1 direction, but excludes policy writes from EveryOut V1.

## Prerequisites

Disposable Windows 10/11 VM with clean snapshot, test accounts only (never real accounts),
[common lab gates](README.md#common-lab-rules-and-evidence-gates), copied snapshot tool and
dummy settings/preservation canaries. Use synthetic token-free configuration for field-edit
experiments. No whole-file parsing, reserialization, backup or content diff of mixed profile files.
A public source/schema review must identify a compliant exact edit mechanism before trying it;
unknown fields or methods are `UNSUPPORTED`, not an invitation to inspect live Preferences.
Authenticated sync-restoration arms inherit S1's lab-method blocker.

## Per-browser matrix to complete

All entries are candidates for investigation, with no validated field mappings here.

| Browser | Closed-profile question                                                                                 | Policy comparison to validate                                                                     | Preservation/identity boundary                                                              |
| ------- | ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Chrome  | Exact versioned field locations, bounded write without mixed-file reads, integrity/restart/idempotence? | Candidate SyncDisabled; validate mandatory/recommended scope and precedence for the actual build. | Root Local State versus profile prefs; Web Data shares autofill; browser identity separate. |
| Edge    | Vendor schema and policy override behavior, without importing Chrome mappings?                          | SyncDisabled with mandatory/recommended and account-type applicability controls.                  | Microsoft/Entra identity and Windows SSO can remain; roaming is separate.                   |
| Firefox | Can sync be disabled without reading signedInUser.json or rewriting a mixed prefs store?                | Verify actual vendor policy name/schema/version, or record unsupported.                           | Disconnecting Sync differs from Mozilla account sign-out; preserve key/password stores.     |
| Brave   | Can a chain be disabled without reading seed/encrypted chain state?                                     | Verify vendor-supported policy rather than assuming Chrome support.                               | Sync chain, Rewards and Wallet are separate; preserve wallet keys.                          |
| Opera   | Is a compliant offline edit defined for this profile layout/release?                                    | Establish a vendor-supported policy or report no supported policy evidence.                       | Browser account, local/server data and profile variants separate.                           |
| Vivaldi | Is a compliant offline edit available and persistent after restart?                                     | Establish supported policy/precedence or report unknown.                                          | Quitting is not sign-out; reconnect/merge and preserved data require separate evidence.     |

The [Edge SyncDisabled reference](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/SyncDisabled)
(checked 2026-09-30) distinguishes recommended/mandatory policy, cloud sync versus roaming and
excludes applicability to Microsoft-account-signed-in profiles. Test that distinction rather than
claiming a policy key's presence proves effective disable. The
[Firefox guide](https://support.mozilla.org/en-US/kb/disable-firefox-sync) (checked 2026-09-30)
distinguishes stopping sync from account sign-out. Other versioned leads are in
[browser research §3](../research/01-browsers.md); revalidate them for the chosen lab builds.

## Numbered manual procedure

1. For every matrix row, record exact build/channel/OS, publicly documented schema/source
   revision, proposed non-secret field and location, method, scope and preservation dependencies.
   If no compliant edit exists, record the reason and skip only that blocked arm.
2. Restore the clean VM baseline. Create only synthetic non-secret field fixtures and dummy
   unrelated settings; record intended values separately from the profile. Predeclare restart
   windows and comparison arms: no edit, fixed disable, already disabled, and conflicting policy.
3. Close all lab browser processes, isolate networking, capture `before.json` for every approved
   profile/root. Apply the exact reviewed disabled-state write; never toggle or use generic JSON
   replacement of a secret-bearing file. Capture `after.json` and diff before→after.
4. Repeat the same write while closed. Capture `second-edit.json` and diff after→second-edit;
   verify idempotence with the approved synthetic field oracle, including already-disabled input.
   Record crash/interruption and rejected schema/version outcomes without broadening the method.
5. Relaunch offline, observe neutral sync/settings UI, close and capture `restart.json`.
   Diff after→restart; reassertion or profile corruption fails the method. Recreated metadata
   alone cannot establish effective sync state or explain its source.
6. In a separate restored VM arm, use only vendor-supported lab administration to apply the
   documented sync policy. This is a manual comparison, never an EveryOut feature or host write.
   Test user/machine scope, mandatory/recommended, unset/enabled/disabled, account type, two
   profiles and a second dummy user where applicable. Record only the specific non-secret
   effective policy/UI state; never export whole diagnostic/policy pages.
7. Capture before/after/restart profile metadata around each policy arm; compare effective sync,
   browser identity, unrelated settings and effects on unselected profiles/users. Repeat the
   profile edit under conflicting existing policy. Do not claim a local edit overrides management.
8. Run three repeats per executable arm with no-edit controls. If a compatible authenticated lab
   method becomes available, add S1's separately gated restoration observation; otherwise record
   restoration unknown. Restore baseline, leaving no lab policy on the host.
9. Complete every row, including unsupported/blocked methods, exact policy evidence and required
   architecture follow-up notes. Do not change architecture documents in this phase.

## Acceptance criteria

- Six-browser matrix has explicit method/field/version or an evidenced unsupported/unknown result.
- Eligible edits are secret-free, closed-profile, preservation-safe, fixed-state and idempotent;
  runtime/restart observations supplement metadata with approved field/UI evidence.
- Policy applicability, precedence and profile/user/machine scope are independently established;
  missing vendor support is not assumed. Policy remains outside EveryOut V1.
- Negative, blocked or corruption outcomes retain unsupported scope; no whole-profile fallback.
- Sync configuration and identity/authentication outcomes stay separate, with all lab invariants.

## Results template

| Field                                                                       | Value   |
| --------------------------------------------------------------------------- | ------- |
| Date / reviewer / case / repeat / lab-method revision                       | NOT RUN |
| Browser build/channel / OS; source or schema revision                       | NOT RUN |
| Exact proposed field / method / scope / eligibility reason                  | UNKNOWN |
| Synthetic input / expected disable / observed approved field/UI state       | NOT RUN |
| Before / after / second-edit / restart evidence IDs                         | NOT RUN |
| Idempotence / interruption / unknown-version / preservation verdicts        | NOT RUN |
| Policy name/revision / mandatory-recommended / effective scope / precedence | UNKNOWN |
| Selected versus unselected profile/user effects                             | NOT RUN |
| Identity / sync / restoration; criteria verdicts and blockers               | UNKNOWN |
| Feasible V1 method or unsupported reason; architecture conflict note        | UNKNOWN |
