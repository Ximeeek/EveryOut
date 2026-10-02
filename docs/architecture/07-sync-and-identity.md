# Browser synchronization and identity

Phase 9 target direction for EveryOut. Evidence:
[browser research §§1, 3–7](../research/01-browsers.md),
[Windows research §§1–2](../research/02-windows-identity-and-multi-account.md),
[preservation and method rules](02-manifest-spec.md) and
[metadata-read boundary](00-overview.md#design-principle-1-delete-and-invalidate-without-reading-secrets).

## Four distinct states

Keep website session persistence, browser account identity, sync configuration and Windows-supplied
SSO separate. Cookies gone does not mean browser identity gone. Firefox Sync disconnected does
not mean Mozilla account signed out; Brave Sync is a chain rather than a browser login account.
Closing Vivaldi does not sign out of Sync. Windows PRT/broker SSO can recreate access independently
of browser files. These distinctions follow browser §3 and Windows §2.

Metadata-only discovery shows identity/sync artifacts as present, absent or unknown, never
“signed in” or “sync active” from a directory size. Preference flags may provide cached configuration
signals only after `metadata-discovery-allowlist` approval; they do not prove runtime token health.
Do not read `signedInUser.json`, OAuth/DBSC rows, extension payloads or Brave's encrypted Sync seed.
Even reading encrypted material violates the no-secret-read boundary (browser §7).

Show a sync restoration warning during selection and dry run whenever sync is indicated or
unknown: **Sync or automatic sign-in can recreate data or access after this wipe. Local deletion
does not remove server data or guarantee a lasting sign-out.** Keep this warning in the final
browser report when coverage is incomplete. Existence of a policy name is not effective-policy
evidence, and missing familiar files is not proof that sync is disabled.

## Adopted V1 default: closed-profile edits inside EveryOut

The adopted direction is an in-app action that disables local browser synchronization by editing
validated non-secret configuration fields **while the browser is closed**, alongside supported
local identity-artifact removal. Preview these effects in the plan; they execute in the identity/
sync stage of [05](05-wipe-sequence.md) while the browser remains closed. Do not launch browser
sign-out UI or a network-dependent vendor logout command during the offline wipe.

This is a product/architecture choice, not a finding that generic offline file edits are supported
by every vendor. Browser §§3, 7 leave exact schemas and restart semantics unresolved. Before an
adapter may run, `browser-sync-profile-edit` must establish versioned field mappings, idempotent
disabled-state writes, integrity requirements and a way to preserve unrelated settings **without
reading or copying secret-bearing portions of a mixed file**. Ordinary parse-and-reserialize of
the entire Preferences/Local State file is not automatically permitted. No temporary copy or
backup of secret-bearing configuration is allowed. If a compliant edit is impossible, that
browser's in-app action remains unsupported; do not delete the whole configuration as a substitute.

Sync disable and browser identity removal have distinct outcomes. Fixed disabled-state writes
must be no-ops when already disabled, never toggles. Identity stores require the same validated
scope and absence observations as other artifact families. Unsupported identity removal leaves
identity coverage unknown even if a sync edit succeeds. Do not promise “signed out of the browser”
from a cached flag alone. Recheck process exit, ownership and version before both operations.

| Browser | Research constraint that the adapter must resolve                                                                                              |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Chrome  | Cached consent/setup fields are not live health; token state in `Web Data` shares storage with autofill; whole-file deletion is blocked        |
| Edge    | Vendor identity/token inventory is unresolved; Windows SSO and managed policy may reassert identity independently                              |
| Firefox | Sync disable and account sign-out differ; `signedInUser.json` must not be read; account key material may conflict with preserved password keys |
| Brave   | Chain state is distinct from browser account identity; never read Sync seed or delete wallet/Rewards state as a shortcut                       |
| Opera   | Local and server data remain after documented sign-out; offline field schema and profile layouts need vendor/version validation                |
| Vivaldi | Reconnection can merge server/local data; quitting is not Sync logout and remote-data reset is outside V1                                      |

These are research constraints, not supported-browser declarations. Browser §1's mixed `Web Data`
and §5's Firefox key-store conflicts are hard blockers under [02](02-manifest-spec.md).
Extra confirmation does not permit loss of saved passwords, autofill, history or passkeys.

## Policy alternative, outside V1

Browser policy can disable sync, but does not necessarily sign out browser identity. A machine-wide
policy affects other users/profiles and can make the browser show as managed; it has a broader
effect than a selected profile edit. Existing enterprise policy may also constrain available
actions. Applicability, precedence and vendor differences require validation (browser §§3, 7).
EveryOut V1 does not install, overwrite or remove browser policies, even in all-accounts mode.
Do not request current-account UAC to enable this alternative. Record policy uncertainty instead
of claiming that a local edit overrides organization policy.

## Restoration and verification limits

Sync may restore settings, extension installations/state or other synchronized data; SSO can
create fresh access without restoring the original cookie bytes. Research does not establish
universal cookie restoration or universal absence of cookie sync. Offline deletion is not a
server tombstone and does not erase data on other devices (browser §3).

During the wipe, verify only approved local artifact metadata and approved non-secret edited
fields. Report sync configuration as unknown where it cannot be safely checked. Do not restart
the browser, contact a website, decrypt tokens or probe authentication to upgrade the outcome.
Release-specific restart evidence is future spike work. User reconnection or later policy/SSO
effects can recreate access after a locally successful run.

## OPEN DECISIONS

- `browser-sync-profile-edit`: establish per-vendor/version secret-free field editing, integrity,
  idempotence, approved field verification and restart behavior; no edits until validated.
- `browser-sync-policy-interaction`: establish how existing managed policy constrains proposed
  profile edits and how to disclose it through approved metadata; unknown precedence blocks any
  claim of effective sync disable. This does not authorize V1 policy writes.
- Existing `metadata-discovery-allowlist` and `browser-artifact-closure` in
  [00](00-overview.md#open-decisions): approve exact readable fields and local identity/DBSC closure.
  Until resolved, report unknown coverage and block unsupported operations.

## Phase 22 implementation boundary

Phase 22 implements metadata signals and restoration warnings only; see
[the implemented scope and revised acceptance criteria](20-browser-identity-metadata.md).
Identity removal and sync profile edits remain unsupported. The adopted V1 direction above
is unchanged, but implementation awaits the open decisions and reviewed S1–S4 evidence.
