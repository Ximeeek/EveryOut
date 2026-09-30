# S1 — Chrome wipe with synchronization and Windows SSO

Status: PENDING USER EXECUTION

## Hypothesis and decision

Deleting a validated local session scope may leave Chrome identity/sync or Windows SSO capable of
recreating access or data. Website state, Chrome account identity, sync and Windows-provided
identity are independent. This hypothesis is untested. Decide what local closure and restoration
warnings a versioned Chrome provider can support, not whether remote credentials are revoked.
Basis: [browser dossier §§1, 3, 7](../research/01-browsers.md),
[Windows SSO dossier §2](../research/02-windows-identity-and-multi-account.md) and
[architecture sync direction](../architecture/07-sync-and-identity.md).

## Prerequisites and blockers

Follow [common lab rules](README.md#common-lab-rules-and-evidence-gates): disposable Windows 10/11
VM with a clean token-free snapshot, test accounts only (never real accounts), no host access,
tool/evidence outside profile roots, exact Chrome build/channel and policy/SSO configuration.
Include user-data root and selected profile/partition roots. Record a preservation-safe candidate
target list and dummy settings/bookmark/extension canaries; do not install wallet/vault extensions.
No deletion until target ownership and preservation are reviewed.

Architecture forbids real test-account tokens and network authentication probes. Sync-enabled/
Windows SSO authentication arms therefore require a reviewed compatible lab method first;
otherwise mark them `NOT RUN — METHOD BLOCKED`. Do not weaken the architecture or infer an
authenticated state from synthetic files. A clean VM snapshot is a rollback prerequisite,
not permission to archive authenticated profiles. Chrome Google identity and Windows Entra SSO
must have separate anonymous test labels; one does not establish the other.

## Numbered manual procedure

1. Record OS build/edition/region/update level, Chrome build/channel, lab-method revision,
   owner/root labels, exact target list/companions, exclusions and observation windows. Verify
   isolation, baseline cleanliness and all gates; stop blocked arms before account setup.
2. Plan four independent arms: sync off/SSO off, sync on/SSO off, sync off/SSO on,
   sync on/SSO on. Add a no-wipe control for each relevant setup. Record unsupported SSO
   configuration explicitly; absence of a test tenant is not a negative result.
3. For each allowed arm, restore the token-free VM baseline. Establish only its approved lab
   setup; use public browser UI and dummy data to record configuration/identity separately.
   Do not export browser diagnostics, copy account files or inspect cookies/tokens.
4. Disable VM networking, close the lab browser gracefully, confirm all owned processes exited,
   and capture `before.json` per root using the tool workflow. Abort on capture errors or locks.
5. Apply only the reviewed local candidate deletion set (and separately validated S2 sync edit,
   if that is the arm's declared method). The scaffold has no wipe command: record the exact
   manual action revision. Never delete all Web Data or mixed configuration/profile files.
6. While still closed/offline, capture `after.json` and diff before→after. Classify each planned
   target/companion as absent/present/inaccessible/unknown. Record untouched/preserved families
   separately; metadata absence is the only conclusion of this stage.
7. Restart offline without signing in or interacting with an account prompt. Observe neutral
   identity/sync UI states; close gracefully, capture `restart-offline.json`, and diff after→restart.
   Record browser initialization separately from possible restoration.
8. Only if the approved lab method permits it, reconnect for the predeclared window and observe
   automatic UI behavior without entering credentials or approving new sign-in/SSO consent.
   Record prompt/no-prompt, browser identity, dummy sync canaries and website-access outcome as
   separate observations. No site navigation/authentication probe is authorized by this document.
   If this cannot be observed compliantly, that outcome stays unknown.
9. Disconnect, close, capture `restart-reconnected.json` and compare to after/offline restart.
   Do not attribute recreated stores to sync/SSO without independent control evidence.
10. Repeat each allowed arm three times and compare no-wipe controls. Restore the token-free
    baseline and fill the sanitized results template, including all blocked/failed attempts.

## Acceptance criteria

- Exact Windows/Chrome/configuration matrix, target revision and three repeats/control evidence.
- Local deletion and companion coverage evidenced by metadata, with capture failures preserved.
- Browser identity, sync disable, data recreation and Windows SSO outcomes recorded independently;
  login prompts/consent never counted as silent login, and silent login never inferred from files.
- No secret reads/copies, forbidden mixed-store deletion, network wipe or host effects; preservation
  independently supported or explicitly inconclusive.
- A scoped conclusion with limitations; blocked authentication evidence prevents a logout claim.
  An observed silent return is a valid finding requiring a warning, not a failed experiment.

## Results template

| Field                                                                        | Value   |
| ---------------------------------------------------------------------------- | ------- |
| Execution date / reviewer / lab-method revision                              | NOT RUN |
| OS build / region / updates; Chrome build / channel                          | NOT RUN |
| Case / repeat; anonymous roots; sync / SSO / policy setup                    | NOT RUN |
| Target revision / companions / exclusions / action                           | NOT RUN |
| Before / after / restart metadata evidence IDs and exit codes                | NOT RUN |
| No-wipe control; elapsed offline / reconnect windows                         | NOT RUN |
| Planned target absence; recreation and its supported cause                   | NOT RUN |
| Chrome identity / sync UI / dummy restoration / Windows SSO / website access | UNKNOWN |
| Preservation evidence; failures / blockers / criteria verdicts               | NOT RUN |
| Supported local scope / warning / unresolved decisions                       | UNKNOWN |

Do not attach profiles, account labels or secret payloads. Status remains pending until actual
results and a review are provided.
