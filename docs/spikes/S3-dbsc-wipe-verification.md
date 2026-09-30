# S3 — DBSC persistence, wipe coverage and verification

Status: PENDING USER EXECUTION

## Hypothesis and decision

Cookie-only absence may leave DBSC persistence/key references able to refresh access. Removing
a validated browser-owned session family may improve local closure, while metadata alone still
cannot prove key destruction or prevent SSO. The exact offline set is unresolved in
[browser dossier §4](../research/01-browsers.md) and
[wipe verification](../architecture/05-wipe-sequence.md). The
[DBSC draft](https://w3c.github.io/webappsec-dbsc/) (checked 2026-09-30) is a protocol reference,
not proof of a particular browser/site deployment. Do not equate DBSC keys with passkeys.

## Prerequisites and evidence gate

Disposable Windows 10/11 VM with token-free snapshot, test accounts only (never real accounts),
[common lab rules](README.md#common-lab-rules-and-evidence-gates), exact browser build/features
and virtual TPM capability. A VM without the required capability cannot validate DBSC behavior.
Record public release/source evidence for candidate session stores and companions in every
partition. No TPM-wide key deletion, private key inspection, database row queries or payload reads.

Real test-account tokens, network login probes and secret snapshots conflict with architecture
test rules. DBSC adoption/expiry/refresh observations require a reviewed compliant lab method
with a non-secret adoption oracle. Without it, metadata fixtures are permitted but authenticated
DBSC arms are `NOT RUN — METHOD BLOCKED`, and absence of adoption cannot count as a passed wipe.
No DBSC service/site/harness is implemented by this phase.

## Numbered manual procedure

1. Record OS/browser/channel/features, virtual TPM availability, draft/source revision and a
   reviewed owned artifact/companion list. Define exclusions for passkeys, password and Windows
   sign-in key material; block unknown shared/key ownership before any mutation.
2. Define independent arms: no wipe, cookie-only removal, and cookie plus the complete reviewed
   DBSC candidate family. Add a DBSC-unavailable/non-adopted control. Predeclare expiry/refresh
   windows and adoption evidence; random files named Device Bound Sessions do not establish adoption.
3. Restore the clean baseline for each allowed arm. Establish only the approved test-site/account
   method if available; record neutral adoption status without session/key/HTTP-header exports.
   Otherwise use opaque synthetic fixtures for layout tests and leave runtime arms blocked.
4. Disconnect networking, close all owned browser processes and capture `before.json` per root,
   covering candidate Network/Device Bound Sessions, legacy/partition variants and companions
   only where the versioned inventory supports them. Unknown paths remain unknown.
5. Perform only the arm's exact reviewed removal set. Preserve all unrelated and excluded stores;
   never search secret databases for key IDs. Capture `after.json` while still closed/offline and
   diff before→after. Record each candidate and companion's local absence separately.
6. Restart offline, record neutral behavior, close, capture `restart-offline.json` and compare
   to after. Empty database recreation may be initialization; do not label it authenticated refresh.
7. Only under the approved lab method, observe restart plus the predeclared cookie-expiry and
   refresh opportunity in a separate network stage. Do not manually log in, supply credentials,
   query cookies or trigger an unapproved authentication probe. Compare cookie-only, complete
   candidate and no-wipe/non-adopted controls; record unavailable refresh evidence explicitly.
8. Disconnect, close and capture `post-window.json`; diff after/restart→post-window. Separate
   metadata recreation, independently observed refresh and fresh Windows/browser SSO. Inability
   to distinguish them makes authentication interpretation inconclusive.
9. Repeat allowed arms three times, restore the token-free baseline and complete the template.
   Candidate local closure cannot be promoted beyond the exact verified version/site scope.

## Acceptance criteria

- DBSC adoption/support and TPM applicability independently evidenced or explicitly unknown.
- Owned versioned artifacts/companions and key-reference boundaries documented without reading
  secret material or deleting preserved passkey/TPM/Windows identity stores.
- Cookie-only versus full-candidate metadata effects/control results reproducible; failed/locked
  companions remain partial, not successful closure.
- Restart/expiry/refresh evidence separate from metadata; blocked runtime observations stay unknown.
- No remote revocation/key-destruction/durable logout inference, and all offline/preservation rules hold.

## Results template

| Field                                                                   | Value   |
| ----------------------------------------------------------------------- | ------- |
| Date / reviewer / case / repeat / approved method                       | NOT RUN |
| OS / browser / channel / features / virtual TPM / draft-source revision | NOT RUN |
| Test-site anonymous label; adoption oracle / expiry-refresh window      | UNKNOWN |
| Arm / target revision / partition roots / companions / exclusions       | NOT RUN |
| Before / after / restart / post-window evidence IDs / exit codes        | NOT RUN |
| Local absence / recreation / independent refresh / possible SSO         | UNKNOWN |
| No-wipe and non-adopted controls / preservation evidence                | NOT RUN |
| Criterion verdicts / failures / unavailable capability / blockers       | NOT RUN |
| Supported metadata scope / unresolved keys-authentication / warning     | UNKNOWN |
