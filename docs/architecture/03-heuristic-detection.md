# Generic heuristic detection

## Evidence and meaning

Heuristics discover possible application/profile owners, not authenticated sessions or safe
deletion targets. [Application research §§1–3](../research/03-apps-detection-process-av.md)
establishes framework layouts, metadata sources, stale-registration and shared-root ambiguity.
No measured false-positive rate is available. The score below is a provisional product policy
with a blocking calibration spike, not an empirical probability.

Use the common provider metadata interface. Do not open `Local State`, cookie stores, databases,
archives, crash reports or credential payloads. Root/key presence and size cannot prove enabled
Sync, signed-in state or process inactivity
([browser research §7](../research/01-browsers.md)).

## Allow-listed roots and bounded enumeration

Candidate discovery is restricted to the selected OS user's known Roaming/Local AppData roots,
registered application-package containers under LocalAppData/Packages, reviewed browser roots,
and exact installation roots supplied by reviewed OS identity metadata. Use one direct-child
enumeration to discover candidates in AppData, then inspect only fixed relative signal paths;
inspect package roots only for registered application packages, excluding framework/resources.
Never recursively search a drive, home directory, Downloads or arbitrary ProgramData trees.
Executable-adjacent WebView2 candidates require an independently identified installation root.

Exclude EveryOut's own data/runtime, OS broker roots and known shared runtime-only roots from
generic candidates. Reject reparse-point traversal, UNC/network locations and paths outside the
resolved allowlist. Portable/custom roots remain undiscovered until an exact reviewed root is
available; no expansion to whole-drive searching. These are design safeguards derived from the
application dossier §§1–3, not evidence of exhaustive discovery.

Install registry key presence can corroborate a known provider without reading values. Reading
InstallLocation/Publisher, shortcut arguments or browser profile mapping remains blocked by
`metadata-discovery-allowlist`. The generic heuristic must tolerate that reduced coverage.

## Independent signals and provisional score

| Evidence family   | Positive signal                                                                                                              | Maximum points |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------- | -------------- |
| Identity          | Exact registered app/package identity corroborated by an existing installation, not a display-name match                     | 4              |
| Runtime packaging | `resources/app.asar` or `resources/app`, identified host WebView2 layout, or reviewed CEF packaging; presence/type/size only | 2              |
| Storage layout    | At least three expected distinct storage artifacts, including a persistence marker such as Cookies/Network/IndexedDB         | 2              |
| Ownership         | Reviewed manifest or OS metadata maps the exact user and data root to one owner                                              | 3              |

Count each family once. Several Chromium directory names count as one storage-layout signal;
multiple registry views/shortcuts for the same install count as one identity signal. A single
process name, `Local State`, `EBWebView` or nonempty cookie file cannot identify an owner. Runtime
process presence is at most corroboration within an existing family, not an extra score.

- **High:** score at least 9, at least three independent families, including identity and
  ownership, and no unresolved owner conflict.
- **Medium:** score 5–8, at least two independent families and a plausible owner. A score of 9+
  missing a high-confidence gate remains medium only if its medium gates hold.
- **Low:** at least two independent families but score below 5, or medium numerical score without
  a plausible exclusive owner. Show as an unresolved candidate with explicit limitations.
- **Suppressed:** fewer than two independent families; do not list random folders as apps.

Conflicting owners or excluded roots override any score: the affected action is non-actionable.
Missing/denied observations are unknown, not negative evidence of a clean machine. Registration
without existing installation is marked residue and cannot pass the high gate.

Examples: one folder named `Discord` is suppressed; a storage cluster and runtime marker score 4
and are low; those plus exact registered identity score 8 and are medium; adding validated unique
root ownership yields 11 and high. These illustrate the policy, not a claim that Discord's session
layout has been validated.

## Presentation and execution eligibility

Only high-confidence heuristic detections are pre-selected. Medium/low detections appear in a
separate unchecked section with evidence and missing ownership/coverage information. Selecting
one cannot manufacture a provider cleaning rule. Even a high-confidence app identity has no
executable plan until a validated manifest or exception adapter defines safe session scope.

Curated supported detections and high-confidence heuristic detections follow the default selection
rules in [04](04-classification-rules.md). Heuristic identity confidence, catalog evidence confidence
and executable scope validation are separate fields; none implies the others.

## AV/EDR and anti-cheat constraints

[Application research §6](../research/03-apps-detection-process-av.md) describes read-oriented
detection rules and unresolved metadata/delete behavior. Avoiding content reads reduces unnecessary
sensitive access but does not guarantee freedom from alerts. Do not impersonate browser identity,
bypass protection, add hooks, inject code, inspect other-process memory or install drivers.
No security-product exclusion is requested as a detector fallback.

Dry run performs metadata observations only, without closing processes or mutating data. Discovery
is bounded and cancellable; reports retain opaque candidate IDs, evidence family results and
stable error kinds, not raw user paths or arbitrary registry/shortcut values. Access blocks become
visible incomplete coverage. Code signing/transparency are useful product measures but are not
proof of AV exemption. Process-closing policy belongs to Phase 9.

## OPEN DECISIONS

- `heuristic-confidence-calibration`: establish precision/recall and false-positive rates for
  labeled real apps, browsers, portable installations, leftover roots, shared runtimes and test
  fixtures before treating these thresholds as validated.
- `metadata-discovery-allowlist`: resolve installation/configuration metadata exceptions without
  reading mixed secret stores; until then accept lower discovery coverage.
- `metadata-av-compatibility`: verify actual metadata/delete access behavior across security
  products; until then report blocks and make no immunity claim.

See the [central register](00-overview.md#open-decisions) for evidence and interim rules. These name
future spikes; this phase does not define a test strategy or perform security-product experiments.
