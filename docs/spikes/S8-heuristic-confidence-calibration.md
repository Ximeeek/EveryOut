# S8 — heuristic false positives and confidence calibration

Status: PENDING USER EXECUTION

Phase 13 definition for EveryOut; no measured detector accuracy exists. Blocks
`heuristic-confidence-calibration` and heuristic preselection. Follow the
[common lab rules](README.md#common-lab-rules-and-evidence-gates) and
[provisional scoring policy](../architecture/03-heuristic-detection.md).

## Question and measurement unit

Measure whether a candidate root belongs to the claimed installed application under the selected
user. This is identity/ownership classification, not authentication detection or permission to
delete session storage. A positive label requires an independently corroborated installation and
one owner of that exact root. Residue, unrelated folders and unresolved/shared ownership are
non-positive; unknown labels remain a separate excluded denominator with reasons.

The observation unit is a unique `(OS baseline, test user, exact candidate root, proposed owner)`.
Deduplicate repeated scans and overlapping representations of that unit before calculating
accuracy. Treat different fixed layouts under a package as distinct roots only when independently
labeled; never turn repeated runs into independent samples. Keep real test installations and
synthetic negative fixtures in separate strata. Freeze labels before seeing scores.

For the high gate: TP = high and correct exclusive owner; FP = high and wrong, uninstalled or
unresolved owner; FN = positive label below high or undiscovered; TN = negative label below high
or undiscovered. Report precision `TP/(TP+FP)`, recall `TP/(TP+FN)`, false-positive rate
`FP/(FP+TN)` and false-discovery proportion `FP/(TP+FP)` separately. Undefined denominators are
`INCONCLUSIVE`, never 100%. Also report medium/low/suppressed distributions, unknown labels,
unobserved roots and incomplete scans; do not discard false positives as unsupported after scoring.

## VM procedure

1. Prepare separate disposable Windows 10/11 baselines with no credentials, real user data or
   signed-in accounts. Record OS/tool/app versions, protection product, architecture, user and
   installation scope using anonymous case labels. Build/copy the
   [read-only scanner](../../spikes/heuristic-scan/README.md) before isolating networking.
2. Install at least 60 distinct apps per OS baseline across native, Electron, CEF, WebView2,
   Store/MSIX, browser and launcher classes, including per-user/machine and 32/64-bit registrations.
   Use a realistic mixed installation set; record per-class counts and absent classes. Do not log
   in merely to create session files. Session-looking layouts may be synthetic fixtures only.
   Browser/PWA identity experiments requiring secret-bearing configuration remain blocked.
3. Include labeled negative cases: stale uninstall keys, leftover data roots, display-name
   collisions, runtime-only packages, framework/resource packages, OS brokers, EveryOut data,
   shared runtime roots, non-Chromium apps with coincidental directory names, empty roots,
   inaccessible roots, junctions and same-name roots belonging to different users. Keep every
   synthetic fixture creation/removal confined to its reviewed VM location; the scanner never
   performs these changes.
4. Include known positives outside discovery coverage: portable/custom/relocated apps and
   executable-adjacent WebView2 UDFs, multiple browser profiles and persistent partitions. Label
   them from reviewed install/UI/vendor metadata; do not open Local State, cookies, databases,
   shortcuts with arbitrary arguments or secret-bearing package settings. Inventory missing roots
   separately so limited discovery cannot produce artificially perfect recall.
5. Two reviewers independently label installation existence, exact user/root owner, exclusive or
   shared scope and framework. Resolve disagreements before running the scanner; retain unknown
   cases. Keep the private label-to-opaque-ID mapping inside the VM, derived only from reviewed
   OS/UI metadata. The scanner's IDs are deterministic for an unchanged inventory, but are run-local
   and can shift after installs; never join changed scans on IDs alone.
6. Under the intended unelevated test user, run `scan-lab` once, with three unchanged repeats for
   reproducibility. Save stdout outside AppData only when the exit code is zero. Report partial
   registry coverage, unknown metadata and top-level failures separately. Restore the baseline
   before changed fixtures. Do not run a live scan of the development machine.
7. Join candidates to frozen labels, deduplicate units and compute confusion matrices per OS,
   framework, install scope and real/synthetic stratum. Audit every high FP and a random sample
   of positives and negatives. Publish only sanitized case IDs, family signals, scores, counts,
   rule/tool versions and stable error kinds; never profiles, paths, usernames or origins.
8. Use a development corpus for proposed tuning and a separate held-out installation corpus for
   acceptance. This phase implements the existing score unchanged: identity 4, runtime 2,
   storage 2, ownership 3, counted once per family; high requires score >=9 and three families
   including identity/ownership without conflict. Medium/low/suppressed gates remain unchanged.
   Any threshold/rule change needs later reviewed architecture work and fresh held-out results.

## Acceptance criteria

- High-confidence precision >=99.5% and its two-sided Wilson 95% lower bound >=99.0% on the
  held-out real-installation corpus, with at least 500 independently labeled high predictions.
  Smaller high samples are `INCONCLUSIVE`; emitting no highs cannot pass calibration. Pool OS
  samples only with separate OS/framework results and no hidden failing stratum.
- High false-positive rate <=0.5% over at least 500 independent known-negative units, reporting
  its Wilson 95% upper bound (target <=1.0%) and real/synthetic strata separately. Precision and
  FPR need different denominators; repeat scans are not extra samples.
- Zero high candidates for excluded OS brokers, EveryOut/shared runtimes, unregistered residue,
  unknown/conflicting owners or framework/resource-only packages. Any violation fails even if
  aggregate precision passes. Metadata access blocks remain explicit unknown coverage.
- Identical signals/scores for an unchanged quiescent baseline across three repeats; zero
  payload reads, mutations, elevation, networking or reparse traversal. Use synthetic locked-file
  tests and source audit in addition to VM observations; no security-product bypass.
- Report recall with denominators and blind spots. There is no evidence-based recall threshold
  yet; do not trade ownership gates for more positives. Registry key inventory intentionally does
  not read InstallLocation/Publisher/App Paths values while `metadata-discovery-allowlist` is open.
  The reduced scan may be unable to meet minimum high sample counts: record that limitation and
  keep calibration/preselection blocked instead of inventing install-root mappings.

## Results template — unexecuted

| Case / baseline / tool version | Stratum / framework | Frozen label / source | Candidate ID / layout | Families / score / confidence | Predicted vs labeled owner | TP / FP / TN / FN / unknown | Incomplete coverage / exclusion | Criterion result / reason |
| ------------------------------ | ------------------- | --------------------- | --------------------- | ----------------------------- | -------------------------- | --------------------------- | ------------------------------- | ------------------------- |
| NOT RUN                        | NOT RUN             | NOT RUN               | NOT RUN               | NOT RUN                       | NOT RUN                    | NOT RUN                     | No VM evidence                  | NOT RUN                   |

| OS / framework / real or synthetic / held-out | TP  | FP  | TN  | FN  | Unknown labels / missing observations | Precision / Wilson interval | Recall | FPR / Wilson interval | False-discovery proportion | Decision |
| --------------------------------------------- | --- | --- | --- | --- | ------------------------------------- | --------------------------- | ------ | --------------------- | -------------------------- | -------- |
| NOT RUN                                       | —   | —   | —   | —   | —                                     | —                           | —      | —                     | —                          | NOT RUN  |

Record reviewers, disagreement resolution, unique-unit counts, sampling/selection biases,
unrepresented app classes, confidence distribution and proposed follow-ups separately. Tests are
tool-boundary evidence, not a measured false-positive rate; status remains pending.
