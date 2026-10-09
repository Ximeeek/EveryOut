# Scope evidence and decision trace

The P0 model extends the existing provider blockers. Confidence remains a discovery ranking;
it cannot authorize cleanup. Every provider instance carries one `DecisionTrace`. Plans retain
the same `ScopeEvidence`; the engine rejects a provider that substitutes stronger evidence
between discovery and planning. Review recalculates the trace before creating `ValidatedPlan`.

Five independent states describe application identity, storage ownership, authentication scope,
preservation and version applicability. Each state includes extensible source and stable reason
codes. Missing serialized evidence defaults to unknown and cannot authorize an old plan.
Discovery without a provider remains unavailable regardless of identity or confidence.

`ScopeEvidence::decide` merges existing method/plan blockers with missing evidence gates and
unknown-loss restrictions. `ProposedPlan::decision_trace` adds action and adapter confinement
checks. Confirmation IDs are reported separately: accepting a known loss satisfies a consent
requirement; it does not remove any safety blocker or change evidence. `action_allowed` means
the scope passes safety review, not that process closing or physical revalidation can be skipped.

Current-account providers and the account helper's discovery scanner both use the same provider
evidence projection. `ScanDto::push` derives the legacy `unverified` flag centrally from the trace,
including discovery-only and unavailable-scope restrictions. Native reports, development logs,
JSON/text export and the UI carry the same trace. The UI translates states and codes into readable
labels; it does not infer permission from confidence, support or a confirmation string.

## Existing rules and Spotify

Previously validated catalog rules retain a compatibility projection whose provenance explicitly
says `catalog-declaration`. Authentication evidence also requires verified artifacts. This is not
a runtime PE/version observation or a newly performed product test. The shipping catalog has no
generally validated product rule. New candidates cannot acquire this projection by increasing
confidence or accepting a `review-candidate-provider-*` confirmation.

Spotify retains its existing compiled saved-login adapter. A checked root, matching executable
SHA-256 and supported prefs format produce exact identity, exclusive bounded storage, current
hash applicability and preservation evidence for the four fixed fields. The existing restart
observation is the provenance for the validated **local saved-login scope**. It does not prove
remote revocation, compatibility with another executable, a new disposable-VM test or preserved
offline playback while signed out. See [the existing dossier](../research/05-spotify-local-logout.md).

Only this fixed adapter can execute while support remains Candidate. Review requires its explicit
confirmation and one exception-adapter action for Spotify; another provider or a delete-file
action cannot reuse the authority. Provider path/method checks and runtime hash/format/physical
revalidation remain active. An unknown executable, changed build or unavailable prefs blocks it.

Discord keeps its current `Local Storage` scope. Catalog declarations provide weak identity and
unconfirmed storage ownership, framework-hint authentication, unknown preservation and unknown
version applicability. The trace retains `unvalidated-product-version`,
`unknown-authentication-closure` and `unreviewed-preservation`, together with ownership, support
and unknown-loss blockers. No product validation, channel inheritance or wider wipe is introduced.

## Formal product validation

`ProductValidationRecord::parse` performs bounded JSON parsing with unknown-field rejection and
metadata validation. The record contains product/executable identity, optional publisher/signature,
version, channel, layout, artifact families, ownership, closure and preservation outcomes, known
losses, repetitions, date, method and status. It contains no credential/token/cookie fields.

A Validated record requires a disposable-VM method, at least two repetitions, signed-out closure,
reviewed preservation, corroborated/exclusive storage and an exact executable hash. Synthetic
safety or historical local-adapter trials cannot be relabeled as this stronger record. An example
with explicitly incomplete fixture results is provided in
[the record template](../testing/product-validation-record.example.json).

Parsing a record is not a trust decision. `bind` is intended for records admitted by the trusted
catalog/maintainer boundary and independently observed runtime metadata. It binds application,
executable/product identity, version, channel, layout and artifact families. Missing observations
produce Unknown; mismatches produce Stale and `product-version-revalidation-required`, which
blocks review. There is no unreviewed compatible-version wildcard or UI record upload endpoint.

P0 prepares this model and decision mechanism. It does not collect generic PE/Uninstall/shortcut
metadata, automatically import maintainer records, or create executable scopes from them.
Runtime collection and broader identity corroboration belong to P1. Teach Mode, filesystem
watchers, ETW and generic destructive scopes remain outside this change.
