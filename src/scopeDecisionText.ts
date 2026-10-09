const reasons: Record<string, string> = {
  "application-identity-unconfirmed":
    "The application identity has not been confirmed.",
  "storage-ownership-unconfirmed":
    "The owner of this storage has not been confirmed.",
  "storage-ownership-conflict":
    "This storage is shared or has conflicting owners.",
  "physical-store-ownership-or-ancestor-overlap-conflict":
    "The selected storage overlaps another application's scope.",
  "unknown-authentication-closure": "The login scope has not been validated.",
  "unreviewed-preservation": "Preservation effects have not been reviewed.",
  "preservation-loss-assessment-mismatch":
    "The reviewed data loss does not match the plan's risk assessment.",
  "known-loss-risk-disclosure-missing":
    "Known data loss needs an explicit risk disclosure.",
  "unvalidated-product-version":
    "The current product version has not been validated.",
  "product-version-revalidation-required":
    "The application changed and needs revalidation.",
  "unknown-permanent-loss":
    "Possible permanent data loss has not been assessed.",
  "automatic-cleanup-unverified":
    "No reviewed automatic operation is available for this scope.",
  "spotify-build-not-reviewed":
    "This Spotify executable does not match the reviewed desktop build.",
  "spotify-login-format-not-reviewed":
    "Spotify's saved login file is unavailable or uses an unreviewed format.",
  "process-preview-unavailable":
    "Running programs could not be safely identified.",
  "process-prerequisite-failed":
    "The required programs could not be safely closed.",
  "protected-credential-data": "The scope includes protected credential data.",
  "discovery-only-no-provider":
    "This is a storage candidate without a reviewed operation.",
  "no-reviewed-actions": "No reviewed operation is available.",
  "evidence-provenance-missing": "The supporting evidence is missing.",
  "scope-not-selectable": "This scope is not available for an operation.",
  "incomplete-metadata-scope": "Storage inspection is incomplete.",
};
export function decisionReason(code: string) {
  return reasons[code] ?? "An additional safety check has not passed.";
}
