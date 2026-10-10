import type { DecisionTrace } from "./api";
import { decisionReason } from "./scopeDecisionText";

const identity = {
  exact: "Recognized",
  corroborated: "Recognized",
  weak: "Needs confirmation",
  unknown: "Unknown",
};
const ownership = {
  exclusive: "Confirmed",
  corroborated: "Corroborated",
  "shared-conflict": "Shared or conflicting",
  unknown: "Unconfirmed",
};
const login = {
  validated: "Verified for the reviewed scope",
  "locally-validated": "Causally verified for this installation",
  observed: "Observed; needs validation",
  "framework-hint": "Possible login storage; not validated",
  unknown: "Unknown",
};
const preservation = {
  validated: "Reviewed",
  "known-losses": "Known effects require review",
  "bounded-known-losses":
    "Entire bounded families will be removed; content semantics unknown",
  "no-abnormal-collateral-mutation-observed":
    "No abnormal changes observed outside scope; bounded losses still apply",
  unknown: "Unknown or mixed data",
};
const version = {
  current: "Matches the reviewed rule",
  stale: "Needs revalidation",
  unknown: "Not validated",
};
export default function ScopeDecision({
  decision,
  compact = false,
}: {
  decision: DecisionTrace;
  compact?: boolean;
}) {
  const content = (
    <div className="scope-decision">
      <dl>
        <dt>Recognized application</dt>
        <dd>{identity[decision.evidence.application_identity.state]}</dd>
        <dt>Storage ownership</dt>
        <dd>{ownership[decision.evidence.storage_ownership.state]}</dd>
        <dt>Login scope</dt>
        <dd>{login[decision.evidence.authentication_scope.state]}</dd>
        <dt>Preservation</dt>
        <dd>{preservation[decision.evidence.preservation.state]}</dd>
        <dt>Version</dt>
        <dd>{version[decision.evidence.version_applicability.state]}</dd>
      </dl>
      {decision.action_allowed ? (
        <p>
          The reviewed operation can proceed after the required confirmations
          and safety checks.
        </p>
      ) : (
        <>
          <p>Why can't EveryOut log this app out?</p>
          <ul>
            {[...new Set(decision.blocked_by.map(decisionReason))].map(
              (reason) => (
                <li key={reason}>{reason}</li>
              ),
            )}
          </ul>
          <p className="muted">
            Accepting data loss does not remove these safety blockers.
          </p>
        </>
      )}
      <details>
        <summary>Technical evidence</summary>
        <pre>{JSON.stringify(decision, null, 2)}</pre>
      </details>
    </div>
  );
  return compact ? (
    <details>
      <summary>
        {decision.action_allowed
          ? "Reviewed logout scope"
          : "Why logout is blocked"}
      </summary>
      {content}
    </details>
  ) : (
    content
  );
}
