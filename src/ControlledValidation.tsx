import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { validation } from "./api";
import type {
  AppOutcome,
  LearnedObservation,
  LocalValidatedRule,
  ValidationReply,
  ValidationRequest,
  ValidationStatus,
  ValidationView,
} from "./api";

const instructions = {
  "ready-control":
    "Close the app while signed in. Begin a new control trial, then launch it normally.",
  control:
    "A1 · Launch the app with its original data. Confirm the state you see. Signed in is required.",
  intervention:
    "B · Launch the app with the displayed families temporarily moved aside. Do not use the app’s Sign out command. Confirm its state.",
  reversal:
    "A2 · Original data has been restored. Launch the app and confirm its state again. Signed in is required.",
  "awaiting-acceptance":
    "Two fresh, complete final trials succeeded. Review the bounded losses before saving this installation’s local rule.",
  complete:
    "Local validation is complete. This rule applies only to this installation and is checked again before each logout.",
  failed:
    "Validation did not establish a repeatable logout. No new rule is available from this attempt.",
  stale:
    "The app or storage layout changed. Repeat learning and validation for the current installation.",
  "recovery-blocked":
    "Restoration needs attention. Close the app and its helpers, then retry recovery. All cleanup is blocked until recovery succeeds.",
};
const empty: ValidationStatus = {
  recovery_required: false,
  pending_sessions: [],
  diagnostics: [],
  rules: [],
  active: null,
};

export default function ControlledValidation({
  disabled,
  observations,
}: {
  disabled: boolean;
  observations: LearnedObservation[];
}) {
  const [status, setStatus] = useState<ValidationStatus>(empty);
  const [view, setView] = useState<ValidationView | null>(null);
  const [observation, setObservation] = useState("");
  const [sessionPolicy, setSessionPolicy] = useState(false);
  const [losses, setLosses] = useState(false);
  const [applyRule, setApplyRule] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const available = isTauri();
  function accept(reply: ValidationReply) {
    if (reply.kind === "view") setView(reply.data);
    else if (reply.kind === "status") {
      setStatus(reply.data);
      setView(reply.data.active);
    } else {
      setApplyRule("");
      setLosses(false);
      setMessage(
        `Local logout completed · ${reply.data.objects} objects removed.`,
      );
    }
  }
  async function command(request: ValidationRequest) {
    setPending(true);
    setMessage("");
    try {
      accept(await validation(request));
    } catch {
      setMessage(
        "Could not complete this operation. Close the app and check recovery or current applicability. Confirmation cannot override a safety blocker.",
      );
    } finally {
      setPending(false);
    }
  }
  useEffect(() => {
    if (!available) return;
    let cancelled = false;
    void validation({ operation: "status" })
      .then((reply) => {
        if (!cancelled) accept(reply);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [available]);
  const id = view?.id;
  const stage = view?.stage;
  useEffect(() => {
    if (
      !available ||
      !id ||
      !stage ||
      !["control", "intervention", "reversal"].includes(stage)
    )
      return;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void validation({ operation: "get", id })
        .then((reply) => {
          if (!cancelled) accept(reply);
        })
        .catch(() => {});
    }, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [available, id, stage]);
  const active =
    view &&
    [
      "ready-control",
      "control",
      "intervention",
      "reversal",
      "awaiting-acceptance",
      "recovery-blocked",
    ].includes(view.stage);
  const blocked = disabled || pending || !available;
  const eligible = observations.filter(
    (r) =>
      r.status === "observed" &&
      r.completeness === "complete" &&
      r.binding.identity.state === "exact" &&
      r.roots.every((root) =>
        ["corroborated", "exclusive"].includes(root.ownership.state),
      ),
  );
  const recovery =
    status.recovery_required || view?.stage === "recovery-blocked";
  return (
    <section className="teach-result" aria-label="Controlled local validation">
      <h2>Controlled local validation</h2>
      <p>
        A/B/A trials temporarily move whole artifact families, restore the
        original physical objects, and check whether sign-in returns. State
        confirmations describe only what you see in the app.
      </p>
      <button
        type="button"
        disabled={blocked}
        onClick={() => void command({ operation: "status" })}
      >
        Refresh validation and recovery
      </button>
      {recovery && (
        <div role="alert">
          <p>
            Recovery required. All cleanup and new validation are blocked. Close
            the app and its helpers before retrying.
          </p>
          <button
            type="button"
            disabled={blocked}
            onClick={() => void command({ operation: "recover" })}
          >
            Retry recovery
          </button>
        </div>
      )}
      {!active && !recovery && (
        <>
          <label>
            Saved complete observation
            <select
              value={observation}
              disabled={blocked}
              onChange={(e) => setObservation(e.target.value)}
            >
              <option value="">Choose an observation</option>
              {eligible.map((r) => (
                <option key={r.session_id} value={r.session_id}>
                  {r.binding.executable_path} · {r.session_id}
                </option>
              ))}
            </select>
          </label>
          <label>
            <input
              type="checkbox"
              checked={sessionPolicy}
              disabled={blocked}
              onChange={(e) => setSessionPolicy(e.target.checked)}
            />
            I accept temporary moves, graceful app closing, and deletion of
            experiment-created replacement data only after the original data is
            restored and physically verified.
          </label>
          <button
            type="button"
            disabled={blocked || !sessionPolicy || !observation}
            onClick={() => {
              setLosses(false);
              void command({
                operation: "start",
                observation_id: observation,
                accept_session_policy: true,
              });
            }}
          >
            Start controlled validation
          </button>
        </>
      )}
      {view && (
        <div aria-live="polite">
          <h3>{view.stage}</h3>
          <p>{instructions[view.stage]}</p>
          <ul>
            {view.scope.map((s) => (
              <li key={`${s.root}/${s.family}`}>
                {s.root} · {s.family}
              </li>
            ))}
          </ul>
          <p>
            Completed trials: {view.trials.length} · Final repeats:{" "}
            {
              view.trials.filter(
                (t) =>
                  t.purpose === "final-repeat" && t.result === "sufficient",
              ).length
            }
          </p>
          {view.trials.some((t) => t.collateral_families.length > 0) && (
            <div className="notice">
              <p>
                Changes beyond the normal control were observed outside the
                tested families. This is metadata evidence; the meaning of those
                changes is unknown.
              </p>
              <ul>
                {[
                  ...new Set(
                    view.trials.flatMap((t) =>
                      t.collateral_families.map(
                        (s) => `${s.root} · ${s.family}`,
                      ),
                    ),
                  ),
                ].map((family) => (
                  <li key={family}>{family}</li>
                ))}
              </ul>
            </div>
          )}
          {view.stage === "ready-control" && (
            <button
              type="button"
              disabled={blocked}
              onClick={() =>
                void command({ operation: "begin-trial", id: view.id })
              }
            >
              Begin A1 control trial
            </button>
          )}
          {["control", "intervention", "reversal"].includes(view.stage) && (
            <div>
              <button
                type="button"
                disabled={blocked}
                onClick={() =>
                  void command({ operation: "launch", id: view.id })
                }
              >
                Launch the bound application
              </button>
              {(["signed-in", "signed-out", "unclear"] as AppOutcome[]).map(
                (outcome) => (
                  <button
                    key={outcome}
                    type="button"
                    disabled={blocked}
                    onClick={() =>
                      void command({
                        operation: "outcome",
                        id: view.id,
                        outcome,
                      })
                    }
                  >
                    {outcome === "signed-in"
                      ? "Signed in"
                      : outcome === "signed-out"
                        ? "Signed out"
                        : "Unclear"}
                  </button>
                ),
              )}
            </div>
          )}
          {view.stage === "awaiting-acceptance" && (
            <>
              <LossConsent
                checked={losses}
                disabled={blocked}
                onChange={setLosses}
              />
              <button
                type="button"
                disabled={blocked || !losses}
                onClick={() =>
                  void command({ operation: "accept-losses", id: view.id })
                }
              >
                Save local logout rule
              </button>
            </>
          )}
          {active && (
            <button
              type="button"
              disabled={blocked}
              onClick={() => void command({ operation: "abort", id: view.id })}
            >
              Stop and restore original data
            </button>
          )}
          {view.diagnostics.length > 0 && (
            <p className="notice">{view.diagnostics.join(", ")}</p>
          )}
          {view.rule && <Rule rule={view.rule} />}
        </div>
      )}
      <h3>Saved local rules</h3>
      {status.rules.map((rule) => (
        <div key={rule.id}>
          <Rule rule={rule} />
          <button
            type="button"
            disabled={blocked || !!active || recovery || rule.stale}
            onClick={() => {
              setApplyRule(rule.id);
              setLosses(false);
            }}
          >
            Review local logout
          </button>
          {applyRule === rule.id && (
            <>
              <LossConsent
                checked={losses}
                disabled={blocked}
                onChange={setLosses}
              />
              <button
                type="button"
                disabled={blocked || !losses || recovery}
                onClick={() =>
                  void command({
                    operation: "apply",
                    rule_id: rule.id,
                    accept_bounded_losses: true,
                  })
                }
              >
                Apply local logout
              </button>
            </>
          )}
        </div>
      ))}
      {status.diagnostics.length > 0 && (
        <p className="notice">{status.diagnostics.join(", ")}</p>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  );
}
function LossConsent({
  checked,
  disabled,
  onChange,
}: {
  checked: boolean;
  disabled: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      I accept removal of the entire displayed families, including any settings,
      drafts, offline documents or other local data they contain. Their content
      semantics are unknown. No long-term account backup is kept.
    </label>
  );
}
function Rule({ rule }: { rule: LocalValidatedRule }) {
  return (
    <div>
      <p>
        Local rule · {rule.stale ? "Stale — revalidation required" : "Current"}{" "}
        · {rule.repetitions} final A/B/A trials · Preservation:{" "}
        {rule.preservation}
      </p>
      <ul>
        {rule.scope.map((s) => (
          <li key={`${s.root}/${s.family}`}>
            {s.root} · {s.family}
          </li>
        ))}
      </ul>
      <p>
        This computer and installation only. This rule is never published to the
        global catalog.
      </p>
    </div>
  );
}
