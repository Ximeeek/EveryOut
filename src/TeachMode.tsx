import { useEffect, useState } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { teach } from "./api";
import type {
  LearnedObservation,
  TeachPhase,
  TeachReply,
  TeachView,
} from "./api";

const phases: Record<
  TeachPhase,
  { title: string; instruction: string; signedIn: boolean }
> = {
  "closed-baseline": {
    title: "A · Closed baseline",
    instruction: "Close the app while signed out.",
    signedIn: false,
  },
  "launch-logged-out": {
    title: "B · Launch signed out",
    instruction: "Launch the app and remain signed out.",
    signedIn: false,
  },
  login: {
    title: "C · Sign in",
    instruction: "Sign in normally inside the app, then continue.",
    signedIn: true,
  },
  "settled-logged-in": {
    title: "D · Settled signed in",
    instruction:
      "Wait for startup and sign-in activity to settle, then continue.",
    signedIn: true,
  },
  "restart-persistence": {
    title: "E · Restart persistence",
    instruction: "Close and reopen the app. Confirm your sign-in state below.",
    signedIn: true,
  },
  "vendor-logout": {
    title: "F · Sign out inside the app",
    instruction: "Use the app’s normal Sign out button, then continue.",
    signedIn: false,
  },
  "closed-logged-out": {
    title: "G · Closed signed out",
    instruction: "Close the app while signed out, then continue.",
    signedIn: false,
  },
};

export default function TeachMode({ disabled }: { disabled: boolean }) {
  const [executable, setExecutable] = useState("");
  const [channel, setChannel] = useState("");
  const [view, setView] = useState<TeachView | null>(null);
  const [history, setHistory] = useState<LearnedObservation[]>([]);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const available = isTauri();
  function accept(reply: TeachReply) {
    if (reply.kind === "view") setView(reply.data);
    else setHistory(reply.data);
  }
  async function command(request: Parameters<typeof teach>[0]) {
    setPending(true);
    setError("");
    try {
      accept(await teach(request));
    } catch (reason) {
      setError(
        reason === "busy"
          ? "Close the app for a closed snapshot, or launch/restart it for the current phase. Try again once it is ready."
          : reason === "stale-plan"
            ? "The executable or process binding changed. Finish this observation and start again."
            : "Could not complete this observation. Check the executable path, sign-in state and access to the app’s folders.",
      );
    } finally {
      setPending(false);
    }
  }
  useEffect(() => {
    if (!available) return;
    let cancelled = false;
    void teach({ operation: "history" })
      .then((reply) => {
        if (!cancelled) accept(reply);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [available]);
  const sessionId = view?.id;
  const stage = view?.stage;
  useEffect(() => {
    if (!sessionId || !stage || !["discovering", "focused"].includes(stage))
      return;
    const id = sessionId;
    let cancelled = false;
    const timer = window.setInterval(() => {
      void teach({ operation: "get", id })
        .then((reply) => {
          if (!cancelled) accept(reply);
        })
        .catch(() => {});
    }, 1000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [sessionId, stage]);
  const active =
    view && ["discovering", "ready", "focused"].includes(view.stage);
  const phase = view?.next_phase ? phases[view.next_phase] : null;
  const blocked = disabled || pending;
  return (
    <section className="teach-mode" aria-label="Learning this app">
      <h2>Learning this app</h2>
      <p>
        EveryOut monitors file metadata only. It does not read passwords,
        tokens, cookies or database contents. Learning saves an observation;
        cleanup stays blocked.
      </p>
      {!available && (
        <p className="notice">
          Teach Mode is available in the Windows desktop app.
        </p>
      )}
      {!active && (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            void command({
              operation: "start",
              executable,
              channel: channel.trim() || null,
            });
          }}
        >
          <label htmlFor="teach-executable">Application executable path</label>
          <input
            id="teach-executable"
            value={executable}
            onChange={(event) => setExecutable(event.target.value)}
            placeholder="C:\\Program Files\\Your app\\App.exe"
            required
            disabled={blocked || !available}
          />
          <label htmlFor="teach-channel">Channel (if known)</label>
          <input
            id="teach-channel"
            value={channel}
            onChange={(event) => setChannel(event.target.value)}
            maxLength={80}
            disabled={blocked || !available}
          />
          <p>
            Close the app while signed out first. Then start discovery and
            launch the app while remaining signed out. Discovery lasts up to 20
            seconds.
          </p>
          <button type="submit" disabled={blocked || !available}>
            Start discovery
          </button>
        </form>
      )}
      {view && (
        <div aria-live="polite">
          <p>
            <strong>{view.application}</strong> · Observation:{" "}
            {view.completeness} · Completed cycles: {view.completed_cycles}
          </p>
          {view.stage === "discovering" && (
            <>
              <h3>Discover changing folders</h3>
              <p>
                Launch the app while signed out. A short discovery pass will
                find changing folders. Each following cycle watches only the
                shortlist.
              </p>
              <button
                type="button"
                disabled={blocked}
                onClick={() =>
                  void command({ operation: "discover", id: view.id })
                }
              >
                Finish discovery now
              </button>
            </>
          )}
          {view.stage === "ready" && (
            <>
              <h3>
                {view.completed_cycles
                  ? "Repeat the cycle"
                  : "Start a focused cycle"}
              </h3>
              <p>
                Close the app while signed out. At least two complete,
                consistent cycles are needed for Observed. Conflicting results
                remain inconclusive.
              </p>
              <button
                type="button"
                disabled={blocked || !view.candidate_roots.length}
                onClick={() =>
                  void command({ operation: "begin-cycle", id: view.id })
                }
              >
                Capture closed baseline
              </button>
            </>
          )}
          {phase && (
            <>
              <h3>{phase.title}</h3>
              <p>{phase.instruction}</p>
              <button
                type="button"
                disabled={blocked}
                onClick={() =>
                  void command({
                    operation: "advance",
                    id: view.id,
                    signed_in: phase.signedIn,
                  })
                }
              >
                {view.next_phase === "restart-persistence"
                  ? "Still signed in"
                  : "Confirm state and continue"}
              </button>
              {view.next_phase === "restart-persistence" && (
                <button
                  type="button"
                  disabled={blocked}
                  onClick={() =>
                    void command({
                      operation: "advance",
                      id: view.id,
                      signed_in: false,
                    })
                  }
                >
                  Not signed in
                </button>
              )}
            </>
          )}
          {view.stage === "stale" && (
            <p className="notice">
              The application binding changed. This observation is stale and
              cannot provide current evidence.
            </p>
          )}
          <details>
            <summary>Candidate folders · {view.candidate_roots.length}</summary>
            <ul>
              {view.candidate_roots.map((root) => (
                <li key={root}>{root}</li>
              ))}
            </ul>
          </details>
          {view.diagnostics.length > 0 && (
            <p className="notice">
              Coverage is limited: {view.diagnostics.join(", ")}
            </p>
          )}
          {(view.stage !== "finished" ||
            view.diagnostics.includes("observation-save-failed")) && (
            <button
              type="button"
              disabled={blocked}
              onClick={() => void command({ operation: "finish", id: view.id })}
            >
              Finish and save observation
            </button>
          )}
          {view.result && <ObservationResult record={view.result} />}
        </div>
      )}
      {error && (
        <p role="alert" className="notice error">
          {error}
        </p>
      )}
      <details>
        <summary>Saved observations · {history.length}</summary>
        <button
          type="button"
          disabled={blocked || !available}
          onClick={() => void command({ operation: "history" })}
        >
          Refresh applicability
        </button>
        {history.map((record) => (
          <ObservationResult key={record.session_id} record={record} />
        ))}
      </details>
    </section>
  );
}
function ObservationResult({ record }: { record: LearnedObservation }) {
  return (
    <div className="teach-result">
      <h3>Result: {record.status}</h3>
      <p>Action: Blocked · Preservation: Unknown · {record.cycles} cycles</p>
      {record.roots.map((root) => (
        <div key={root.root}>
          <p>
            {root.root} · Ownership: {root.ownership.state}
          </p>
          <p>
            {
              root.families.filter((f) =>
                ["strongly-observed", "observed"].includes(f.verdict),
              ).length
            }{" "}
            observed families ·{" "}
            {root.families.filter((f) => f.verdict === "noise").length} noise
            families
          </p>
          <details>
            <summary>Artifact families · {root.families.length}</summary>
            <ul>
              {root.families.slice(0, 20).map((family) => (
                <li key={family.family}>
                  {family.family} · {family.verdict} · {family.class}
                </li>
              ))}
            </ul>
            {root.families.length > 20 && (
              <p>
                Showing the first 20 families. Full metadata evidence is saved
                locally.
              </p>
            )}
          </details>
        </div>
      ))}
      <p>
        Sign-in confirmations label the app’s state. They do not validate files
        or authorize removal.
      </p>
    </div>
  );
}
