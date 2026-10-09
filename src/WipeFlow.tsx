import { useEffect, useRef, useState } from "react";
import {
  buildPlan,
  cancel,
  closeReviewed,
  dryRun,
  execute,
  scan,
} from "./client";
import type {
  ExecuteRequest,
  ItemDto,
  PlanDto,
  ReportDto,
  ScanDto,
  SelectionRequest,
  Stage,
} from "./api";
import Reports, { ItemEffects } from "./Reports";
import Hero from "./Hero";
import HoldButton from "./HoldButton";
import CategorySummary from "./CategorySummary";
import {
  acknowledgedCounts,
  categories,
  errorText,
  freshSelection,
  reportItems,
  retryable,
  needsAttention,
  previewBlocked,
  blockingReason,
  targetsFor,
} from "./wipe";
import type { Target } from "./wipe";
import {
  homeStrings as h,
  shortCategoryNames,
  lossDescriptions,
  riskNames,
  stageNames,
  strings as s,
  wipeStrings as w,
} from "./strings";

export default function WipeFlow({
  inventory,
  selection,
  setBusy,
  back,
}: {
  inventory: ScanDto;
  selection: SelectionRequest;
  setBusy: (busy: boolean) => void;
  back: (requiresScan: boolean) => void;
}) {
  const [plan, setPlan] = useState<PlanDto | null>(null);
  const [report, setReport] = useState<ReportDto | null>(null);
  const [targets, setTargets] = useState(() =>
    targetsFor(inventory, selection),
  );
  const [skipped, setSkipped] = useState<Target[]>([]);

  const [working, setWorking] = useState(true);
  const [running, setRunning] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<Record<string, Stage>>({});
  const operation = useRef(false);
  const starting = useRef<Promise<PlanDto> | null>(null);
  const mounted = useRef(true);
  const requiresScan = useRef(inventory.mode !== "current");
  useEffect(() => {
    mounted.current = true;
    setBusy(true);
    starting.current ??= buildPlan(selection).then((p) => dryRun(p.plan_id));
    let active = true;
    starting.current
      .then((p) => {
        if (active) setPlan(p);
      })
      .catch((e) => {
        if (e === "stale-plan" || e === "worker-unavailable")
          requiresScan.current = true;
        if (active) setError(errorText(e));
      })
      .finally(() => {
        if (active) {
          setWorking(false);
          setBusy(false);
        }
      });
    return () => {
      active = false;
      mounted.current = false;
    };
  }, [selection, setBusy]);
  const entries = plan ? reportItems(plan.report) : [];
  const blockedEntries = entries.filter((e) => previewBlocked(e.item));
  const allBlocked =
    entries.length > 0 && blockedEntries.length === entries.length;
  const blockers = entries.filter(
    (e) => !previewBlocked(e.item) && e.item.processes.length > 0,
  );
  const force = plan?.report.process_close_policy === "hard-kill-after2s";
  const key = (account: string, item: ItemDto, flag: string) =>
    JSON.stringify([account, item.instance, flag]);
  const riskEntries = entries.filter(
    (e) =>
      e.item.risks.length > 0 ||
      e.item.confirmations.length > 0 ||
      e.item.loss !== "none",
  );
  const hasDataLoss = riskEntries.some(
    (entry) => entry.item.loss !== "none" || entry.item.risks.length > 0,
  );
  function request(): ExecuteRequest {
    if (!plan) throw new Error("missing-plan");
    return {
      plan_id: plan.plan_id,
      confirmed_risks: riskEntries.map((e) => ({
        account: e.account,
        instance: e.item.instance,
        flags: e.item.risks,
        confirmations: e.item.confirmations,
      })),
      category_tokens: plan.category_tokens.map((token) => token.token),
      force_close_accounts: force
        ? plan.report.accounts.map((a) => a.account)
        : [],
    };
  }
  function name(account: string, item: ItemDto) {
    return (
      targets.find((t) => t.account === account && t.provider === item.provider)
        ?.name ?? item.instance
    );
  }
  async function refresh(next: Target[], close = false, omitted = skipped) {
    if (operation.current || running) return;
    operation.current = true;
    setWorking(true);
    setBusy(true);
    setError(null);
    const approval = close ? request() : null;
    setPlan(null);

    try {
      requiresScan.current = true;
      if (approval) await closeReviewed(approval);
      const fresh = await scan();
      const chosen = freshSelection(fresh, next, omitted);
      const preview = await buildPlan(chosen);
      const reviewed = await dryRun(preview.plan_id);
      if (mounted.current) {
        setPlan(reviewed);
        setTargets(next);
        setReport(null);
        setComplete(false);
        setProgress({});
        setCancelled(false);
      }
    } catch (e) {
      if (mounted.current)
        setError(
          e instanceof Error && e.message === "unmatched"
            ? w.unavailable
            : errorText(e),
        );
    } finally {
      operation.current = false;
      if (mounted.current) {
        setWorking(false);
        setBusy(false);
      }
    }
  }
  function skipBlocked() {
    const affected = targets.filter((t) =>
      blockers.some(
        (b) => b.account === t.account && b.item.provider === t.provider,
      ),
    );
    const omitted = [...skipped, ...affected];
    setSkipped(omitted);
    const remaining = targets.filter((t) => !affected.includes(t));
    void refresh(remaining, false, omitted);
  }
  async function start() {
    if (
      !plan ||
      operation.current ||
      running ||
      allBlocked ||
      (!force && blockers.length > 0)
    )
      return;
    const approval = request(),
      id = plan.plan_id;
    operation.current = true;
    requiresScan.current = true;
    setWorking(true);
    setBusy(true);
    setRunning(true);
    setError(null);
    setComplete(false);
    setCancelled(false);
    setProgress({});
    // Before any acknowledged result, coverage remains unknown rather than cleaned.
    let retained: ReportDto = {
      ...plan.report,
      mode: "apply",
      accounts: plan.report.accounts.map((a) => ({
        ...a,
        sections: a.sections.map((c) => ({
          ...c,
          status: c.items.length ? "blocked" : "not-requested",
          succeeded: 0,
          would_apply: 0,
          items: c.items.map((i) => ({
            ...i,
            status: "blocked",
            issues: [...i.issues, "unacknowledged"],
            actions: i.actions.map((action) => ({
              ...action,
              outcome: "blocked",
              verification: "unknown",
              issues: [...action.issues, "unacknowledged"],
            })),
          })),
        })),
      })),
    };
    let terminal = false;
    function finish() {
      terminal = true;
      operation.current = false;
      setRunning(false);
      setWorking(false);
      setBusy(false);
    }
    try {
      const started = await execute(approval, (event) => {
        if (!mounted.current || event.run_id !== id || terminal) return;
        if (event.kind === "progress")
          setProgress((old) => ({
            ...old,
            [JSON.stringify([event.account, event.category])]: event.stage,
          }));
        if (event.kind === "item") {
          retained = {
            ...retained,
            accounts: retained.accounts.map((a) =>
              a.account === event.account
                ? {
                    ...a,
                    sections: a.sections.map((c) => {
                      if (c.category !== event.category) return c;
                      const items = c.items.map((i) =>
                        i.instance === event.item.instance ? event.item : i,
                      );
                      return { ...c, ...acknowledgedCounts(items), items };
                    }),
                  }
                : a,
            ),
          };
          setReport(retained);
        }
        if (event.kind === "finished") {
          setReport(event.report);
          setComplete(true);
          finish();
        }
        if (event.kind === "failed") {
          setReport(retained);
          setError(`${errorText(event.error)} ${w.noResults}`);
          finish();
        }
      });
      if (started.run_id !== id && !terminal) throw new Error("unexpected-run");
    } catch (e) {
      if (!terminal && mounted.current) {
        setError(errorText(e));
        setReport(retained);
        finish();
      }
    }
  }
  async function stop() {
    if (!plan || cancelled) return;
    setCancelled(true);
    try {
      await cancel(plan.plan_id);
    } catch (e) {
      setError(errorText(e));
      setCancelled(false);
    }
  }
  function retry(instance?: string, account?: string) {
    if (!report) return;
    const failed = reportItems(report).filter(
      (e) =>
        retryable(e.item) &&
        (!instance || (e.item.instance === instance && e.account === account)),
    );
    const next = targets.filter((t) =>
      failed.some(
        (e) => e.account === t.account && e.item.provider === t.provider,
      ),
    );
    if (!next.length) {
      setError(w.unavailable);
      return;
    }
    void refresh(next);
  }
  const counts = Object.fromEntries(
    categories.map((category) => [
      category,
      targets.filter((t) => t.category === category).length,
    ]),
  ) as Record<import("./api").Category, number>;
  const statuses = Object.fromEntries(
    categories.map((category) => {
      const sections =
        (report ?? plan?.report)?.accounts.flatMap((a) =>
          a.sections.filter((c) => c.category === category),
        ) ?? [];
      const items = sections.flatMap((c) => c.items);
      const done = items.filter((item) => !needsAttention(item)).length;
      const stages =
        plan?.report.accounts
          .map((a) => progress[JSON.stringify([a.account, category])])
          .filter(Boolean) ?? [];
      return [
        category,
        !counts[category]
          ? "Not selected"
          : done === items.length && done > 0
            ? "Verified locally"
            : stages.length
              ? stageNames[stages[stages.length - 1]]
              : "Waiting",
      ];
    }),
  );
  return (
    <div className="wipe-flow">
      {error && (
        <p className="notice error" role="alert">
          <span className="status-pill error">Couldn’t continue</span> {error}
        </p>
      )}
      {working && !running && (
        <>
          <Hero
            meta="READ ONLY · LOCAL SCAN"
            title="Checking the details"
            description="Reviewing the selected data before anything is removed."
            icon="grid"
            animated
          />
          <CategorySummary counts={counts} />
          <p className="control-help" role="status">
            Preparing your local cleanup plan…
          </p>
        </>
      )}
      {!working && !plan && !report && (
        <>
          <Hero
            meta="NOTHING HAS BEEN REMOVED"
            title="Couldn’t prepare cleanup"
            description="Return to the overview to adjust your selection."
            icon="attention"
          />
          <button
            className="primary"
            type="button"
            onClick={() => back(requiresScan.current)}
          >
            Back to overview
          </button>
        </>
      )}
      {plan && !report && !running && !working && (
        <>
          <Hero
            meta="REVIEW · NOTHING REMOVED YET"
            title={
              allBlocked
                ? "Automatic cleanup unavailable"
                : !force && blockers.length
                  ? "Save your work first"
                  : "Ready to let go?"
            }
            description={
              allBlocked
                ? "Nothing will be removed. Review the limitations below and use the app’s own logout option."
                : !force && blockers.length
                  ? "Selected programs are open. Save your work before requesting a gentle close."
                  : hasDataLoss
                    ? "This permanently removes the selected local session data. There is no undo."
                    : "You may need to sign in again. Review the listed local changes."
            }
          />
          <CategorySummary counts={counts} />
          {!allBlocked && (
            <div className="confirmation-notice">
              <span className="status-pill warning">
                {hasDataLoss ? "Permanent deletion" : "Local sign-out"}
              </span>
              <p>
                {riskEntries.length
                  ? `${hasDataLoss ? "Also at risk" : "Effect"}: ${[...new Set(riskEntries.flatMap((e) => (e.item.affected_data.length ? e.item.affected_data : e.item.risks.map((risk) => riskNames[risk]))))].join(", ") || "local session data"}.`
                  : "Local-only drafts, documents or settings may be lost with session data."}
              </p>
              {plan.category_tokens.length > 0 && (
                <p>
                  Windows stays signed in. Windows sign-in can restore browser
                  or Office sessions.
                </p>
              )}
              {force && <p>{s.forceWarning}</p>}
              {blockers.length > 0 && (
                <p>
                  Programs to {force ? "force close" : "close gently"}:{" "}
                  {[
                    ...new Set(
                      blockers.map((entry) => name(entry.account, entry.item)),
                    ),
                  ].join(", ")}
                  .
                </p>
              )}
              <p className="muted">
                Holding confirms{" "}
                {hasDataLoss
                  ? "the listed data loss"
                  : "the listed local changes"}
                {plan.category_tokens.length
                  ? ", Windows sign-in limitations"
                  : ""}
                {force ? " and force closing the listed programs" : ""}.
              </p>
            </div>
          )}
          {blockedEntries.length > 0 && (
            <div className="notice warning" role="status">
              {blockedEntries.map((e) => (
                <p key={key(e.account, e.item, "blocked")}>
                  <strong>{name(e.account, e.item)}</strong>:{" "}
                  {blockingReason(e.item)}
                  {e.item.provider === "spotify" &&
                    e.item.limitations.includes(
                      "unknown-authentication-closure",
                    ) &&
                    " In Spotify, click your profile picture, then choose Log out."}
                </p>
              ))}
              <p>These items will not be cleaned or closed.</p>
            </div>
          )}
          {!allBlocked && (
            <HoldButton
              key={plan.plan_id}
              label={
                !force && blockers.length
                  ? "Hold to close programs"
                  : entries.length
                    ? "Hold to log out locally"
                    : "Hold to finish report"
              }
              onConfirm={() => {
                if (!force && blockers.length) void refresh(targets, true);
                else void start();
              }}
            />
          )}
          <details className="review-details">
            <summary>
              Review {entries.length} selected{" "}
              {entries.length === 1 ? "item" : "items"} & data loss
            </summary>
            {entries.map((e) => (
              <article key={key(e.account, e.item, "review")}>
                <h3>
                  {name(e.account, e.item)}{" "}
                  <span className="muted">
                    ·{" "}
                    {e.account === "current-account"
                      ? "Your Windows account"
                      : e.account}{" "}
                    · {shortCategoryNames[e.category]}
                  </span>
                </h3>
                <ItemEffects item={e.item} preview />
                {e.item.risks.map((risk) => (
                  <p key={risk}>{lossDescriptions[risk]}</p>
                ))}
                {e.item.affected_data.length > 0 && (
                  <p>Data at risk: {e.item.affected_data.join(", ")}</p>
                )}
                {e.item.processes.length > 0 && (
                  <p>Open programs: {e.item.processes.join(", ")}</p>
                )}
              </article>
            ))}
            {inventory.groups
              .flatMap((g) => g.items)
              .some((i) => selection.items.includes(i.id) && i.unverified) && (
              <p>{w.unverified}</p>
            )}
            {entries.some((e) => e.category === "browser") && (
              <p>{h.syncHelp}</p>
            )}
          </details>
          {!force && blockers.length > 0 && (
            <div className="flow-actions">
              <button type="button" onClick={() => void refresh(targets)}>
                I closed them — check again
              </button>
              <button type="button" onClick={skipBlocked}>
                Skip open programs
              </button>
            </div>
          )}
          {skipped.length > 0 && (
            <p className="scope-note">
              {skipped.length} {skipped.length === 1 ? "item" : "items"} skipped
              by choice. No cleanup requested for them.
            </p>
          )}
          <button
            className="text-button back-button"
            type="button"
            onClick={() => back(requiresScan.current)}
          >
            Back to overview
          </button>
        </>
      )}
      {running && (
        <>
          <Hero
            meta="IN PROGRESS · ON THIS DEVICE"
            title="Letting go"
            description="Clearing selected local sessions, then checking what remains."
            icon="grid"
            animated
          />
          <div aria-live="polite">
            <CategorySummary counts={counts} statuses={statuses} active />
          </div>
          <p className="progress-caption" role="status">
            {cancelled
              ? "Stopping after the current operation. Completed changes will remain."
              : "You can stop the remaining work. Completed changes cannot be undone."}
          </p>
          <button
            className="secondary cancel-button"
            type="button"
            disabled={cancelled}
            onClick={() => void stop()}
          >
            {cancelled ? "Stopping…" : "Stop remaining work"}
          </button>
        </>
      )}
      {report && !running && !working && (
        <Reports
          report={report}
          name={name}
          retry={retry}
          working={working}
          canExport={complete}
          back={() => back(requiresScan.current)}
          coverage={inventory.coverage}
        />
      )}
    </div>
  );
}
