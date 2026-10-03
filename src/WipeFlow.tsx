import { useEffect, useRef, useState } from "react";
import { buildPlan, cancel, closeReviewed, dryRun, execute, scan } from "./api";
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
import {
  acknowledgedCounts,
  categories,
  errorText,
  freshSelection,
  reportItems,
  retryable,
  targetsFor,
} from "./wipe";
import type { Target } from "./wipe";
import {
  categoryNames,
  homeStrings as h,
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
  back: () => void;
}) {
  const [plan, setPlan] = useState<PlanDto | null>(null);
  const [report, setReport] = useState<ReportDto | null>(null);
  const [targets, setTargets] = useState(() =>
    targetsFor(inventory, selection),
  );
  const [skipped, setSkipped] = useState<Target[]>([]);
  const [checked, setChecked] = useState<Record<string, boolean>>({});
  const [working, setWorking] = useState(true);
  const [running, setRunning] = useState(false);
  const [cancelled, setCancelled] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<Record<string, Stage>>({});
  const operation = useRef(false);
  const starting = useRef<Promise<PlanDto> | null>(null);
  const mounted = useRef(true);
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
  const blockers = entries.filter((e) => e.item.processes.length > 0);
  const force = plan?.report.process_close_policy === "hard-kill-after2s";
  const key = (account: string, item: ItemDto, flag: string) =>
    JSON.stringify([account, item.instance, flag]);
  const riskEntries = entries.filter(
    (e) =>
      e.item.risks.length > 0 ||
      e.item.confirmations.length > 0 ||
      e.item.loss !== "none",
  );
  const approved =
    !!plan &&
    riskEntries.every((e) =>
      (e.item.risks.length ? e.item.risks : ["effects"]).every(
        (flag) => checked[key(e.account, e.item, flag)],
      ),
    ) &&
    (!plan.category_tokens.length || checked.windows) &&
    (!force || checked.force);
  function request(): ExecuteRequest {
    if (!plan || !approved) throw new Error("unapproved");
    return {
      plan_id: plan.plan_id,
      confirmed_risks: riskEntries.map((e) => ({
        account: e.account,
        instance: e.item.instance,
        flags: e.item.risks,
        confirmations: e.item.confirmations,
      })),
      category_tokens: checked.windows
        ? plan.category_tokens.map((t) => t.token)
        : [],
      force_close_accounts:
        force && checked.force
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
    setChecked({});
    try {
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
      !approved ||
      operation.current ||
      running ||
      (!force && blockers.length > 0)
    )
      return;
    const approval = request(),
      id = plan.plan_id;
    operation.current = true;
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
  function retry() {
    if (!report) return;
    const failed = reportItems(report).filter((e) => retryable(e.item));
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
  function checkbox(id: string, label: string) {
    return (
      <label className="choice">
        <input
          type="checkbox"
          checked={!!checked[id]}
          disabled={working}
          onChange={(e) =>
            setChecked((old) => ({ ...old, [id]: e.target.checked }))
          }
        />
        {label}
      </label>
    );
  }
  return (
    <div className="wipe-flow" aria-busy={working}>
      {error && (
        <p className="notice error" role="alert">
          {error}
        </p>
      )}
      {working && !running && <p role="status">{w.loading}</p>}
      {skipped.length > 0 && !report && (
        <aside className="warning">
          <p>{w.skipped}</p>
          <ul>
            {skipped.map((t, i) => (
              <li key={i}>
                {categoryNames[t.category]} · {t.account} · {t.name}
              </li>
            ))}
          </ul>
        </aside>
      )}
      {plan && !report && !running && (
        <>
          <h3>{w.review}</h3>
          {categories.map((category) => (
            <section
              key={category}
              aria-label={categoryNames[category]}
              className="category"
            >
              <h4>{categoryNames[category]}</h4>
              {entries.filter((e) => e.category === category).length === 0 && (
                <p>{h.empty}</p>
              )}
              {entries
                .filter((e) => e.category === category)
                .map((e) => (
                  <article key={`${e.account}-${e.item.instance}`}>
                    <h5>
                      {name(e.account, e.item)} · {e.account}
                    </h5>
                    <ItemEffects item={e.item} preview />
                    {inventory.groups
                      .flatMap((g) => g.items)
                      .some(
                        (i) =>
                          i.provider === e.item.provider &&
                          i.account === e.account &&
                          i.unverified,
                      ) && <p className="warning">{w.unverified}</p>}
                  </article>
                ))}
              {category === "browser" &&
                entries.some((e) => e.category === category) && (
                  <p className="warning">{h.syncHelp}</p>
                )}
              {category === "windows-microsoft-and-dev-tools" &&
                entries.some((e) => e.category === category) && (
                  <p className="warning">{h.windowsWarning}</p>
                )}
            </section>
          ))}
          {riskEntries.length > 0 && (
            <fieldset disabled={working}>
              <legend>{w.riskHeading}</legend>
              <p>{w.lossHelp}</p>
              {riskEntries.map((e) => (
                <div key={key(e.account, e.item, "risks")}>
                  <h4>
                    {name(e.account, e.item)} · {e.account}
                  </h4>
                  {e.item.affected_data.length > 0 && (
                    <p>{e.item.affected_data.join(", ")}</p>
                  )}
                  {e.item.risks.length
                    ? e.item.risks.map((flag) => (
                        <div key={flag}>
                          <p>{lossDescriptions[flag]}</p>
                          {checkbox(
                            key(e.account, e.item, flag),
                            `${name(e.account, e.item)} · ${e.account}: ${riskNames[flag]}`,
                          )}
                        </div>
                      ))
                    : checkbox(
                        key(e.account, e.item, "effects"),
                        `${name(e.account, e.item)}: ${w.confirmEffect}`,
                      )}
                </div>
              ))}
            </fieldset>
          )}
          {plan.category_tokens.length > 0 && (
            <fieldset disabled={working}>
              <legend>{w.windowsHeading}</legend>
              <p className="warning">{h.windowsWarning}</p>
              {checkbox("windows", w.windowsConfirm)}
            </fieldset>
          )}
          <section aria-label={w.processes}>
            <h4>{w.processes}</h4>
            {blockers.length ? (
              <ul>
                {blockers.map((e) => (
                  <li key={key(e.account, e.item, "processes")}>
                    {name(e.account, e.item)} · {e.account}
                    <ul>
                      {e.item.processes.map((p) => (
                        <li key={p}>{p}</li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            ) : (
              <p>{w.none}</p>
            )}
            {force ? (
              <>
                <p className="warning">{s.forceWarning}</p>
                {checkbox("force", w.forceConfirm)}
              </>
            ) : (
              <>
                <p>{w.askHelp}</p>
                {blockers.length > 0 && (
                  <div className="flow-actions">
                    <button
                      type="button"
                      disabled={working || !approved}
                      onClick={() => void refresh(targets, true)}
                    >
                      {w.close}
                    </button>
                    <button
                      type="button"
                      disabled={working}
                      onClick={() => void refresh(targets)}
                    >
                      {w.refresh}
                    </button>
                    <button
                      type="button"
                      disabled={working}
                      onClick={skipBlocked}
                    >
                      {w.skip}
                    </button>
                  </div>
                )}
              </>
            )}
          </section>
          <button
            className="primary"
            type="button"
            disabled={working || !approved || (!force && blockers.length > 0)}
            onClick={() => void start()}
          >
            {entries.length ? w.execute : w.finishSkipped}
          </button>
        </>
      )}
      {running && (
        <section aria-label={w.executing}>
          <h3>{w.executing}</h3>
          <ul aria-live="polite">
            {plan?.report.accounts.flatMap((a) =>
              categories
                .filter((c) =>
                  a.sections.some(
                    (section) =>
                      section.category === c && section.items.length > 0,
                  ),
                )
                .map((c) => (
                  <li key={`${a.account}-${c}`}>
                    {a.account} · {categoryNames[c]}:{" "}
                    {progress[JSON.stringify([a.account, c])]
                      ? stageNames[progress[JSON.stringify([a.account, c])]]
                      : stageNames.review}
                  </li>
                )),
            )}
          </ul>
          <button
            type="button"
            disabled={cancelled}
            onClick={() => void stop()}
          >
            {w.cancel}
          </button>
          {cancelled && <p role="status">{w.cancelling}</p>}
        </section>
      )}
      {report && !running && (
        <Reports
          report={report}
          name={name}
          retry={retry}
          working={working}
          canExport={complete}
        />
      )}
      <button type="button" disabled={working || running} onClick={back}>
        {w.recover}
      </button>
    </div>
  );
}
