import { emptyHome, scopes, isSelected, selectionRequest } from "./selection";
import type { HomeState } from "./selection";
import { useRef, useEffect } from "react";
import { scan } from "./api";
import type {
  Category,
  Confidence,
  DetectedItem,
  SelectionRequest,
} from "./api";
import {
  categoryNames,
  commandErrors,
  homeStrings as h,
  riskNames,
  signalNames,
  unknownError,
} from "./strings";
const categories = Object.keys(categoryNames) as Category[];

function Check({
  label,
  checked,
  mixed = false,
  disabled = false,
  change,
}: {
  label: string;
  checked: boolean;
  mixed?: boolean;
  disabled?: boolean;
  change: (value: boolean) => void;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = mixed;
  }, [mixed]);
  return (
    <label className="choice">
      <input
        ref={ref}
        type="checkbox"
        checked={checked}
        aria-checked={mixed ? "mixed" : checked}
        disabled={disabled}
        onChange={(e) => change(e.target.checked)}
      />
      {label}
    </label>
  );
}

export default function Home({
  state,
  update,
  busy,
  setBusy,
  review,
  disabled,
}: {
  state: HomeState;
  update: (state: HomeState) => void;
  busy: boolean;
  setBusy: (value: boolean) => void;
  review: (selection: SelectionRequest) => void;
  disabled: boolean;
}) {
  const scanning = useRef(false);
  const active = useRef(true);
  useEffect(() => {
    active.current = true;
    return () => {
      active.current = false;
    };
  }, []);
  const detections =
    state.inventory?.groups.flatMap((g) =>
      g.items.map((item) => ({
        item,
        category: g.category,
        confidence: g.confidence,
      })),
    ) ?? [];
  async function startScan() {
    if (scanning.current || disabled) return;
    scanning.current = true;
    setBusy(true);
    update(emptyHome);
    try {
      const inventory = await scan();
      const selected: Record<string, string[]> = {};
      for (const group of inventory.groups)
        for (const item of group.items) {
          if (
            group.confidence === "high" &&
            group.category &&
            item.selectable &&
            item.default_selected
          )
            selected[item.id] = scopes(item);
        }
      if (active.current) update({ inventory, selected, error: null });
    } catch (error: unknown) {
      if (active.current)
        update({
          ...emptyHome,
          error:
            typeof error === "string" && Object.hasOwn(commandErrors, error)
              ? commandErrors[error as keyof typeof commandErrors]
              : unknownError,
        });
    } finally {
      scanning.current = false;
      if (active.current) setBusy(false);
    }
  }
  function toggle(items: DetectedItem[], checked: boolean) {
    const selected = { ...state.selected };
    for (const item of items.filter((i) => i.selectable)) {
      if (checked) selected[item.id] = scopes(item);
      else delete selected[item.id];
    }
    update({ ...state, selected });
  }
  function master(items: DetectedItem[], label: string) {
    const eligible = items.filter((i) => i.selectable);
    const total = eligible.reduce((n, i) => n + scopes(i).length, 0);
    const count = eligible.reduce(
      (n, i) => n + (state.selected[i.id]?.length ?? 0),
      0,
    );
    return (
      <Check
        label={`${h.select} ${label}`}
        checked={total > 0 && count === total}
        mixed={count > 0 && count < total}
        disabled={busy || !total}
        change={(v) => toggle(eligible, v)}
      />
    );
  }
  function row(item: DetectedItem, confidence: Confidence) {
    const selected = state.selected[item.id] ?? [];
    return (
      <li key={item.id} className="detection-row">
        <Check
          label={`${h.select} ${item.name} (${item.account === "current-account" ? h.currentAccount : item.account})`}
          checked={selected.length === scopes(item).length}
          mixed={selected.length > 0 && selected.length < scopes(item).length}
          disabled={busy || !item.selectable}
          change={(v) => toggle([item], v)}
        />
        <div className="badges">
          <span className="badge">{h[confidence]}</span>
          {item.unverified && <span className="badge">{h.unverified}</span>}
          {item.loss !== "none" && (
            <span className="badge risk">
              {item.loss === "known" ? h.loss : h.unknownLoss}:{" "}
              {item.risks.length
                ? item.risks.map((r) => riskNames[r]).join(", ")
                : riskNames.unknown}
            </span>
          )}
          {item.sync_warning && <span className="badge warning">{h.sync}</span>}
        </div>
        {item.sync_warning && <p className="muted">{h.syncHelp}</p>}
        {!item.selectable && <p className="muted">{h.unavailable}</p>}
        {item.profiles.length > 0 ? (
          <details>
            <summary>
              {h.profile} ({item.profiles.length})
            </summary>
            {item.profiles.map((id, index) => (
              <Check
                key={id}
                label={`${item.name} — ${h.profile} ${index + 1}`}
                checked={selected.includes(id)}
                disabled={busy || !item.selectable}
                change={(checked) => {
                  const next = checked
                    ? [...selected, id]
                    : selected.filter((p) => p !== id);
                  update({
                    ...state,
                    selected: { ...state.selected, [item.id]: next },
                  });
                }}
              />
            ))}
          </details>
        ) : (
          <p className="muted">{h.indivisible}</p>
        )}
        <details>
          <summary>{h.signals}</summary>
          <ul>
            {item.signals.length ? (
              [
                ...new Set(
                  item.signals.map(
                    (signal) => signalNames[signal] ?? h.unspecifiedSignal,
                  ),
                ),
              ].map((label) => <li key={label}>{label}</li>)
            ) : (
              <li>{h.noSignals}</li>
            )}
          </ul>
        </details>
      </li>
    );
  }
  function section(items: typeof detections) {
    if (!items.length) return <p className="muted">{h.empty}</p>;
    const providers = [
      ...new Set(items.map((d) => d.item.provider ?? d.item.id)),
    ];
    return providers.map((provider) => {
      const group = items.filter(
        (d) => (d.item.provider ?? d.item.id) === provider,
      );
      return (
        <details className="provider-group" key={provider} open>
          <summary>{group[0].item.name}</summary>
          {master(
            group.map((d) => d.item),
            group[0].item.name,
          )}
          {state.inventory?.mode === "all-accounts" ? (
            [...new Set(group.map((d) => d.item.account))].map((account) => {
              const accountItems = group.filter(
                (d) => d.item.account === account,
              );
              return (
                <details key={account}>
                  <summary>
                    {h.account}: {account}
                  </summary>
                  {master(
                    accountItems.map((d) => d.item),
                    `${h.account} ${account}`,
                  )}
                  <ul className="detections">
                    {accountItems.map((d) => row(d.item, d.confidence))}
                  </ul>
                </details>
              );
            })
          ) : (
            <ul className="detections">
              {group.map((d) => row(d.item, d.confidence))}
            </ul>
          )}
        </details>
      );
    });
  }
  const request = selectionRequest(state);
  return (
    <div className="home-selection">
      <button
        className="primary"
        type="button"
        disabled={busy || disabled}
        onClick={() => void startScan()}
      >
        {busy ? h.scanning : h.scan}
      </button>
      {busy && <p role="status">{h.scanning}</p>}
      {state.error && (
        <p className="notice error" role="alert">
          {state.error}
        </p>
      )}
      {state.inventory && (
        <>
          {state.inventory.coverage.length > 0 && (
            <p className="warning" role="status">
              {h.incomplete}
            </p>
          )}
          {categories.map((category) => {
            const items = detections.filter((d) => d.category === category);
            return (
              <section
                className="category"
                key={category}
                aria-label={categoryNames[category]}
              >
                <h3>{categoryNames[category]}</h3>
                {category === "windows-microsoft-and-dev-tools" && (
                  <p className="warning">{h.windowsWarning}</p>
                )}
                {master(
                  items.map((d) => d.item),
                  categoryNames[category],
                )}
                {section(items.filter((d) => d.confidence === "high"))}
                {items.some((d) => d.confidence !== "high") && (
                  <details className="uncertain">
                    <summary>{h.uncertain}</summary>
                    <p>{h.uncertainHelp}</p>
                    {section(items.filter((d) => d.confidence !== "high"))}
                  </details>
                )}
              </section>
            );
          })}
          {detections.some((d) => !d.category) && (
            <details className="uncertain">
              <summary>{h.unclassified}</summary>
              {section(detections.filter((d) => !d.category))}
            </details>
          )}
        </>
      )}
      <div className="selection-summary" aria-label={h.reviewTitle}>
        {categories.map((category) => (
          <span key={category}>
            {categoryNames[category]}:{" "}
            {
              detections.filter(
                (d) => d.category === category && isSelected(state, d.item),
              ).length
            }{" "}
            {h.selected}
          </span>
        ))}
        <button
          className="primary"
          type="button"
          disabled={busy || !request?.items.length}
          onClick={() => {
            if (request?.items.length) review(request);
          }}
        >
          {h.review}
        </button>
      </div>
    </div>
  );
}
