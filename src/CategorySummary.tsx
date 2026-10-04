import { useEffect, useState, type CSSProperties } from "react";
import type { Category } from "./api";
import DotIcon from "./DotIcon";
import type { DotIconName } from "./DotIcon";
import { categories } from "./wipe";
import { shortCategoryNames } from "./strings";
import {
  categoryItems,
  scopes,
  type CategoryDelta,
  type HomeState,
} from "./selection";
import { motion } from "./motion";
const icons: Record<Category, DotIconName> = {
  application: "apps",
  browser: "browser",
  "windows-microsoft-and-dev-tools": "accounts",
};

function RollingCount({
  value,
  delta,
}: {
  value: number;
  delta?: CategoryDelta;
}) {
  if (!delta || delta.direction === "same") return <>{value}</>;
  const steps = Math.min(Math.abs(delta.change), 30);
  const values = Array.from({ length: steps + 1 }, (_, index) =>
    Math.round(delta.previous + (delta.change * index) / steps),
  );
  return (
    <span className="rolling-count" aria-label={String(value)}>
      <span
        className="rolling-track"
        aria-hidden="true"
        style={{ "--roll-offset": `${-steps * 14}px` } as CSSProperties}
      >
        {values.map((number, index) => (
          <span key={index}>{number}</span>
        ))}
      </span>
    </span>
  );
}

function DeltaFeedback({ delta }: { delta: CategoryDelta }) {
  const [visible, setVisible] = useState(true);
  useEffect(() => {
    let remaining = motion.delta as number;
    let started = performance.now();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const resume = () => {
      clearTimeout(timer);
      if (document.hidden) remaining -= performance.now() - started;
      else {
        started = performance.now();
        timer = setTimeout(() => setVisible(false), Math.max(0, remaining));
      }
    };
    if (!document.hidden) resume();
    document.addEventListener("visibilitychange", resume);
    return () => {
      clearTimeout(timer);
      document.removeEventListener("visibilitychange", resume);
    };
  }, []);
  return visible ? (
    <span
      role="status"
      className={`delta-pill status-pill ${delta.direction === "up" ? "success" : delta.direction === "down" ? "warning" : "neutral"}`}
    >
      {delta.direction === "same" && (
        <span className="delta-beacon" aria-hidden="true" />
      )}
      {delta.direction === "same"
        ? "No change"
        : `${delta.change > 0 ? "+" : "−"}${Math.abs(delta.change)}`}
    </span>
  ) : null;
}

export default function CategorySummary({
  counts,
  statuses,
  active = false,
  totals,
  state,
  toggle,
  scanning = false,
  disabled = false,
  deltas,
}: {
  counts: Record<Category, number>;
  statuses?: Partial<Record<Category, string>>;
  active?: boolean;
  totals?: Record<Category, number>;
  state?: HomeState;
  toggle?: (category: Category) => void;
  scanning?: boolean;
  disabled?: boolean;
  deltas?: Record<Category, CategoryDelta>;
}) {
  const [focusIndex, setFocusIndex] = useState(0);
  const tabIndex =
    state && !categoryItems(state, categories[focusIndex]).length
      ? categories.findIndex(
          (category) => categoryItems(state, category).length > 0,
        )
      : focusIndex;
  return (
    <ul
      className={`category-summary${toggle ? " category-selection" : ""}`}
      aria-label={
        active
          ? "Cleanup progress by category"
          : "Selected local accounts by category"
      }
      aria-busy={scanning}
    >
      {categories.map((category, index) => {
        const items = state ? categoryItems(state, category) : [];
        const selectedScopes = items.reduce(
          (sum, item) => sum + (state?.selected[item.id]?.length ?? 0),
          0,
        );
        const totalScopes = items.reduce(
          (sum, item) => sum + scopes(item).length,
          0,
        );
        const checked = totalScopes > 0 && selectedScopes === totalScopes;
        const mixed = selectedScopes > 0 && !checked;
        const delta = scanning ? undefined : deltas?.[category];
        const content = (
          <>
            <DotIcon
              name={icons[category]}
              size={36}
              delta={delta?.direction}
              deltaCount={Math.abs(delta?.change ?? 0)}
            />
            <div className="category-copy">
              <span className="category-name">
                {shortCategoryNames[category]}
              </span>
              <span className="category-detail">
                {totals ? (
                  <>
                    <RollingCount
                      value={counts[category]}
                      delta={
                        counts[category] === totals[category]
                          ? delta
                          : undefined
                      }
                    />{" "}
                    of <RollingCount value={totals[category]} delta={delta} />{" "}
                    selected
                  </>
                ) : (
                  (statuses?.[category] ?? `${counts[category]} selected`)
                )}
              </span>
            </div>
            {toggle && (
              <DotIcon
                name={mixed ? "mixed" : checked ? "checked" : "checkbox"}
                size={20}
              />
            )}
            {delta && <DeltaFeedback delta={delta} />}
          </>
        );
        return (
          <li key={category}>
            {toggle ? (
              <button
                className="category-cell"
                type="button"
                role="checkbox"
                aria-label={`${shortCategoryNames[category]}: ${counts[category]} of ${totals?.[category] ?? 0} selected`}
                aria-checked={mixed ? "mixed" : checked}
                disabled={disabled || !items.length}
                tabIndex={index === tabIndex ? 0 : -1}
                onFocus={() => setFocusIndex(index)}
                onClick={() => toggle(category)}
                onKeyDown={(event) => {
                  if (
                    ![
                      "ArrowRight",
                      "ArrowDown",
                      "ArrowLeft",
                      "ArrowUp",
                      "Home",
                      "End",
                    ].includes(event.key)
                  )
                    return;
                  event.preventDefault();
                  const cells = Array.from(
                    event.currentTarget
                      .closest("ul")!
                      .querySelectorAll<HTMLButtonElement>(
                        "button:not(:disabled)",
                      ),
                  );
                  const position = cells.indexOf(event.currentTarget);
                  const next =
                    event.key === "Home"
                      ? 0
                      : event.key === "End"
                        ? cells.length - 1
                        : (position +
                            (event.key === "ArrowRight" ||
                            event.key === "ArrowDown"
                              ? 1
                              : -1) +
                            cells.length) %
                          cells.length;
                  cells[next]?.focus();
                }}
              >
                {content}
              </button>
            ) : (
              content
            )}
          </li>
        );
      })}
    </ul>
  );
}
