import { useState } from "react";
import type { ItemDto, ReportDto } from "./api";
import { exportReport } from "./api";
import { categories, retryable, errorText } from "./wipe";
import {
  aggregateNames,
  categoryNames,
  homeStrings as h,
  outcomeNames,
  uncertaintyNames,
  verificationNames,
  wipeStrings as w,
} from "./strings";
export function ItemEffects({
  item,
  preview = false,
}: {
  item: ItemDto;
  preview?: boolean;
}) {
  return (
    <>
      <p>
        {item.issues.includes("unacknowledged")
          ? w.unknownOutcome
          : aggregateNames[item.status]}
        {item.locked ? ` · ${w.locked}` : ""}
      </p>
      <p>
        {w.counts}: {item.actions.length}
      </p>
      {item.profiles.length > 0 && (
        <p>
          {w.profiles}: {item.profiles.join(", ")}
        </p>
      )}
      <ul className="target-list" aria-label={w.paths}>
        {item.actions.map((action) => (
          <li key={action.id}>
            <code>{action.path}</code> —{" "}
            {action.issues.includes("unacknowledged")
              ? w.unknownOutcome
              : action.locked
                ? w.locked
                : outcomeNames[action.outcome]}{" "}
            · {verificationNames[action.verification]}
            {preview && (
              <span>
                {" "}
                ·{" "}
                {action.bytes === null
                  ? w.unknownSize
                  : `${action.bytes} ${w.bytes}`}
              </span>
            )}
            {action.issues.length > 0 && <p className="muted">{w.coverage}</p>}
          </li>
        ))}
      </ul>
      {preview && (
        <p>
          {w.identity}: {uncertaintyNames[item.identity]} · {w.sync}:{" "}
          {uncertaintyNames[item.sync]} · {w.sso}:{" "}
          {uncertaintyNames[item.silent_sso]}
        </p>
      )}
      {(item.limitations.length > 0 || item.issues.length > 0) && (
        <p className="warning">{w.unverified}</p>
      )}
    </>
  );
}
export default function Reports({
  report,
  name,
  retry,
  working,
  canExport = true,
}: {
  report: ReportDto;
  name: (account: string, item: ItemDto) => string;
  retry: () => void;
  working: boolean;
  canExport?: boolean;
}) {
  const [category, setCategory] = useState(categories[0]);
  const [message, setMessage] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const extra = [...new Set(report.skipped.map((i) => i.account))]
    .filter((id) => !report.accounts.some((a) => a.account === id))
    .map((account) => ({
      account,
      sections: [],
      limitations: [],
      issues: [],
      residual_hive: false,
      residual_hku_key: null,
      unload_attempts: 0,
    }));
  const accounts = [...report.accounts, ...extra].map((a) => ({
    ...a,
    section: a.sections.find((s) => s.category === category),
  }));
  async function save(format: "json" | "text") {
    if (exporting) return;
    setExporting(true);
    setMessage(null);
    try {
      setMessage(`${w.exported} ${await exportReport(format)}`);
    } catch (error) {
      setMessage(errorText(error));
    } finally {
      setExporting(false);
    }
  }
  return (
    <section aria-label={w.reports}>
      <h3>{w.reports}</h3>
      <div className="report-tabs" role="tablist" aria-label={w.reports}>
        {categories.map((c) => (
          <button
            key={c}
            id={`tab-${c}`}
            type="button"
            role="tab"
            aria-selected={category === c}
            aria-controls="category-report"
            onClick={() => setCategory(c)}
          >
            {categoryNames[c]}
          </button>
        ))}
      </div>
      <div
        role="tabpanel"
        id="category-report"
        aria-labelledby={`tab-${category}`}
      >
        {accounts.map((account) => (
          <section
            key={account.account}
            aria-label={`${h.account}: ${account.account}`}
          >
            <h4>
              {h.account}:{" "}
              {account.account === "current-account"
                ? h.currentAccount
                : account.account}
            </h4>
            <p>
              {account.section?.items.some((i) =>
                i.issues.includes("unacknowledged"),
              )
                ? w.unknownOutcome
                : aggregateNames[account.section?.status ?? "not-requested"]}
            </p>
            {account.section && account.section.status !== "not-requested" && (
              <p>
                {w.removed}:{" "}
                {Math.max(
                  0,
                  account.section.succeeded - account.section.already_absent,
                )}{" "}
                · {outcomeNames["already-absent"]}:{" "}
                {account.section.already_absent} · {w.failed}:{" "}
                {account.section.failed} · {w.locked}: {account.section.locked}{" "}
                · {w.omitted}: {account.section.skipped}
              </p>
            )}
            {report.skipped
              .filter(
                (i) => i.account === account.account && i.category === category,
              )
              .map((i) => (
                <article key={i.instance}>
                  <h5>{i.name}</h5>
                  <p>
                    {w.omitted} · {w.skipped}
                  </p>
                </article>
              ))}
            {account.section?.items.map((item) => (
              <article key={item.instance} className="report-item">
                <h5>{name(account.account, item)}</h5>
                <ItemEffects item={item} />
                <p>
                  {w.identity}: {uncertaintyNames[item.identity]} · {w.sync}:{" "}
                  {uncertaintyNames[item.sync]} · {w.sso}:{" "}
                  {uncertaintyNames[item.silent_sso]}
                </p>
              </article>
            ))}
            <h5>{w.remains}</h5>
            <p>{w.remainsHelp}</p>
            {account.section?.items.flatMap((i) =>
              i.actions
                .filter((a) => a.verification !== "target-absent")
                .map((a) => (
                  <p key={`${i.instance}-${a.id}`}>
                    <code>{a.path}</code> · {verificationNames[a.verification]}
                  </p>
                )),
            )}
            {account.limitations.length > 0 ||
            account.issues.length > 0 ||
            account.section?.warnings.length ? (
              <p className="warning">{w.coverage}</p>
            ) : null}
            {account.residual_hive && <p role="alert">{w.residualHive}</p>}
            {category === "browser" && !!account.section?.items.length && (
              <>
                <p className="warning">{h.syncHelp}</p>
                <p>{w.uncertainty}</p>
              </>
            )}
            {category === "windows-microsoft-and-dev-tools" && (
              <p className="warning">{h.windowsWarning}</p>
            )}
          </section>
        ))}
      </div>
      {report.accounts.some((a) =>
        a.sections.some((s) => s.items.some(retryable)),
      ) && (
        <>
          <p>{w.retryHelp}</p>
          <button type="button" disabled={working} onClick={retry}>
            {w.retry}
          </button>
        </>
      )}
      {canExport && (
        <div className="flow-actions">
          <button
            type="button"
            disabled={exporting || working}
            onClick={() => void save("json")}
          >
            {w.json}
          </button>
          <button
            type="button"
            disabled={exporting || working}
            onClick={() => void save("text")}
          >
            {w.text}
          </button>
        </div>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  );
}
