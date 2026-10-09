import { useState } from "react";
import ScopeDecision from "./ScopeDecision";
import type { ItemDto, ReportDto } from "./api";
import { exportReport } from "./client";
import {
  reportItems,
  retryable,
  errorText,
  needsAttention,
  attentionReason,
  blockingReason,
  previewBlocked,
} from "./wipe";
import Hero from "./Hero";
import DotIcon from "./DotIcon";
import {
  aggregateNames,
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
      {preview && previewBlocked(item) && <p>{blockingReason(item)}</p>}
      <ScopeDecision decision={item.decision} />
      {(previewBlocked(item) || item.status === "blocked") &&
        item.provider === "spotify" &&
        item.limitations.includes("unknown-authentication-closure") && (
          <p>
            In Spotify, click your profile picture, then choose Log out.
            EveryOut has no verified automatic logout method for Spotify yet.
          </p>
        )}
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
  back,
  coverage = [],
}: {
  report: ReportDto;
  name: (account: string, item: ItemDto) => string;
  retry: (instance?: string, account?: string) => void;
  working: boolean;
  canExport?: boolean;
  back?: () => void;
  coverage?: string[];
}) {
  const [message, setMessage] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const entries = reportItems(report);
  const attention = entries.filter((entry) => needsAttention(entry.item));
  const accountGaps = report.accounts.filter(
    (a) =>
      a.residual_hive ||
      a.issues.length ||
      a.limitations.length ||
      a.sections.some(
        (section) =>
          section.warnings.length ||
          (section.status !== "complete-local-scope" &&
            section.status !== "not-requested"),
      ),
  );
  const hasGaps =
    coverage.length > 0 ||
    accountGaps.length > 0 ||
    report.skipped.length > 0 ||
    (!entries.length && !report.skipped.length);
  const clean = !attention.length && !hasGaps && canExport;
  const nothingRemoved =
    canExport &&
    entries.length > 0 &&
    entries.every(
      ({ item }) =>
        !item.issues.includes("unacknowledged") &&
        item.status === "blocked" &&
        item.actions.every((a) => a.outcome === "blocked"),
    );
  const title = nothingRemoved
    ? "Nothing was removed"
    : attention.length
      ? `Done, ${attention.length} ${attention.length === 1 ? "item needs" : "items need"} attention`
      : clean
        ? "Done"
        : canExport
          ? "Done, check coverage"
          : "Cleanup interrupted";
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
    <section className="results" aria-label="Local cleanup result">
      <Hero
        meta="RESULT · SUPPORTED LOCAL SCOPE"
        title={title}
        description={
          nothingRemoved
            ? "Cleanup was blocked. Review the limitations for each selected app."
            : clean
              ? "Selected local session data was removed and verified absent."
              : "Review the results below. Unverified or skipped data may remain."
        }
        icon={clean ? "check" : "attention"}
      >
        <span className={`status-pill ${clean ? "success" : "warning"}`}>
          {nothingRemoved
            ? "Blocked"
            : clean
              ? "Verified locally"
              : "Needs attention"}
        </span>
      </Hero>
      <p className="scope-note">
        Local cleanup only. Remote sessions remain active. Windows or browser
        sync can sign you in again.
      </p>
      {back && (
        <button
          className="primary result-primary"
          type="button"
          onClick={back}
          disabled={working}
        >
          Back to overview
        </button>
      )}
      <ul className="result-list" aria-label="Results by item">
        {[...entries]
          .sort(
            (left, right) =>
              Number(needsAttention(right.item)) -
              Number(needsAttention(left.item)),
          )
          .map(({ account, item }) => (
            <li key={JSON.stringify([account, item.instance])}>
              <DotIcon
                name={needsAttention(item) ? "attention" : "check"}
                size={24}
              />
              <div className="result-copy">
                <strong>{name(account, item)}</strong>
                {report.account_mode === "all-accounts" && (
                  <span className="muted">{account}</span>
                )}
                <p>
                  {needsAttention(item)
                    ? attentionReason(item)
                    : "Selected session data verified absent."}
                </p>
                <details>
                  <summary>Local data details</summary>
                  <ItemEffects item={item} />
                </details>
              </div>
              {retryable(item) ? (
                <button
                  className="small-button"
                  type="button"
                  disabled={working}
                  onClick={() => retry(item.instance, account)}
                  aria-label={`Retry ${name(account, item)}${report.account_mode === "all-accounts" ? ` (${account})` : ""}`}
                >
                  Retry
                </button>
              ) : (
                <span
                  className={`status-pill ${needsAttention(item) ? "warning" : "success"}`}
                >
                  {needsAttention(item) ? "Check" : "Done"}
                </span>
              )}
            </li>
          ))}
        {report.skipped.map((item) => (
          <li key={`skipped-${item.account}-${item.instance}`}>
            <DotIcon name="attention" size={24} />
            <div className="result-copy">
              <strong>{item.name}</strong>
              <p>Skipped by choice. No cleanup requested.</p>
            </div>
            <span className="status-pill warning">Skipped</span>
          </li>
        ))}
      </ul>
      {hasGaps && (
        <div className="coverage-note">
          <span className="status-pill warning">Coverage incomplete</span>
          <p>
            {coverage.length
              ? "The scan could not verify all local stores. "
              : ""}
            {report.skipped.length
              ? `${report.skipped.length} items were skipped. `
              : ""}
            {accountGaps.length
              ? "Some account or category results are incomplete. "
              : ""}
            {!entries.length && !report.skipped.length
              ? "No selected item results were returned."
              : ""}
          </p>
          {accountGaps.map((account) => (
            <p key={account.account}>
              {account.account === "current-account"
                ? "Your Windows account"
                : account.account}
              :{" "}
              {account.residual_hive
                ? w.residualHive
                : "Some local coverage is unresolved."}
            </p>
          ))}
        </div>
      )}
      <details className="report-details">
        <summary>Report & coverage</summary>
        <p>{w.remainsHelp}</p>
        <p>Identity, sync and remote sign-out have not been verified.</p>
        {canExport && (
          <div className="flow-actions">
            <button
              type="button"
              disabled={exporting || working}
              onClick={() => void save("json")}
            >
              Save JSON report
            </button>
            <button
              type="button"
              disabled={exporting || working}
              onClick={() => void save("text")}
            >
              Save text report
            </button>
          </div>
        )}
        {message && <p role="status">{message}</p>}
      </details>
    </section>
  );
}
