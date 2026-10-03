import { useRef, useState } from "react";
import { activateCatalogUpdate, checkCatalogUpdates } from "./api";
import type { CatalogUpdateDto, Settings } from "./api";

const errors: Record<string, string> = {
  "catalog-unconfigured":
    "Catalog updates are not configured in this application build.",
  "catalog-storage":
    "Catalog state is unavailable or inconsistent. Cleanup is blocked. Do not delete the state to reset its version; contact the maintainers for recovery.",
  "catalog-transport":
    "The download failed. Your accepted local catalog has not changed.",
  "catalog-signature":
    "The catalog signature is invalid. The update was rejected.",
  "catalog-rollback":
    "This catalog is older, or changes an already accepted version. The update was rejected.",
  "catalog-revision":
    "The catalog reuses or downgrades a provider revision. The update was rejected.",
  "catalog-no-proposal":
    "This proposal is no longer available. Check again before accepting.",
  "catalog-compatibility":
    "This catalog requires a different application version. The update was rejected.",
};
export default function CatalogUpdates({
  settings,
  busy,
  setBusy,
  invalidate,
}: {
  settings: Settings;
  busy: boolean;
  setBusy: (value: boolean) => void;
  invalidate: () => void;
}) {
  const [status, updateStatus] = useState<CatalogUpdateDto | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const running = useRef(false);
  async function run(activate: boolean) {
    if (running.current) return;
    running.current = true;
    setBusy(true);
    setMessage(null);
    try {
      if (!activate) {
        // The native check also discards the previous inventory and review.
        invalidate();
      }
      const result =
        activate && status?.digest
          ? await activateCatalogUpdate(status.digest)
          : await checkCatalogUpdates();
      updateStatus(result);
      if (result.error)
        setMessage(
          errors[result.error] ??
            "Catalog validation failed. The update was rejected.",
        );
      else if (activate) {
        invalidate();
        setMessage("Catalog accepted. Scan again before any cleanup.");
      }
    } catch {
      setMessage(
        "The catalog operation could not complete. Retry when no cleanup or review is active.",
      );
    } finally {
      running.current = false;
      setBusy(false);
    }
  }
  return (
    <section aria-labelledby="catalog-title">
      <h3 id="catalog-title">Provider catalog</h3>
      <p>
        Updates download rules only when you choose to check. Cleanup stays
        offline. Checking clears your previous scan and review.
      </p>
      <button type="button" disabled={busy} onClick={() => void run(false)}>
        Check for catalog updates
      </button>
      {status && <p>Installed catalog: {status.installed_version}</p>}
      {status?.proposed_version && !status.error && (
        <>
          <p>Proposed catalog: {status.proposed_version}</p>
          <pre style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>
            {status.changelog}
          </pre>
          <p>
            Acceptance changes rules, risks and provider availability. It does
            not approve any cleanup.
          </p>
          <p>
            If manifests change, all-accounts cleanup will require a compatible
            helper/application release after acceptance.
          </p>
          <button type="button" disabled={busy} onClick={() => void run(true)}>
            Accept catalog update
          </button>
        </>
      )}
      {status && !status.helper_compatible && !status.error && (
        <p>
          All-accounts cleanup requires a compatible helper application release
          for this catalog. Current-account cleanup remains available.
          {settings.account_mode === "all-accounts" &&
            " Select current-account mode in Settings before scanning."}
        </p>
      )}
      {message && <p role="status">{message}</p>}
    </section>
  );
}
