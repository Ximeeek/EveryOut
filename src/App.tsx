import { useEffect, useRef, useState, type CSSProperties } from "react";
import { isTauri } from "@tauri-apps/api/core";
import {
  enableAllAccountsMode,
  getSettings,
  setSettings,
  scan,
} from "./client";
import type {
  AccountMode,
  Category,
  CommandError,
  SelectionRequest,
  Settings,
} from "./api";
import Home from "./Home";
import RollingCount from "./RollingCount";
import WipeFlow from "./WipeFlow";
import CatalogUpdates from "./CatalogUpdates";
import {
  emptyHome,
  defaultSelection,
  selectionRequest,
  isSelected,
  categoryItems,
  detectedCounts,
  categoryDeltas,
  toggleCategory,
  rescanSelection,
} from "./selection";
import DotIcon from "./DotIcon";
import Hero from "./Hero";
import TitleBar from "./TitleBar";
import { motionStyle, visibleScan } from "./motion";
import CategorySummary from "./CategorySummary";
import { categories } from "./wipe";
import type { HomeState } from "./selection";
import {
  commandErrors,
  modeFailures,
  strings as s,
  unknownError,
} from "./strings";

type Page = "home" | "advanced" | "review";
type Notice = { text: string; error: boolean } | null;
const browserPreview = import.meta.env.DEV && !isTauri();

function errorText(error: unknown) {
  return typeof error === "string" && Object.hasOwn(commandErrors, error)
    ? commandErrors[error as CommandError]
    : unknownError;
}
function NoticeView({
  notice,
  dismiss,
}: {
  notice: Notice;
  dismiss: () => void;
}) {
  return notice ? (
    <div
      className={`notice ${notice.error ? "error" : ""}`}
      role={notice.error ? "alert" : "status"}
    >
      {notice.error && (
        <span className="status-pill error">Couldn’t continue</span>
      )}
      <p>{notice.text}</p>
      <button type="button" onClick={dismiss}>
        {s.dismiss}
      </button>
    </div>
  ) : null;
}
function AccountChoice({
  value,
  onChange,
}: {
  value: AccountMode;
  onChange: (mode: AccountMode) => void;
}) {
  return (
    <fieldset aria-describedby="account-help">
      <legend>{s.question}</legend>
      <label className="choice">
        <input
          type="radio"
          name="account"
          checked={value === "current"}
          onChange={() => onChange("current")}
        />
        {s.current}
      </label>
      <label className="choice">
        <input
          type="radio"
          name="account"
          checked={value === "all-accounts"}
          onChange={() => onChange("all-accounts")}
        />
        {s.all}
      </label>
      <p id="account-help" className="muted">
        {s.accountHelp}
      </p>
    </fieldset>
  );
}
function Preferences({
  settings,
  firstRun,
  busy,
  save,
}: {
  settings: Settings;
  firstRun: boolean;
  busy: boolean;
  save: (next: Settings) => Promise<void>;
}) {
  const [mode, setMode] = useState<AccountMode>(
    firstRun ? "current" : settings.account_mode,
  );
  const [policy, setPolicy] = useState(settings.process_close_policy);
  const [acknowledged, setAcknowledged] = useState(false);
  const needsAcknowledgment =
    !firstRun &&
    policy === "hard-kill-after2s" &&
    settings.process_close_policy !== policy;
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        if (!busy && (!needsAcknowledgment || acknowledged)) {
          void save({
            ...settings,
            account_mode: mode,
            process_close_policy: policy,
            first_run_completed: true,
          });
        }
      }}
    >
      <fieldset className="form-controls" disabled={busy}>
        {!firstRun && (
          <fieldset aria-describedby="process-help">
            <legend>{s.processHeading}</legend>
            <label className="choice">
              <input
                type="radio"
                name="process"
                checked={policy === "ask"}
                onChange={() => {
                  setPolicy("ask");
                  setAcknowledged(false);
                }}
              />
              {s.ask}
            </label>
            <label className="choice">
              <input
                type="radio"
                name="process"
                checked={policy === "hard-kill-after2s"}
                onChange={() => setPolicy("hard-kill-after2s")}
              />
              {s.force}
            </label>
            <p id="process-help" className="muted">
              {s.processHelp}
            </p>
            <p className="warning" id="force-warning">
              {s.forceWarning}
            </p>
            {needsAcknowledgment && (
              <label className="choice">
                <input
                  type="checkbox"
                  required
                  checked={acknowledged}
                  aria-describedby="force-warning"
                  onChange={(event) => setAcknowledged(event.target.checked)}
                />
                {s.acknowledge}
              </label>
            )}
          </fieldset>
        )}
        <AccountChoice value={mode} onChange={setMode} />
        {!firstRun && <p className="muted">{s.rememberedMode}</p>}
        <button
          className="primary"
          type="submit"
          disabled={needsAcknowledgment && !acknowledged}
        >
          {busy ? s.saving : firstRun ? s.continue : s.save}
        </button>
      </fieldset>
    </form>
  );
}
export default function App() {
  const [page, setPage] = useState<Page>("home");
  const [navigation, setNavigation] = useState({
    direction: "fresh",
    version: 0,
  });
  const [revealOrigin, setRevealOrigin] = useState("50% 50%");
  function navigate(
    next: Page,
    direction = next === "advanced" ? "right" : "left",
  ) {
    setDeltas(undefined);
    setNavigation((current) => ({ direction, version: current.version + 1 }));
    setPage(next);
  }
  const [settings, updateSettings] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(true);
  const [notice, setNotice] = useState<Notice>(null);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [loadFailed, setLoadFailed] = useState(false);
  const [formVersion, setFormVersion] = useState(0);
  const [home, updateHome] = useState<HomeState>(emptyHome);
  const [selection, storeSelection] = useState<SelectionRequest | null>(null);
  const [deltas, setDeltas] = useState<
    ReturnType<typeof categoryDeltas> | undefined
  >();
  const [scanVersion, setScanVersion] = useState(0);
  const [hidden, setHidden] = useState(document.hidden);
  useEffect(() => {
    const changed = () => setHidden(document.hidden);
    document.addEventListener("visibilitychange", changed);
    return () => document.removeEventListener("visibilitychange", changed);
  }, []);
  const saving = useRef(false);
  const scanOperation = useRef(false);
  const initialScan = useRef<{
    settings: Settings;
    promise: ReturnType<typeof scan>;
  } | null>(null);
  useEffect(() => {
    let active = true;
    getSettings()
      .then((value) => {
        if (!active) return;
        updateSettings(value);
        setLoadFailed(false);
        setScanning(value.account_mode === "current");
        setNotice(null);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setLoadFailed(true);
        setScanning(false);
        setNotice({ text: errorText(error), error: true });
      });
    return () => {
      active = false;
    };
  }, [loadAttempt]);
  useEffect(() => {
    if (!settings || settings.account_mode !== "current") return;
    let active = true;
    if (initialScan.current?.settings !== settings)
      initialScan.current = { settings, promise: visibleScan(scan) };
    initialScan.current.promise
      .then((inventory) => {
        if (active) updateHome(defaultSelection(inventory));
      })
      .catch((error: unknown) => {
        if (active) updateHome({ ...emptyHome, error: errorText(error) });
      })
      .finally(() => {
        if (active) setScanning(false);
      });
    return () => {
      active = false;
    };
  }, [settings]);
  useEffect(() => {
    const content = document.getElementById("content");
    if (content) content.scrollTop = 0;
    const frame = requestAnimationFrame(() =>
      document.getElementById("flow-title")?.focus(),
    );
    return () => cancelAnimationFrame(frame);
  }, [page, navigation.version]);

  function invalidate() {
    setDeltas(undefined);
    updateHome(emptyHome);
    storeSelection(null);
  }
  async function rescan(openReview = false) {
    if (busy || scanning || scanOperation.current || !settings) return;
    scanOperation.current = true;
    setScanning(true);
    setNotice(null);
    storeSelection(null);
    setDeltas(undefined);
    const previous = home;
    try {
      if (settings.account_mode === "all-accounts") {
        const result = await enableAllAccountsMode();
        if (result.effective_mode !== "all-accounts") {
          updateSettings(await getSettings());
          setNotice({
            text: result.reason ? modeFailures[result.reason] : s.fallback,
            error: true,
          });
          return;
        }
      }
      const next = rescanSelection(previous, await visibleScan(scan));
      updateHome(next);
      if (previous.inventory) setDeltas(categoryDeltas(previous, next));
      setScanVersion((version) => version + 1);
      const request = selectionRequest(next);
      if (openReview && request?.items.length) {
        storeSelection(request);
        navigate("review");
      }
    } catch (error: unknown) {
      updateHome({ ...emptyHome, error: errorText(error) });
    } finally {
      scanOperation.current = false;
      setScanning(false);
    }
  }
  async function save(next: Settings) {
    if (saving.current) return;
    saving.current = true;
    setBusy(true);
    setNotice(null);
    invalidate();
    let fallback: string | null = null;
    try {
      if (
        next.account_mode === "all-accounts" &&
        settings?.account_mode !== "all-accounts"
      ) {
        const result = await enableAllAccountsMode();
        next = { ...next, account_mode: result.effective_mode };
        if (result.effective_mode === "current")
          fallback = result.reason ? modeFailures[result.reason] : s.fallback;
      }
      const saved = await setSettings(next);
      setScanning(saved.account_mode === "current");
      updateSettings(saved);
      setFormVersion((version) => version + 1);
      setNotice({ text: fallback ?? s.saved, error: fallback !== null });
    } catch (error: unknown) {
      setNotice({
        text: fallback ? `${fallback} ${errorText(error)}` : errorText(error),
        error: true,
      });
      try {
        const saved = await getSettings();
        setScanning(saved.account_mode === "current");
        updateSettings(saved);
        setFormVersion((version) => version + 1);
      } catch {
        /* Preserve the command error. */
      }
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }
  const request = selectionRequest(home);
  const counts = Object.fromEntries(
    categories.map((category) => [
      category,
      home.inventory?.groups
        .filter((g) => g.category === category)
        .flatMap((g) => g.items)
        .filter((item) => isSelected(home, item)).length ?? 0,
    ]),
  ) as Record<Category, number>;
  const total = Object.values(counts).reduce((sum, count) => sum + count, 0);
  const unavailable =
    (home.inventory?.groups.flatMap((g) => g.items).length ?? 0) -
    categories.reduce(
      (sum, category) => sum + categoryItems(home, category).length,
      0,
    );
  const ready = !!home.inventory && total > 0;
  return (
    <div
      className={`app-shell${hidden ? " motion-paused" : ""}`}
      style={motionStyle}
    >
      <a className="skip-link" href="#content">
        {s.skip}
      </a>
      <TitleBar onBrandClick={() => navigate("home", "fresh")}>
        <button
          className="text-button navigation-button"
          type="button"
          aria-label={page === "advanced" ? "Back to overview" : "Settings"}
          title={page === "advanced" ? "Back to overview" : "Settings"}
          disabled={busy || scanning || page === "review"}
          onClick={() => navigate(page === "advanced" ? "home" : "advanced")}
        >
          <DotIcon
            name={page === "advanced" ? "back" : "settings"}
            size={28}
          />
        </button>
      </TitleBar>
      <main
        id="content"
        className={page === "home" ? "overview-content" : undefined}
        tabIndex={-1}
      >
        <div
          key={navigation.version}
          className={`page-view page-${page} enter-${navigation.direction}`}
        >
          <NoticeView notice={notice} dismiss={() => setNotice(null)} />
          {!settings ? (
            <>
              <Hero
                meta="ON THIS DEVICE"
                title={loadFailed ? "Couldn’t load settings" : "Getting ready"}
                description={
                  loadFailed
                    ? "Your data is untouched. Reload settings to continue."
                    : "Loading your local preferences."
                }
                icon={loadFailed ? "attention" : "grid"}
                animated={!loadFailed}
              />
              {loadFailed && (
                <button
                  className="primary"
                  type="button"
                  onClick={() => {
                    setLoadFailed(false);
                    setNotice(null);
                    setLoadAttempt((attempt) => attempt + 1);
                  }}
                >
                  Reload settings
                </button>
              )}
            </>
          ) : page === "review" && selection && home.inventory ? (
            <WipeFlow
              inventory={home.inventory}
              selection={selection}
              setBusy={setBusy}
              back={() => {
                invalidate();
                navigate("home");
                void rescan();
              }}
            />
          ) : page === "advanced" ? (
            <div className="advanced-view">
              <p className="meta">MAKE IT YOURS</p>
              <h1 id="flow-title" tabIndex={-1}>
                Customize your cleanup
              </h1>
              <p className="muted">
                Choose the local accounts and profiles to include. Every
                selection gets a fresh review.
              </p>
              <details open>
                <summary>Selected items · {total}</summary>
                {home.inventory ? (
                  <Home
                    state={home}
                    update={updateHome}
                    busy={busy || scanning}
                  />
                ) : (
                  <p>Return to the overview to scan local accounts.</p>
                )}
              </details>
              <details>
                <summary>Account scope & closing programs</summary>
                <Preferences
                  key={formVersion}
                  settings={settings}
                  firstRun={false}
                  busy={busy || scanning}
                  save={save}
                />
              </details>
              <details>
                <summary>Provider catalog</summary>
                <CatalogUpdates
                  settings={settings}
                  busy={busy || scanning}
                  setBusy={setBusy}
                  invalidate={invalidate}
                />
              </details>
              <details>
                <summary>Privacy & supported coverage</summary>
                <p>{s.aboutIntro}</p>
                <dl className="limitations">
                  {s.limitations.map(([heading, description]) => (
                    <div key={heading}>
                      <dt>{heading}</dt>
                      <dd>{description}</dd>
                    </div>
                  ))}
                </dl>
              </details>
              {browserPreview && (
                <details>
                  <summary>Development preview states</summary>
                  <label htmlFor="preview-state">Simulated scenario</label>
                  <select
                    id="preview-state"
                    className="preview-scenarios"
                    defaultValue={
                      new URLSearchParams(window.location.search).get("demo") ??
                      "idle"
                    }
                    onChange={(event) => {
                      window.location.search = `?demo=${event.target.value}`;
                    }}
                  >
                    {[
                      "idle",
                      "scanning",
                      "rescan",
                      "medium",
                      "preparing",
                      "running",
                      "partial",
                      "success",
                      "error",
                      "processes",
                      "empty",
                    ].map((state) => (
                      <option key={state} value={state}>
                        {state}
                      </option>
                    ))}
                  </select>
                  <p>
                    To preview confirmation, choose idle and select Log out
                    locally. Hold to run the simulation.
                  </p>
                </details>
              )}
            </div>
          ) : (
            <div className="dashboard">
              <Hero
                meta="YOUR SESSIONS · YOUR DEVICE"
                title={
                  scanning
                    ? "Finding your sessions"
                    : home.error
                      ? "Couldn’t scan this device"
                      : home.inventory && !total
                        ? "Nothing selected"
                        : home.inventory
                          ? `${total} ${total === 1 ? "session" : "sessions"} will be cleared`
                          : "Leave your sessions behind."
                }
                description={
                  home.error
                    ? "Your data is untouched. Run a fresh scan to try again."
                    : "Clear supported local sessions in one deliberate action."
                }
                icon={scanning ? "grid" : home.error ? "attention" : "logout"}
                animated={scanning}
                animateTitle
              >
                {home.inventory && (
                  <p className="hero-counter">
                    <span className="hero-counter-value">
                      <RollingCount value={total} zeroLabel="No" padded />
                    </span>
                    {total === 1 ? "item selected" : "items selected"} on this
                    device
                  </p>
                )}
              </Hero>
              <CategorySummary
                key={scanVersion}
                counts={counts}
                totals={detectedCounts(home)}
                state={home}
                scanning={scanning}
                disabled={busy || scanning || !home.inventory}
                deltas={deltas}
                toggle={(category) => {
                  if (!total)
                    setRevealOrigin(
                      `${15 + Math.random() * 70}% ${20 + Math.random() * 60}%`,
                    );
                  updateHome((state) => toggleCategory(state, category));
                }}
              />
              {home.error && (
                <p className="notice error" role="alert">
                  {home.error}
                </p>
              )}
              <button
                className={`primary logout-action${ready ? " is-ready" : ""}${scanning && ready ? " scan-pending" : ""}`}
                style={{ "--reveal-origin": revealOrigin } as CSSProperties}
                type="button"
                disabled={busy || scanning || (!!home.inventory && !total)}
                onClick={() => {
                  if (request?.items.length) {
                    storeSelection(request);
                    navigate("review");
                  } else void rescan(true);
                }}
              >
                <span>
                  <DotIcon name="logout" size={36} />
                  {scanning && !home.inventory
                    ? "Checking local accounts…"
                    : home.error
                      ? "Scan again"
                      : !home.inventory
                        ? settings.account_mode === "all-accounts"
                          ? "Check all Windows accounts"
                          : "Check local accounts"
                        : "Log out locally"}
                </span>
                <span className="button-meta">
                  {ready ? "REVIEW FIRST" : ""}
                </span>
              </button>
              <p className="control-help">
                {ready
                  ? "Review the data, then hold to confirm. Nothing is removed yet."
                  : home.inventory
                    ? "Choose categories above, or scan again."
                    : settings.account_mode === "all-accounts"
                      ? "Administrator access is requested only when you choose to check."
                      : "Session data is never read or sent."}
              </p>
              {(unavailable > 0 || !!home.inventory?.coverage.length) && (
                <p className="scope-note">
                  <span className="status-pill warning">Limited coverage</span>
                  {unavailable > 0
                    ? `${unavailable} detected items excluded. `
                    : ""}
                  {home.inventory?.coverage.length
                    ? "Some local stores could not be checked. "
                    : ""}
                  <button
                    className="coverage-link"
                    type="button"
                    disabled={busy || scanning}
                    onClick={() => navigate("advanced")}
                  >
                    Review detected items
                  </button>
                </p>
              )}
              {home.inventory && (
                <button
                  className="text-button rescan-button"
                  type="button"
                  disabled={busy || scanning}
                  onClick={() => void rescan()}
                >
                  Scan again
                </button>
              )}
            </div>
          )}
        </div>
      </main>
      <footer className="app-footer">
        <span className="meta">
          LOCAL ONLY ·{" "}
          {settings?.account_mode === "all-accounts"
            ? "ALL WINDOWS ACCOUNTS"
            : "YOUR WINDOWS ACCOUNT"}
        </span>
        <p>
          Remote sessions stay active. Windows or sync can sign you in again.
        </p>
      </footer>
      {browserPreview && (
        <div className="preview-notice">
          Development preview · Simulated data · No files are deleted
        </div>
      )}
    </div>
  );
}
