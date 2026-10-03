import { useEffect, useRef, useState } from "react";
import { enableAllAccountsMode, getSettings, setSettings } from "./api";
import type {
  AccountMode,
  CommandError,
  SelectionRequest,
  Settings,
} from "./api";
import Home from "./Home";
import WipeFlow from "./WipeFlow";
import { emptyHome } from "./selection";
import type { HomeState } from "./selection";
import {
  commandErrors,
  modeFailures,
  strings as s,
  unknownError,
  homeStrings as h,
} from "./strings";

type Page = "home" | "settings" | "about" | "review";
type Notice = { text: string; error: boolean } | null;

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
function FirstRun({
  settings,
  busy,
  save,
  notice,
  dismiss,
}: {
  settings: Settings;
  busy: boolean;
  save: (next: Settings) => Promise<void>;
  notice: Notice;
  dismiss: () => void;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const element = dialog.current;
    element?.showModal();
    return () => element?.close();
  }, []);
  return (
    <dialog
      ref={dialog}
      aria-labelledby="welcome-title"
      aria-describedby="welcome-description"
      onCancel={(event) => event.preventDefault()}
    >
      <h2 id="welcome-title">{s.welcome}</h2>
      <p id="welcome-description">{s.introduction}</p>
      <NoticeView notice={notice} dismiss={dismiss} />
      <Preferences
        key={JSON.stringify(settings)}
        settings={settings}
        firstRun
        busy={busy}
        save={save}
      />
    </dialog>
  );
}
export default function App() {
  const [page, setPage] = useState<Page>("home");
  const [settings, updateSettings] = useState<Settings | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [loadAttempt, setLoadAttempt] = useState(0);
  const [loadFailed, setLoadFailed] = useState(false);
  const [formVersion, setFormVersion] = useState(0);
  const [home, updateHome] = useState<HomeState>(emptyHome);
  const [selection, storeSelection] = useState<SelectionRequest | null>(null);
  const title = useRef<HTMLHeadingElement>(null);
  const saving = useRef(false);
  useEffect(() => {
    let active = true;
    getSettings()
      .then((value) => {
        if (active) {
          updateSettings(value);
          setLoadFailed(false);
          setNotice(null);
        }
      })
      .catch((error: unknown) => {
        if (active) {
          setLoadFailed(true);
          setNotice({ text: errorText(error), error: true });
        }
      });
    return () => {
      active = false;
    };
  }, [loadAttempt]);

  const firstRun = settings !== null && !settings.first_run_completed;
  async function save(next: Settings) {
    if (saving.current) return;
    saving.current = true;
    updateHome(emptyHome);
    storeSelection(null);
    setBusy(true);
    setNotice(null);
    let fallback: string | null = null;
    try {
      if (
        next.account_mode === "all-accounts" &&
        (firstRun || settings?.account_mode !== "all-accounts")
      ) {
        const result = await enableAllAccountsMode();
        next = { ...next, account_mode: result.effective_mode };
        if (result.effective_mode === "current") {
          fallback = result.reason ? modeFailures[result.reason] : s.fallback;
          setNotice({ text: fallback, error: true });
        }
      }
      const saved = await setSettings(next);
      updateSettings(saved);
      setFormVersion((version) => version + 1);
      setNotice({ text: fallback ?? s.saved, error: fallback !== null });
    } catch (error: unknown) {
      setNotice({
        text: fallback ? `${fallback} ${errorText(error)}` : errorText(error),
        error: true,
      });
      // Enabling the helper may already have changed persisted account mode.
      try {
        updateSettings(await getSettings());
        setFormVersion((version) => version + 1);
      } catch {
        /* Keep the command error visible. */
      }
    } finally {
      saving.current = false;
      setBusy(false);
    }
  }
  return (
    <>
      <div className="app-shell" inert={firstRun}>
        <a className="skip-link" href="#content">
          {s.skip}
        </a>
        <header>
          <div>
            <h1>{s.appName}</h1>
            <p className="muted">{s.platform}</p>
          </div>
          <nav aria-label={s.navigation}>
            {(["home", "settings", "about"] as const).map((route) => (
              <button
                key={route}
                type="button"
                aria-current={page === route ? "page" : undefined}
                disabled={busy || page === "review"}
                onClick={() => {
                  setPage(route);
                  requestAnimationFrame(() => title.current?.focus());
                }}
              >
                {s[route]}
              </button>
            ))}
          </nav>
        </header>
        <main id="content" tabIndex={-1}>
          {!firstRun && (
            <NoticeView notice={notice} dismiss={() => setNotice(null)} />
          )}
          {!settings ? (
            <section className="panel">
              {loadFailed ? (
                <button
                  type="button"
                  onClick={() => {
                    setLoadFailed(false);
                    setNotice(null);
                    setLoadAttempt((attempt) => attempt + 1);
                  }}
                >
                  {s.retry}
                </button>
              ) : (
                <p role="status">{s.loading}</p>
              )}
            </section>
          ) : (
            <section className="panel" aria-busy={busy}>
              <h2 ref={title} tabIndex={-1}>
                {page === "home"
                  ? s.homeTitle
                  : page === "settings"
                    ? s.settings
                    : page === "review"
                      ? h.reviewTitle
                      : s.aboutTitle}
              </h2>
              {page === "home" && (
                <>
                  <p>{s.homeDescription}</p>
                  <Home
                    state={home}
                    update={updateHome}
                    busy={busy}
                    setBusy={setBusy}
                    disabled={firstRun}
                    review={(request) => {
                      storeSelection(request);
                      setPage("review");
                      requestAnimationFrame(() => title.current?.focus());
                    }}
                  />
                </>
              )}
              {page === "review" && selection && home.inventory && (
                <WipeFlow
                  inventory={home.inventory}
                  selection={selection}
                  setBusy={setBusy}
                  back={() => {
                    updateHome(emptyHome);
                    storeSelection(null);
                    setPage("home");
                    requestAnimationFrame(() => title.current?.focus());
                  }}
                />
              )}
              {page === "settings" && !firstRun && (
                <Preferences
                  key={formVersion}
                  settings={settings}
                  firstRun={false}
                  busy={busy}
                  save={save}
                />
              )}
              {page === "about" && (
                <>
                  <p>{s.aboutIntro}</p>
                  <dl className="limitations">
                    {s.limitations.map(([heading, description]) => (
                      <div key={heading}>
                        <dt>{heading}</dt>
                        <dd>{description}</dd>
                      </div>
                    ))}
                  </dl>
                  <p className="muted">{s.aboutClosing}</p>
                </>
              )}
            </section>
          )}
        </main>
      </div>
      {firstRun && (
        <FirstRun
          key={formVersion}
          settings={settings}
          busy={busy}
          save={save}
          notice={notice}
          dismiss={() => setNotice(null)}
        />
      )}
    </>
  );
}
