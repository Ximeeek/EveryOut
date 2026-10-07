import { useEffect, useState, type ReactNode } from "react";
import { isTauri } from "@tauri-apps/api/core";
import { getCurrentWindow } from "@tauri-apps/api/window";
import DotIcon from "./DotIcon";

export default function TitleBar({
  children,
  onBrandClick,
}: {
  children: ReactNode;
  onBrandClick?: () => void;
}) {
  const [maximized, setMaximized] = useState(false);
  const [error, setError] = useState(false);
  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    let dispose: (() => void) | undefined;
    const window = getCurrentWindow();
    const refresh = () =>
      void window
        .isMaximized()
        .then((value) => {
          if (active) setMaximized(value);
        })
        .catch(() => {
          if (active) setError(true);
        });
    refresh();
    void window
      .onResized(refresh)
      .then((unlisten) => {
        if (active) dispose = unlisten;
        else unlisten();
      })
      .catch(() => {
        if (active) setError(true);
      });
    return () => {
      active = false;
      dispose?.();
    };
  }, []);
  function control(action: "minimize" | "toggleMaximize" | "close") {
    if (!isTauri()) return;
    setError(false);
    const window = getCurrentWindow();
    void window[action]().catch(() => setError(true));
  }
  return (
    <>
      <header className="app-header" data-tauri-drag-region>
        <button
          className="brand"
          type="button"
          aria-label="EveryOut — main menu"
          onClick={onBrandClick}
        >
          <span>EveryOut</span>
        </button>
        <div className="title-actions">
          {children}
          <div className="window-controls">
            <button
              type="button"
              aria-label="Minimize window"
              onClick={() => control("minimize")}
            >
              <DotIcon name="minimize" size={20} />
            </button>
            <button
              type="button"
              aria-label={maximized ? "Restore window" : "Maximize window"}
              onClick={() => control("toggleMaximize")}
            >
              <DotIcon name={maximized ? "restore" : "maximize"} size={20} />
            </button>
            <button
              type="button"
              className="window-close"
              aria-label="Close window"
              onClick={() => control("close")}
            >
              <DotIcon name="close" size={20} />
            </button>
          </div>
        </div>
      </header>
      {error && (
        <p className="window-error" role="alert">
          Couldn’t change the window. Try again.
        </p>
      )}
    </>
  );
}
