import { useCallback, useEffect, useRef, useState } from "react";
import type { CSSProperties } from "react";
import DotIcon from "./DotIcon";

export const HOLD_DURATION = 1200;

export default function HoldButton({
  label,
  disabled = false,
  onConfirm,
}: {
  label: string;
  disabled?: boolean;
  onConfirm: () => void;
}) {
  const [progress, setProgress] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const source = useRef<"pointer" | "keyboard" | null>(null);
  const completed = useRef(false);
  const cancel = useCallback(() => {
    if (timer.current) clearInterval(timer.current);
    timer.current = null;
    source.current = null;
    setProgress(0);
  }, []);
  useEffect(() => {
    const interrupt = () => cancel();
    window.addEventListener("blur", interrupt);
    document.addEventListener("visibilitychange", interrupt);
    return () => {
      if (timer.current) clearInterval(timer.current);
      window.removeEventListener("blur", interrupt);
      document.removeEventListener("visibilitychange", interrupt);
    };
  }, [cancel]);
  function begin(input: "pointer" | "keyboard") {
    if (disabled || timer.current || completed.current) return;
    source.current = input;
    const started = performance.now();
    setProgress(0.01);
    timer.current = setInterval(() => {
      const elapsed = performance.now() - started;
      const fraction = Math.min(elapsed / HOLD_DURATION, 1);
      setProgress(fraction * fraction * (3 - 2 * fraction));
      if (elapsed >= HOLD_DURATION) {
        completed.current = true;
        cancel();
        onConfirm();
      }
    }, 20);
  }
  return (
    <div className="hold-control">
      <button
        className={`primary hold-button${progress > 0 ? " is-holding" : ""}`}
        type="button"
        disabled={disabled}
        aria-describedby="hold-help"
        style={{ "--hold-duration": `${HOLD_DURATION}ms` } as CSSProperties}
        onPointerDown={(event) => {
          if (event.button === 0) begin("pointer");
        }}
        onPointerUp={() => {
          if (source.current === "pointer") cancel();
        }}
        onPointerLeave={cancel}
        onPointerCancel={cancel}
        onLostPointerCapture={cancel}
        onBlur={cancel}
        onKeyDown={(event) => {
          if (event.key === "Escape") cancel();
          if (event.key === " " || event.key === "Enter") {
            event.preventDefault();
            if (!event.repeat) begin("keyboard");
          }
        }}
        onKeyUp={(event) => {
          if (event.key === " " || event.key === "Enter") {
            event.preventDefault();
            if (source.current === "keyboard") cancel();
          }
        }}
        onContextMenu={(event) => event.preventDefault()}
      >
        <span>
          <DotIcon
            name={progress ? "grid" : "logout"}
            size={22}
            fill={progress || 1}
          />
          {label}
        </span>
        <span className="button-meta">1.2 SEC</span>
      </button>
      <p id="hold-help" className="control-help">
        Hold with your mouse, Space or Enter. Release to cancel.
      </p>
      <span className="sr-only" role="status">
        {progress > 0
          ? "Keep holding to confirm. Release to cancel."
          : "Confirmation ready."}
      </span>
    </div>
  );
}
