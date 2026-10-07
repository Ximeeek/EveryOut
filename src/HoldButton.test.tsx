import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import HoldButton, { HOLD_DURATION } from "./HoldButton";

beforeEach(() =>
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "performance"] }),
);
afterEach(() => vi.useRealTimers());
const advance = (ms: number) => act(() => vi.advanceTimersByTime(ms));

it.each([" ", "Enter"])(
  "requires a full hold with %s and cancels early release",
  (key) => {
    const confirm = vi.fn();
    render(<HoldButton label="Hold to confirm" onConfirm={confirm} />);
    const button = screen.getByRole("button");
    fireEvent.keyDown(button, { key });
    advance(900);
    fireEvent.keyUp(button, { key });
    advance(HOLD_DURATION);
    expect(confirm).not.toHaveBeenCalled();
    fireEvent.keyDown(button, { key });
    fireEvent.keyDown(button, { key, repeat: true });
    advance(HOLD_DURATION);
    expect(confirm).toHaveBeenCalledTimes(1);
    fireEvent.keyUp(button, { key });
    fireEvent.keyDown(button, { key });
    advance(HOLD_DURATION * 2);
    expect(confirm).toHaveBeenCalledTimes(1);
  },
);

it.each(["escape", "blur", "window-blur", "hidden", "unmount"])(
  "cancels confirmation on %s",
  (reason) => {
    const confirm = vi.fn();
    const view = render(
      <HoldButton label="Hold to confirm" onConfirm={confirm} />,
    );
    const button = screen.getByRole("button");
    fireEvent.keyDown(button, { key: "Enter" });
    advance(800);
    if (reason === "escape") fireEvent.keyDown(button, { key: "Escape" });
    if (reason === "blur") fireEvent.blur(button);
    if (reason === "window-blur") fireEvent(window, new Event("blur"));
    if (reason === "hidden") fireEvent(document, new Event("visibilitychange"));
    if (reason === "unmount") view.unmount();
    advance(HOLD_DURATION);
    expect(confirm).not.toHaveBeenCalled();
  },
);

it("never confirms a normal click or a disabled control", () => {
  const confirm = vi.fn();
  const view = render(
    <HoldButton label="Hold to confirm" onConfirm={confirm} />,
  );
  fireEvent.click(screen.getByRole("button"));
  advance(HOLD_DURATION);
  expect(confirm).not.toHaveBeenCalled();
  view.rerender(
    <HoldButton label="Hold to confirm" onConfirm={confirm} disabled />,
  );
  fireEvent.keyDown(screen.getByRole("button"), { key: "Enter" });
  advance(HOLD_DURATION);
  expect(confirm).not.toHaveBeenCalled();
});
