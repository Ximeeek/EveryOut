import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import TitleBar from "./TitleBar";
const windowApi = vi.hoisted(() => ({
  minimize: vi.fn(),
  toggleMaximize: vi.fn(),
  close: vi.fn(),
  isMaximized: vi.fn(),
  onResized: vi.fn(),
  unlisten: vi.fn(),
}));
vi.mock("@tauri-apps/api/core", () => ({ isTauri: () => true }));
vi.mock("@tauri-apps/api/window", () => ({
  getCurrentWindow: () => windowApi,
}));
beforeEach(() => {
  vi.resetAllMocks();
  windowApi.isMaximized.mockResolvedValue(false);
  windowApi.onResized.mockResolvedValue(windowApi.unlisten);
  for (const action of [
    windowApi.minimize,
    windowApi.toggleMaximize,
    windowApi.close,
  ])
    action.mockResolvedValue(undefined);
});
it("connects accessible controls to window commands and releases listeners", async () => {
  const user = userEvent.setup();
  const { unmount } = render(
    <TitleBar>
      <button>Customize & settings</button>
    </TitleBar>,
  );
  await user.click(screen.getByRole("button", { name: "Minimize window" }));
  await user.click(screen.getByRole("button", { name: "Maximize window" }));
  await user.click(screen.getByRole("button", { name: "Close window" }));
  expect(windowApi.minimize).toHaveBeenCalledTimes(1);
  expect(windowApi.toggleMaximize).toHaveBeenCalledTimes(1);
  expect(windowApi.close).toHaveBeenCalledTimes(1);
  expect(document.querySelectorAll("[data-tauri-drag-region]")).toHaveLength(1);
  expect(document.querySelector("[data-tauri-drag-region]")?.tagName).toBe(
    "HEADER",
  );
  unmount();
  expect(windowApi.unlisten).toHaveBeenCalledTimes(1);
});
it("names the maximized control Restore and surfaces command failures", async () => {
  windowApi.isMaximized.mockResolvedValue(true);
  windowApi.toggleMaximize.mockRejectedValueOnce(new Error("native error"));
  render(
    <TitleBar>
      <button>Customize & settings</button>
    </TitleBar>,
  );
  await userEvent.click(
    await screen.findByRole("button", { name: "Restore window" }),
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(
    "Couldn’t change the window",
  );
});
