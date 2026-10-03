import { StrictMode } from "react";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "./api";
import type { ModeFailure, Settings } from "./api";
import {
  commandErrors,
  modeFailures,
  strings as s,
  unknownError,
} from "./strings";

vi.mock("./api", () => ({
  getSettings: vi.fn(),
  setSettings: vi.fn(),
  enableAllAccountsMode: vi.fn(),
}));
const defaults: Settings = {
  process_close_policy: "ask",
  account_mode: "current",
  first_run_completed: false,
};
let persisted: Settings;
beforeEach(() => {
  vi.resetAllMocks();
  persisted = { ...defaults };
  vi.mocked(api.getSettings).mockImplementation(async () => ({ ...persisted }));
  vi.mocked(api.setSettings).mockImplementation(async (settings) => {
    persisted = { ...settings };
    return { ...persisted };
  });
  vi.mocked(api.enableAllAccountsMode).mockImplementation(async () => {
    persisted.account_mode = "all-accounts";
    return {
      effective_mode: "all-accounts",
      requires_fresh_review: true,
      reason: null,
    };
  });
});
async function openSettings() {
  persisted.first_run_completed = true;
  const user = userEvent.setup();
  render(<App />);
  await screen.findByText(s.placeholder);
  await user.click(screen.getByRole("button", { name: s.settings }));
  return user;
}
describe("first run", () => {
  it("defaults to current, persists completion and never shows again after remount", async () => {
    const user = userEvent.setup();
    const view = render(
      <StrictMode>
        <App />
      </StrictMode>,
    );
    const dialog = await screen.findByRole("dialog", { name: s.welcome });
    expect(
      within(dialog).getByRole("radio", { name: s.current }),
    ).toBeChecked();
    expect(document.querySelector(".app-shell")).toHaveAttribute("inert");
    await user.click(within(dialog).getByRole("button", { name: s.continue }));
    await waitFor(() =>
      expect(screen.queryByRole("dialog")).not.toBeInTheDocument(),
    );
    expect(api.setSettings).toHaveBeenCalledWith({
      ...defaults,
      first_run_completed: true,
    });
    expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
    view.unmount();
    render(<App />);
    await screen.findByText(s.placeholder);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  it("enables all accounts only on explicit submission and persists that answer", async () => {
    const user = userEvent.setup();
    render(<App />);
    const dialog = await screen.findByRole("dialog");
    await user.click(within(dialog).getByRole("radio", { name: s.all }));
    expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: s.continue }));
    await screen.findByText(s.saved);
    expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
    expect(api.setSettings).toHaveBeenCalledWith({
      ...defaults,
      account_mode: "all-accounts",
      first_run_completed: true,
    });
    expect(
      vi.mocked(api.enableAllAccountsMode).mock.invocationCallOrder[0],
    ).toBeLessThan(vi.mocked(api.setSettings).mock.invocationCallOrder[0]);
  });
  it("persists current mode and completion after declined UAC", async () => {
    vi.mocked(api.enableAllAccountsMode).mockResolvedValue({
      effective_mode: "current",
      requires_fresh_review: true,
      reason: "uac-declined",
    });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("dialog");
    await user.click(screen.getByRole("radio", { name: s.all }));
    await user.click(screen.getByRole("button", { name: s.continue }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      modeFailures["uac-declined"],
    );
    expect(api.setSettings).toHaveBeenCalledWith({
      ...defaults,
      first_run_completed: true,
    });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: s.settings }));
    expect(screen.getByRole("radio", { name: s.current })).toBeChecked();
  });
  it("keeps the dialog incomplete after a failed save and permits retry", async () => {
    vi.mocked(api.setSettings).mockRejectedValueOnce("settings-io");
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("dialog");
    await user.click(screen.getByRole("button", { name: s.continue }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      commandErrors["settings-io"],
    );
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(persisted.first_run_completed).toBe(false);
    await user.click(screen.getByRole("button", { name: s.continue }));
    await screen.findByText(s.saved);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
  it("requests explicit enablement when an incomplete first run remembers all accounts", async () => {
    persisted.account_mode = "all-accounts";
    const user = userEvent.setup();
    render(<App />);
    await screen.findByRole("dialog");
    expect(screen.getByRole("radio", { name: s.current })).toBeChecked();
    expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
    await user.click(screen.getByRole("radio", { name: s.all }));
    await user.click(screen.getByRole("button", { name: s.continue }));
    await screen.findByText(s.saved);
    expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
  });
});
describe("settings", () => {
  it("requires warning acknowledgment and persists both process policies", async () => {
    const user = await openSettings();
    expect(screen.getByText(s.forceWarning)).toBeVisible();
    await user.click(screen.getByRole("radio", { name: s.force }));
    expect(screen.getByRole("button", { name: s.save })).toBeDisabled();
    expect(api.setSettings).not.toHaveBeenCalled();
    await user.click(screen.getByRole("checkbox", { name: s.acknowledge }));
    await user.click(screen.getByRole("button", { name: s.save }));
    await screen.findByText(s.saved);
    expect(api.setSettings).toHaveBeenLastCalledWith({
      ...defaults,
      first_run_completed: true,
      process_close_policy: "hard-kill-after2s",
    });
    await user.click(screen.getByRole("radio", { name: s.ask }));
    await user.click(screen.getByRole("button", { name: s.save }));
    await waitFor(() =>
      expect(api.setSettings).toHaveBeenLastCalledWith({
        ...defaults,
        first_run_completed: true,
      }),
    );
  });
  it("enables and disables all accounts, preserving process policy", async () => {
    persisted = { ...defaults, process_close_policy: "hard-kill-after2s" };
    const user = await openSettings();
    await user.click(screen.getByRole("radio", { name: s.all }));
    await user.click(screen.getByRole("button", { name: s.save }));
    await screen.findByText(s.saved);
    expect(api.setSettings).toHaveBeenLastCalledWith({
      account_mode: "all-accounts",
      first_run_completed: true,
      process_close_policy: "hard-kill-after2s",
    });
    await user.click(screen.getByRole("radio", { name: s.current }));
    await user.click(screen.getByRole("button", { name: s.save }));
    await waitFor(() =>
      expect(api.setSettings).toHaveBeenLastCalledWith({
        ...persisted,
        account_mode: "current",
      }),
    );
    expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
  });
  it.each<ModeFailure>([
    "uac-declined",
    "start-failed",
    "authentication-failed",
    "timeout",
    "trust-pin-unavailable",
  ])(
    "shows %s and keeps current-account mode without repeating UAC",
    async (reason) => {
      vi.mocked(api.enableAllAccountsMode).mockResolvedValue({
        effective_mode: "current",
        requires_fresh_review: true,
        reason,
      });
      const user = await openSettings();
      await user.click(screen.getByRole("radio", { name: s.all }));
      await user.click(screen.getByRole("button", { name: s.save }));
      expect(await screen.findByRole("alert")).toHaveTextContent(
        modeFailures[reason],
      );
      await waitFor(() =>
        expect(screen.getByRole("radio", { name: s.current })).toBeChecked(),
      );
      expect(api.setSettings).toHaveBeenCalledWith({
        ...defaults,
        first_run_completed: true,
      });
      expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
    },
  );
  it("does not request UAC on startup or an unchanged remembered preference", async () => {
    persisted.account_mode = "all-accounts";
    const user = await openSettings();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("radio", { name: s.all })).toBeChecked();
    await user.click(screen.getByRole("button", { name: s.save }));
    await screen.findByText(s.saved);
    expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
  });
  it("retains the saved choice on failure and never renders arbitrary error payloads", async () => {
    vi.mocked(api.setSettings).mockRejectedValue({
      secret: "private-system-payload",
    });
    const user = await openSettings();
    await user.click(screen.getByRole("radio", { name: s.force }));
    await user.click(screen.getByRole("checkbox", { name: s.acknowledge }));
    await user.click(screen.getByRole("button", { name: s.save }));
    expect(await screen.findByRole("alert")).toHaveTextContent(unknownError);
    expect(document.body).not.toHaveTextContent("private-system-payload");
    expect(persisted.process_close_policy).toBe("ask");
    await user.click(screen.getByRole("button", { name: s.dismiss }));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
  it("reconciles a helper mode change if the subsequent settings save fails", async () => {
    vi.mocked(api.setSettings).mockRejectedValueOnce("settings-io");
    const user = await openSettings();
    await user.click(screen.getByRole("radio", { name: s.all }));
    await user.click(screen.getByRole("button", { name: s.save }));
    await screen.findByRole("alert");
    await waitFor(() =>
      expect(screen.getByRole("radio", { name: s.all })).toBeChecked(),
    );
    await user.click(screen.getByRole("button", { name: s.save }));
    await screen.findByText(s.saved);
    expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
  });
  it("blocks duplicate submission while a command is pending", async () => {
    let finish!: (value: Settings) => void;
    vi.mocked(api.setSettings).mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = resolve;
        }),
    );
    const user = await openSettings();
    await user.dblClick(screen.getByRole("button", { name: s.save }));
    expect(api.setSettings).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: s.saving })).toBeDisabled();
    expect(screen.getByRole("radio", { name: s.all })).toBeDisabled();
    finish({ ...defaults, first_run_completed: true });
    await screen.findByText(s.saved);
  });
});
it("offers retry after initial settings loading fails", async () => {
  vi.mocked(api.getSettings).mockRejectedValueOnce("settings-io");
  const user = userEvent.setup();
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    commandErrors["settings-io"],
  );
  expect(api.setSettings).not.toHaveBeenCalled();
  await user.click(screen.getByRole("button", { name: s.retry }));
  await screen.findByRole("dialog");
});
it("shows every About limitation from the strings module and navigates back home", async () => {
  const user = await openSettings();
  await user.click(screen.getByRole("button", { name: s.about }));
  expect(
    screen.getByRole("heading", { name: s.aboutTitle }),
  ).toBeInTheDocument();
  for (const [heading, description] of s.limitations) {
    expect(screen.getByText(heading)).toBeVisible();
    expect(screen.getByText(description)).toBeVisible();
  }
  await user.click(screen.getByRole("button", { name: s.home }));
  expect(screen.getByText(s.placeholder)).toBeVisible();
  expect(api.setSettings).not.toHaveBeenCalled();
  expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
});
