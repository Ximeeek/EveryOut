import { StrictMode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import App from "./App";
import * as api from "./client";
import type { ModeFailure, Settings } from "./api";
import { demoInventory, demoPlan } from "./demoFixtures";
import {
  strings as s,
  commandErrors,
  modeFailures,
  unknownError,
} from "./strings";

vi.mock("./client", () => ({
  getSettings: vi.fn(),
  setSettings: vi.fn(),
  enableAllAccountsMode: vi.fn(),
  scan: vi.fn(),
  buildPlan: vi.fn(),
  dryRun: vi.fn(),
  execute: vi.fn(),
  checkCatalogUpdates: vi.fn(),
  activateCatalogUpdate: vi.fn(),
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
  vi.mocked(api.setSettings).mockImplementation(async (next) => {
    persisted = { ...next };
    return { ...persisted };
  });
  vi.mocked(api.scan).mockResolvedValue(demoInventory());
  vi.mocked(api.enableAllAccountsMode).mockImplementation(async () => {
    persisted.account_mode = "all-accounts";
    return {
      effective_mode: "all-accounts",
      requires_fresh_review: true,
      reason: null,
    };
  });
  vi.mocked(api.buildPlan).mockImplementation(async (selection) =>
    demoPlan(selection),
  );
  vi.mocked(api.dryRun).mockImplementation(async () =>
    demoPlan({
      inventory_id: "preview-inventory",
      items: ["Discord"],
      profiles: [],
    }),
  );
});
async function openSettings() {
  const user = userEvent.setup();
  render(<App />);
  await screen.findByRole("button", { name: /Log out locally/ });
  await user.click(
    screen.getByRole("button", { name: "Customize & settings" }),
  );
  await user.click(screen.getByText("Account scope & closing programs"));
  return user;
}

it("automatically scans current-account metadata on first launch with one primary action", async () => {
  render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
  await screen.findByRole("button", { name: /Log out locally/ });
  expect(api.scan).toHaveBeenCalledTimes(1);
  expect(api.setSettings).not.toHaveBeenCalled();
  expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(document.querySelectorAll(".primary")).toHaveLength(1);
  expect(screen.getByText("4 selected")).toBeVisible();
});

it("reaches confirmation in one click and never executes on the initial action", async () => {
  const user = userEvent.setup();
  render(<App />);
  await user.click(
    await screen.findByRole("button", { name: /Log out locally/ }),
  );
  await screen.findByRole("button", { name: /Hold to log out locally/ });
  expect(api.buildPlan).toHaveBeenCalledWith(
    expect.objectContaining({
      items: [
        "Discord",
        "Steam",
        "Spotify",
        "Slack",
        "Chrome",
        "Edge",
        "GitHub CLI",
        "Docker",
      ],
    }),
  );
  expect(api.execute).not.toHaveBeenCalled();
  expect(document.querySelectorAll(".primary")).toHaveLength(1);
  expect(
    screen.getByRole("button", { name: "Customize & settings" }),
  ).toBeDisabled();
});

it("keeps a remembered all-accounts mode inactive until an explicit action", async () => {
  persisted = {
    ...defaults,
    account_mode: "all-accounts",
    first_run_completed: true,
  };
  render(<App />);
  const button = await screen.findByRole("button", {
    name: /Check all Windows accounts/,
  });
  expect(api.scan).not.toHaveBeenCalled();
  expect(api.enableAllAccountsMode).not.toHaveBeenCalled();
  await userEvent.click(button);
  await screen.findByRole("button", { name: /Hold to log out locally/ });
  expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
  expect(api.scan).toHaveBeenCalledTimes(1);
});

it("requires acknowledgment before saving force-close preferences", async () => {
  const user = await openSettings();
  await user.click(screen.getByRole("radio", { name: s.force }));
  expect(screen.getByRole("button", { name: s.save })).toBeDisabled();
  expect(api.setSettings).not.toHaveBeenCalled();
  await user.click(screen.getByRole("checkbox", { name: s.acknowledge }));
  await user.click(screen.getByRole("button", { name: s.save }));
  await screen.findByText(s.saved);
  expect(api.setSettings).toHaveBeenCalledWith({
    ...defaults,
    process_close_policy: "hard-kill-after2s",
    first_run_completed: true,
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

it.each<ModeFailure>([
  "uac-declined",
  "start-failed",
  "authentication-failed",
  "timeout",
  "trust-pin-unavailable",
])(
  "preserves a visible %s fallback and saves only the effective scope",
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
    expect(api.setSettings).toHaveBeenCalledWith({
      ...defaults,
      first_run_completed: true,
    });
    expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
    await waitFor(() =>
      expect(screen.getByRole("radio", { name: s.current })).toBeChecked(),
    );
  },
);

it("reconciles a helper mode change after settings persistence fails", async () => {
  vi.mocked(api.setSettings).mockRejectedValueOnce("settings-io");
  const user = await openSettings();
  await user.click(screen.getByRole("radio", { name: s.all }));
  await user.click(screen.getByRole("button", { name: s.save }));
  expect(await screen.findByRole("alert")).toHaveTextContent(
    commandErrors["settings-io"],
  );
  await waitFor(() =>
    expect(screen.getByRole("radio", { name: s.all })).toBeChecked(),
  );
  await user.click(screen.getByRole("button", { name: s.save }));
  await screen.findByText(s.saved);
  expect(api.enableAllAccountsMode).toHaveBeenCalledTimes(1);
});

it("blocks duplicate settings submissions and sanitizes arbitrary errors", async () => {
  let reject!: (reason: unknown) => void;
  vi.mocked(api.setSettings).mockImplementationOnce(
    () =>
      new Promise((_, fail) => {
        reject = fail;
      }),
  );
  const user = await openSettings();
  await user.dblClick(screen.getByRole("button", { name: s.save }));
  expect(api.setSettings).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("radio", { name: s.all })).toBeDisabled();
  reject({ secret: "private-payload" });
  expect(await screen.findByRole("alert")).toHaveTextContent(unknownError);
  expect(document.body).not.toHaveTextContent("private-payload");
});

it("offers a safe retry after loading settings fails", async () => {
  vi.mocked(api.getSettings).mockRejectedValueOnce("settings-io");
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    commandErrors["settings-io"],
  );
  await userEvent.click(
    screen.getByRole("button", { name: "Reload settings" }),
  );
  await screen.findByRole("button", { name: /Log out locally/ });
  expect(api.setSettings).not.toHaveBeenCalled();
});

it("exposes an explicit scan error and recovers with a fresh inventory", async () => {
  vi.mocked(api.scan).mockRejectedValueOnce("worker-unavailable");
  render(<App />);
  expect(await screen.findByRole("alert")).toHaveTextContent(
    commandErrors["worker-unavailable"],
  );
  await userEvent.click(
    screen.getAllByRole("button", { name: /Scan again/ })[0],
  );
  await screen.findByRole("button", { name: /Hold to log out locally/ });
  expect(api.execute).not.toHaveBeenCalled();
});

it("can reach and operate the main confirmation entirely from the keyboard", async () => {
  const user = userEvent.setup();
  render(<App />);
  const primary = await screen.findByRole("button", {
    name: /Log out locally/,
  });
  primary.focus();
  await user.keyboard("{Enter}");
  const hold = await screen.findByRole("button", {
    name: /Hold to log out locally/,
  });
  hold.focus();
  fireEvent.keyDown(hold, { key: "Enter" });
  fireEvent.keyUp(hold, { key: "Enter" });
  expect(api.execute).not.toHaveBeenCalled();
  expect(hold).toHaveFocus();
});

it("keeps all privacy boundaries available behind the single secondary entry", async () => {
  const user = await openSettings();
  await user.click(screen.getByText("Privacy & supported coverage"));
  for (const [heading, description] of s.limitations) {
    expect(screen.getByText(heading)).toBeVisible();
    expect(screen.getByText(description)).toBeVisible();
  }
});
