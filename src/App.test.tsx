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
  await user.click(screen.getByRole("button", { name: "Settings" }));
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
  expect(
    screen.getByRole("checkbox", { name: "Apps: 4 of 4 selected" }),
  ).toBeVisible();
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
  expect(screen.getByRole("button", { name: "Settings" })).toBeDisabled();
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
  await waitFor(() =>
    expect(screen.getByRole("radio", { name: s.ask })).toBeEnabled(),
  );
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

it("selects and clears categories on the overview with keyboard navigation", async () => {
  const user = userEvent.setup();
  render(<App />);
  await screen.findByRole("button", { name: /Log out locally/ });
  const apps = screen.getByRole("checkbox", { name: "Apps: 4 of 4 selected" });
  expect(apps).toBeChecked();
  apps.focus();
  await user.keyboard(" ");
  expect(apps).not.toBeChecked();
  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "4 sessions will be cleared",
  );
  await user.keyboard("{ArrowRight}");
  const browsers = screen.getByRole("checkbox", {
    name: "Browsers: 2 of 2 selected",
  });
  expect(browsers).toHaveFocus();
  await user.keyboard("{Enter}{ArrowRight}{Enter}");
  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "Nothing selected",
  );
  expect(
    screen.getByRole("button", { name: /Log out locally/ }),
  ).toBeDisabled();
  await user.keyboard("{ArrowRight}{Enter}");
  expect(screen.getByRole("button", { name: /Log out locally/ })).toBeEnabled();
  expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
    "4 sessions will be cleared",
  );
  expect(api.execute).not.toHaveBeenCalled();
});
it("shows independent rescan deltas while preserving previous counts during the scan", async () => {
  const user = userEvent.setup();
  const next = demoInventory();
  next.groups[0].items.push({ ...next.groups[0].items[0], id: "new-app" });
  next.groups[1].items.pop();
  vi.mocked(api.scan)
    .mockResolvedValueOnce(demoInventory())
    .mockResolvedValueOnce(next);
  render(<App />);
  await screen.findByRole("button", { name: /Log out locally/ });
  await user.click(screen.getByRole("button", { name: "Scan again" }));
  expect(
    screen.getByRole("checkbox", { name: "Apps: 4 of 4 selected" }),
  ).toBeDisabled();
  expect(screen.queryByText("Checking…")).not.toBeInTheDocument();
  expect(await screen.findByText("+1")).toBeVisible();
  expect(screen.getByText("−1")).toBeVisible();
  expect(screen.getByText("No change")).toBeVisible();
  expect(api.execute).not.toHaveBeenCalled();
});

it("keeps the rescan surface stable and preserves unchecked medium-confidence categories", async () => {
  const user = userEvent.setup();
  const inventory = demoInventory();
  inventory.groups.forEach((group) => {
    group.confidence = "medium";
  });
  vi.mocked(api.scan).mockResolvedValue(inventory);
  render(<App />);
  await screen.findByRole("button", { name: /Log out locally/ });
  const apps = screen.getByRole("checkbox", { name: "Apps: 4 of 4 selected" });
  expect(apps).toBeEnabled();
  await user.click(apps);
  const primary = screen.getByRole("button", { name: /Log out locally/ });
  const description = document.querySelector(".hero-description")!.textContent;
  const meta = document.querySelector(".hero .meta")!.textContent;
  await user.click(screen.getByRole("button", { name: "Scan again" }));
  expect(primary).toHaveTextContent("Log out locally");
  expect(primary).toHaveClass("scan-pending");
  expect(document.querySelector(".hero-description")!.textContent).toBe(
    description,
  );
  expect(document.querySelector(".hero .meta")!.textContent).toBe(meta);
  expect(
    document.querySelectorAll(".category-summary .dot-animated"),
  ).toHaveLength(0);
  expect(
    screen
      .getByRole("heading", { name: "Finding your sessions" })
      .querySelector(".hero-title-text"),
  ).not.toBeNull();
  expect(screen.getByText("items selected", { exact: false })).toBeVisible();
  await screen.findByRole("heading", { name: "4 sessions will be cleared" });
  expect(
    screen.getByRole("checkbox", { name: "Apps: 0 of 4 selected" }),
  ).not.toBeChecked();
  expect(
    document.querySelector(".delta-pill.neutral .delta-beacon"),
  ).not.toBeNull();
  expect(api.execute).not.toHaveBeenCalled();
});
