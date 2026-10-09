import { StrictMode } from "react";
import {
  act,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import WipeFlow from "./WipeFlow";
import Reports from "./Reports";
import * as api from "./client";
import type { PlanDto, ReportDto, WipeEvent } from "./api";
import { defaultSelection, selectionRequest } from "./selection";
import { demoInventory, demoPlan, demoResult } from "./demoFixtures";
import { unknownError, wipeStrings as w } from "./strings";
import { HOLD_DURATION } from "./HoldButton";

vi.mock("./client", () => ({
  buildPlan: vi.fn(),
  dryRun: vi.fn(),
  scan: vi.fn(),
  execute: vi.fn(),
  cancel: vi.fn(),
  closeReviewed: vi.fn(),
  exportReport: vi.fn(),
}));
const selection = selectionRequest(defaultSelection(demoInventory()))!;
let preview: PlanDto;
let events: (event: WipeEvent) => void;
const back = vi.fn();
const setBusy = vi.fn();

beforeEach(() => {
  vi.resetAllMocks();
  preview = demoPlan(selection);
  vi.mocked(api.buildPlan).mockImplementation(async () =>
    structuredClone(preview),
  );
  vi.mocked(api.dryRun).mockImplementation(async () =>
    structuredClone(preview),
  );
  vi.mocked(api.scan).mockResolvedValue(demoInventory());
  vi.mocked(api.closeReviewed).mockResolvedValue(preview.report);
  vi.mocked(api.execute).mockImplementation(async (_, onEvent) => {
    events = onEvent;
    return { run_id: preview.plan_id };
  });
  vi.mocked(api.cancel).mockResolvedValue();
  vi.mocked(api.exportReport).mockResolvedValue("reports/fixture.json");
});
afterEach(() => vi.useRealTimers());

async function mount(strict = false) {
  const flow = (
    <WipeFlow
      inventory={demoInventory()}
      selection={selection}
      setBusy={setBusy}
      back={back}
    />
  );
  render(strict ? <StrictMode>{flow}</StrictMode> : flow);
  return screen.findByRole("button", { name: /Hold to/ });
}
async function hold(button = screen.getByRole("button", { name: /Hold to/ })) {
  vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "performance"] });
  fireEvent.keyDown(button, { key: " " });
  await act(async () => {
    vi.advanceTimersByTime(HOLD_DURATION);
  });
  fireEvent.keyUp(button, { key: " " });
  vi.useRealTimers();
}
function finish(report: ReportDto = demoResult(preview)) {
  act(() => events({ kind: "finished", run_id: preview.plan_id, report }));
}

it("previews metadata once in StrictMode, with no deletion or checkbox gates", async () => {
  await mount(true);
  expect(api.buildPlan).toHaveBeenCalledTimes(1);
  expect(api.buildPlan).toHaveBeenCalledWith(selection);
  expect(api.dryRun).toHaveBeenCalledWith(preview.plan_id);
  expect(screen.queryByRole("checkbox")).not.toBeInTheDocument();
  expect(
    screen.getByText(/Also at risk: local app settings, offline drafts/),
  ).toBeVisible();
  expect(api.execute).not.toHaveBeenCalled();
  expect(api.closeReviewed).not.toHaveBeenCalled();
  await userEvent.click(screen.getByText(/Review 8 selected items/));
  expect(screen.getByText("Discord/session-store")).toBeVisible();
});

it("reviews supported saved-login changes without claiming unrelated permanent loss", async () => {
  const spotify = preview.report.accounts[0].sections[0].items.find(
    (item) => item.provider === "Spotify",
  )!;
  spotify.provider = "spotify";
  spotify.loss = "none";
  spotify.risks = [];
  spotify.limitations = ["local-saved-login-only", "no-remote-revocation"];
  spotify.confirmations = [
    "review-candidate-provider-spotify",
    "review-spotify-permanent-loss",
  ];
  spotify.affected_data = [
    "Saved desktop login; sign in again to use your account",
  ];
  spotify.processes = [];
  preview.report.accounts[0].sections.forEach((section, index) => {
    section.items = index === 0 ? [spotify] : [];
  });
  await mount();
  expect(screen.getByText("Local sign-out")).toBeVisible();
  expect(screen.queryByText("Permanent deletion")).not.toBeInTheDocument();
  expect(
    screen.queryByText(/EveryOut has no verified automatic logout/),
  ).not.toBeInTheDocument();
  await hold();
  expect(api.execute).toHaveBeenCalledWith(
    expect.objectContaining({
      confirmed_risks: [
        expect.objectContaining({
          flags: [],
          confirmations: spotify.confirmations,
        }),
      ],
    }),
    expect.any(Function),
  );
});

it("explains an unsupported Spotify cleanup without offering execution or closing", async () => {
  const spotify = preview.report.accounts[0].sections[0].items.find(
    (item) => item.provider === "Spotify",
  )!;
  spotify.provider = "spotify";
  spotify.limitations = [
    "unknown-authentication-closure",
    "unreviewed-preservation",
  ];
  spotify.actions.forEach((action) => {
    action.outcome = "blocked";
  });
  spotify.processes = ["open-spotify"];
  preview.report.accounts[0].sections.forEach((section, index) => {
    section.items = index === 0 ? [spotify] : [];
  });
  render(
    <WipeFlow
      inventory={demoInventory()}
      selection={selection}
      setBusy={setBusy}
      back={back}
    />,
  );
  await screen.findByText("Automatic cleanup unavailable");
  expect(
    screen.getAllByText(/Closing the app does not resolve/)[0],
  ).toBeVisible();
  expect(
    screen.getAllByText(/In Spotify, click your profile picture/)[0],
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: /Hold to/ }),
  ).not.toBeInTheDocument();
  expect(screen.queryByText("Save your work first")).not.toBeInTheDocument();
  expect(api.execute).not.toHaveBeenCalled();
  expect(api.closeReviewed).not.toHaveBeenCalled();
  await userEvent.click(
    screen.getByRole("button", { name: "Back to overview" }),
  );
  expect(back).toHaveBeenCalledWith(false);
});

it("sends every plan-bound risk, confirmation and category token only after the full hold", async () => {
  const button = await mount();
  fireEvent.click(button);
  expect(api.execute).not.toHaveBeenCalled();
  await hold(button);
  expect(api.execute).toHaveBeenCalledTimes(1);
  expect(api.execute).toHaveBeenCalledWith(
    {
      plan_id: preview.plan_id,
      confirmed_risks: preview.report.accounts[0].sections.flatMap((section) =>
        section.items.map((item) => ({
          account: "current-account",
          instance: item.instance,
          flags: item.risks,
          confirmations: item.confirmations,
        })),
      ),
      category_tokens: ["preview-category-token"],
      force_close_accounts: [],
    },
    expect.any(Function),
  );
  expect(screen.getByRole("heading", { name: "Letting go" })).toBeVisible();
  finish();
  expect(screen.getByRole("heading", { name: "Done" })).toBeVisible();
  expect(screen.getByText("Verified locally")).toBeVisible();
  await userEvent.click(
    screen.getByRole("button", { name: "Back to overview" }),
  );
  expect(back).toHaveBeenCalledWith(true);
});

it("requests graceful closure after a deliberate hold, then requires a new hold on a fresh plan", async () => {
  preview.report.accounts[0].sections[0].items[0].processes = [
    "Discord-preview-process",
  ];
  await mount();
  vi.mocked(api.closeReviewed).mockImplementation(async () => {
    preview = demoPlan(selection);
    preview.plan_id = "fresh-plan";
    return preview.report;
  });
  await hold();
  expect(api.closeReviewed).toHaveBeenCalledTimes(1);
  expect(api.execute).not.toHaveBeenCalled();
  const button = await screen.findByRole("button", {
    name: /Hold to log out locally/,
  });
  await hold(button);
  expect(api.execute).toHaveBeenCalledWith(
    expect.objectContaining({
      plan_id: "fresh-plan",
      force_close_accounts: [],
    }),
    expect.any(Function),
  );
});

it("can recheck manually closed programs without requesting closure", async () => {
  preview.report.accounts[0].sections[0].items[0].processes = [
    "Discord-preview-process",
  ];
  await mount();
  preview = demoPlan(selection);
  await userEvent.click(
    screen.getByRole("button", { name: "I closed them — check again" }),
  );
  await screen.findByRole("button", {
    name: /Hold to log out locally/,
  });
  expect(api.closeReviewed).not.toHaveBeenCalled();
  expect(api.execute).not.toHaveBeenCalled();
});

it("does not force close in Ask mode and can skip only affected items", async () => {
  preview.report.accounts[0].sections[1].items[0].processes = [
    "Chrome-preview-process",
  ];
  await mount();
  vi.mocked(api.buildPlan).mockImplementation(async (request) => {
    preview = demoPlan(request);
    return preview;
  });
  await userEvent.click(
    screen.getByRole("button", { name: "Skip open programs" }),
  );
  await screen.findByRole("button", {
    name: /Hold to log out locally/,
  });
  expect(api.buildPlan).toHaveBeenLastCalledWith(
    expect.objectContaining({
      skipped: ["Chrome"],
      items: selection.items.filter((id) => id !== "Chrome"),
      profiles: selection.profiles.filter(
        (profile) => profile.item !== "Chrome",
      ),
    }),
  );
  expect(api.execute).not.toHaveBeenCalled();
  expect(api.closeReviewed).not.toHaveBeenCalled();
});

it("shows the force-close loss warning and sends only reviewed account acknowledgments", async () => {
  preview.report.process_close_policy = "hard-kill-after2s";
  preview.report.accounts[0].sections[0].items[0].processes = [
    "Discord-preview-process",
  ];
  await mount();
  expect(
    screen.getByText(/Force closing can destroy unsaved work/),
  ).toBeVisible();
  expect(api.execute).not.toHaveBeenCalled();
  await hold();
  expect(api.execute).toHaveBeenCalledWith(
    expect.objectContaining({ force_close_accounts: ["current-account"] }),
    expect.any(Function),
  );
});

it("filters foreign events, exposes category progress and stops only the active run", async () => {
  await mount();
  await hold();
  act(() => {
    events({
      kind: "progress",
      run_id: "foreign",
      account: "current-account",
      category: "browser",
      stage: "cleaning",
      instance: null,
      action: null,
    });
    events({
      kind: "progress",
      run_id: preview.plan_id,
      account: "current-account",
      category: "application",
      stage: "verification",
      instance: null,
      action: null,
    });
  });
  expect(screen.getByText("Verifying")).toBeVisible();
  expect(screen.queryByText("Cleaning")).not.toBeInTheDocument();
  await userEvent.click(
    screen.getByRole("button", { name: "Stop remaining work" }),
  );
  expect(api.cancel).toHaveBeenCalledWith(preview.plan_id);
  expect(screen.getByRole("button", { name: "Stopping…" })).toBeDisabled();
  expect(api.execute).toHaveBeenCalledTimes(1);
});

it("retries one failed item with a fresh plan and its original profile subset", async () => {
  await mount();
  await hold();
  finish(demoResult(preview, true));
  expect(
    screen.getByRole("heading", { name: "Done, 2 items need attention" }),
  ).toBeVisible();
  vi.mocked(api.buildPlan).mockImplementation(async (request) => {
    preview = demoPlan(request);
    preview.plan_id = "retry-plan";
    return preview;
  });
  await userEvent.click(screen.getByRole("button", { name: "Retry Chrome" }));
  await screen.findByRole("button", { name: /Hold to log out locally/ });
  expect(api.buildPlan).toHaveBeenLastCalledWith({
    inventory_id: "preview-inventory",
    items: ["Chrome"],
    profiles: [{ item: "Chrome", profiles: ["Chrome-default", "Chrome-work"] }],
  });
  expect(api.execute).toHaveBeenCalledTimes(1);
  await hold();
  expect(api.execute).toHaveBeenCalledTimes(2);
});

it("refuses a retry if the account or profile cannot be matched safely", async () => {
  await mount();
  await hold();
  finish(demoResult(preview, true));
  const inventory = demoInventory();
  inventory.groups[1].items[0].profiles = ["Chrome-work"];
  vi.mocked(api.scan).mockResolvedValue(inventory);
  await userEvent.click(screen.getByRole("button", { name: "Retry Chrome" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(w.unavailable);
  expect(api.execute).toHaveBeenCalledTimes(1);
  expect(api.buildPlan).toHaveBeenCalledTimes(1);
});

it("retains acknowledged item results on stream failure, without exporting an older report", async () => {
  await mount();
  await hold();
  act(() => {
    events({
      kind: "item",
      run_id: preview.plan_id,
      account: "current-account",
      category: "application",
      item: demoResult(preview).accounts[0].sections[0].items[0],
    });
    events({
      kind: "failed",
      run_id: preview.plan_id,
      error: "worker-unavailable",
    });
  });
  expect(screen.getByRole("alert")).toHaveTextContent(w.noResults);
  expect(
    screen.getAllByText(
      "No result was received. The local effects are unknown.",
    ),
  ).toHaveLength(7);
  expect(
    screen.getByText("Selected session data verified absent."),
  ).toBeVisible();
  expect(
    screen.queryByRole("button", { name: "Save JSON report" }),
  ).not.toBeInTheDocument();
});

it("sanitizes failed planning errors and never submits deletion", async () => {
  vi.mocked(api.dryRun).mockRejectedValue({ secret: "private-payload" });
  render(
    <WipeFlow
      inventory={demoInventory()}
      selection={selection}
      setBusy={setBusy}
      back={back}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(unknownError);
  expect(document.body).not.toHaveTextContent("private-payload");
  expect(api.execute).not.toHaveBeenCalled();
});

it("never claims clean coverage for a residual hive, unknown verification or skipped item", async () => {
  const result = demoResult(preview);
  result.accounts[0].residual_hive = true;
  result.accounts[0].sections[0].items[0].actions[0].verification = "unknown";
  result.skipped = [
    {
      account: "account-2",
      category: "browser",
      instance: "other-browser",
      name: "Other browser",
      provider: "browser",
    },
  ];
  render(
    <Reports
      report={result}
      name={(_, item) => item.instance}
      retry={vi.fn()}
      working={false}
      coverage={["coverage-unresolved"]}
    />,
  );
  expect(
    screen.queryByRole("heading", { name: "Done" }),
  ).not.toBeInTheDocument();
  expect(
    screen.getByText(/temporary account hive remains mounted/),
  ).toBeVisible();
  expect(screen.getByText("Other browser")).toBeVisible();
  expect(screen.getByText("Coverage incomplete")).toBeVisible();
  await userEvent.click(screen.getByText("Report & coverage"));
  await userEvent.click(
    screen.getByRole("button", { name: "Save JSON report" }),
  );
  await waitFor(() => expect(api.exportReport).toHaveBeenCalledWith("json"));
});

it("finishes a skipped-only plan without representing it as successful cleanup", async () => {
  preview = demoPlan({
    ...selection,
    items: [],
    profiles: [],
    skipped: selection.items,
  });
  await mount();
  await hold();
  const report = structuredClone(preview.report);
  report.mode = "apply";
  finish(report);
  expect(
    screen.getByRole("heading", { name: "Done, check coverage" }),
  ).toBeVisible();
  expect(
    screen.getAllByText("Skipped by choice. No cleanup requested."),
  ).toHaveLength(8);
  expect(api.execute).toHaveBeenCalledWith(
    {
      plan_id: preview.plan_id,
      confirmed_risks: [],
      category_tokens: [],
      force_close_accounts: [],
    },
    expect.any(Function),
  );
});
