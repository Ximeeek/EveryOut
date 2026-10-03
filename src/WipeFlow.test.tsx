import { StrictMode } from "react";
import { render, screen, within, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import * as api from "./api";
import type {
  ItemDto,
  PlanDto,
  ReportDto,
  ScanDto,
  SelectionRequest,
  WipeEvent,
} from "./api";
import WipeFlow from "./WipeFlow";
import Reports from "./Reports";
import { categories } from "./wipe";
import {
  categoryNames,
  homeStrings as h,
  strings as s,
  wipeStrings as w,
  unknownError,
} from "./strings";
vi.mock("./api", () => ({
  buildPlan: vi.fn(),
  dryRun: vi.fn(),
  execute: vi.fn(),
  scan: vi.fn(),
  closeReviewed: vi.fn(),
  cancel: vi.fn(),
  exportReport: vi.fn(),
}));
let events: (e: WipeEvent) => void;
let preview: PlanDto;
const setBusy = vi.fn(),
  back = vi.fn();
const selection: SelectionRequest = {
  inventory_id: "inventory-1",
  items: ["chat", "browser", "dev"],
  profiles: [{ item: "chat", profiles: ["p1"] }],
};
function item(id: string): ItemDto {
  return {
    instance: id,
    provider: id,
    loss: id === "chat" ? "known" : "none",
    affected_data: id === "chat" ? ["Offline chat drafts"] : [],
    locked: false,
    status: "dry-run",
    actions: [
      {
        id: id + "-action",
        path: id + "/local-store",
        bytes: 128,
        locked: false,
        outcome: "would-apply",
        verification: "not-performed",
        issues: [],
      },
    ],
    risks:
      id === "chat"
        ? ["drafts-or-offline-messages", "settings-or-profiles"]
        : [],
    confirmations: id === "chat" ? ["loss-chat"] : [],
    profiles: id === "chat" ? ["p1"] : [],
    processes: [],
    limitations: [],
    issues: [],
    identity: "unknown",
    sync: "unsupported",
    authentication: "unknown",
    remote_revocation: "unsupported",
    silent_sso: "unknown",
  };
}
const ids = ["chat", "browser", "dev"];
function inventory(): ScanDto {
  return {
    inventory_id: "inventory-fresh",
    mode: "current",
    coverage: [],
    accounts: [],
    groups: categories.map((category, n) => ({
      category,
      confidence: "high",
      items: [
        {
          id: ids[n],
          provider: ids[n],
          name: ids[n],
          account: "current-account",
          origin: "known-provider",
          default_selected: true,
          selectable: true,
          profiles: n === 0 ? ["p1", "p2"] : [],
          risks: [],
          loss: "none",
          signals: [],
          limitations: [],
          unverified: n === 1,
          sync_warning: n === 1,
        },
      ],
    })),
  };
}
function plan(request = selection): PlanDto {
  return {
    plan_id: "plan-1",
    category_tokens: request.items.includes("dev")
      ? [
          {
            account: "current-account",
            category: "windows-microsoft-and-dev-tools",
            token: "category-1",
          },
        ]
      : [],
    report: {
      skipped: [],
      mode: "dry-run",
      account_mode: "current",
      process_close_policy: "ask",
      accounts: [
        {
          account: "current-account",
          sections: categories.map((category, n) => ({
            category,
            status: request.items.includes(ids[n])
              ? "dry-run"
              : "not-requested",
            items: request.items.includes(ids[n]) ? [item(ids[n])] : [],
            warnings: [],
            succeeded: 0,
            failed: 0,
            locked: 0,
            skipped: 0,
            would_apply: request.items.includes(ids[n]) ? 1 : 0,
            already_absent: 0,
          })),
          limitations: [],
          issues: [],
          residual_hive: false,
          residual_hku_key: null,
          unload_attempts: 0,
        },
      ],
    },
  };
}
function completed(): ReportDto {
  return {
    ...preview.report,
    mode: "apply",
    accounts: preview.report.accounts.map((a) => ({
      ...a,
      sections: a.sections.map((c) => ({
        ...c,
        status: c.items.length ? "complete-local-scope" : "not-requested",
        items: c.items.map((i) => ({
          ...i,
          status: "complete-local-scope",
          actions: i.actions.map((action) => ({
            ...action,
            outcome: "applied",
            verification: "target-absent",
          })),
        })),
      })),
    })),
  };
}
beforeEach(() => {
  vi.resetAllMocks();
  preview = plan();
  vi.mocked(api.buildPlan).mockImplementation(async () => preview);
  vi.mocked(api.dryRun).mockImplementation(async () => preview);
  vi.mocked(api.scan).mockResolvedValue(inventory());
  vi.mocked(api.closeReviewed).mockResolvedValue(preview.report);
  vi.mocked(api.cancel).mockResolvedValue();
  vi.mocked(api.exportReport).mockResolvedValue("reports/test.json");
  vi.mocked(api.execute).mockImplementation(async (_, onEvent) => {
    events = onEvent;
    return { run_id: preview.plan_id };
  });
});
function mount(strict = false) {
  const element = (
    <WipeFlow
      inventory={inventory()}
      selection={selection}
      setBusy={setBusy}
      back={back}
    />
  );
  render(strict ? <StrictMode>{element}</StrictMode> : element);
  return screen.findByRole("button", { name: w.execute });
}
async function approvals(user: ReturnType<typeof userEvent.setup>) {
  for (const box of screen.getAllByRole("checkbox"))
    if (!(box as HTMLInputElement).checked) await user.click(box);
}
function finish(report = completed()) {
  act(() => events({ kind: "finished", run_id: preview.plan_id, report }));
}
it("renders native dry-run paths, sizes, losses, unverified scope and sync without mutations", async () => {
  await mount(true);
  expect(api.buildPlan).toHaveBeenCalledTimes(1);
  expect(api.buildPlan).toHaveBeenCalledWith(selection);
  expect(api.dryRun).toHaveBeenCalledWith("plan-1");
  expect(screen.getByText("chat/local-store")).toBeVisible();
  expect(screen.getAllByText(/128 bytes/)).toHaveLength(3);
  expect(screen.getByText("Offline chat drafts")).toBeVisible();
  expect(screen.getByText(w.unverified)).toBeVisible();
  expect(screen.getByText(h.syncHelp)).toBeVisible();
  expect(api.execute).not.toHaveBeenCalled();
  expect(api.closeReviewed).not.toHaveBeenCalled();
});
it("requires every item risk and a separate Windows confirmation before execute", async () => {
  const user = userEvent.setup(),
    button = await mount();
  expect(button).toBeDisabled();
  await user.click(
    screen.getByRole("checkbox", { name: /drafts or offline messages/ }),
  );
  await user.click(screen.getByRole("checkbox", { name: w.windowsConfirm }));
  expect(button).toBeDisabled();
  expect(api.execute).not.toHaveBeenCalled();
  await user.click(
    screen.getByRole("checkbox", { name: /settings or profiles/ }),
  );
  await user.click(screen.getByRole("checkbox", { name: w.windowsConfirm }));
  expect(button).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: w.windowsConfirm }));
  await user.click(button);
  expect(api.execute).toHaveBeenCalledTimes(1);
  expect(api.execute).toHaveBeenCalledWith(
    {
      plan_id: "plan-1",
      confirmed_risks: [
        {
          account: "current-account",
          instance: "chat",
          flags: ["drafts-or-offline-messages", "settings-or-profiles"],
          confirmations: ["loss-chat"],
        },
      ],
      category_tokens: ["category-1"],
      force_close_accounts: [],
    },
    expect.any(Function),
  );
  expect(
    screen.queryByRole("button", { name: w.execute }),
  ).not.toBeInTheDocument();
});
it("blocks Ask, requests only graceful closure and requires fresh review before resuming", async () => {
  preview.report.accounts[0].sections[0].items[0].processes = [
    "process-42-100",
  ];
  const user = userEvent.setup(),
    button = await mount();
  await approvals(user);
  expect(button).toBeDisabled();
  expect(screen.getByText("process-42-100")).toBeVisible();
  vi.mocked(api.closeReviewed).mockImplementation(async () => {
    preview = plan();
    preview.plan_id = "plan-2";
    return preview.report;
  });
  await user.click(screen.getByRole("button", { name: w.close }));
  await screen.findByText(w.none);
  expect(api.execute).not.toHaveBeenCalled();
  expect(api.closeReviewed).toHaveBeenCalledTimes(1);
  expect(api.buildPlan).toHaveBeenLastCalledWith({
    ...selection,
    inventory_id: "inventory-fresh",
  });
  expect(screen.getByRole("button", { name: w.execute })).toBeDisabled();
  await approvals(user);
  await user.click(screen.getByRole("button", { name: w.execute }));
  expect(api.execute).toHaveBeenCalledWith(
    expect.objectContaining({ plan_id: "plan-2" }),
    expect.any(Function),
  );
});
it("can recheck manually closed processes or skip only dependent items", async () => {
  preview.report.accounts[0].sections[1].items[0].processes = ["process-99"];
  vi.mocked(api.buildPlan).mockImplementation(async (request) => {
    if (request.inventory_id === "inventory-fresh") preview = plan(request);
    return preview;
  });
  const user = userEvent.setup();
  await mount();
  await user.click(screen.getByRole("button", { name: w.skip }));
  await screen.findByText(w.none);
  expect(api.buildPlan).toHaveBeenLastCalledWith({
    inventory_id: "inventory-fresh",
    items: ["chat", "dev"],
    profiles: [{ item: "chat", profiles: ["p1"] }],
    skipped: ["browser"],
  });
  expect(screen.getByText(w.skipped)).toBeVisible();
  expect(api.closeReviewed).not.toHaveBeenCalled();
});
it("shows force-close work-loss warning and gates account acknowledgments", async () => {
  preview.report.process_close_policy = "hard-kill-after2s";
  preview.report.accounts[0].sections[1].items[0].processes = ["process-5"];
  const user = userEvent.setup(),
    button = await mount();
  expect(screen.getByText(s.forceWarning)).toBeVisible();
  await user.click(
    screen.getByRole("checkbox", { name: /drafts or offline messages/ }),
  );
  await user.click(
    screen.getByRole("checkbox", { name: /settings or profiles/ }),
  );
  await user.click(screen.getByRole("checkbox", { name: w.windowsConfirm }));
  expect(button).toBeDisabled();
  await user.click(screen.getByRole("checkbox", { name: w.forceConfirm }));
  await user.click(button);
  expect(api.execute).toHaveBeenCalledWith(
    expect.objectContaining({ force_close_accounts: ["current-account"] }),
    expect.any(Function),
  );
});
it("streams category progress, filters foreign events and cancels without starting another wipe", async () => {
  const user = userEvent.setup();
  await mount();
  await approvals(user);
  await user.click(screen.getByRole("button", { name: w.execute }));
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
      run_id: "plan-1",
      account: "current-account",
      category: "application",
      stage: "verification",
      instance: "chat",
      action: null,
    });
  });
  expect(screen.getByText(/Applications: Verifying/)).toBeVisible();
  expect(screen.queryByText(/Browsers: Cleaning/)).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: w.cancel }));
  expect(api.cancel).toHaveBeenCalledWith("plan-1");
  expect(screen.getByRole("button", { name: w.cancel })).toBeDisabled();
  expect(api.execute).toHaveBeenCalledTimes(1);
  const result = completed();
  result.accounts[0].sections[0].status = "cancelled";
  finish(result);
  expect(screen.getByText("Cancelled")).toBeVisible();
  expect(back).not.toHaveBeenCalled();
});
it("separates all three reports and exports only through the native command", async () => {
  const user = userEvent.setup();
  const report = completed();
  report.accounts[0].sections[0].succeeded = 1;
  report.accounts[0].sections[0].already_absent = 1;
  report.accounts[0].sections[0].items[0].actions[0].outcome = "already-absent";
  report.accounts[0].sections[1] = {
    ...report.accounts[0].sections[1],
    items: [],
    status: "not-requested",
  };
  render(
    <Reports
      report={report}
      name={(_, i) => i.instance}
      retry={vi.fn()}
      working={false}
    />,
  );
  expect(screen.getByText("chat/local-store")).toBeVisible();
  expect(
    screen.getByText(/Removed \/ changed: 0 · Already absent: 1/),
  ).toBeVisible();
  expect(screen.queryByText("dev/local-store")).not.toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: categoryNames.browser }));
  expect(screen.getByText("Not requested")).toBeVisible();
  expect(screen.queryByText("chat/local-store")).not.toBeInTheDocument();
  await user.click(
    screen.getByRole("tab", {
      name: categoryNames["windows-microsoft-and-dev-tools"],
    }),
  );
  expect(screen.getByText("dev/local-store")).toBeVisible();
  expect(screen.getByText(h.windowsWarning)).toBeVisible();
  expect(screen.getByText(w.remainsHelp)).toBeVisible();
  await user.click(screen.getByRole("button", { name: w.json }));
  expect(api.exportReport).toHaveBeenCalledWith("json");
  await screen.findByText(/reports\/test.json/);
  await user.click(screen.getByRole("button", { name: w.text }));
  expect(api.exportReport).toHaveBeenCalledWith("text");
});
it("retries only failed or locked items with original profile subsets and fresh confirmations", async () => {
  const user = userEvent.setup();
  await mount();
  await approvals(user);
  await user.click(screen.getByRole("button", { name: w.execute }));
  const result = completed();
  result.accounts[0].sections[0].items[0].actions[0].outcome = "failed";
  result.accounts[0].sections[2].items[0].locked = true;
  finish(result);
  vi.mocked(api.buildPlan).mockImplementation(async (request) => {
    preview = plan(request);
    preview.plan_id = "retry-plan";
    return preview;
  });
  await user.click(screen.getByRole("button", { name: w.retry }));
  await screen.findByRole("button", { name: w.execute });
  expect(api.scan).toHaveBeenCalledTimes(1);
  expect(api.buildPlan).toHaveBeenLastCalledWith({
    inventory_id: "inventory-fresh",
    items: ["chat", "dev"],
    profiles: [{ item: "chat", profiles: ["p1"] }],
  });
  expect(screen.getByRole("button", { name: w.execute })).toBeDisabled();
  expect(api.execute).toHaveBeenCalledTimes(1);
  await approvals(user);
  await user.click(screen.getByRole("button", { name: w.execute }));
  expect(api.execute).toHaveBeenLastCalledWith(
    expect.objectContaining({ plan_id: "retry-plan" }),
    expect.any(Function),
  );
});
it("refuses retries when accounts or profile scopes cannot be matched safely", async () => {
  const user = userEvent.setup();
  await mount();
  await approvals(user);
  await user.click(screen.getByRole("button", { name: w.execute }));
  const result = completed();
  result.accounts[0].sections[0].items[0].locked = true;
  finish(result);
  const fresh = inventory();
  fresh.groups[0].items[0].profiles = ["p2"];
  vi.mocked(api.scan).mockResolvedValue(fresh);
  await user.click(screen.getByRole("button", { name: w.retry }));
  await screen.findByText(w.unavailable);
  expect(api.buildPlan).toHaveBeenCalledTimes(1);
  expect(api.execute).toHaveBeenCalledTimes(1);
});
it("retains received results after stream failure and hides export of an older native report", async () => {
  const user = userEvent.setup();
  await mount();
  await approvals(user);
  await user.click(screen.getByRole("button", { name: w.execute }));
  act(() => {
    events({
      kind: "item",
      run_id: "plan-1",
      account: "current-account",
      category: "application",
      item: completed().accounts[0].sections[0].items[0],
    });
    events({ kind: "failed", run_id: "plan-1", error: "cancelled" });
  });
  expect(screen.getByText("chat/local-store").closest("li")).toHaveTextContent(
    "Removed / changed",
  );
  expect(screen.getByRole("alert")).toHaveTextContent(w.noResults);
  expect(
    screen.queryByRole("button", { name: w.json }),
  ).not.toBeInTheDocument();
  expect(api.exportReport).not.toHaveBeenCalled();
});
it("renders separate per-account results and residual hive coverage", async () => {
  const result = completed();
  result.account_mode = "all-accounts";
  result.accounts.push({
    ...result.accounts[0],
    account: "account-2",
    residual_hive: true,
  });
  render(
    <Reports
      report={result}
      name={(_, i) => i.instance}
      retry={vi.fn()}
      working={false}
    />,
  );
  expect(
    within(
      screen.getByRole("region", { name: "Windows account: account-2" }),
    ).getByText(w.residualHive),
  ).toBeVisible();
  expect(screen.getAllByText("chat/local-store")).toHaveLength(2);
});
it("sanitizes unexpected API errors and never executes a failed dry run", async () => {
  vi.mocked(api.dryRun).mockRejectedValue({ secret: "must-not-be-rendered" });
  render(
    <WipeFlow
      inventory={inventory()}
      selection={selection}
      setBusy={setBusy}
      back={back}
    />,
  );
  expect(await screen.findByRole("alert")).toHaveTextContent(unknownError);
  expect(screen.queryByText(/must-not-be-rendered/)).not.toBeInTheDocument();
  expect(api.execute).not.toHaveBeenCalled();
});

it("keeps skipped-only reports separate and records native export eligibility", async () => {
  const user = userEvent.setup();
  const result = plan({ ...selection, items: [], profiles: [] }).report;
  result.mode = "apply";
  result.skipped = [
    {
      account: "current-account",
      category: "browser",
      instance: "browser",
      provider: "browser",
      name: "Skipped browser",
    },
  ];
  render(
    <Reports
      report={result}
      name={(_, i) => i.instance}
      retry={vi.fn()}
      working={false}
    />,
  );
  expect(screen.queryByText("Skipped browser")).not.toBeInTheDocument();
  await user.click(screen.getByRole("tab", { name: categoryNames.browser }));
  expect(screen.getByText("Skipped browser")).toBeVisible();
  expect(screen.getByText("Not requested")).toBeVisible();
  expect(screen.getByText(/Items skipped by choice/)).toBeVisible();
  await user.click(screen.getByRole("button", { name: w.json }));
  expect(api.exportReport).toHaveBeenCalledWith("json");
});
it("rechecks manually closed processes without issuing a close command", async () => {
  const user = userEvent.setup();
  preview.report.accounts[0].sections[0].items[0].processes = ["process-1"];
  await mount();
  vi.mocked(api.buildPlan).mockImplementation(async () => {
    preview = plan();
    return preview;
  });
  await user.click(screen.getByRole("button", { name: w.refresh }));
  await screen.findByText(w.none);
  expect(api.closeReviewed).not.toHaveBeenCalled();
  expect(api.execute).not.toHaveBeenCalled();
  expect(screen.getByRole("button", { name: w.execute })).toBeDisabled();
});
