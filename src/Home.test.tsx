import { useState } from "react";
import { render, screen, within, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import Home from "./Home";
import App from "./App";
import { emptyHome } from "./selection";
import type { HomeState } from "./selection";
import * as api from "./api";
import type { DetectedItem, ScanDto } from "./api";
import {
  categoryNames,
  homeStrings as h,
  riskNames,
  signalNames,
  unknownError,
} from "./strings";

vi.mock("./api", () => ({
  scan: vi.fn(),
  getSettings: vi.fn(),
  setSettings: vi.fn(),
  enableAllAccountsMode: vi.fn(),
}));
const review = vi.fn();
function item(id: string, extra: Partial<DetectedItem> = {}): DetectedItem {
  return {
    id,
    name: id,
    account: "current-account",
    provider: id,
    origin: "known-provider",
    default_selected: true,
    selectable: true,
    profiles: [],
    risks: [],
    loss: "none",
    signals: ["ownership"],
    unverified: false,
    sync_warning: false,
    limitations: [],
    ...extra,
  };
}
function inventory(): ScanDto {
  return {
    inventory_id: "inventory-1",
    mode: "current",
    coverage: [],
    accounts: [],
    groups: [
      {
        category: "application",
        confidence: "high",
        items: [
          item("Chat", {
            profiles: ["chat-p1", "chat-p2"],
            risks: ["drafts-or-offline-messages"],
            loss: "known",
            unverified: true,
          }),
        ],
      },
      {
        category: "browser",
        confidence: "high",
        items: [item("Browser", { sync_warning: true })],
      },
      {
        category: "windows-microsoft-and-dev-tools",
        confidence: "high",
        items: [item("Developer")],
      },
      {
        category: "application",
        confidence: "medium",
        items: [item("Maybe", { default_selected: false })],
      },
      {
        category: "application",
        confidence: "low",
        items: [item("Weak", { default_selected: false })],
      },
    ],
  };
}
function Harness() {
  const [state, update] = useState<HomeState>(emptyHome);
  const [busy, setBusy] = useState(false);
  return (
    <Home
      state={state}
      update={update}
      busy={busy}
      setBusy={setBusy}
      review={review}
      disabled={false}
    />
  );
}
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(api.scan).mockResolvedValue(inventory());
  vi.mocked(api.getSettings).mockResolvedValue({
    account_mode: "current",
    process_close_policy: "ask",
    first_run_completed: true,
  });
});
async function start() {
  const user = userEvent.setup();
  render(<Harness />);
  await user.click(screen.getByRole("button", { name: h.scan }));
  await screen.findByRole("region", { name: categoryNames.application });
  return user;
}
const category = (name: keyof typeof categoryNames) =>
  within(screen.getByRole("region", { name: categoryNames[name] }));
const master = (name: keyof typeof categoryNames) =>
  category(name).getByRole("checkbox", {
    name: `${h.select} ${categoryNames[name]}`,
  });

it("selects high confidence only and keeps medium/low in a separate collapsed section", async () => {
  const user = await start();
  expect(
    screen.getByRole("checkbox", {
      name: "Select Chat (Current Windows account)",
    }),
  ).toBeChecked();
  expect(
    screen.getByRole("checkbox", {
      name: "Select Browser (Current Windows account)",
    }),
  ).toBeChecked();
  expect(master("windows-microsoft-and-dev-tools")).toBeChecked();
  const disclosure = category("application")
    .getByText(h.uncertain)
    .closest("details");
  expect(disclosure).not.toHaveAttribute("open");
  await user.click(category("application").getByText(h.uncertain));
  expect(
    screen.getByRole("checkbox", {
      name: "Select Maybe (Current Windows account)",
    }),
  ).not.toBeChecked();
  expect(
    screen.getByRole("checkbox", {
      name: "Select Weak (Current Windows account)",
    }),
  ).not.toBeChecked();
  expect(screen.getByText(h.medium)).toBeVisible();
  expect(screen.getByText(h.low)).toBeVisible();
  expect(master("application")).toBePartiallyChecked();
});

it("category masters select or clear only their own category including uncertain items", async () => {
  const user = await start();
  await user.click(master("application"));
  expect(master("application")).toBeChecked();
  expect(master("browser")).toBeChecked();
  await user.click(master("application"));
  expect(master("application")).not.toBeChecked();
  expect(master("browser")).toBeChecked();
  expect(master("windows-microsoft-and-dev-tools")).toBeChecked();
  await user.click(master("browser"));
  expect(master("windows-microsoft-and-dev-tools")).toBeChecked();
  expect(screen.getByText("Applications: 0 selected")).toBeVisible();
  expect(screen.getByText("Browsers: 0 selected")).toBeVisible();
});

it("propagates profile partial states to item, provider and category and stores the exact subset", async () => {
  const user = await start();
  await user.click(screen.getByText("Profile (2)"));
  await user.click(screen.getByRole("checkbox", { name: "Chat — Profile 2" }));
  expect(
    screen.getByRole("checkbox", {
      name: "Select Chat (Current Windows account)",
    }),
  ).toBePartiallyChecked();
  expect(
    screen.getByRole("checkbox", { name: "Select Chat" }),
  ).toBePartiallyChecked();
  expect(master("application")).toBePartiallyChecked();
  await user.click(screen.getByRole("button", { name: h.review }));
  expect(review).toHaveBeenCalledWith({
    inventory_id: "inventory-1",
    items: ["Chat", "Browser", "Developer"],
    profiles: [{ item: "Chat", profiles: ["chat-p1"] }],
  });
  await user.click(
    screen.getByRole("checkbox", {
      name: "Select Chat (Current Windows account)",
    }),
  );
  expect(
    screen.getByRole("checkbox", { name: "Chat — Profile 2" }),
  ).toBeChecked();
});

it("renders loss type, unverified and sync badges, metadata signals and Windows SSO warning", async () => {
  const user = await start();
  expect(
    screen.getByText(`${h.loss}: ${riskNames["drafts-or-offline-messages"]}`),
  ).toBeVisible();
  expect(screen.getByText(h.unverified)).toBeVisible();
  expect(screen.getByText(h.sync)).toBeVisible();
  expect(screen.getByText(h.syncHelp)).toBeVisible();
  expect(screen.getByText(h.windowsWarning)).toBeVisible();
  await user.click(screen.getAllByText(h.signals)[0]);
  expect(screen.getAllByText(signalNames.ownership)[0]).toBeVisible();
});

it("disables Review before scan and when no selected scopes remain", async () => {
  const user = userEvent.setup();
  render(<Harness />);
  expect(screen.getByRole("button", { name: h.review })).toBeDisabled();
  await user.click(screen.getByRole("button", { name: h.scan }));
  await screen.findByRole("region", { name: categoryNames.application });
  await user.click(
    screen.getByRole("checkbox", {
      name: "Select Chat (Current Windows account)",
    }),
  );
  await user.click(master("browser"));
  await user.click(master("windows-microsoft-and-dev-tools"));
  expect(screen.getByRole("button", { name: h.review })).toBeDisabled();
  expect(review).not.toHaveBeenCalled();
});

it("blocks duplicate scans, shows loading and sanitizes errors before retry", async () => {
  let reject!: (error: unknown) => void;
  vi.mocked(api.scan).mockImplementationOnce(
    () =>
      new Promise((_, fail) => {
        reject = fail;
      }),
  );
  const user = userEvent.setup();
  render(<Harness />);
  await user.dblClick(screen.getByRole("button", { name: h.scan }));
  expect(api.scan).toHaveBeenCalledTimes(1);
  expect(screen.getByRole("status")).toHaveTextContent(h.scanning);
  expect(screen.getByRole("button", { name: h.scanning })).toBeDisabled();
  reject("sensitive arbitrary error payload");
  expect(await screen.findByRole("alert")).toHaveTextContent(unknownError);
  expect(
    screen.queryByText("sensitive arbitrary error payload"),
  ).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: h.scan }));
  await screen.findByRole("region", { name: categoryNames.application });
  expect(screen.queryByRole("alert")).not.toBeInTheDocument();
});

it("keeps inaccessible and unclassified detections disabled even with high confidence", async () => {
  const data = inventory();
  data.groups.push({
    category: null,
    confidence: "high",
    items: [item("Unresolved", { selectable: false, default_selected: false })],
  });
  data.coverage = ["unverified-coverage"];
  vi.mocked(api.scan).mockResolvedValue(data);
  const user = await start();
  expect(screen.getByRole("status")).toHaveTextContent(h.incomplete);
  await user.click(screen.getByText(h.unclassified));
  expect(
    screen.getByRole("checkbox", {
      name: "Select Unresolved (Current Windows account)",
    }),
  ).toBeDisabled();
  await user.click(screen.getByRole("button", { name: h.review }));
  expect(review.mock.calls[0][0].items).not.toContain("Unresolved");
});

it("groups all-account provider rows by Windows account and keeps their selection independent", async () => {
  const data = inventory();
  data.mode = "all-accounts";
  data.groups[0].items = [
    item("chat-a", { name: "Chat", provider: "chat", account: "account-1" }),
    item("chat-b", { name: "Chat", provider: "chat", account: "account-2" }),
  ];
  vi.mocked(api.scan).mockResolvedValue(data);
  const user = await start();
  await user.click(screen.getByText("Windows account: account-1"));
  await user.click(
    screen.getByRole("checkbox", { name: "Select Windows account account-1" }),
  );
  expect(
    screen.getByRole("checkbox", { name: "Select Chat" }),
  ).toBePartiallyChecked();
  await user.click(screen.getByText("Windows account: account-2"));
  expect(
    screen.getByRole("checkbox", { name: "Select Chat (account-2)" }),
  ).toBeChecked();
  await user.click(screen.getByRole("button", { name: h.review }));
  expect(review.mock.calls[0][0]).toEqual({
    inventory_id: "inventory-1",
    items: ["chat-b", "Browser", "Developer"],
    profiles: [],
  });
});

it("rescan discards previous selections and binds Review to the new inventory", async () => {
  const user = await start();
  await user.click(master("browser"));
  vi.mocked(api.scan).mockResolvedValue({
    ...inventory(),
    inventory_id: "inventory-2",
  });
  await user.click(screen.getByRole("button", { name: h.scan }));
  await waitFor(() => expect(master("browser")).toBeChecked());
  await user.click(screen.getByRole("button", { name: h.review }));
  expect(review.mock.calls[0][0].inventory_id).toBe("inventory-2");
});

it("App stores selection across Review and navigation and invalidates it when settings are saved", async () => {
  vi.mocked(api.setSettings).mockImplementation(async (next) => next);
  const user = userEvent.setup();
  render(<App />);
  await user.click(await screen.findByRole("button", { name: h.scan }));
  await screen.findByRole("region", { name: categoryNames.application });
  await user.click(screen.getByText("Profile (2)"));
  await user.click(screen.getByRole("checkbox", { name: "Chat — Profile 2" }));
  await user.click(screen.getByRole("button", { name: h.review }));
  expect(screen.getByRole("heading", { name: h.reviewTitle })).toBeVisible();
  expect(screen.getByText(h.reviewPlaceholder)).toBeVisible();
  expect(screen.getByText("3 selected")).toBeVisible();
  await user.click(screen.getByRole("button", { name: h.back }));
  await user.click(screen.getByText("Profile (2)"));
  expect(
    screen.getByRole("checkbox", { name: "Chat — Profile 2" }),
  ).not.toBeChecked();
  await user.click(screen.getByRole("button", { name: "Settings" }));
  await user.click(screen.getByRole("button", { name: "Save settings" }));
  await screen.findByText("Settings saved.");
  await user.click(screen.getByRole("button", { name: "Home" }));
  expect(screen.getByRole("button", { name: h.review })).toBeDisabled();
  expect(
    screen.queryByRole("region", { name: categoryNames.application }),
  ).not.toBeInTheDocument();
});
