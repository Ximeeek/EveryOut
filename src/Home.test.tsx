import { useState } from "react";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it } from "vitest";
import Home from "./Home";
import { defaultSelection, selectionRequest } from "./selection";
import { demoInventory } from "./demoFixtures";
import type { ScanDto } from "./api";
import { homeStrings as h } from "./strings";

function Harness({ inventory = demoInventory() }: { inventory?: ScanDto }) {
  const [state, update] = useState(() => defaultSelection(inventory));
  return (
    <>
      <Home state={state} update={update} busy={false} />
      <output aria-label="Selected request">
        {JSON.stringify(selectionRequest(state))}
      </output>
    </>
  );
}

it("keeps uncertain and inaccessible detections out of the default scope", async () => {
  const inventory = demoInventory();
  inventory.groups.push({
    category: "application",
    confidence: "medium",
    items: [
      {
        ...inventory.groups[0].items[0],
        id: "uncertain",
        name: "Uncertain app",
      },
    ],
  });
  inventory.groups.push({
    category: null,
    confidence: "high",
    items: [
      {
        ...inventory.groups[0].items[0],
        id: "inaccessible",
        name: "Inaccessible app",
        selectable: false,
      },
    ],
  });
  render(<Harness inventory={inventory} />);
  expect(screen.getByLabelText("Selected request")).not.toHaveTextContent(
    "uncertain",
  );
  expect(screen.getByLabelText("Selected request")).not.toHaveTextContent(
    "inaccessible",
  );
  await userEvent.click(screen.getByText(h.uncertain));
  expect(
    screen.getByRole("checkbox", {
      name: "Select Uncertain app (Current Windows account)",
    }),
  ).not.toBeChecked();
  await userEvent.click(screen.getByText(h.unclassified));
  expect(
    screen.getByRole("checkbox", {
      name: "Select Inaccessible app (Current Windows account)",
    }),
  ).toBeDisabled();
});

it("preserves the exact profile subset and shows a partial item selection", async () => {
  const user = userEvent.setup();
  render(<Harness />);
  await user.click(screen.getAllByText("Profile (2)")[0]);
  await user.click(
    screen.getByRole("checkbox", { name: "Chrome — Profile 2" }),
  );
  expect(
    screen.getByRole("checkbox", {
      name: "Select Chrome (Current Windows account)",
    }),
  ).toBePartiallyChecked();
  const request = JSON.parse(
    screen.getByLabelText("Selected request").textContent!,
  );
  expect(request.profiles).toContainEqual({
    item: "Chrome",
    profiles: ["Chrome-default"],
  });
  expect(request.items).toContain("Chrome");
});

it("changes only the selected category and makes an empty selection explicit", async () => {
  const user = userEvent.setup();
  render(<Harness />);
  await user.click(
    screen.getByRole("checkbox", { name: "Select Applications" }),
  );
  expect(
    screen.getByRole("checkbox", { name: "Select Browsers" }),
  ).toBeChecked();
  await user.click(screen.getByRole("checkbox", { name: "Select Browsers" }));
  await user.click(
    screen.getByRole("checkbox", {
      name: "Select Windows/Microsoft accounts & developer tools",
    }),
  );
  expect(
    JSON.parse(screen.getByLabelText("Selected request").textContent!).items,
  ).toEqual([]);
});

it("keeps the same provider in two Windows accounts independent", async () => {
  const inventory = demoInventory();
  inventory.mode = "all-accounts";
  inventory.groups[0].items = ["account-1", "account-2"].map((account) => ({
    ...inventory.groups[0].items[0],
    id: `discord-${account}`,
    account,
  }));
  const user = userEvent.setup();
  render(<Harness inventory={inventory} />);
  const applications = within(
    screen.getByRole("region", { name: "Applications" }),
  );
  await user.click(applications.getByText("Windows account: account-1"));
  await user.click(
    applications.getByRole("checkbox", {
      name: "Select Windows account account-1",
    }),
  );
  const request = JSON.parse(
    screen.getByLabelText("Selected request").textContent!,
  );
  expect(request.items).toContain("discord-account-2");
  expect(request.items).not.toContain("discord-account-1");
});
