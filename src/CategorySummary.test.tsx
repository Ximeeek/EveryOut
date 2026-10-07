import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { expect, it, vi } from "vitest";
import CategorySummary from "./CategorySummary";
import { defaultSelection, detectedCounts } from "./selection";
import { demoInventory } from "./demoFixtures";
it("keeps categories reachable by Tab when the first category is empty", async () => {
  const inventory = demoInventory();
  inventory.groups[0].items = [];
  const state = defaultSelection(inventory);
  const counts = detectedCounts(state);
  render(
    <CategorySummary
      counts={counts}
      totals={counts}
      state={state}
      toggle={vi.fn()}
    />,
  );
  await userEvent.tab();
  expect(screen.getByRole("checkbox", { name: /Browsers:/ })).toHaveFocus();
  await userEvent.keyboard("{ArrowRight}");
  expect(
    screen.getByRole("checkbox", { name: /Windows & dev:/ }),
  ).toHaveFocus();
});
