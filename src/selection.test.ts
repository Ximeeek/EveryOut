import { expect, it } from "vitest";
import { demoInventory } from "./demoFixtures";
import { categories } from "./wipe";
import {
  categoryDeltas,
  defaultSelection,
  selectionRequest,
  toggleCategory,
  rescanSelection,
} from "./selection";

it("defaults all supported high-confidence items and their profiles to selected", () => {
  const inventory = demoInventory();
  inventory.groups[0].items[0].default_selected = false;
  inventory.groups[0].items[1].selectable = false;
  const state = defaultSelection(inventory);
  expect(selectionRequest(state)?.items).toHaveLength(7);
  expect(state.selected.Discord).toEqual(["Discord"]);
  expect(state.selected.Steam).toBeUndefined();
  expect(state.selected.Chrome).toEqual(["Chrome-default", "Chrome-work"]);
});
it("allows medium-confidence known providers and keeps unsupported detections excluded", () => {
  const inventory = demoInventory();
  inventory.groups.forEach((group) => {
    group.confidence = "medium";
  });
  inventory.groups[0].items[0].selectable = false;
  const state = defaultSelection(inventory);
  expect(selectionRequest(state)?.items).toHaveLength(7);
  expect(state.selected.Chrome).toHaveLength(2);
  const cleared = toggleCategory(state, "browser");
  expect(cleared.selected.Chrome).toEqual([]);
  expect(toggleCategory(cleared, "browser").selected.Chrome).toHaveLength(2);
  expect(toggleCategory(state, "application").selected.Discord).toBeUndefined();
});
it("retains deselected categories and exact surviving profiles on rescan", () => {
  const before = toggleCategory(
    defaultSelection(demoInventory()),
    "application",
  );
  before.selected.Chrome = ["Chrome-work"];
  const inventory = demoInventory();
  inventory.groups[1].items[0].profiles.push("Chrome-new");
  const next = rescanSelection(before, inventory);
  expect(next.selected.Discord).toEqual([]);
  expect(next.selected.Chrome).toEqual(["Chrome-work"]);
  expect(selectionRequest(next)?.items).not.toContain("Discord");
});
it("toggles only one category, restores all profiles and handles a mixed selection", () => {
  const original = defaultSelection(demoInventory());
  const cleared = toggleCategory(original, "browser");
  expect(cleared.selected.Chrome).toEqual([]);
  expect(cleared.selected.Discord).toEqual(original.selected.Discord);
  expect(original.selected.Chrome).toHaveLength(2);
  expect(toggleCategory(cleared, "browser")).toEqual(original);
  const mixed = {
    ...original,
    selected: { ...original.selected, Chrome: ["Chrome-default"] },
  };
  expect(toggleCategory(mixed, "browser")).toEqual(original);
});
it.each(categories)(
  "calculates increased, decreased and unchanged detection counts for %s",
  (category) => {
    const before = defaultSelection(demoInventory());
    const inventory = demoInventory();
    const group = inventory.groups.find(
      (group) => group.category === category,
    )!;
    group.items.push({ ...group.items[0], id: "new-item" });
    const after = defaultSelection(inventory);
    expect(categoryDeltas(before, after)[category]).toMatchObject({
      change: 1,
      direction: "up",
    });
    expect(categoryDeltas(after, before)[category]).toMatchObject({
      change: -1,
      direction: "down",
    });
    expect(categoryDeltas(before, before)[category]).toMatchObject({
      change: 0,
      direction: "same",
    });
    for (const other of categories.filter((value) => value !== category))
      expect(categoryDeltas(before, after)[other].direction).toBe("same");
    expect(
      categoryDeltas(before, toggleCategory(before, category))[category]
        .direction,
    ).toBe("same");
  },
);
