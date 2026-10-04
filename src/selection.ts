import type { Category, DetectedItem, ScanDto, SelectionRequest } from "./api";
import { categories } from "./wipe";

export type HomeState = {
  inventory: ScanDto | null;
  selected: Record<string, string[]>;
  error: string | null;
};
export const emptyHome: HomeState = {
  inventory: null,
  selected: {},
  error: null,
};
export const scopes = (item: DetectedItem) =>
  item.profiles.length ? item.profiles : [item.id];
export const isSelected = (state: HomeState, item: DetectedItem) =>
  (state.selected[item.id]?.length ?? 0) > 0;
export function defaultSelection(inventory: ScanDto): HomeState {
  const selected: HomeState["selected"] = {};
  for (const group of inventory.groups) {
    for (const item of group.items) {
      if (group.category && group.confidence === "high" && item.selectable)
        selected[item.id] = scopes(item);
    }
  }
  return { inventory, selected, error: null };
}
export function categoryItems(state: HomeState, category: Category) {
  return (
    state.inventory?.groups
      .filter(
        (group) => group.category === category && group.confidence === "high",
      )
      .flatMap((group) => group.items)
      .filter((item) => item.selectable) ?? []
  );
}

export function detectedCounts(state: HomeState): Record<Category, number> {
  return Object.fromEntries(
    categories.map((category) => [
      category,
      state.inventory?.groups
        .filter((group) => group.category === category)
        .reduce((sum, group) => sum + group.items.length, 0) ?? 0,
    ]),
  ) as Record<Category, number>;
}

export function toggleCategory(
  state: HomeState,
  category: Category,
): HomeState {
  const items = categoryItems(state, category);
  const checked =
    items.length > 0 &&
    items.every((item) =>
      scopes(item).every((scope) => state.selected[item.id]?.includes(scope)),
    );
  const selected = { ...state.selected };
  for (const item of items) selected[item.id] = checked ? [] : scopes(item);
  return { ...state, selected };
}

export type CategoryDelta = {
  previous: number;
  current: number;
  change: number;
  direction: "up" | "down" | "same";
};
export function categoryDeltas(previous: HomeState, next: HomeState) {
  const before = detectedCounts(previous);
  const after = detectedCounts(next);
  return Object.fromEntries(
    categories.map((category) => {
      const change = after[category] - before[category];
      return [
        category,
        {
          previous: before[category],
          current: after[category],
          change,
          direction: change > 0 ? "up" : change < 0 ? "down" : "same",
        },
      ];
    }),
  ) as Record<Category, CategoryDelta>;
}
export function selectionRequest(state: HomeState): SelectionRequest | null {
  if (!state.inventory) return null;
  const items = state.inventory.groups
    .flatMap((g) => g.items)
    .filter((i) => i.selectable && isSelected(state, i));
  return {
    inventory_id: state.inventory.inventory_id,
    items: items.map((i) => i.id),
    profiles: items
      .filter((i) => i.profiles.length)
      .map((i) => ({ item: i.id, profiles: state.selected[i.id] })),
  };
}
