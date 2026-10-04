import type { DetectedItem, ScanDto, SelectionRequest } from "./api";

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
      if (
        group.category &&
        group.confidence === "high" &&
        item.selectable &&
        item.default_selected
      )
        selected[item.id] = scopes(item);
    }
  }
  return { inventory, selected, error: null };
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
