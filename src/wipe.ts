import { commandErrors, unknownError } from "./strings";
import type {
  Category,
  DetectedItem,
  ItemDto,
  ReportDto,
  ScanDto,
  SelectionRequest,
} from "./api";
export const categories: Category[] = [
  "application",
  "browser",
  "windows-microsoft-and-dev-tools",
];
export const reportItems = (report: ReportDto) =>
  report.accounts.flatMap((account) =>
    account.sections.flatMap((section) =>
      section.items.map((item) => ({
        account: account.account,
        category: section.category,
        item,
      })),
    ),
  );
export const retryable = (item: ItemDto) =>
  item.locked ||
  item.status === "failed" ||
  item.actions.some((a) => a.locked || a.outcome === "failed");
export type Target = {
  account: string;
  provider: string;
  profiles: string[];
  name: string;
  category: Category;
};
export function targetsFor(
  inventory: ScanDto,
  selection: SelectionRequest,
): Target[] {
  return inventory.groups.flatMap((g) =>
    g.category
      ? g.items
          .filter((i) => selection.items.includes(i.id) && i.provider)
          .map((i) => ({
            account: i.account,
            provider: i.provider!,
            name: i.name,
            category: g.category!,
            profiles:
              selection.profiles.find((p) => p.item === i.id)?.profiles ?? [],
          }))
      : [],
  );
}
export function matching(item: DetectedItem, target: Target) {
  return item.account === target.account && item.provider === target.provider;
}
export function freshSelection(
  inventory: ScanDto,
  targets: Target[],
  skipped: Target[] = [],
): SelectionRequest {
  const items: string[] = [],
    profiles: SelectionRequest["profiles"] = [];
  for (const target of targets) {
    const matches = inventory.groups
      .filter((g) => g.category === target.category)
      .flatMap((g) => g.items)
      .filter((i) => i.selectable && matching(i, target));
    if (matches.length !== 1) throw new Error("unmatched");
    const item = matches[0];
    if (target.profiles.some((p) => !item.profiles.includes(p)))
      throw new Error("unmatched");
    items.push(item.id);
    if (target.profiles.length)
      profiles.push({ item: item.id, profiles: target.profiles });
  }
  const skippedIds = skipped.map((target) => {
    const matches = inventory.groups
      .filter((g) => g.category === target.category)
      .flatMap((g) => g.items)
      .filter((i) => matching(i, target));
    if (matches.length !== 1) throw new Error("unmatched");
    return matches[0].id;
  });
  if (
    (!items.length && !skippedIds.length) ||
    new Set(items).size !== items.length
  )
    throw new Error("unmatched");
  return {
    inventory_id: inventory.inventory_id,
    items,
    profiles,
    ...(skippedIds.length ? { skipped: skippedIds } : {}),
  };
}

export function errorText(error: unknown) {
  return typeof error === "string" && Object.hasOwn(commandErrors, error)
    ? commandErrors[error as keyof typeof commandErrors]
    : unknownError;
}

export function acknowledgedCounts(items: ItemDto[]) {
  const actions = items
    .filter((i) => !i.issues.includes("unacknowledged"))
    .flatMap((i) => i.actions);
  return {
    succeeded: actions.filter(
      (a) => a.outcome === "applied" || a.outcome === "already-absent",
    ).length,
    failed: actions.filter((a) => a.outcome === "failed").length,
    locked: actions.filter((a) => a.locked).length,
    skipped: actions.filter(
      (a) => a.outcome === "skipped" || a.outcome === "blocked",
    ).length,
    already_absent: actions.filter((a) => a.outcome === "already-absent")
      .length,
    would_apply: 0,
  };
}
