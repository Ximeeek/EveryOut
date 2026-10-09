import { commandErrors, unknownError } from "./strings";
import { decisionReason } from "./scopeDecisionText";
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
export const previewBlocked = (item: ItemDto) =>
  !item.decision.action_allowed ||
  item.status === "blocked" ||
  (item.actions.length > 0 &&
    item.actions.every((a) => a.outcome === "blocked"));

export function blockingReason(item: ItemDto) {
  if (!item.decision.action_allowed && item.decision.blocked_by.length > 0)
    return [...new Set(item.decision.blocked_by.map(decisionReason))].join(" ");
  if (item.limitations.includes("spotify-build-not-reviewed"))
    return "This Spotify installation has not been reviewed yet. The automatic logout method supports a verified desktop build; scan again after installing a supported build.";
  if (item.limitations.includes("spotify-login-format-not-reviewed"))
    return "Spotify's saved login file is locked or uses an unsupported format. Close Spotify and scan again; no preferences were changed.";
  if (
    item.limitations.some((reason) =>
      [
        "unvalidated-product-version",
        "unknown-authentication-closure",
        "unreviewed-preservation",
        "unknown-permanent-loss",
        "automatic-cleanup-unverified",
      ].includes(reason),
    )
  )
    return "Automatic logout is not verified for this app. Removing the listed files may leave you signed in or remove unrelated data. Closing the app does not resolve this limitation.";
  if (item.issues.includes("process-preview-unavailable"))
    return "Open programs could not be safely identified. No program will be closed and no data will be removed for this item.";
  return "Cleanup was blocked. The data could not be safely removed.";
}
export const needsAttention = (item: ItemDto) =>
  item.status !== "complete-local-scope" ||
  item.locked ||
  item.issues.length > 0 ||
  item.limitations.length > 0 ||
  item.actions.some(
    (a) =>
      a.locked ||
      (a.outcome !== "applied" && a.outcome !== "already-absent") ||
      a.verification !== "target-absent" ||
      a.issues.length > 0,
  );

export function attentionReason(item: ItemDto) {
  if (item.issues.includes("unacknowledged"))
    return "No result was received. The local effects are unknown.";
  if (item.locked || item.actions.some((a) => a.locked))
    return "Local data is locked. Close the program, then retry.";
  if (item.status === "cancelled")
    return "Stopped before cleanup finished. Some local data may remain.";
  if (
    item.status === "failed" ||
    item.actions.some((a) => a.outcome === "failed")
  )
    return "A local operation failed. Check access to the selected data, then retry.";
  if (item.actions.some((a) => a.verification === "target-present"))
    return "Some selected local data is still present.";
  if (
    item.status === "blocked" ||
    item.actions.some((a) => a.outcome === "blocked")
  )
    return blockingReason(item);
  if (item.actions.some((a) => a.outcome === "skipped"))
    return "Some selected data was skipped.";
  return "The complete local scope could not be verified. Some data may remain.";
}
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
