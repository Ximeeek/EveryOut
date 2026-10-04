import type * as native from "./api";
import type { PlanDto, ReportDto, Settings, WipeEvent } from "./api";
import { demoInventory, demoPlan, demoResult } from "./demoFixtures";

const scenario =
  new URLSearchParams(window.location.search).get("demo") ?? "idle";
let settings: Settings = {
  account_mode: "current",
  process_close_policy: "ask",
  first_run_completed: false,
};
let plan: PlanDto | null = null;
let lastReport: ReportDto | null = null;
let sink: ((event: WipeEvent) => void) | null = null;
let programsClosed = false;
let scanNumber = 0;
const timers = new Set<ReturnType<typeof setTimeout>>();
const delay = (milliseconds: number) =>
  new Promise<void>((resolve) => setTimeout(resolve, milliseconds));
function later(milliseconds: number, callback: () => void) {
  const timer = setTimeout(() => {
    timers.delete(timer);
    callback();
  }, milliseconds);
  timers.add(timer);
}
function finish(report: ReportDto) {
  timers.forEach(clearTimeout);
  timers.clear();
  lastReport = report;
  sink?.({ kind: "finished", run_id: plan!.plan_id, report });
  sink = null;
}

export const demo: typeof native = {
  async getSettings() {
    return { ...settings };
  },
  async setSettings(next) {
    settings = { ...next };
    return { ...settings };
  },
  async enableAllAccountsMode() {
    settings.account_mode = "all-accounts";
    return {
      effective_mode: "all-accounts",
      requires_fresh_review: true,
      reason: null,
    };
  },
  async scan() {
    if (scenario === "scanning") return new Promise(() => {});
    await delay(450);
    if (scenario === "error") throw "worker-unavailable";
    const inventory = demoInventory();
    if (scenario === "medium") {
      inventory.groups.forEach((group) => {
        group.confidence = "medium";
        group.items.forEach((item) => {
          item.default_selected = false;
        });
      });
    }
    if (scenario === "rescan" && scanNumber++ % 2 === 1) {
      inventory.groups[0].items.push({
        ...inventory.groups[0].items[0],
        id: "New app",
        name: "New app",
      });
      inventory.groups[1].items.pop();
    }
    inventory.mode = settings.account_mode;
    if (scenario === "empty") inventory.groups = [];
    return inventory;
  },
  async buildPlan(selection) {
    plan = demoPlan(selection);
    plan.report.account_mode = settings.account_mode;
    plan.report.process_close_policy = settings.process_close_policy;
    if (scenario === "processes" && !programsClosed)
      plan.report.accounts[0].sections[0].items.forEach((item) => {
        item.processes = [`${item.instance} (preview)`];
      });
    return structuredClone(plan);
  },
  async dryRun(id) {
    if (!plan || plan.plan_id !== id) throw "stale-plan";
    if (scenario === "preparing") return new Promise(() => {});
    await delay(250);
    return structuredClone(plan);
  },
  async closeReviewed() {
    if (!plan) throw "stale-plan";
    programsClosed = true;
    return structuredClone(plan.report);
  },
  async execute(request, onEvent) {
    if (!plan || plan.plan_id !== request.plan_id) throw "stale-plan";
    sink = onEvent;
    const result = demoResult(plan, scenario === "partial");
    const sections = result.accounts[0].sections;
    sections.forEach((section, index) => {
      later(index * 1500 + 100, () =>
        sink?.({
          kind: "progress",
          run_id: request.plan_id,
          account: "current-account",
          category: section.category,
          stage: "cleaning",
          instance: null,
          action: null,
        }),
      );
      if (scenario !== "running")
        later(index * 1500 + 1100, () =>
          section.items.forEach((item) =>
            sink?.({
              kind: "item",
              run_id: request.plan_id,
              account: "current-account",
              category: section.category,
              item,
            }),
          ),
        );
    });
    if (scenario !== "running") later(4900, () => finish(result));
    return { run_id: request.plan_id };
  },
  async cancel(id) {
    if (!plan || id !== plan.plan_id) throw "stale-plan";
    const result = demoResult(plan);
    for (const account of result.accounts)
      for (const section of account.sections) {
        section.status = section.items.length ? "cancelled" : "not-requested";
        section.succeeded = 0;
        for (const item of section.items) {
          item.status = "cancelled";
          for (const action of item.actions) {
            action.outcome = "skipped";
            action.verification = "not-performed";
          }
        }
      }
    finish(result);
  },
  async getLastReport() {
    return lastReport;
  },
  async exportReport() {
    return "Preview only — no report was written.";
  },
  async checkCatalogUpdates() {
    return {
      installed_version: "Preview",
      proposed_version: null,
      digest: null,
      changelog: null,
      error: "catalog-unconfigured",
      helper_compatible: true,
    };
  },
  async activateCatalogUpdate() {
    throw "worker-unavailable";
  },
};
