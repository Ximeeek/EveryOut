import type {
  Category,
  DetectedItem,
  DecisionTrace,
  ItemDto,
  PlanDto,
  ReportDto,
  ScanDto,
  SelectionRequest,
} from "./api";
import { categories } from "./wipe";

const names: Record<Category, string[]> = {
  application: ["Discord", "Steam", "Spotify", "Slack"],
  browser: ["Chrome", "Edge"],
  "windows-microsoft-and-dev-tools": ["GitHub CLI", "Docker"],
};

// Visual fixtures are explicit mock domain results, never runtime authorization.
export function demoDecision(): DecisionTrace {
  const provenance = [
    { source: "synthetic-fixture", reason_code: "fixture-only-review" },
  ];
  return {
    evidence: {
      application_identity: { state: "exact", provenance },
      storage_ownership: { state: "exclusive", provenance },
      authentication_scope: { state: "validated", provenance },
      preservation: { state: "known-losses", provenance },
      version_applicability: { state: "current", provenance },
      authority: "reviewed-catalog",
    },
    support: "validated",
    action_allowed: true,
    blocked_by: [],
    confirmations_required: [],
  };
}

export function demoInventory(): ScanDto {
  return {
    inventory_id: "preview-inventory",
    mode: "current",
    coverage: [],
    accounts: [],
    groups: categories.map((category) => ({
      category,
      confidence: "high",
      items: names[category].map((name): DetectedItem => ({
        decision: demoDecision(),
        id: name,
        provider: name,
        name,
        account: "current-account",
        origin: "known-provider",
        default_selected: true,
        selectable: true,
        profiles:
          category === "browser" ? [`${name}-default`, `${name}-work`] : [],
        risks: ["settings-or-profiles"],
        loss: "known",
        signals: ["known-provider"],
        limitations: [],
        unverified: false,
        sync_warning: category === "browser",
      })),
    })),
  };
}

export function demoPlan(selection: SelectionRequest): PlanDto {
  const inventory = demoInventory();
  return {
    plan_id: "preview-plan",
    category_tokens: selection.items.some((id) =>
      names["windows-microsoft-and-dev-tools"].includes(id),
    )
      ? [
          {
            account: "current-account",
            category: "windows-microsoft-and-dev-tools",
            token: "preview-category-token",
          },
        ]
      : [],
    report: {
      mode: "dry-run",
      account_mode: "current",
      process_close_policy: "ask",
      skipped: inventory.groups.flatMap((group) =>
        group.items
          .filter((item) => selection.skipped?.includes(item.id))
          .map((item) => ({
            account: item.account,
            category: group.category!,
            instance: item.id,
            provider: item.provider!,
            name: item.name,
          })),
      ),
      accounts: [
        {
          account: "current-account",
          limitations: [],
          issues: [],
          residual_hive: false,
          residual_hku_key: null,
          unload_attempts: 0,
          sections: inventory.groups.map((group) => {
            const items = group.items
              .filter((item) => selection.items.includes(item.id))
              .map((item): ItemDto => ({
                decision: item.decision,
                instance: item.id,
                provider: item.provider,
                loss: item.loss,
                locked: false,
                affected_data: ["local app settings", "offline drafts"],
                status: "dry-run",
                actions: [
                  {
                    id: `preview-${item.id}`,
                    path: `${item.name}/session-store`,
                    bytes: 2048,
                    locked: false,
                    outcome: "would-apply",
                    verification: "not-performed",
                    issues: [],
                  },
                ],
                risks: item.risks,
                confirmations: [`preview-loss-${item.id}`],
                profiles:
                  selection.profiles.find((profile) => profile.item === item.id)
                    ?.profiles ?? item.profiles,
                processes: [],
                limitations: [],
                issues: [],
                identity: "unknown",
                sync: "unknown",
                authentication: "unknown",
                remote_revocation: "unsupported",
                silent_sso: "unknown",
              }));
            return {
              category: group.category!,
              status: items.length ? "dry-run" : "not-requested",
              items,
              warnings: [],
              succeeded: 0,
              failed: 0,
              locked: 0,
              skipped: 0,
              would_apply: items.length,
              already_absent: 0,
            };
          }),
        },
      ],
    },
  };
}

export function demoResult(plan: PlanDto, partial = false): ReportDto {
  const report: ReportDto = structuredClone(plan.report);
  report.mode = "apply";
  for (const account of report.accounts)
    for (const section of account.sections) {
      section.status = section.items.length
        ? "complete-local-scope"
        : "not-requested";
      section.would_apply = 0;
      section.succeeded = section.items.length;
      for (const item of section.items) {
        item.status = "complete-local-scope";
        for (const action of item.actions) {
          action.outcome = "applied";
          action.verification = "target-absent";
        }
        if (
          partial &&
          (item.instance === "Chrome" || item.instance === "Discord")
        ) {
          item.locked = true;
          item.status = "failed";
          item.actions[0].locked = true;
          item.actions[0].outcome = "failed";
          item.actions[0].verification = "target-present";
          section.status = "partial";
          section.failed++;
          section.succeeded--;
        }
      }
    }
  return report;
}
