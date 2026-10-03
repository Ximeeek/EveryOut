// Rust IPC definitions. Update with pnpm bindings:generate.

export type AccountDto = { account: string, sections: Array<SectionDto>, limitations: Array<string>, issues: Array<string>, residual_hive: boolean, residual_hku_key: string | null, unload_attempts: number, };

export type AccountMode = "current" | "all-accounts";

export type AccountScanDto = { account: string, logged_on: boolean | null, residual_hive: boolean, residual_hku_key: string | null, unload_attempts: number, limitations: Array<string>, };

export type ActionDto = { id: string, path: string, outcome: ActionStatus, verification: VerificationStatus, issues: Array<string>, };

export type ActionStatus = "would-apply" | "applied" | "already-absent" | "skipped" | "blocked" | "failed";

export type AggregateStatus = "complete-local-scope" | "partial" | "blocked" | "failed" | "cancelled" | "dry-run" | "not-requested";

export type Category = "application" | "browser" | "windows-microsoft-and-dev-tools";

export type CategoryToken = { account: string, category: Category, token: string, };

export type CommandError = "busy" | "stale-plan" | "invalid-selection" | "confirmation-required" | "settings-io" | "helper-unavailable" | "worker-unavailable" | "cancelled";

export type Confidence = "high" | "medium" | "low";

export type DetectedItem = { id: string, account: string, provider: string | null, name: string, origin: DetectionOrigin, default_selected: boolean, selectable: boolean, limitations: Array<string>, profiles: Array<string>, risks: Array<RiskFlag>, loss: LossAssessment, signals: Array<string>, unverified: boolean, sync_warning: boolean, };

export type DetectionGroup = { category: Category | null, confidence: Confidence, items: Array<DetectedItem>, };

export type DetectionOrigin = "known-provider" | "heuristic";

export type ExecuteRequest = { plan_id: string, confirmed_risks: Array<RiskAcceptance>, category_tokens: Array<string>, force_close_accounts: Array<string>, };

export type ExecutionMode = "dry-run" | "apply";

export type ItemDto = { instance: string, status: AggregateStatus, actions: Array<ActionDto>, risks: Array<RiskFlag>, confirmations: Array<string>, profiles: Array<string>, processes: Array<string>, limitations: Array<string>, issues: Array<string>, identity: Uncertainty, sync: Uncertainty, authentication: Uncertainty, remote_revocation: Uncertainty, silent_sso: Uncertainty, };

export type LossAssessment = "known" | "none" | "unknown";

export type ModeFailure = "uac-declined" | "start-failed" | "authentication-failed" | "timeout" | "trust-pin-unavailable";

export type ModeResult = { effective_mode: AccountMode, requires_fresh_review: boolean, reason: ModeFailure | null, };

export type PlanDto = { plan_id: string, category_tokens: Array<CategoryToken>, report: ReportDto, };

export type ProcessClosePolicy = "ask" | "hard-kill-after2s";

export type ProfileSelection = { item: string, profiles: Array<string>, };

export type ReportDto = { mode: ExecutionMode, account_mode: AccountMode, process_close_policy: ProcessClosePolicy, accounts: Array<AccountDto>, };

export type RiskAcceptance = { account: string, instance: string, flags: Array<RiskFlag>, confirmations: Array<string>, };

export type RiskFlag = "local-only-documents" | "drafts-or-offline-messages" | "settings-or-profiles" | "wallet-or-key-material" | "vault-or-2fa-recovery" | "saved-passwords-passkeys-autofill-history" | "shared-store" | "unknown";

export type RunStarted = { run_id: string, };

export type ScanDto = { inventory_id: string, mode: AccountMode, groups: Array<DetectionGroup>, coverage: Array<string>, accounts: Array<AccountScanDto>, };

export type SectionDto = { category: Category, status: AggregateStatus, warnings: Array<string>, items: Array<ItemDto>, succeeded: number, failed: number, skipped: number, locked: number, would_apply: number, already_absent: number, };

export type SelectionRequest = { inventory_id: string, items: Array<string>,
/**
 * Omission preserves the legacy whole-instance selection. Entries narrow scope only.
 */
profiles: Array<ProfileSelection>, };

export type Settings = { process_close_policy: ProcessClosePolicy, account_mode: AccountMode, first_run_completed: boolean, };

export type Stage = "scan" | "selection" | "dry-run" | "review" | "closing" | "cleaning" | "identity-sync" | "verification" | "report";

export type Uncertainty = "unknown" | "unsupported" | "not-requested";

export type VerificationStatus = "target-absent" | "target-present" | "inaccessible" | "unknown" | "not-performed";

export type WipeEvent = { "kind": "progress", run_id: string, account: string, stage: Stage, category: Category, instance: string | null, action: string | null, } | { "kind": "item", run_id: string, account: string, category: Category, item: ItemDto, } | { "kind": "finished", run_id: string, report: ReportDto, } | { "kind": "failed", run_id: string, error: CommandError, };
