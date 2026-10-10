import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  ExecuteRequest,
  CatalogUpdateDto,
  ModeResult,
  PlanDto,
  ReportDto,
  RunStarted,
  ScanDto,
  SelectionRequest,
  Settings,
  WipeEvent,
} from "./types";
export type * from "./types";
export const scan = () => invoke<ScanDto>("scan");
export const teach = (request: import("./types").TeachRequest) =>
  invoke<import("./types").TeachReply>("teach", { request });
export const checkCatalogUpdates = () =>
  invoke<CatalogUpdateDto>("check_catalog_updates");
export const activateCatalogUpdate = (digest: string) =>
  invoke<CatalogUpdateDto>("activate_catalog_update", { digest });
export const buildPlan = (selection: SelectionRequest) =>
  invoke<PlanDto>("build_plan", { selection });
export const dryRun = (planId: string) =>
  invoke<PlanDto>("dry_run", { planId });
export function execute(
  request: ExecuteRequest,
  onEvent: (event: WipeEvent) => void,
) {
  const onEventChannel = new Channel<WipeEvent>();
  onEventChannel.onmessage = onEvent;
  return invoke<RunStarted>("execute", { request, onEvent: onEventChannel });
}
export const cancel = (runId: string) => invoke<void>("cancel", { runId });
export const getSettings = () => invoke<Settings>("get_settings");
export const setSettings = (settings: Settings) =>
  invoke<Settings>("set_settings", { settings });
export const getLastReport = () => invoke<ReportDto | null>("get_last_report");
export const enableAllAccountsMode = () =>
  invoke<ModeResult>("enable_all_accounts_mode");

export const closeReviewed = (request: ExecuteRequest) =>
  invoke<ReportDto>("close_reviewed", { request });
export const exportReport = (format: import("./types").ExportFormat) =>
  invoke<string>("export_report", { format });
