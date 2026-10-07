import { isTauri } from "@tauri-apps/api/core";
import * as native from "./api";

// Browser previews never reach native commands; production always uses IPC.
const client =
  import.meta.env.DEV && !isTauri()
    ? import("./demo").then((module) => module.demo)
    : Promise.resolve(native);

export const scan: typeof native.scan = () => client.then((api) => api.scan());
export const getSettings: typeof native.getSettings = () =>
  client.then((api) => api.getSettings());
export const setSettings: typeof native.setSettings = (settings) =>
  client.then((api) => api.setSettings(settings));
export const enableAllAccountsMode: typeof native.enableAllAccountsMode = () =>
  client.then((api) => api.enableAllAccountsMode());
export const buildPlan: typeof native.buildPlan = (selection) =>
  client.then((api) => api.buildPlan(selection));
export const dryRun: typeof native.dryRun = (id) =>
  client.then((api) => api.dryRun(id));
export const execute: typeof native.execute = (request, onEvent) =>
  client.then((api) => api.execute(request, onEvent));
export const cancel: typeof native.cancel = (id) =>
  client.then((api) => api.cancel(id));
export const closeReviewed: typeof native.closeReviewed = (request) =>
  client.then((api) => api.closeReviewed(request));
export const exportReport: typeof native.exportReport = (format) =>
  client.then((api) => api.exportReport(format));
export const checkCatalogUpdates: typeof native.checkCatalogUpdates = () =>
  client.then((api) => api.checkCatalogUpdates());
export const activateCatalogUpdate: typeof native.activateCatalogUpdate = (
  digest,
) => client.then((api) => api.activateCatalogUpdate(digest));
export const getLastReport: typeof native.getLastReport = () =>
  client.then((api) => api.getLastReport());
