import type { Category, CommandError, ModeFailure, RiskFlag } from "./api";

export const strings = {
  appName: "EveryOut",
  platform: "Local session clearing · Windows",
  navigation: "Main navigation",
  home: "Home",
  settings: "Settings",
  about: "About",
  skip: "Skip to content",
  loading: "Loading settings…",
  retry: "Retry",
  dismiss: "Dismiss notice",
  homeTitle: "Review before you clear",
  homeDescription:
    "EveryOut clears supported local app and browser session data. It stays offline and never reads or displays secrets. Clearing local data does not guarantee logout on servers or other devices.",
  welcome: "Welcome to EveryOut",
  introduction:
    "EveryOut can remove local session data to help you log out of apps and browsers. Deletion cannot be undone and may remove local-only data. You will review targets and risks before any cleanup.",
  question: "Which Windows accounts should EveryOut cover?",
  current: "Only my current Windows account",
  all: "All user accounts on this machine",
  accountHelp:
    "Current account is the default and does not request administrator access. All accounts requires administrator rights: Windows will ask for UAC approval only when you enable this mode. Ineligible or inaccessible profiles may be skipped; account scopes still require review.",
  rememberedMode:
    "A saved all-accounts preference does not grant administrator access. A future all-accounts scan will request a helper on demand and require fresh review.",
  continue: "Continue",
  saving: "Saving…",
  save: "Save settings",
  saved: "Settings saved.",
  processHeading: "Closing selected programs",
  ask: "Ask me",
  force: "Force close after 2 seconds",
  processHelp:
    "Ask me requests graceful closure and asks you what to do if selected programs remain open. It never automatically force closes them.",
  forceWarning:
    "Force closing can destroy unsaved work in other programs, interrupt uploads or drafts, and leave data inconsistent. Two seconds does not make termination safe.",
  acknowledge: "I understand the risk of losing unsaved work.",
  fallback:
    "Administrator access could not be enabled. Current-account mode is available. Other accounts were not cleaned; a fresh scan and review will be required.",
  aboutTitle: "What EveryOut will not do in V1",
  aboutIntro:
    "EveryOut V1 means local session clearing, not guaranteed global logout. These are scope boundaries, not a claim that every provider is implemented.",
  aboutClosing:
    "Applications, browsers, and Windows/Microsoft + developer-tools are independent report scopes. Success in one does not imply success in another. Unsupported operations and unresolved preservation conflicts stay blocked.",
  limitations: [
    [
      "No server-side session invalidation",
      "No remote token revocation, remote Sync reset or logout of other devices. Copied tokens and remote sessions may remain usable; the wipe stays offline.",
    ],
    [
      "No Windows account sign-out",
      "No Windows logout, sign-in identity removal, PRT clearing, WAM/broker-cache purge or device/work-account disconnect.",
    ],
    [
      "No secret reading, copying, decryption or transmission",
      "No credential blobs, cookie/token rows, browser key extraction, payload inspection or database authentication queries. Credential enumeration is excluded even if blobs would be ignored.",
    ],
    [
      "No undo or backup of a wipe",
      "Deletion is irreversible through EveryOut. No profile snapshots, secret-store copies or rollback after partial failure; local-only losses require review.",
    ],
    [
      "No protection against silent SSO re-login",
      "Windows identity, retained browser identity or another authentication source can create fresh sessions. Results describe local effects at verification time.",
    ],
    [
      "No clearing saved passwords, autofill, history or passkeys",
      "These are outside session scope. Mixed stores that cannot be isolated without secret reads stay blocked, even with extra confirmation.",
    ],
    [
      "No universal application/browser coverage",
      "Relocated profiles, vendor stores, partitions, DBSC keys and extension state may remain unresolved. Unsupported candidates are coverage gaps, not executable rules.",
    ],
    [
      "No safe-loss guarantee for extensions or web storage",
      "Session storage can contain drafts, offline documents, vaults, wallet/recovery data and settings. Known losses need extra confirmation; unknown preservation conflicts block execution.",
    ],
    [
      "No forced cleanup of every Windows profile",
      "Inaccessible, special and unsupported user scopes remain excluded. Administrator access does not prove another user's ownership or authorize their protected stores. All-accounts work follows the reviewed account and process boundaries.",
    ],
    [
      "No automatic privilege or protection bypass",
      "Current mode does not request UAC on errors. No ACL takeover, AV/EDR disablement or protected-process bypass.",
    ],
    [
      "No hooking, injection, foreign-memory reads or drivers",
      "Only reviewed file, registry and OS operations are allowed. Anti-cheat compatibility is not certification or an immunity guarantee.",
    ],
    [
      "No automatic restart or authenticated verification",
      "Metadata absence is not remote logout, destroyed TPM keys or proof of failed refresh. No browser restart or network login probe in the wipe.",
    ],
    [
      "No guarantee that hard kill preserves work",
      "Graceful close may wait for user interaction. Force close can destroy unsaved work; two seconds is a policy, not a Windows safety guarantee.",
    ],
    [
      "No machine-wide browser policy changes",
      "Profile edits require secret-free validation. Existing policy or sync may recreate state.",
    ],
    [
      "No global hotkey or shutdown-triggered wipe",
      "These are V2 roadmap items, not alternate V1 authorization paths.",
    ],
  ],
} as const;

export const commandErrors: Record<CommandError, string> = {
  busy: "An operation is already running. Wait for it to finish, then try again.",
  "stale-plan":
    "The previous review is out of date. A fresh scan and review are required.",
  "invalid-selection":
    "The selection could not be accepted. Review it and try again.",
  "confirmation-required": "The required confirmations have not been provided.",
  "settings-io":
    "Settings could not be read or saved. Check access to the app settings folder and retry.",
  "helper-unavailable":
    "The administrator helper is unavailable. Current-account mode is available.",
  "worker-unavailable": "The local command could not be completed. Try again.",
  cancelled: "The operation was cancelled.",
  "report-io":
    "The report could not be saved. Check access to the app configuration folder.",
};
export const unknownError = "The local command failed. Try again.";
export const modeFailures: Record<ModeFailure, string> = {
  "uac-declined":
    "Administrator access was declined. Other accounts were not cleaned; current-account mode is available. A fresh scan and review will be required.",
  "start-failed":
    "The administrator helper could not start. Current-account mode is available. Other accounts were not cleaned; a fresh scan and review will be required.",
  "authentication-failed":
    "The administrator helper could not be authenticated. Current-account mode is available. Other accounts were not cleaned; a fresh scan and review will be required.",
  timeout:
    "The administrator helper timed out. Current-account mode is available. Other accounts were not cleaned; a fresh scan and review will be required.",
  "trust-pin-unavailable":
    "This build cannot verify the administrator helper. Current-account mode is available. Other accounts were not cleaned; a fresh scan and review will be required.",
};

export const homeStrings = {
  scan: "Scan",
  scanning: "Scanning…",
  review: "Review",
  empty: "No detections were found in this category.",
  uncertain: "Uncertain detections",
  uncertainHelp:
    "Medium and low confidence detections start unchecked. Selecting an item does not validate its cleanup scope.",
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
  unverified: "Unverified",
  unavailable: "Selection unavailable: no reviewed scope or account access.",
  sync: "Sync / identity warning",
  syncHelp:
    "Sync or automatic sign-in can recreate data or access after this wipe. Local deletion does not remove server data or guarantee a lasting sign-out. Metadata does not prove active sync or sign-in.",
  windowsWarning:
    "Browsers and Office may silently sign in again through Windows SSO after local cleanup. Full logout means disconnecting the account from Windows. EveryOut does not disconnect Windows accounts or alter the Windows sign-in identity.",
  loss: "Permanent data loss risk",
  unknownLoss: "Data loss risk is unknown",
  select: "Select",
  profile: "Profile",
  account: "Windows account",
  currentAccount: "Current Windows account",
  indivisible:
    "This provider's detected scope is indivisible within this Windows account.",
  signals: "Detection signals",
  unspecifiedSignal:
    "Additional metadata evidence was reported; its meaning is unverified.",
  noSignals: "No additional detection signals were supplied.",
  incomplete:
    "Scan coverage is incomplete. Some targets could not be verified.",
  selected: "selected",
  reviewTitle: "Review selection",
  back: "Back to selection",
  unclassified: "Unclassified detections",
} as const;

export const categoryNames: Record<Category, string> = {
  application: "Applications",
  browser: "Browsers",
  "windows-microsoft-and-dev-tools":
    "Windows/Microsoft accounts & developer tools",
};
export const riskNames: Record<RiskFlag, string> = {
  "local-only-documents": "local-only documents",
  "drafts-or-offline-messages": "drafts or offline messages",
  "settings-or-profiles": "settings or profiles",
  "wallet-or-key-material": "wallet or key material",
  "vault-or-2fa-recovery": "vault or 2FA recovery data",
  "saved-passwords-passkeys-autofill-history":
    "saved passwords, passkeys, autofill or history (preservation required)",
  "shared-store": "data in a shared store",
  unknown: "unknown local data",
};
export const signalNames: Record<string, string> = {
  "artifact-present": "Expected session artifact metadata is present.",
  "store-present": "An expected local session store exists.",
  "scope-unresolved":
    "The provider's data ownership or scope could not be resolved.",
  "root-present": "The expected provider data root exists.",
  "cookies-present": "Session cookie storage metadata is present.",
  identity: "An installed application identity was detected.",
  ownership: "Metadata maps the data store to an owner.",
  "runtime-packaging": "Application runtime packaging was detected.",
  "storage-layout": "An expected session storage layout was detected.",
  "known-provider": "A reviewed catalog provider detected this scope.",
  "registered-identity": "A registered application identity was detected.",
};
export const wipeStrings = {
  loading: "Preparing metadata-only dry run…",
  review: "Review local effects",
  paths: "Reviewed relative target paths",
  bytes: "bytes",
  unknownSize: "Size unavailable; directory sizes are not summed recursively.",
  counts: "Planned targets",
  locked: "Locked",
  removed: "Removed / changed",
  failed: "Failed",
  omitted: "Skipped",
  finishSkipped: "Finish report without cleanup",
  riskHeading: "Confirm permanent data loss",
  lossHelp:
    "Deletion cannot be undone. Confirm every risk for every selected item. These confirmations do not deselect any targets or authorize protected data.",
  confirmEffect: "I accept the listed local effects and coverage limitations.",
  windowsHeading: "Confirm Windows/Microsoft and developer tools",
  windowsConfirm:
    "I understand silent SSO and that EveryOut never signs me out of Windows.",
  forceConfirm: "I accept force closing the listed programs after 2 seconds.",
  execute: "Clear reviewed local data",
  processes: "Programs blocking cleanup",
  askHelp:
    "Save your work first. Request graceful closure, close the programs yourself and retry, or skip affected items. Ask never force closes a program. A fresh review follows any process change.",
  close: "Close gracefully",
  refresh: "Retry process check",
  skip: "Skip affected items",
  skipped: "Items skipped by choice; no cleanup was requested for them.",
  none: "No selected blocking programs were reported.",
  executing: "Clearing local data",
  cancel: "Cancel remaining work",
  cancelling: "Cancellation requested; waiting for retained results…",
  reports: "Local cleanup report",
  remains: "What remains",
  remainsHelp:
    "Saved passwords, autofill, history, passkeys, unsupported stores and remote sessions remain outside cleanup. Unknown verification is not proof of absence.",
  coverage:
    "Additional coverage is unresolved; no complete cleanup is claimed.",
  residualHive:
    "A temporary account hive remains mounted. Manual recovery is required before another run.",
  unverified: "Unverified scope or coverage",
  uncertainty:
    "Browser identity and sync are not proven cleared; authentication and remote logout are not verified.",
  retry: "Retry failed or locked items",
  retryHelp:
    "A retry is a new run limited to failed or locked provider/account items and the previously selected profiles. It requires a fresh scan, plan and confirmations.",
  unavailable:
    "Some previous targets could not be matched safely. Return to selection and scan again.",
  json: "Export JSON",
  text: "Export text",
  exported: "Saved under the app configuration folder:",
  recover: "Return to selection for a fresh scan",
  unknownOutcome: "Unacknowledged outcome; effects unknown",
  noResults:
    "No completed report is available. Retained item results are shown; unacknowledged effects remain unknown.",
  profiles: "Reviewed profiles",
  identity: "Identity",
  sync: "Sync",
  sso: "Silent SSO",
} as const;
export const lossDescriptions: Record<import("./api").RiskFlag, string> = {
  "local-only-documents":
    "Local-only documents may be permanently deleted without a server copy.",
  "drafts-or-offline-messages":
    "Unsent drafts and offline messages may be permanently lost.",
  "settings-or-profiles":
    "Local settings or selected profile data may be permanently lost.",
  "wallet-or-key-material":
    "Local wallet or key material may be lost, preventing access to funds or accounts.",
  "vault-or-2fa-recovery":
    "Local vault or two-factor recovery data may be lost, preventing account recovery.",
  "saved-passwords-passkeys-autofill-history":
    "Protected passwords, passkeys, autofill and history must be preserved. Confirmation cannot authorize deleting them.",
  "shared-store":
    "The reviewed shared store may contain data belonging to multiple selected owners.",
  unknown:
    "The local data loss is unknown. Unsupported operations and preservation conflicts remain blocked.",
};
export const outcomeNames: Record<import("./api").ActionStatus, string> = {
  "would-apply": "Would remove or change",
  applied: "Removed / changed",
  "already-absent": "Already absent",
  skipped: "Skipped",
  blocked: "Blocked",
  failed: "Failed",
};
export const verificationNames: Record<
  import("./api").VerificationStatus,
  string
> = {
  "target-absent": "Verified absent",
  "target-present": "Residual data present",
  inaccessible: "Verification inaccessible",
  unknown: "Unverified",
  "not-performed": "Not verified",
};
export const aggregateNames: Record<import("./api").AggregateStatus, string> = {
  "complete-local-scope": "Complete supported local scope",
  partial: "Partial",
  blocked: "Blocked",
  failed: "Failed",
  cancelled: "Cancelled",
  "dry-run": "Dry run",
  "not-requested": "Not requested",
};
export const stageNames: Record<import("./api").Stage, string> = {
  scan: "Scanning",
  selection: "Selecting",
  "dry-run": "Dry run",
  review: "Review",
  closing: "Closing programs",
  cleaning: "Cleaning",
  "identity-sync": "Identity / sync",
  verification: "Verifying",
  report: "Reporting",
};
export const uncertaintyNames: Record<import("./api").Uncertainty, string> = {
  unknown: "Unknown",
  unsupported: "Unsupported",
  "not-requested": "Not requested",
};
