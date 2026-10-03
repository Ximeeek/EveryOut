import type { CommandError, ModeFailure } from "./api";

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
  placeholder:
    "Scan and selection will be available in the next phase. No scan or cleanup is started on this screen.",
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
