# Classification, ownership and selection rules

## Evidence and category meaning

The categories are `application`, `browser` and `windows-microsoft-and-dev-tools`.
Classification follows the owner of the session store, not the rendering engine, shortcut name
or installer technology. These are adopted architecture policies based on the ownership proposal
in [application research §2](../research/03-apps-detection-process-av.md) and identity boundaries
in [Windows research §§1–4](../research/02-windows-identity-and-multi-account.md).

The Windows/Microsoft + developer-tools category is a presentation/risk group for explicit
providers, not one giant provider authorized to wipe Windows identity. It includes reviewed
developer-credential providers and Microsoft/Windows shared-identity observations. Edge is a
browser; an independent Microsoft desktop app is normally an application unless its specific
provider targets reviewed shared-identity/developer-tool scope. Unknown broker caches are
informational and have no executable plan.

## Deterministic precedence

Apply these rules in order to each storage target. Exactly one category/owner is required before
an action is executable; unresolved discoveries are explicitly unclassified.

1. **Browser-owned root/profile:** classify as browser, including browser-installed PWAs,
   site shortcuts and MSIX/Store/Uninstall wrappers that merely launch that browser profile.
   The wrapper cannot establish a second wipe root. Edge/Chrome PWA data shared with tabs
   stays under its browser owner.
2. **Reviewed shared identity or developer-tool provider:** classify as
   `windows-microsoft-and-dev-tools` only for its explicit supported targets; never infer a broad
   broker deletion rule from a Microsoft directory name.
3. **Independent application owner:** native, Electron, CEF or WebView2 hosts with their own
   reviewed data root are applications. Independently registered MSIX apps with exclusive app
   containers are applications regardless of packaging or browser-like rendering.
4. **Insufficient/conflicting ownership:** leave unclassified and block affected actions. Do not
   default an unknown WebView2 or package folder to application merely to complete the list.

SSO describes a relationship, not a new category. The application/browser remains in its owner
category; a shared identity provider appears separately with explicit links and limitations.
Windows sign-in/PRT state is not an actionable logout item. Classification does not authorize
Windows account disconnection; that behavior is reserved for later design.

| Case                                                          | Owner/category and presentation                                                                                   |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Chrome-installed PWA with browser profile storage             | Browser; expandable PWA alias under Chrome, no independent cleaning action                                        |
| Store wrapper launching Edge `--app-id`                       | Browser if ownership corroborated; arguments alone are insufficient and their content-read exception remains open |
| Independent WebView2 app with exclusive UDF                   | Application; runtime process is not a separate list item                                                          |
| WebView2 apps sharing one UDF                                 | Application owners linked to a shared store; no unique-owner assumption                                           |
| Independently registered MSIX chat app with its own container | Application; container is not automatically session-only                                                          |
| Edge using Entra SSO                                          | Browser plus a shared-identity relationship; local cleanup cannot promise durable global sign-out                 |
| GitHub CLI credential scope                                   | Windows/Microsoft + developer-tools; supported local behavior only                                                |
| TokenBroker folder without supported target semantics         | Informational identity observation; no delete plan                                                                |

PWA/UDF outcomes are architecture policy, with release-specific enumeration and ownership still
open (`pwa-shared-store-ownership`). Shared SSO reauthentication is configuration-dependent;
see Windows dossier §2 and [browser dossier §3](../research/01-browsers.md).

## Overlap and deduplication

Provider identity is stable per application/browser. Instance keys distinguish OS user plus PFN,
or user plus installation identity and resolved root. Browser profiles are children; aliases
never create duplicate instances. Registry views, shortcuts and multiple discovery sources merge
as evidence for the same instance.

Plans identify exact artifact families and owning scopes. When two selected items reference the
same physical store, schedule at most one action and attribute its outcome to all affected items.
Ancestor/descendant deletion and companion-family overlaps are conflicts as well as exact path
duplicates. Do not use lexical path equality alone to decide physical identity.

If a shared store affects an unselected owner, disclose that effect and block its deletion until
all affected scopes are explicitly included and required confirmations are satisfied. If ownership
or isolation cannot be established, block even when every visible item is selected. No silent
per-origin/account row edits are possible in secret-bearing databases. Preserving a shared store
can leave sessions present; the report marks the corresponding providers incomplete.
Browser dossier §§1, 5–6 and application dossier §§1–2 support these constraints.

## Default selection and confirmations

Selection granularity is per application/browser provider, with expandable installation, profile
and account scopes. A parent initially includes all detected children within the global account
mode; changing a child shows partial selection. Account labels are neutral when safe metadata
cannot identify them. An undifferentiated shared account store cannot offer fictional per-account
selection; disclose the indivisible scope instead.

**Everything detected is pre-selected by default**, including known data-loss risks and the
Windows/Microsoft + developer-tools category, subject to the explicit heuristic exception:
all heuristic candidates, including high confidence, remain in a separate unchecked section
until S8 passes. Known-provider selection does not depend on catalog support/confidence. Unknown
folders below the detector's minimum signal requirement are suppressed, not list items.

“Select all” selects all resolved detected provider items and does not silently deselect risky
ones. The heuristic candidate section has a separate explicit selection control; the main
control preserves its unchecked default. Selection expresses intent, not execution eligibility:
selected unsupported/blocked observations stay visibly selected with no executable action.

| Selected item                                           | Initial selection                                                           | Additional execution requirement                                            |
| ------------------------------------------------------- | --------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| Resolved known-provider detection                       | Checked                                                                     | Validated scope and normal plan review                                      |
| Any heuristic candidate, including high until S8 passes | Unchecked, separate section                                                 | Explicit selection plus ownership and supported-scope validation            |
| Known permanent-data-loss risk                          | Checked                                                                     | Additional explicit confirmation naming affected data and provider/profile  |
| Windows/Microsoft + developer-tools                     | Checked                                                                     | Separate category confirmation naming the included targets and consequences |
| Both special category and permanent loss                | Checked                                                                     | Both confirmations required; neither substitutes for the other              |
| Unsupported or unresolved cleaning scope                | Checked if resolved detection; unresolved candidate follows confidence rule | Blocked; confirmation cannot authorize unsupported deletion                 |

Confirmations attach to the reviewed plan and its exact selected scopes. Changing scopes or effects
invalidates affected confirmations. Declining a confirmation blocks the affected actions without
changing the select-all default. Unknown loss assessments are disclosed and remain blocked until
supported scope is established, rather than downgraded to “no risk”.

The research proposed opt-in developer operations; Phase 8 adopts the requested pre-selection
plus separate-confirmation policy instead. Pre-selection never authorizes automatic deletion of
unsupported broker caches or protected browser stores.

## Global account mode

`current` / `all accounts` is one global setting, never a list item. Default `current` means the
invoking Windows user's detected provider scopes, including all discovered app/browser profiles;
it does not mean one guessed signed-in website account. `all accounts` means eligible detected OS
user scopes. It does not imply that all hives/profiles are accessible or that all accounts inside
an opaque store can be enumerated. Expand user/profile/account children where safe metadata is
available, showing unknown/inaccessible coverage explicitly.

This default chooses the current-user research baseline (Windows dossier §5). The permission/UAC
mechanics, profile eligibility and handling of simultaneous sessions are reserved for Phase 9.
Changing global mode requires a new inventory/plan review so an old plan cannot widen implicitly.

## OPEN DECISIONS

See [the central register](00-overview.md#open-decisions): `pwa-shared-store-ownership` validates
PWA and shared UDF mappings; `metadata-discovery-allowlist` determines safe profile/account labels;
`extension-preservation-boundary` and `browser-artifact-closure` determine whether shared/mixed
stores can support isolated cleanup. Unresolved effects remain blocked, not guessed.
