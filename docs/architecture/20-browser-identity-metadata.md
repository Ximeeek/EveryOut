# Browser identity and sync metadata

Phase 22 implements metadata discovery and warnings for Chrome, Edge, Brave, Opera,
Vivaldi and Firefox. Identity removal and closed-profile sync edits remain unsupported
until the decisions in [07](07-sync-and-identity.md) are validated. This replaces the
original phase requirement to implement unvalidated identity mutations and profile edits.

## Signals and reporting

The five Chromium-derived providers observe only existence of profile-relative `Sync Data`,
`Accounts` and `Account Web Data`. Firefox observes `signedInUser.json` as the safe
account-residue fallback, leaving Sync configuration unknown.
These are unverified research candidates, not complete vendor/version inventories.
The implementation uses retained root capabilities and shallow metadata probes, without
recursion or content reads. Inaccessible or unsafe paths produce `unknown`; absent paths
never mean signed out or sync disabled. Brave chain state cannot be established by these
signals; wallet, Rewards and encrypted seed content are never read.

Observations are captured during discovery and rendered under generated profile IDs in
provider descriptions and selected-profile plan limitations. They describe discovery-time
metadata, not post-wipe verification. Plans and engine JSON/text reports retain the warning:

> Sync or automatic sign-in can recreate data or access after this wipe. Local deletion
> does not remove server data or guarantee a lasting sign-out.

Warnings remain present with absent or unknown signals. The identity/sync hook validates
the plan and closed-process scope, performs no mutation, and returns `Unsupported` for
both operations. A skipped, blocked or cancelled hook leaves the engine outcome unknown.
Authentication, current identity/sync health and silent SSO remain unknown; remote revocation
remains unsupported. Unsupported identity actions do not block otherwise eligible session
cleanup. Shipping manifests remain candidate and unverified with S1–S4 pending.

## Revised phase acceptance criteria

- All six shipping manifests validate and disclose unsupported operations and unverified signals.
- Fixtures cover present/absent signals, inaccessible metadata, selected-profile observations,
  restoration warnings in plans/reports, dry-run immutability and closed-process gating.
- Account/configuration and sync-state payloads remain byte-identical after eligible cleanup.
  Invalid UTF-8 and synthetic email/token canaries never appear in reports.
- No configuration parsing exception is added. No sign-out, profile edit, registry/policy write,
  browser restart, real profile access or network authentication probe is implemented.
- Workspace build, tests, clippy and formatting plus frontend checks pass before one phase commit.

Fixture success establishes only this implementation contract. S1–S4 runtime/restart evidence,
exact readable field allowlists, preservation-safe identity closure, secret-free idempotent
editing and managed-policy precedence remain prerequisites for future mutation support.
