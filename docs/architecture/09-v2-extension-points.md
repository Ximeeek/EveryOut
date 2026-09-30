# V2 roadmap and extension points

Roadmap only for EveryOut. No V2 feature is implemented, promised or specified in detail here.
V1 boundaries remain those of [08](08-not-doing.md). Proposed triggers must reuse the reviewed
engine plan and explicit effects in [05](05-wipe-sequence.md), not bypass confirmations.

| Possible V2 feature            | Reserved extension point                                                                                     | OPEN DECISION / named spike                                                                                                                              |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Global hotkey                  | Host input trigger feeding the ordinary engine selection/review flow                                         | `v2-global-hotkey-feasibility`: investigate registration conflicts, user intent and confirmation delivery                                                |
| Wipe on system shutdown        | Platform lifecycle trigger feeding the engine, subject to shutdown constraints                               | `v2-shutdown-wipe-feasibility`: investigate shutdown deadlines, cancellation, partial results and whether required review can be completed safely        |
| Server-side session revocation | Provider `revoke()` hook already reserved by [01](01-provider-contract.md), separate from V1 local execution | `v2-server-revocation-feasibility`: investigate supported provider mechanisms, network authorization and compatibility with the no-secret-read principle |
| Possible backup/undo           | Optional engine recovery boundary around reviewed reversible effects                                         | `v2-backup-undo-feasibility`: investigate whether any useful recovery is compatible with never reading or copying secrets and with irreversible deletion |

These are requested product directions, not capabilities established by the dossiers. Research
leaves feasibility open: [browser §§3–4](../research/01-browsers.md) separates local effects from
remote invalidation; [Windows §4](../research/02-windows-identity-and-multi-account.md) identifies
provider-specific remote logout behavior; [application §5](../research/03-apps-detection-process-av.md)
shows closing and unsaved-work constraints relevant to new triggers. None supplies a safe hotkey,
shutdown, revocation or recovery implementation.

V1 does not implement/register `revoke()`, use network logout as a fallback, or create backup
copies in anticipation of V2. Each named spike must establish feasibility before a later design
phase selects protocols, storage, scheduling or permissions. Backup/undo may remain infeasible
under the central principle; the roadmap does not authorize changing that principle.
