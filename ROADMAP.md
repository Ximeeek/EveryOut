# EveryOut roadmap

## V1 status

The V1 implementation includes metadata scanning, review/dry-run/confirmation, confined local
execution, account-scoped elevation, reports, manifest providers and signed catalog update
tooling. Release engineering supplies draft-only MSI builds, checksums, provenance and an
advisory two-build comparison. Authenticode signing remains conditional on provider onboarding.

This is pre-alpha validation, not universal application coverage or a certified release. Real
product/version validation, unresolved ownership/preservation blockers, disposable-VM
installation checks and signing approval remain release gates. Follow the
[catalog](docs/catalog/CATALOG.md), [VM guide](docs/testing/vm-guide.md),
[V1 exclusions](docs/architecture/08-not-doing.md) and
[release process](docs/oss/release-process.md).

## Possible V2 directions

These are roadmap items and reserved extension points only; no implementation or detailed V2
design is included and feasibility remains open. See
[V2 extension points](docs/architecture/09-v2-extension-points.md).

| Direction                        | Reserved extension point                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------- |
| Global hotkey                    | Host trigger feeding the ordinary selection/review flow                                     |
| Wipe on system shutdown          | Platform lifecycle trigger subject to shutdown deadlines and required review                |
| Server-side session invalidation | Provider `revoke()` hook, separate from V1 local execution                                  |
| Possible backup/undo             | Optional engine recovery boundary, only if compatible with never reading or copying secrets |

None of these directions permits bypassing confirmation, secret inspection or unreviewed network
logout. Backup/undo may remain infeasible under the central safety principle. V1 does not call
`revoke()`, register a global hotkey, wipe on shutdown or create backups in anticipation of V2.
