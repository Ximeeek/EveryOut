# Provider contract

## Model and evidence

One provider describes one application or browser, with multiple instances for installations,
Windows users and profiles. A browser PWA is an alias of its browser provider when storage is
browser-owned. A shared framework runtime is not a provider.
See [application research §§1–2](../research/03-apps-detection-process-av.md) and
[classification rules](04-classification-rules.md).

Providers contain declarations interpreted by the common implementation. Exceptional Rust
adapters may implement the same contract only when declarations cannot express a reviewed local
operation. Steam is a candidate exception, not validated support; its implementation is blocked
on `app-session-scope` in the [open-decision register](00-overview.md#open-decisions).

## Six methods

| Method            | Inputs / outputs                                                                                  | Required semantics                                                                                                                  |
| ----------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `detect`          | Bounded detection context → instances, metadata observations, confidence and issues               | Read-only existence/type/size observation; identify residue and uncertainty without claiming sign-in                                |
| `describe`        | Instance → name, category, profiles, risks, expected effects, evidence and limitations            | Pure projection; no fresh I/O or hidden account-content reads                                                                       |
| `plan`            | Snapshot, selected instance scopes → actions, shared effects, blockers and required confirmations | No mutation; use only reviewed manifest operations and identified owners; no arbitrary paths from UI                                |
| `execute(dryRun)` | Engine-held plan, mode and operation context → per-action outcomes                                | Dry run performs only metadata revalidation and predicts effects; live execution stays within the plan and returns partial progress |
| `verify`          | Plan and execution result → per-artifact verification observations                                | Metadata-only check; missing stores do not establish remote logout, active token invalidity or safe restart                         |
| `report`          | Description, execution and verification → sanitized report                                        | Pure projection; preserve failures, skips, unsupported coverage and uncertainty; no raw secret stores or command output             |

The contract specifies dependencies between results, not shutdown/deletion order. Scheduling,
permissions and synchronization handling are reserved for Phase 9.

`revoke()` is reserved for V2 server-side invalidation. **V1 does not implement `revoke()`**,
register an IPC command for it, or fall back to it. The following separate interface only records
the required reservation; it does not define a V2 protocol. Known CLI logout commands that revoke
remotely, such as token-based npm logout or user-account gcloud revoke, are not V1 operations
([Windows research §4](../research/02-windows-identity-and-multi-account.md)).

## Rust trait and type sketches

These are intentionally non-compilable design sketches; auxiliary types represent the semantic
fields described below. They do not add source files or settle async/runtime implementation.

```rust
pub trait Provider {
    fn detect(&self, cx: &DetectionContext) -> DetectionResult;
    fn describe(&self, instance: &ProviderInstance) -> ProviderDescription;
    fn plan(&self, cx: &PlanContext, selected: &Selection) -> PlanResult;
    fn execute(
        &self,
        cx: &OperationContext,
        plan: &ValidatedPlan,
        mode: ExecutionMode,
    ) -> ExecutionResult;
    fn verify(&self, cx: &VerificationContext, result: &ExecutionResult)
        -> VerificationResult;
    fn report(&self, result: &ProviderResult) -> SanitizedReport;
}

pub enum ExecutionMode { DryRun, Apply }
pub enum Confidence { High, Medium, Low }
pub enum AccountMode { Current, AllAccounts }
pub enum Category { Application, Browser, WindowsMicrosoftAndDevTools }

pub struct ProviderInstance {
    pub provider_id: ProviderId,
    pub instance_id: InstanceId,
    pub owner: OwnerIdentity,
    pub profiles: Vec<ProfileScope>,
    pub confidence: Confidence,
    pub evidence: Vec<EvidenceRef>,
    pub issues: Vec<ProviderIssue>,
}

pub struct ExecutionResult {
    pub plan_id: PlanId,
    pub mode: ExecutionMode,
    pub outcomes: Vec<ActionOutcome>,
    pub issues: Vec<ProviderIssue>,
}

pub enum ActionStatus {
    WouldApply, Applied, AlreadyAbsent, Skipped, Blocked, Failed,
}
pub enum VerificationStatus {
    TargetAbsent, TargetPresent, Inaccessible, Unknown, NotPerformed,
}
pub enum ErrorKind {
    AccessDenied, Locked, OwnershipConflict, StalePlan, Unsupported,
    InvalidManifest, ScopeViolation, SecurityProductBlocked, Cancelled, Io,
}

// Reserved only; no V1 implementation or command registration.
pub trait ReservedServerRevocation {
    fn revoke(&self, request: &RevocationRequest) -> RevocationResult;
}
```

Contexts expose narrow metadata/operation interfaces, reviewed manifest identities and
cancellation state, never database readers, decryption helpers or general shell execution.
The API permits no session bytes in results. Credential APIs that return secret blobs cannot
be used to populate identity fields (Windows research §3).

`OwnerIdentity` associates an OS user, installation/package identity and root scope inside Rust.
Public DTOs use opaque IDs and neutral labels when an account name cannot be safely determined.
`ProfileScope` is a storage scope; it is not proof of one authenticated account. `Selection`
references an inventory snapshot and the global account mode. `ValidatedPlan` is engine-created
and records manifest revision, fixed targets, effects, ownership, blockers and confirmations.

## Errors and partial results

Each issue records phase, provider/instance/action ID, stable error kind, optional OS error code,
sanitized explanation and whether the affected action is blocked. Do not serialize arbitrary OS
messages containing paths or captured CLI output. Failures of one action retain earlier outcomes;
no all-or-nothing rollback is promised, and no session backup is created.

Planning returns either an executable scoped plan or a blocked result with the missing evidence.
An unresolved shared store, preservation conflict or unsupported operation blocks the affected
action even when its list item is selected. Confirmations acknowledge known consequences; they
cannot authorize an operation outside the supported contract.

Aggregate outcome definitions:

- **Complete local scope:** all planned supported actions are applied/already absent and all
  required metadata checks establish absence; coverage limits remain in the report.
- **Partial:** at least one action succeeded and at least one failed, was blocked/skipped or
  remains unverified. Never relabel this as complete logout.
- **Blocked/failed:** no action completed and issues explain why.
- **Cancelled:** cancellation is the aggregate state, preserving any prior mutation and counts.
- **Dry run:** `WouldApply` and predicted counts only; verification is `NotPerformed` for deletion
  effects, while metadata observations may still be reported.

For example, deleting a targeted cookie artifact while a companion is locked produces one
`Applied`, one `Failed(Locked)` and a partial result, even if the main file is absent. Cookie
absence never proves browser identity removal or remote revocation.
See [browser research §§1–5](../research/01-browsers.md) and
[application research §§5–6](../research/03-apps-detection-process-av.md).

## OPEN DECISIONS

See the central register: `browser-artifact-closure` for verification coverage,
`app-session-scope` for exceptional provider operations, and `metadata-discovery-allowlist` for
account/profile discovery. Until resolved, affected methods return explicit unknown/unsupported
results rather than inspecting session contents.
