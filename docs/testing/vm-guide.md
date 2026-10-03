# EveryOut Windows VM testing guide

Use a disposable Windows 10 or 11 guest on Hyper-V or another hypervisor. This is a manual lab
workflow, not VM automation or an undo feature. Use local test accounts only, synthetic profiles
and owned dummy processes; never import real profiles or create authentic login/session payloads.
Local deletion and random fixtures do not establish logout, DBSC, sync or remote revocation.

## Prepare and checkpoint

1. Create a fresh guest with a supported local NTFS disk. Record Windows edition/build, hypervisor
   version, architecture, security-product version/policy, test account role and filesystem.
2. Disable shared host folders/disks, clipboard, profile import and drive redirection. Keep
   personal accounts, browsers and stores outside the guest. Do not disable or evade security
   products; record denials and alerts as observed limitations.
3. Install the pinned Rust/MSVC and frontend toolchains from
   [CONTRIBUTING](../../CONTRIBUTING.md#running-the-app), or copy reviewed lab binaries into
   `C:\Lab\Tools`. Build dependencies may need networking; disable it for destructive trials.
4. Enable Developer Mode or grant the lab account symlink privilege for adversarial fixtures.
   Unsupported fixture creation fails the test; do not count skipped confinement checks as passes.
5. Shut down/quiesce the guest and take a clean hypervisor checkpoint before **each** scenario,
   including failure/retry/force-close cases. On Hyper-V use the VM's Checkpoints pane and record
   its checkpoint name; use the equivalent snapshot/revert control in another hypervisor.
   Start each scenario from this baseline with no authentic credentials or session stores.

## Automated synthetic harness

From a checkout of the recorded revision inside the guest:

```powershell
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The test-support crate creates and owns temporary trees. The injected fixture resolver pins
Local/Roaming AppData inside that tree and never uses host AppData or an environment override.
Deletion is performed through the real guarded Windows adapter. Registry tests use only their
unique volatile namespace and process tests spawn and clean up their own invisible dummy children.
The ignored `dummy_process` entry is invoked explicitly by its parent tests; do not run all ignored
tests directly. Layout and metadata assertion details are in the
[test-support reference](../../crates/test-support/README.md).

## Spike tools and manual scenarios

Build the independent tools before disabling networking:

```powershell
cargo build --locked --manifest-path spikes/tree-snapshot/Cargo.toml
cargo build --locked --manifest-path spikes/identity-probe/Cargo.toml
cargo build --locked --manifest-path spikes/process-close/Cargo.toml
cargo build --locked --manifest-path spikes/heuristic-scan/Cargo.toml
```

Run each tool using its README's exact flags and safety constraints:

- [Tree snapshot](../../spikes/tree-snapshot/README.md): `capture C:\Lab\Profiles\Case01`,
  then `diff` the explicit before/after snapshot JSON files. Keep evidence in
  `C:\Lab\Evidence\Case01`, outside every captured root. Check exit codes before saving output.
  This spike records timestamps as well as relative paths/sizes; harness snapshots use paths/sizes
  only. Neither reads profile payloads or proves authentication state.
- [Identity probe](../../spikes/identity-probe/README.md): `inspect-lab`, inside the guest under
  the intended lab user. Keep raw identifiers local and sanitize names before publishing evidence.
- [Heuristic scan](../../spikes/heuristic-scan/README.md): `scan-lab` in a quiescent guest. This
  read-only inventory does not establish active login, ownership or cleaning permission.
- [Process close](../../spikes/process-close/README.md): review one owned dummy PID and exact
  executable basename, then use `--pid`, `--image`, `--method` and
  `--i-understand-this-closes-processes`. Use a fresh baseline/dummy for each method. Force and
  two-second escalation require the explicit trial described there; never target real host apps.

The wipe engine and production providers are not implemented. There is no general wipe command
to run. Follow the individual [S1–S8 protocols](../spikes/README.md) and
[destructive test strategy](../architecture/11-test-strategy.md) only for their declared scope.
Real-product layout trials may use unused synthetic profiles inside the guest; do not sign into
real services, collect tokens, capture secret stores or infer logout from file absence.

Include absent/idempotent targets, preserved canaries, Unicode/spaces, traversal/absolute paths,
sibling-prefix escape, junction/symlink/hard-link aliases, root/ancestor/leaf substitution, locked
companions and access denial. Process cases cover dry run, graceful/refusing/windowless dummies,
approved force timing and unrelated sibling preservation. Record partial effects honestly;
remaining cross-user/helper/catalog and authentication cases are future gates, not implemented
harness coverage. Security-product denial is a limitation, not successful cleanup.

## Elevated helper and UAC (phase 27)

S6 remains **PENDING USER EXECUTION**. Run this checklist only inside the disposable guest.
Automated workspace tests exercise fake endpoints and a same-process pipe without elevation.
The optional manual driver requests real UAC; it is excluded from ordinary builds and tests.
It can exercise the boundary, but no other-account inventory or deletion is available in phase 27.

1. Build the helper and the explicitly opted-in driver from the recorded checkout:

   ```powershell
   cargo build -p everyout-elevated-helper --features manual-lab
   $labHelperDigest = (Get-FileHash -Algorithm SHA256 target\debug\everyout-elevated-helper.exe).Hash.ToLowerInvariant()
   ```

   Record this digest from the reviewed build before any tampering tests. The shipping native
   host must use a trusted distribution pin, never dynamically trust an installed file's hash.
   Keep both executables beside each other. Disconnect networking before these trials.

2. Run `target\debug\everyout-helper-lab.exe --disposable-vm $labHelperDigest current`.
   Expect no UAC, no helper, and the current-account status. Repeat with a manually elevated
   driver; ambient elevation must not widen mode. No real app/profile/process is targeted.
3. Run the same command with `finish`. Accept UAC for test user A. Expect authenticated IPC,
   `ProfilesReady` (Phase 28; `ScopeUnavailable` was the Phase 27 result), `Finished`, and helper exit. Inspect process metadata
   only. Repeat under a standard user with separate test administrator consent; account scope
   must still bind to A's retained parent token, never the administrator's HKCU/AppData.
4. Restore baseline and repeat `finish`, declining UAC. Expect `UacDeclined` fallback, one
   prompt, current effective/saved mode and fresh-review requirement; no privileged work.
   UI persistence, notification and actual rescan integration are phase 30 and remain untested.
5. With the previously recorded pin, remove the helper or replace it with another synthetic lab
   executable. Expect `StartFailed` or `AuthenticationFailed` before UAC. Test a synthetic
   reparse installation path and binary modification/ancestor rename while IPC is active;
   reject redirection or prevent replacement with retained locks. Restore the reviewed binary.
6. Run `parent-loss`; after authentication the driver exits immediately. Verify helper exit on
   the retained parent's termination, without waiting for the idle deadline. Run `timeout`;
   leave the driver alive and silent, and verify helper exit at the 30-second idle limit.
   The five-minute absolute lifetime must also apply to a client sending valid heartbeats.
7. Inspect the private pipe DACL in a reviewed VM metadata harness: only A and built-in
   administrators have specific data/attribute/control rights; no Everyone/authenticated-users
   grant or generic-write/pipe-instance right. Remote clients are denied. Try an unrelated test
   user, A in another logon/session, an administrator with a different PID, pipe squatting,
   wrong nonce/version/run, replay, unknown fields/commands and a path-injection payload.
   Authentication must reject every mismatch and end the helper before any operation.
   The driver deliberately has no arbitrary-message injection option: use a reviewed synthetic
   harness for cross-user adversarial cases; absent that harness record `NOT RUN`, never PASS.
8. Record OS/build, ordinary/elevated/consenting account relationships using neutral labels,
   revision, digest, scenario, prompt count, sanitized status and measured process-exit timing.
   Never record raw SID, nonce, private pipe name, secrets or profile payloads. Restore the
   checkpoint after every scenario; failures remain unresolved S6 gates.

See the [implemented boundary and limits](../architecture/22-elevated-helper.md).
Publisher signing, hostile installation trust, real cross-user ACL denial and UAC behavior
remain unverified until the corresponding VM evidence is recorded. These Phase 27 transport tests supply no multi-user/hive validation; use the Phase 28 checklist
below for the new account compartments.

## All-accounts mode (phase 28)

Status: **NOT RUN — S6 remains PENDING USER EXECUTION**. Execute manually only in
a disposable Windows 10/11 VM with local test users A and B. Keep B logged on for
the simultaneous-session arm, including locked/disconnected cases; use neutral
labels in exported evidence. Network access stays disconnected. Never run these
experiments on the development host or authenticated personal profiles.

1. Restore a token-free checkpoint. Prepare A/B synthetic fixture folders under
   their own standard AppData paths, including `EveryOutFixtureElectron/Cookies`
   and unrelated canaries. Use the same small dummy fixtures for each repetition.
   Build the opted-in driver as in the Phase 27 section and record its helper pin.
   Do not change a shipping candidate to validated merely to enable a wipe.
2. Run `everyout-helper-lab.exe --disposable-vm <recorded-sha256> current` under A.
   Expect no UAC or other-user discovery. Under all-account mode, first test UAC
   decline, then separate-admin consent; owner roots must remain A/B, never the
   consenting administrator. UI persistence/rescan behavior is still phase 30.
3. With B signed out, run the same driver with `all-accounts-preview`. It performs
   authenticated enumeration, planning and a metadata dry run only. Inspect opaque
   account IDs, logged-on/mounted indicators and exclusions. Compare SID/root
   associations locally using a reviewed OS metadata harness; never export SIDs or
   absolute profile paths. Test stale `.bak`, system/service/temporary, missing,
   denied, nonlocal, unresolved-variable and reparse/redirected profile records.
   Record unknown nonzero ProfileList state as excluded, not validated eligibility.
4. Inspect temporary HKU mount presence locally before and after offline preview.
   Confirm only A/B's selected owner-bound `NTUSER.DAT` can be mounted, key names are
   unique, no hive contents are copied/read, and all registry handles are released
   before unload. AppData metadata must resolve from B's hive/profile. Synthetic
   profile locations may not redirect into another account. Dry run must preserve
   every fixture/canary and must not send process-close messages.
5. Repeat with B logged on, then locked/disconnected, then both A/B active. Observe
   live `HKU\B-SID` borrowing, zero RegLoadKey/RegUnLoadKey calls for B and separate
   account report sections. Change B's logon state between enumeration, review and
   execution; expect stale-scope refusal and fresh review. Rechecks do not prove a
   race-free global profile lock; record any inconclusive transition evidence.
6. Through a separately reviewed VM fixture harness exercise exact synthetic
   registry canaries using RegistryExecutor and the normal engine guard. No actual
   browser, broker, Credential Manager, Windows sign-in or CLI credential target is
   authorized by this checklist. If the harness is absent, record this applied arm
   **NOT RUN — HARNESS BLOCKED**. The shipping catalog still contains candidates;
   the preview driver must report blocked scopes, never successful deletion.
7. Exercise success, denied registry work, cancellation, held-key unload failure
   and callback error. Require up to three unload attempts, separate operation and
   cleanup outcomes, and an explicit temporary-key residual report on exhaustion.
   A residual preview must block that account's apply while another account can
   proceed. Recover only the exact owned temporary VM mount after releasing its
   handles; never unload a SID/live hive. Restore the checkpoint afterwards.
8. In B's session start only a disposable dummy app with no unsaved data. Use a
   reviewed exact App Paths registration and retain PID, creation time, image, SID
   and session. Review the actual process set per account. Test Ask: graceful
   requests first, two-second observation, survivors block cleanup, no force.
   Separately acknowledge HardKillAfter2s loss for B and test termination of only
   the retained survivors after the full grace interval. Cross-session desktop
   access may expose zero windows; the report must show that unverified limitation.
   Record access-denied, unresponsive, no-window, PID reuse, new-owner/relaunch and
   registration-change cases. Never target browsers, Office, system/security apps
   or use hooks/injection/memory access. An absent reviewed harness blocks this arm.
9. For fixture-only applied trials, deny A's access or change A's profile root and
   ensure B's independent section still completes. Confirm Windows/developer
   category and each loss/force acknowledgment bind only to that account and the
   exact plan digest. Test missing/foreign consent, stale file identity (including
   equal-size replacement), candidate support and overlapping physical targets.
   Preservation and candidate blockers cannot be confirmed away.
10. Read every report page, concatenate its JSON and check per-account plan,
    execution, verification, three category sections, exclusions, SSO warning,
    unload attempts and S6-unverified markers. Test changed-state dry run, replay
    after apply, parent exit, pipe disconnect during a fixture action, finish and
    the absolute deadline. Previously applied effects must remain accounted for;
    no new effects are scheduled after cancellation. A disconnected client may
    lose the final residual reply; inspect the owned temporary namespace locally.
11. In an isolated snapshot force helper termination during a synthetic mount.
    Record that crash cleanup is not guaranteed, identify any owned residual mount
    locally and restore the VM. Do not mark this gap resolved by RAII fixture tests.
12. Repeat each executable arm three times from baseline. Record OS/build,
    revision/pin, neutral A/B/admin relationships, statuses, relative fixture
    metadata, process timing, preservation and recovery results. Sanitize temporary
    mount run/nonce names before exporting evidence. Leave missing/unverified arms
    NOT RUN or INCONCLUSIVE and restore after every trial.

See [all-accounts implementation and remaining limits](../architecture/23-all-accounts-mode.md).

## Evidence and restore

Record case ID, date, OS/product/channel versions, checkpoint, source revision, fixture seed
and generator revision, exact commands/exit codes, expected and observed relative metadata,
preservation results, partial effects, security alerts and limitations. Keep evidence free of
secrets, payloads, absolute personal paths, account identifiers and memory dumps. Sanitize tool
metadata before exporting it. Capture canary metadata before teardown, including failed trials.
Equal-size payload changes are invisible to harness snapshots; avoid claiming content preservation.

After every scenario, save sanitized evidence outside the guest snapshot, stop the guest and
apply the recorded checkpoint/revert through the hypervisor. Restart and verify the clean baseline
and canaries before another scenario. Restore after errors and aborted trials too. Do not keep
guest secret backups or claim that EveryOut can reverse deletion. Never mark a trial passed
merely because a requested operation returned zero; record actual effects and unresolved state.
