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
