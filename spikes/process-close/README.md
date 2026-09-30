# EveryOut process close lab tool

Independent Windows Rust CLI for [S7](../../docs/spikes/S7-process-close-coordination.md).
Its own `[workspace]` and ignored target directory keep it outside the application build.
It changes process state, never deletes data or reads application payloads. Use only disposable
VM applications with synthetic work. Force closing can destroy unsaved documents/drafts,
interrupt uploads and leave state inconsistent; two seconds does not make termination safe.

```powershell
cargo build --locked --manifest-path spikes/process-close/Cargo.toml
cargo test --locked --manifest-path spikes/process-close/Cargo.toml
cargo fmt --manifest-path spikes/process-close/Cargo.toml -- --check
cargo clippy --locked --manifest-path spikes/process-close/Cargo.toml --all-targets -- -D warnings
```

Inside a disposable VM, review one PID and its exact executable basename using OS tools. Replace
the placeholders below with the reviewed test process; no process-name enumeration or wildcard
selection is performed. Each arm needs a fresh dummy/test app from the clean baseline.

```powershell
$tool = 'C:\Lab\Tools\everyout-process-close.exe'
$targetPid = 1234 # replace with the reviewed test PID
$targetImage = 'lab-dummy.exe' # replace with its exact basename
& $tool --pid $targetPid --image $targetImage --method restart-manager --i-understand-this-closes-processes
& $tool --pid $targetPid --image $targetImage --method wm-close --i-understand-this-closes-processes
# Explicit force acknowledgment applies only to the reviewed target:
& $tool --pid $targetPid --image $targetImage --method force --i-understand-this-closes-processes
& $tool --pid $targetPid --image $targetImage --method wm-close --hard-kill-after-2s --i-understand-this-closes-processes
```

The flag, nonzero PID, exact `.exe` basename and method are mandatory. Duplicates, wildcard/path
images, unknown flags and unsupported combinations are refused before any process API. The PID
cannot be the CLI itself. The tool opens only that PID, retains the handle and creation time,
queries image metadata and compares token owner SID and Windows session to the invoking process.
No token privileges, credentials, foreign memory, hooks, injection, driver or elevation are used.
It revalidates identity before requests/escalation. Access denial stays a refusal. The retained
identity is established at tool invocation; this CLI does not bind an earlier plan's creation time,
resolve child ownership, protect every HWND reuse race or prevent app relaunch.

`wm-close` enumerates at most 1,024 top-level windows belonging to the explicit PID, rechecks
each window's PID and posts WM_CLOSE asynchronously. Applications can prompt, ignore or refuse.
No-window processes report a refusal; there is no force fallback. Ordinary requests wait up to
five seconds for actual process-handle signaling. `force` uses TerminateProcess on the same handle.
`--hard-kill-after-2s` is allowed only with WM_CLOSE: wait until at least two seconds from starting
the graceful request, then terminate only the pinned approved survivor and wait up to five more
seconds. Windows scheduling can delay escalation; there is no hard real-time guarantee.

`restart-manager` uses official bindings, an RAII session, RM_UNIQUE_PROCESS (PID + creation time),
no file/service registrations, and RmGetList validation requiring exactly that process, no service
and no reboot reason. RmShutdown uses flags 0; it never calls RmRestart or forces automatically.
The shutdown call is synchronous and can outlast the five-second subsequent wait. There is no
tool-level cancellation/deadline. Combining RM with two-second escalation is refused pending
separate coordination research, as described in S7. RM's own OS bookkeeping is not a read-only
operation; this executable is intentionally separate from the metadata scanner.

Exit 0 means actual selected-process exit observed (not proof of released resources or logout).
Exit 2 means still-running or failed wait, with JSON outcome. Exit 1 means invalid arguments,
refusal or API/serialization failure. Invalid arguments emit sanitized stderr and empty stdout;
post-parse refusals/API failures emit sanitized JSON with total elapsed time and possible partial
closure, because previously posted windows can already be closing. Successful requests report
method, PID, request/total milliseconds, API status, windows requested, escalation and exit state.
`escalation_ms` records the monotonic time of a force request in the two-second arm, or null.
`grace_ms_before_force` measures the interval since the first successful WM_CLOSE post; enumeration
and identity-query time cannot shorten that two-second grace period.
An RM failure code can coexist with observed process exit; inspect both fields. No image path,
window title, SID, payload or memory dump is exported. Resource release is always unverified.

Tests refuse missing acknowledgment before process access. Windows integration tests spawn their
own invisible dummy-window test subprocesses, exercise all three APIs, retain an unrelated
same-image sibling, refuse mismatched image, observe refusal without escalation and verify the
two-second force arm on a refusing dummy. Cleanup kills only those owned test subprocesses.
The ignored `dummy_process` test is explicitly invoked by its parent test, not skipped coverage;
do not run all ignored tests directly. No real host application is targeted. These tests do not
measure S7 target-app success, lock release or unsaved-data behavior; VM results remain pending.
