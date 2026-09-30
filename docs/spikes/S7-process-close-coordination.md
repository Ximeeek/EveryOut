# S7 — application close methods and unsaved work

Status: PENDING USER EXECUTION

Phase 13 definition for EveryOut; no application experiment results exist. Resolves evidence for
`process-close-coordination`, not permission to implement wiping. Follow the
[common lab rules](README.md#common-lab-rules-and-evidence-gates) and
[wipe sequence](../architecture/05-wipe-sequence.md#process-closing-setting).

## Question and boundaries

Compare Restart Manager without force, asynchronous `WM_CLOSE`, and explicit `TerminateProcess`.
Measure actual exit, prompts/refusal, surviving resource holders and synthetic unsaved-work loss.
Compare a fourth arm: WM_CLOSE followed by termination of the same approved survivor after two
seconds. Two seconds does not make termination safe: unsaved documents, uploads and drafts can be
lost and local state can become inconsistent. Default ask mode must never escalate automatically.

The [process-close CLI](../../spikes/process-close/README.md) takes a single PID and exact image
basename, checks the invoking user/session and retains its process handle/creation time. A name
is an additional check, not an instruction to close every process with that name. Child/helper
processes need separate reviewed identities; do not close all WebView2 instances or services.
Exit does not establish lock release, ownership of session data or logout. No deletion occurs.

Microsoft documents process identities in
[RmRegisterResources](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmregisterresources)
and the shutdown behavior of
[RmShutdown](https://learn.microsoft.com/en-us/windows/win32/api/restartmanager/nf-restartmanager-rmshutdown)
(accessed 2026-09-30). RmShutdown refreshes its affected list; its forced timeout is not the
EveryOut two-second interval. The CLI registers only the explicit unique process, verifies the
affected set contains only that identity, uses no forced flag and never calls RmRestart.
Its synchronous shutdown call has no tool-level deadline. Two-second escalation with Restart
Manager is deliberately refused: cancellation, concurrency and in-flight shutdown coordination
need a future reviewed harness. Record `NOT RUN — METHOD BLOCKED` for that combination; it is
not a validated EveryOut implementation or an excuse to substitute a global taskkill command.

## VM procedure

1. Prepare separate disposable Windows 10 and Windows 11 VMs, with test users A/B and no host
   shares, clipboard, imports or real profiles. Build all lab executables before network isolation.
   Record OS build, app versions, protection-product version, tool commit, privileges and timers.
   Do not log in to apps, collect credentials, copy profiles or read session-store contents.
2. Start with synthetic cooperative/refusing/no-window dummy processes and synthetic lock
   canaries. Review PID, image, creation identity and selected user/session through OS tools.
   Keep an unrelated same-image dummy and a B-session dummy alive as negative controls.
   Use a secret-free lock canary controlled by the harness to observe release; never probe a
   browser database for content or equate missing lockfiles with released handles.
3. Install the target corpus: Notepad, Paint, Visual Studio Code, Discord, Slack, Spotify, Steam,
   Chrome, Edge and Firefox. These are measurement targets, not supported providers. Record exact
   process images/versions from the installed build; do not assume product names equal executable
   names. Mark unavailable or unreviewed apps `NOT RUN` with reason. Disable automatic app restart
   only through supported lab/UI controls; record any unavoidable relaunch.
4. For each app, restore the clean baseline and prepare saved/idle, synthetic unsaved document or
   draft, user-declined prompt, busy/refusing and multiple-process cases where applicable. Record
   `NOT APPLICABLE` rather than simulating an unsupported state. Use only disposable synthetic text
   and UI observations. Establish ground truth and the exact close set before issuing a request.
5. Repeat each applicable app/state/method arm at least 20 times from a reset baseline. Include a
   no-close control. Run Restart Manager, WM_CLOSE, direct force and WM_CLOSE + two-second force
   independently; do not chain methods on the same altered case. See CLI commands in its README.
   The confirmation flag acknowledges closure; the additional two-second flag acknowledges
   forced loss. Never run these commands on the development host or against other users' apps.
6. Record request duration, total duration, API status, prompt/refusal, actual selected-process exit,
   surviving helpers and unselected-control liveness. The CLI waits five seconds after an ordinary
   request; Restart Manager's request itself can take longer. Define a separate 60-second external
   observation window before the trial. If RM blocks, preserve the case as incomplete and restore
   the VM; do not assume terminating the CLI cancels an in-flight RM operation safely.
7. Observe synthetic unsaved text through app UI after a separately authorized manual restart.
   Count preserved/lost/recovered/unknown, prompts honored or bypassed and interrupted work.
   Do not export content, dumps, profiles or post-login snapshots. Observe synthetic lock release
   and relaunch at 0, 2, 5 and 30 seconds after reported exit. Relaunch or continuing lock blocks
   any subsequent wipe. This procedure never performs one.
8. Exercise absent/stale PID, mismatched image, inaccessible process, another user/session,
   same-image sibling and exit between review/request. Test PID reuse with a controlled dummy
   harness, retaining creation-time identity. The CLI pins only the process observed when it opens
   the PID; it does not bind an earlier external plan. Record that gap, HWND reuse and unresolved
   child ownership as blockers for production. No hooking, injection, memory reads or drivers.

## Acceptance criteria

- Saved/idle cooperative cases: at least 95% actual exit within the declared observation window
  for each app/method/OS with at least 20 applicable trials. Report numerator/denominator and a
  Wilson 95% interval; aggregate success cannot hide a failing app. Unsupported methods stay
  unsupported, rather than passing by forced fallback.
- Graceful cancellation/refusal: 100% of reviewed refusal trials retain the process and unsaved
  canary without automatic force; prompt-preserved process survival is the expected outcome here,
  not a saved/idle failure. WM_CLOSE + two-second and direct force arms may lose all unsaved work;
  measure that loss explicitly, with unknown outcomes separate from preserved ones.
- Force only the approved identity: zero closures of unrelated/same-image/cross-session controls,
  zero widening to services/helpers and zero identity substitutions. Any such event fails the
  coordination method regardless of success rate.
- Two-second WM_CLOSE arm: no force request earlier than 2,000 ms from the first graceful request;
  target scheduling delay no more than 500 ms in quiescent dummy VM trials, reported separately
  from process-exit latency. Scheduling overruns are failures for this timing criterion, not a
  promise that production Windows supplies a hard real-time deadline. Only approved survivors
  may be forced; wait for actual exit and independently observe resource release.
- Account for every applicable loss/prompt/control observation. Never claim force-safe, lock-free
  or logout success from an API return code. RM + two-second coordination, earlier-plan identity,
  HWND races, relaunch and child ownership remain blocked until independently validated.

## Results template — unexecuted

| Case / OS / app version / commit | State / method / repetition | PID identity check | Request / total ms / API code | Prompt / refused | Actual exit / surviving helpers | Lock release / relaunch | Unsaved preserved / lost / recovered / unknown | Unselected controls | Criterion result / reason |
| -------------------------------- | --------------------------- | ------------------ | ----------------------------- | ---------------- | ------------------------------- | ----------------------- | ---------------------------------------------- | ------------------- | ------------------------- |
| NOT RUN                          | NOT RUN                     | NOT RUN            | NOT RUN                       | NOT RUN          | NOT RUN                         | NOT RUN                 | NOT RUN                                        | NOT RUN             | NOT RUN                   |

| OS / app / state / method | Applicable trials | Exits / trials | Success % / Wilson 95% interval | Lost / observed / unknown | Refusals honored / trials | Timing overruns | Exclusions / blockers | Decision |
| ------------------------- | ----------------- | -------------- | ------------------------------- | ------------------------- | ------------------------- | --------------- | --------------------- | -------- |
| NOT RUN                   | —                 | —              | —                               | —                         | —                         | —               | No VM evidence        | NOT RUN  |

Use the register's result vocabulary. Unit/integration tests with spawned dummies validate tool
boundaries only; they do not populate this table or change the pending status.

## Local tool verification — 2026-09-30 (not spike execution)

The `process-close` crate test suite passed on the development PC: 3 tests passed and the helper test was invoked by its parent integration test. Integration coverage used only test subprocesses spawned by that test: it exercised Restart Manager, WM_CLOSE, direct termination, exact-image refusal, same-image sibling preservation, refusal without escalation, and the two-second escalation timing. No real application or unrelated process was targeted. These are tool safety tests, not the VM target-app trials or measured success-rate/data-loss results; S7 remains PENDING USER EXECUTION.
