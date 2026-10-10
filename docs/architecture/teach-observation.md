# EveryOut Teach observation (P2)

P2 learns metadata correlations for an exact P1 application binding. It records
observations, never a catalog validation, provider, executable plan or deletion
capability. The existing P0 decision gates and P1 identity resolution remain in place.

## Session and boundaries

`core-model::observation` contains the portable session, phase, differential and
learned-record model. `platform-windows::observation::TeachController` owns native
metadata capabilities and the phase machine. A separate desktop Teach worker owns
these non-Send capabilities on one thread. Its IPC vocabulary has only start, get,
discovery completion, cycle start, phase advance, finish and history operations.
It has no engine, executor, provider router, account helper or elevation operation.

The session binds the exact selected executable using P1: canonical path, physical
file identity, size/write stamp, publisher, signature status/certificate, PE version,
optional channel label and framework metadata fingerprint. Each phase retains the
observed PIDs and process creation times. Process image objects are checked against
the selected physical executable; basename matches only narrow process enumeration.
An unrelated same-name process, changed image or changed binding makes the session
stale. The optional channel is a user-supplied label; an unobservable configuration-only
channel change cannot be independently detected without a future metadata adapter.

Framework fingerprints inspect identity, size and timestamps of generic P1
installation artifacts (`resources/app.asar`, `libcef.dll`, `WebView2Loader.dll`,
`Update.exe`). They never parse their contents. Framework presence/fingerprint,
version, executable or signing changes invalidate the observation. Re-observing an
application at the same canonical executable path is treated as a version/identity
replacement, rather than automatically inventing an unrelated application owner.

Discovery can finish without an authentication cycle. Focused cycles require:

| Phase | Boundary snapshot   | App state label / native gate                                      |
| ----- | ------------------- | ------------------------------------------------------------------ |
| A     | Closed baseline     | Signed out; bound app is closed                                    |
| B     | Launch logged out   | Signed out; bound app is running                                   |
| C     | Login               | Signed in; bound app is running                                    |
| D     | Settled logged in   | Signed in; user waits for activity to settle                       |
| E     | Restart persistence | User labels still/not signed in; previous process objects are gone |
| F     | Vendor logout       | Signed out using the normal in-app action                          |
| G     | Closed logged out   | Signed out; bound app is closed                                    |

These labels describe the application's state. There is no input that claims a
folder is a token, validates an artifact or grants permission to remove it.

## Discovery and resource limits

Broad discovery starts while the selected app is closed and takes bounded baseline
snapshots. It watches current-user Local/Roaming AppData and LocalLow when available,
using fixed OS known-folder resolution. The existing bounded storage scanner provides
framework and registered MSIX candidates; P1 metadata-name candidates are additional
hints. Arbitrary activity can discover a directory without any match to EXE, catalog,
allowlist or known layout. MSIX events are aggregated to `Packages/<container>`;
other events are aggregated to their highest child directory under the broad root.
Hints are shortlisted only when their subtrees actually changed.

Broad watchers stop after 20 seconds, or when the user ends discovery. The shortlist
is ranked deterministically by activity and bounded to eight roots. Discovery snapshots
and coverage provenance remain separate from the subsequent authentication cycles.
No watchers remain active while waiting between cycles. Each focused cycle has a
20-minute deadline; sessions support at most four cycles and 100,000 retained phase
entries. Finishing/staleness releases directory watchers and root capabilities.

Snapshot defaults: 10,000 entries, depth 32, two-second traversal budget per root.
Focused/discovery candidate snapshots use 2,000 entries per root. Revalidation uses
2,000 entries and 100 ms per root. An enumeration error, budget limit, inaccessible
entry or omitted reparse marks the snapshot incomplete. Native enumeration itself
also caps an individual directory at 10,000 entries. Counts and approximate byte
totals are derivable from the entries; no content hashing is used.

Root disappearance, layout changes or changed physical root identity require
reobservation. Root physical changes across otherwise consistent cycles are also
inconclusive. Metadata enumeration retains the existing P0 no-reparse/hard-link and
ancestor binding constraints; these short-lived handles can delay directory renames.
Finishing releases the observation capabilities rather than holding app roots forever.

## Directory watcher and lost history

The backend dynamically resolves `ReadDirectoryChangesExW` and prefers its extended
notification format. When unavailable, unsupported or unusable, it falls back to
`ReadDirectoryChangesW`. Each watch uses subtree monitoring, a 64 KiB aligned buffer,
an OVERLAPPED request and its own event. Polls do not wait. Notification records are
length/bounds checked before UTF-16 filenames are decoded. Create, remove, modify and
both sides of a rename are supported. The retained watch handle is checked against
the already bound root's physical identity before starting I/O.

Buffers and OVERLAPPED structures live at stable heap addresses. Cancellation waits
for the pending request to finish before freeing them. The handle has directory-list
and attribute rights, never generic file-content read rights.

Completeness is explicit:

- `Complete`: no known history loss and complete phase endpoints.
- `RecoveredByRescan`: lost history, but a bounded metadata endpoint was recovered.
- `Incomplete`: recovery/enumeration/backend/process coverage remains incomplete.

A zero-byte result, notification error, invalid notification chain or event budget
loss triggers conservative recovery. The root is enumerated again and the provenance
includes `directory-watcher / history-lost-metadata-rescan`. Recovery never reconstructs
missing intermediate events. A recovered phase cannot provide negative event evidence
and cannot count as a complete authentication cycle. Persistent incomplete session
coverage prevents promotion entirely. An earlier recovered cycle can be retained while
two later complete cycles establish a result; a recovered cycle itself does not count.

Directory modify notifications are aggregate signals: Windows can deliver a directory
write notification after a child's removal has already been captured. They do not
represent a second auth transition. Structural directory create/remove/rename and
file modifications remain signals. Empty-directory timestamps are similarly excluded
from family transition comparison; their existence, identity and attributes remain.

The Win32 behavior and asynchronous lifetime requirements follow Microsoft's
[ReadDirectoryChangesExW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesexw)
and [ReadDirectoryChangesW documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-readdirectorychangesw).

## Artifact families and behavior classification

Family normalization uses paths/structure only:

- `Local Storage/leveldb/{log,ldb,MANIFEST...}` maps to `local storage`.
- SQLite `.db`, `.sqlite`, `.sqlite3` and their `-wal`, `-shm`, `-journal` companions
  map to the same database family.
- IndexedDB, Session Storage, cache, Code Cache and GPUCache map to their bounded
  containing family; standalone `leveldb` directories are also bounded families.
- Unknown nested files map to their containing directory. Root-level ordinary files
  retain a file family. Rotation cannot create a new auth scope for each member.

For each family and each cycle, compare six intervals between the seven endpoints.
Combine file identity/existence, metadata and structural changes with observed events.
Track the original per-cycle boolean differential, rather than averaging confidence.

A positive cycle requires a login change and a vendor-logout change, signed-in
persistence across the restart, and no family change during logged-out launch,
settling, restart or final closing. This deliberately conservative policy can leave
real auth stores inconclusive if they compact or rewrite on every launch. It does
not claim to inspect or understand their authentication values.

At least two complete positive cycles produce `StronglyObserved`, mapped only to
`AuthenticationScope::Observed`. A complete contradictory cycle makes the family
`Inconclusive`, even when two other cycles are positive. A continuously changing
family across launch/login/restart/logout is `BackgroundNoise`; all other non-auth
state is `PersistentAppState`. This is based on behavior: an opaque, non-cache-named
fixture is also classified as noise. Filenames do not establish auth evidence.

Repeated focused correlation or bounded P1 Restart Manager usage can corroborate
ownership; neither grants exclusivity. Restart Manager cannot supply authentication
evidence. An unrelated owner signal or independently corroborated observations from
different application bindings on the same physical root produces `SharedConflict`.
Historical projections show the conflict for both owners without rewriting history.

## Persistence, applicability and action

Finishing atomically creates a local `observations/<session-id>.json` record in the
desktop configuration directory. It retains the session (discovery, phases, endpoints,
labels, processes, timestamps and provenance) and the learned projection. A record is
bounded to 32 MiB, and history loading is bounded to 128 records / 64 MiB of serialized
history per load. Repeated saves cannot
overwrite an existing session. Malformed/reparse files are not adopted as observations.

History refresh re-resolves P1 application identity and bounded current-user roots,
then checks version/channel/framework, physical identities and directory layout.
The current projection becomes `Stale` or `NeedsReobservation`; historical JSON is
preserved. There is no path from this store into catalog loading or provider creation.
Physical file IDs and 64-bit metadata exposed over IPC use decimal strings so the
webview cannot round them through JavaScript numbers. Native comparisons remain exact.

The desktop entry is Settings → Learn an application. It shows phase, completeness,
candidate roots, cycle count and the final observation. Root/family technical details
are collapsed; family lists show at most 20 entries at a time. Browser previews cannot
invoke native observation.

Every learned result keeps `OperationAuthority::Unreviewed` and preservation unknown.
P0 decision evaluation blocks it even if a caller projects catalog support as Validated.
The module cannot read token/cookie/database payloads, decrypt Local State, enumerate
credentials, read foreign memory, inject code or delete learned scopes. P1 executable
PE/signature metadata and EveryOut's own JSON records are separate from app storage.

## Follow-up boundary

Controlled destructive scope validation, preservation review, VM compatibility trials,
validated surgical logout and any reviewed provider creation belong to the next stage.
P2 has no generic registry backend; registry-heavy apps can remain incomplete and need
an adapter. ETW and USN recovery are optional future backends, not runtime requirements.
Additional work may improve late-event phase attribution, high-noise family policies,
custom storage locations, MSIX executable selection, channel discovery and history UI.
