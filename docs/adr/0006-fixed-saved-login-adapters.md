# ADR 0006: Confine saved-login edits to fixed reviewed adapters

- Status: Accepted for the pinned Spotify desktop scope only
- Date: 2026-10-08

## Context

Deleting a mixed preferences file risks unrelated settings. Blocking every candidate also prevents
an operation whose exact saved-login fields have been tested on a real desktop build.

## Decision

Permit one compiled, bounded Spotify `prefs` adapter with an executable hash pin. Four exact
saved-login keys are removed; all other bytes and the original file identity/ACLs are preserved.
An unknown executable, encoding, layout or `autologin.*` key blocks mutation. Catalog and UI
input cannot supply arbitrary executable hashes, paths, key names or content-reading methods.

The file, including saved credential values, briefly enters private adapter memory. Preview
returns field presence only. Apply needs the engine-held reviewed plan and explicit confirmation.
Zeroizing buffers contain the original, filtered and verification bytes. No values are decoded,
logged, serialized, transmitted or written to an on-disk backup by successful cleanup. A failed
write attempts to restore original bytes from memory; interruption during writing remains a risk.

The engine accepts a logical target-presence predicate only from trusted compiled provider code.
An arbitrary exception method retains unknown verification. File-field absence does not prove
remote revocation, other-device logout, or authenticated UI state at runtime.

## Boundaries

This exception does not authorize Credential Manager enumeration, cookie/token database reads,
generic framework resets, foreign-process memory access or new readers supplied by catalog data.
Other credential-returning APIs require a separate policy decision and review. General AppData
discovery remains metadata-only. Version-specific live evidence is recorded in the
[Spotify review](../research/05-spotify-local-logout.md#live-review).
