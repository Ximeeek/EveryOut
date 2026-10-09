# Spotify local saved-login removal

## Live review

On 2026-10-08, desktop Spotify 1.2.98.301 started with a remembered account. Its executable
had a valid Spotify AB Authenticode signature. The compiled adapter pins that exact executable
with SHA-256; the catalog cannot supply replacement executable names, hashes or configuration
keys. This evidence does not establish compatibility with other releases or Store builds.

After gracefully exiting the desktop, removing these four fields from Roaming Spotify/prefs
and starting it again showed Spotify's login screen:

- `autologin.username`
- `autologin.saved_credentials`
- `autologin.canonical_username`
- `autologin.blob`

All other preference bytes were preserved. Installation resources, per-user directories,
cache and downloaded-file stores were not cleanup targets. The test measures local remembered
login; it does not revoke server credentials, prove other devices signed out, or establish
that downloaded audio remains playable while signed out.

## Execution contract

The manifest uses the compiled `spotify-saved-login-v1` exception adapter, never whole-file
deletion. It remains candidate support with an explicit reviewed-provider confirmation.
Unsupported executable hashes and unsupported login-file layouts block execution.

The fixed file is opened relative to a retained, checked root. Reparse points, hard links,
target substitution, invalid UTF-8, files over 64 KiB and unknown `autologin.*` fields are
refused. Existing duplicate reviewed keys are all removed. Line endings, comments, BOM and
all unrelated bytes survive unchanged. Preview reads return only field presence; credential
values remain in zeroized adapter buffers and are not included in diagnostics or reports.

An exclusive write handle retains the original file identity and ACLs. Apply writes, truncates,
flushes and reads back the result. Any I/O/read-back failure attempts to restore the original
bytes from memory. Failure to restore is reported as a failed operation. Power interruption
during in-place rewriting is a remaining limitation; this is not an atomic replacement protocol.
Successful cleanup creates no on-disk credential backup. The one-off development test used
a private recovery copy outside the repository.

Verification checks absence of the saved-login fields, rather than absence of `prefs`.
The logical target label explicitly names saved-login fields. Runtime authentication remains
unknown: file verification is not a live inspection of the Spotify UI.

The final opt-in CurrentSession/engine trial closed seven matching Spotify processes and reported
`complete-local-scope`, `applied` and `target-absent`, without issues. A byte comparison immediately
after execution confirmed that `prefs` equaled the original with only those four fields removed.
No other application's logout was tested. See the [reproducible probe procedure](../testing/vm-checklist.md#spotify-development-probe).

## Relation to universal discovery

AppData discovery and Electron/CEF/WebView2 layout recognition provide candidates, ownership
evidence and storage hints. Cache presence does not identify an authentication boundary.
This adapter illustrates the promotion path: discover, identify the executable and owner,
isolate login state from unrelated data, perform a real restart test, then enable only the
reviewed operation. Guessing an entire AppData directory cannot replace those steps.

Spotify distinguishes cache from offline downloads in its
[storage documentation](https://support.spotify.com/us/article/storage-information/).
Spicetify documents the separate Spotify `prefs_path` in its
[configuration reference](https://spicetify.app/docs/customization/config-file).
The meanings and tested removal behavior of the four fields above are empirical observations
from the live review, not a vendor-supported logout API.
