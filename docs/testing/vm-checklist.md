# Real application logout review in a disposable Windows VM

This complements the [synthetic VM guide](vm-guide.md). Synthetic files establish confinement
and failure handling; real disposable service accounts establish observable logout behavior.
Never import personal host profiles or use personal service credentials. These trials have not
been performed for every app below and do not automatically remove catalog blockers.

## Common procedure

1. Create an isolated Windows guest and a dedicated local user. Disable host folder, drive,
   clipboard and profile sharing. Record Windows build, application version/channel, executable
   signature/hash, EveryOut revision, manifest revision and each independently identified root.
2. Create an owned disposable service account. Enter its credentials manually inside the guest;
   keep passwords, tokens, cookies and raw preference/database contents out of evidence and Git.
   Do not capture authentication screens containing secrets or reusable QR codes.
3. Prepare the preservation canaries in the table. Confirm signed-in behavior and normal restart.
   Stop the app and take a VM checkpoint. Keep every independent trial tied to that checkpoint.
4. Review the EveryOut plan, exact logical targets, process identities, loss disclosure and
   confirmations. A blocked plan is a blocked trial. Do not remove blockers just to run the test;
   review and implement the proposed bounded adapter in a lab build first.
5. Execute with recorded close policy. Confirm unrelated apps remain running and unselected
   stores are unchanged. Record partial effects and failures, including locks or access denial.
6. Restart the selected app; check the signed-out UI and inability to access account content.
   Repeat with networking restored to detect silent SSO. Reboot and repeat. Distinguish local
   field removal, observable logout and remote revocation; one does not establish the others.
7. Check every preservation canary. For mutable app files, compare immediately after cleanup
   before restarting, then check visible behavior after restart. Report expected loss explicitly.
8. From separate fresh checkpoints test absence/idempotence, refusing processes, cancellation,
   unsupported version/format, denied access and changed target identity. Keep synthetic adversarial
   junction/hard-link/race tests in the existing harness rather than mixing them with live profiles.
9. Publish only sanitized evidence: version/hash, reviewed relative targets, fixed outcome codes,
   visible logout result, preservation results and remaining uncertainties. Enable only the exact
   operation/version supported by that evidence; shared framework layout alone is insufficient.

## Application checks

| Application         | Prepare and observe logout                                                                                                       | Preserve or disclose                                                                                                                                                          |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Discord             | Disposable account; normal client restart; check account/guild access and network reconnect after cleanup                        | Canary settings, local drafts and attachments. Test Local Storage/IndexedDB separately; do not assume they contain only tokens.                                               |
| Slack               | Disposable workspace/account; check workspace access and background/helper processes after restart/reboot                        | Drafts, downloaded files, settings and unrelated workspaces. Confirm shared stores are correctly scoped.                                                                      |
| Spotify             | Record desktop versus Store build. For the pinned adapter check remembered login fields are absent and the restart shows sign-in | Compare all other `prefs` bytes immediately after apply; verify settings and downloaded-file/cache bytes. Signed-out offline playback availability is a separate observation. |
| Telegram            | Disposable account on a test phone; check client startup requires sign-in and whether the device session remains listed remotely | Local history, downloads, drafts and unrelated account directories. Record which are intentionally lost before enabling any operation.                                        |
| Steam               | Disposable account; check startup, online reconnect and Steam Guard behavior                                                     | Installed games, save files, screenshots, settings and other accounts. Test launcher state separately from games and shared identity.                                         |
| Epic Games Launcher | Disposable account; test restart/reboot and any browser-mediated SSO                                                             | Installed games, save files, manifests, downloads and preferences. Treat silent browser SSO as unresolved until measured.                                                     |
| Chrome              | Disposable browser profile and test website/browser accounts; test website logout and browser sync identity separately           | Bookmarks, saved passwords, history, extensions and other profiles. Do not infer account logout from deleted site cookies alone.                                              |
| Edge                | Disposable browser profile; test website sessions, browser account and Windows-mediated SSO separately                           | Same browser canaries plus unchanged Windows sign-in/account settings. Shared WebView2 or system identity stores require separate scope.                                      |

## Spotify development probe

The opt-in probe uses the same provider, CurrentSession and engine as the app. Default invocation
only previews. It accepts neither arbitrary providers nor arbitrary paths/accounts:

```powershell
cargo run -p everyout --example spotify_logout_probe
```

Only in an approved live trial, the following executes the reviewed Spotify operation and authorizes
closing its matching processes, escalating to force close after two seconds if necessary:

```powershell
cargo run -p everyout --example spotify_logout_probe -- --apply-reviewed-spotify
```

The result must include `complete-local-scope`, `applied` or an already absent target, and
`target-absent` for the saved-login fields. This code result does not inspect authenticated UI state.
Record the manual restart separately. The 2026-10-08 development trial is documented in the
[Spotify review](../research/05-spotify-local-logout.md).
