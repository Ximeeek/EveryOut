# Windows identity, developer credentials, and multi-account research

Research dossier for EveryOut, Phase 6. Evidence cutoff and access date: 2026-09-30.
Scope: Windows identity state, developer credentials, optional multi-account operation, and
privilege-boundary options. This dossier records evidence and design proposals; it does not select a
final product architecture.

Evidence convention: every factual statement or table row has a [VERIFIED: URL, accessed
2026-09-30] tag. Proposals, uncited implementation inferences, and unresolved details are marked
[HYPOTHESIS]. A citation verifies only the adjacent claim. The identity used to sign in to Windows
is out of scope and must never be altered by EveryOut.

## 1. Windows and Microsoft identity state

Windows identity is distributed across Credential Manager/Vault, Windows account broker state,
app-specific token stores, device registration, and possibly a Primary Refresh Token (PRT). Microsoft
documents their purpose and supported account-management flows, but not a complete stable file
inventory or a public API to clear every broker cache. [VERIFIED:
https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication,
accessed 2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token,
accessed 2026-09-30] [HYPOTHESIS]

| Store/state                        | Location and contents                                                                                                                                                                                                                                                                                                                                                 | Clearing safety and supported user action                                                                                                                                                                                                                                                                                                                                      |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Credential Manager / Windows Vault | Encrypted folders under the user's profile; saved usernames, passwords, and related credentials for network resources and supported apps. Exact on-disk layout is an implementation detail. [VERIFIED: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication, accessed 2026-09-30]         | Prefer deleting only an explicitly selected target with cmdkey /delete:<target>; removal can break that resource's sign-in. Manage entries in Credential Manager. [VERIFIED: https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey, accessed 2026-09-30] [HYPOTHESIS]                                                                              |
| TokenBroker                        | Commonly observed under %LOCALAPPDATA%\Microsoft\TokenBroker; associated with brokered identity/token state. Microsoft documents WAM's broker role, not this directory as a supported deletion interface or stable format. [VERIFIED: https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam, accessed 2026-09-30] [HYPOTHESIS] | Do not delete files directly. For a work/school connection, use Settings > Accounts > Access work or school > select connection > Disconnect, where available. Managed policy can block manual unenrollment and disconnect can cause data loss. [VERIFIED: https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices, accessed 2026-09-30] |
| IdentityCache                      | %LOCALAPPDATA%\Microsoft\IdentityCache is observed in Windows/Office environments; primary documentation located here does not specify schema, ownership boundaries, or supported deletion contract. [HYPOTHESIS]                                                                                                                                                     | Do not delete directly; use app sign-out or Windows account disconnect UI when intended. [HYPOTHESIS]                                                                                                                                                                                                                                                                          |
| OneAuth                            | %LOCALAPPDATA%\Microsoft\OneAuth is observed as Microsoft app authentication state; primary documentation located here does not specify contents or supported deletion contract. [HYPOTHESIS]                                                                                                                                                                         | Do not delete directly; use app sign-out or Windows account disconnect UI. [HYPOTHESIS]                                                                                                                                                                                                                                                                                        |
| Web Account Manager (WAM)          | Windows 10+ authentication broker used by MSAL, integrating accounts known to Windows and supporting silent SSO. Public documentation covers token acquisition, not arbitrary cache deletion. [VERIFIED: https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam, accessed 2026-09-30]                                           | Do not clear WAM cache. Remove an app account using its UI or disconnect a work/school connection in Settings when that is the user's intent. [HYPOTHESIS]                                                                                                                                                                                                                     |
| Entra device registration/join     | dsregcmd /status reports device join and user registration state; an account can be connected without being the Windows sign-in identity. [VERIFIED: https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd, accessed 2026-09-30]                                                                                                      | A work account may be disconnected in Settings. A joined or managed device may require administrator or organizational unenrollment; do not automate dsregcmd /leave or device deregistration. [VERIFIED: https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices, accessed 2026-09-30] [HYPOTHESIS]                                     |
| Primary Refresh Token (PRT)        | Protected Microsoft Entra SSO artifact used by CloudAP/WAM to obtain app tokens. It is broker/device state, not a normal user-visible file to delete. Supported Edge, Chrome, and Firefox configurations can obtain browser SSO from Windows. [VERIFIED: https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token, accessed 2026-09-30] | Never read or clear the PRT. A user/administrator must decide whether to disconnect the relevant work account/device; browser-file deletion cannot guarantee global sign-out. [VERIFIED: https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token, accessed 2026-09-30] [HYPOTHESIS]                                                             |

Microsoft's supported route for a work connection is Settings > Accounts > Access work or school.
Microsoft warns disconnect may cause data loss and documents exceptions where policy blocks manual
unenrollment. [VERIFIED:
https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices,
accessed 2026-09-30]

## 2. Browser reauthentication hypothesis and Windows sign-in protection

The hypothesis that a browser wipe can be followed by silent reauthentication is verified for
supported Microsoft Entra SSO configurations: Edge has native PRT SSO, Chrome supports PRT SSO
through native support or Microsoft's Single Sign On extension, and Firefox 91+ has a Windows SSO
setting. Firefox exposes a user setting; Edge may automatically sign in using the Windows default
account depending on device configuration and policy. [VERIFIED:
https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token,
accessed 2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-identity, accessed 2026-09-30]
[VERIFIED: https://support.mozilla.org/en-US/kb/windows-sso, accessed 2026-09-30]

A browser-data wipe cannot be described as guaranteed global logout while Windows still supplies
SSO. Removing Windows-provided work identity is a separate decision owned by the user or
organization. EveryOut must never touch the Windows sign-in identity; present instructions for
Windows Settings and require a separate informed user action for account disconnection. [VERIFIED:
https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token,
accessed 2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices,
accessed 2026-09-30] [HYPOTHESIS]

Microsoft confirms broker support, but not that every browser build, extension, tenant, policy,
profile, or website will silently sign in after a wipe. Behavior remains configuration-dependent.
[VERIFIED: https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token,
accessed 2026-09-30]

For the European Economic Area, Microsoft documents a Windows 11 24H2/25H2 change (with the July
2026 security update) that asks the user before reusing Windows credentials to sign in to another
Microsoft app or service; if the user accepts, the prompt does not appear again. This makes silent
sign-in less universal in this region and further supports treating the Windows account as a
separate user decision. [VERIFIED:
https://learn.microsoft.com/en-us/entra/identity/devices/sso-admin-control, accessed 2026-09-30]

## 3. Credential target enumeration without reading secrets

cmdkey /list is the preferred discovery interface. It lists stored usernames and credentials as
metadata, not credential blobs; it may show usernames as well as target names, so avoid logging its
output. A selected target can be removed with cmdkey /delete:<target>. [VERIFIED:
https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey, accessed
2026-09-30] [HYPOTHESIS]

CredEnumerateW returns CREDENTIALW structures with a CredentialBlob pointer and size; its single
returned memory block must be released with CredFree. Calling it therefore places secret material in
the app's address space, even if the app ignores the blob. [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew, accessed
2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw, accessed
2026-09-30]

**Recommendation:** enumerate metadata with cmdkey /list; do not call CredEnumerateW for inventory.
If a blob-returning API becomes unavoidable, immediately zero each blob before freeing the returned
block. Zeroing mitigates exposure but cannot prove secrets never entered memory; this would be a
documented exception to the no-secret-read rule and requires a security decision before
implementation. [VERIFIED:
https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey, accessed
2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew, accessed
2026-09-30] [HYPOTHESIS]

## 4. Developer tool credentials

| Tool                               | Common Windows location                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Logout and server-side effect                                                                                                                                                                                                                                                                                                                                                                                                                           | File deletion alternative and user loss                                                                                                                                                                                                                                                               |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Git + Git Credential Manager (GCM) | Default store is Windows Credential Manager; alternate stores include DPAPI files under %USERPROFILE%\.gcm\dpapi_store, plaintext %USERPROFILE%\.gcm\store, or configured stores. [VERIFIED: https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/credstores.md, accessed 2026-09-30]                                                                                                                                                                      | git credential reject requests helper erase; GCM supports erase. Local removal only; server-side OAuth revocation is provider-specific. [VERIFIED: https://git-scm.com/docs/gitcredentials, accessed 2026-09-30] [VERIFIED: https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/usage.md, accessed 2026-09-30] [HYPOTHESIS]                                                                                                          | Delete one target via helper/Credential Manager. Deleting .gitconfig also loses aliases, identity, helper config and other Git preferences; wiping all GCM storage removes all hosted Git credentials. [VERIFIED: https://git-scm.com/docs/git-config, accessed 2026-09-30] [HYPOTHESIS]              |
| GitHub CLI (gh)                    | Windows uses an OS credential store when available, or gh config storage when plaintext storage is configured. [VERIFIED: https://cli.github.com/manual/gh_auth_login, accessed 2026-09-30]                                                                                                                                                                                                                                                                                  | gh auth logout [--hostname ...] [--user ...] is local only and does not revoke tokens. Revoking the GitHub CLI app in GitHub settings revokes its tokens across devices. [VERIFIED: https://cli.github.com/manual/gh_auth_logout, accessed 2026-09-30]                                                                                                                                                                                                  | Deleting the gh configuration directory can remove local settings and, when plaintext storage is configured, local auth; it does not revoke tokens server-side. [VERIFIED: https://cli.github.com/manual/gh_help_environment, accessed 2026-09-30] [HYPOTHESIS]                                       |
| npm                                | %USERPROFILE%\.npmrc by default (overridable with userconfig); can contain registry tokens and other configuration. [VERIFIED: https://docs.npmjs.com/cli/v11/commands/npm-config, accessed 2026-09-30]                                                                                                                                                                                                                                                                      | npm logout invalidates token-based auth everywhere that token is used; legacy username/password auth is cleared from user config. [VERIFIED: https://docs.npmjs.com/cli/v11/commands/npm-logout, accessed 2026-09-30]                                                                                                                                                                                                                                   | Deleting .npmrc also loses registry URLs, scopes, proxy settings, and other npm settings. [VERIFIED: https://docs.npmjs.com/cli/v11/commands/npm-config, accessed 2026-09-30] [HYPOTHESIS]                                                                                                            |
| Docker CLI/Desktop                 | %USERPROFILE%\.docker\config.json; credentials may live in Docker Desktop's Windows Credential Manager, a configured helper, or base64 in config.json without a helper. [VERIFIED: https://docs.docker.com/reference/cli/docker/login/, accessed 2026-09-30]                                                                                                                                                                                                                 | docker logout [SERVER] removes local registry credentials; docs do not state server-side revocation. [VERIFIED: https://docs.docker.com/reference/cli/docker/logout/, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                                                                                                 | Deleting config.json loses registry auth, helpers, proxy config, and CLI formatting/preferences. [VERIFIED: https://docs.docker.com/reference/cli/docker/, accessed 2026-09-30]                                                                                                                       |
| Azure CLI                          | %USERPROFILE%\.azure; MSAL cache is msal_token_cache.bin or .json, encrypted on Windows. [VERIFIED: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows, accessed 2026-09-30] [VERIFIED: https://learn.microsoft.com/en-us/cli/azure/msal-based-azure-cli, accessed 2026-09-30]                                                                                                                                                                            | az logout [--username] removes local CLI access to subscriptions. Located reference does not establish server-side refresh-token revocation; that effect remains unverified. [VERIFIED: https://learn.microsoft.com/en-us/cli/azure/reference-index, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                                  | Microsoft documents deleting the MSAL cache when not reinstalling. Deleting all .azure can also lose CLI configuration, extensions, history, and subscription cache. [VERIFIED: https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows, accessed 2026-09-30] [HYPOTHESIS]              |
| AWS CLI                            | %USERPROFILE%\.aws\config and credentials; IAM Identity Center cache under .aws\sso\cache; aws login cache under .aws\login\cache. [VERIFIED: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html, accessed 2026-09-30] [VERIFIED: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso-tutorial.html, accessed 2026-09-30] [VERIFIED: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html, accessed 2026-09-30] | aws sso logout removes cached IAM Identity Center tokens and temporary credentials across profiles; aws logout clears aws login sessions locally. They do not claim revocation of upstream sessions or long-lived IAM keys. [VERIFIED: https://docs.aws.amazon.com/cli/latest/reference/sso/logout.html, accessed 2026-09-30] [VERIFIED: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html, accessed 2026-09-30] [HYPOTHESIS] | Deleting .aws also loses named profiles, regions, output settings, role configuration, and static credentials. Prefer supported logout commands. [VERIFIED: https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html, accessed 2026-09-30] [HYPOTHESIS]                              |
| Google Cloud CLI (gcloud)          | %APPDATA%\gcloud by default, overridable with CLOUDSDK_CONFIG; contains credentials and named CLI configurations. [VERIFIED: https://docs.cloud.google.com/sdk/docs/configurations, accessed 2026-09-30]                                                                                                                                                                                                                                                                     | gcloud auth revoke ACCOUNT revokes user credentials on Google's authorization servers and removes local credentials. Service-account and external-account revoke is local only; upstream key/identity revocation is separate. [VERIFIED: https://docs.cloud.google.com/sdk/gcloud/reference/auth/revoke, accessed 2026-09-30]                                                                                                                           | Deleting config directory loses credentials plus named configs, active project/account, defaults, and preferences. [VERIFIED: https://docs.cloud.google.com/sdk/docs/uninstall-cloud-sdk, accessed 2026-09-30] [VERIFIED: https://docs.cloud.google.com/sdk/docs/configurations, accessed 2026-09-30] |
| kubectl                            | Kubeconfig selected by KUBECONFIG, otherwise %USERPROFILE%\.kube\config; may contain bearer tokens, client certificates, or exec credential commands. [VERIFIED: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/, accessed 2026-09-30]                                                                                                                                                                                                 | No generic logout/server-side revoke command. Remove a selected user/context only by user choice; revoke credentials at the IdP/cluster separately. [VERIFIED: https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_unset/, accessed 2026-09-30] [HYPOTHESIS]                                                                                                                                                           | Deleting kubeconfig loses contexts, endpoints, certs, namespace defaults and auth setup; issued credentials may remain valid. [VERIFIED: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/, accessed 2026-09-30] [HYPOTHESIS]                                     |

Developer credentials are outside browser scope and may overlap Credential Manager or shared
configuration files. Proposed behavior is opt-in and target-specific, with consequences shown before
removal. [HYPOTHESIS]

## 5. Optional multi-account mode and elevated operation

The profile registry hive is NTUSER.DAT; Windows loads it at logon under HKEY_USERS and maps it to
HKEY_CURRENT_USER. RegLoadKey/RegUnLoadKey load and unload a hive; restore privilege is required. Do
not independently load or unload a hive already mounted for a simultaneously logged-on user.
[VERIFIED: https://learn.microsoft.com/en-us/windows/win32/shell/about-user-profiles, accessed
2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions, accessed 2026-09-30]
[VERIFIED: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_se_exports,
accessed 2026-09-30] [HYPOTHESIS]

Win32_UserProfile exposes SID, local path, loaded state, and whether a profile is special. These
fields support profile enumeration and filtering. [VERIFIED:
https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee886409%28v%3Dvs.85%29,
accessed 2026-09-30] The ProfileList registry key under HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList is a candidate profile inventory; primary documentation found here does not endorse it as a supported enumeration API. [HYPOTHESIS]

Tool Help snapshots enumerate process/thread state, and ProcessIdToSessionId reports the Remote
Desktop Services session for a process. Listing a process does not authorize closing another user's
process in a different session. Termination needs appropriate access and should be limited to
user-selected known target apps. No foreign-process memory access is needed. [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/toolhelp/snapshots-of-the-system, accessed
2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid,
accessed 2026-09-30] [HYPOTHESIS]

| Elevated architecture                              | Comparison                                                                                                                                                                                                                                                     | Assessment                                                                                                                                                                           |
| -------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| (a) Normal app + on-demand elevated helper via UAC | Microsoft recommends keeping the main app asInvoker and launching a helper with runas only for privileged operations. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/secbp/running-with-administrator-privileges, accessed 2026-09-30]             | **Recommended candidate:** short-lived, action-scoped, explicit UAC consent. If declined, cancel elevated work, explain it did not run, and keep the normal app usable. [HYPOTHESIS] |
| (b) Windows service                                | A persistent privileged service introduces service installation/lifecycle and IPC security needs. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/services/services, accessed 2026-09-30] [HYPOTHESIS]                                              | Not recommended for one-shot desktop actions; durable privilege increases attack surface. [HYPOTHESIS]                                                                               |
| (c) Scheduled task                                 | Task Scheduler supports interactive logon contexts and a highest run level. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks, accessed 2026-09-30]                                                      | Not recommended for synchronous work; persistent registration and cleanup are harder to scope than a short-lived helper. [HYPOTHESIS]                                                |
| (d) COM elevation moniker                          | Activates a COM class for a limited elevated function, but requires elevation metadata registered under HKLM and has compatibility constraints. [VERIFIED: https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker, accessed 2026-09-30] | Viable for a narrowly exposed installed component, but registration/deployment is more complex for this optional helper. [HYPOTHESIS]                                                |

For option (a), create a named pipe with an explicit DACL for the launching user's SID and logon SID.
Windows warns that default pipe ACLs allow broad read access and recommends logon SID isolation.
Validate client identity and a one-time nonce/handshake, accept only a small typed command schema,
and fail closed if impersonation or validation fails. Do not accept arbitrary paths, command lines,
or registry operations. [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights, accessed
2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient,
accessed 2026-09-30] [HYPOTHESIS]

The helper must not disconnect the Windows sign-in account. Operate only on an explicitly selected
other SID after showing profile identity and consequences; skip profiles with already-loaded hives
unless operating in that user's session. UAC consent is not per-profile consent. [HYPOTHESIS]

## 6. Anti-cheat safety boundary

The proposed techniques use file/configuration operations, registry enumeration or targeted hive
operations, process listing and selected process closing, and Windows account/credential APIs or
account settings. They require no hooks, code injection, foreign-process memory reads, or kernel
drivers. [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/toolhelp/snapshots-of-the-system, accessed
2026-09-30] [VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions, accessed 2026-09-30]
[VERIFIED:
https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew, accessed
2026-09-30] [HYPOTHESIS]

This is a scope audit of research proposals, not certification of future code or third-party CLI
binaries. Review actual APIs and invoked binaries before implementation. [HYPOTHESIS]

## Open questions

- Microsoft publishes no stable file inventory or deletion contract for TokenBroker, IdentityCache,
  and OneAuth; get first-party clarification before proposing direct deletion. [HYPOTHESIS]
- Verify whether az logout revokes server-side refresh tokens for each supported auth flow; the
  located command reference does not specify this. [HYPOTHESIS]
- Confirm Git/GCM provider-specific revocation before productizing generic Git logout. [HYPOTHESIS]
- Validate cmdkey /list output across supported Windows locales/builds before parsing; do not log
  target metadata. [HYPOTHESIS]
- Establish behavior for hives in disconnected/RDP sessions and process termination rights by
  Windows edition. [HYPOTHESIS]
- Define managed-device behavior when organizational policy blocks disconnection. [VERIFIED:
  https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices,
  accessed 2026-09-30]
- Validate named-pipe handshake, SID checks, UAC-cancel handling, and helper trust model before
  implementation. [HYPOTHESIS]

## Sources

1. [Microsoft: Windows Vault and Credential Manager](https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/credentials-processes-in-windows-authentication) — accessed 2026-09-30.
2. [Microsoft: cmdkey](https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey) — accessed 2026-09-30.
3. [Microsoft: CredEnumerateW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/nf-wincred-credenumeratew) — accessed 2026-09-30.
4. [Microsoft: CREDENTIALW](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw) — accessed 2026-09-30.
5. [Microsoft: WAM token acquisition](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam) — accessed 2026-09-30.
6. [Microsoft: PRT and browser SSO](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token) — accessed 2026-09-30.
7. [Microsoft: Admin control for SSO prompts](https://learn.microsoft.com/en-us/entra/identity/devices/sso-admin-control) — accessed 2026-09-30.
8. [Microsoft: dsregcmd device state](https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd) — accessed 2026-09-30.
9. [Microsoft: MDM enrollment and disconnect](https://learn.microsoft.com/en-us/windows/client-management/mdm-enrollment-of-windows-devices) — accessed 2026-09-30.
10. [Microsoft: Edge identity support](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-security-identity) — accessed 2026-09-30.
11. [Mozilla: Windows SSO in Firefox](https://support.mozilla.org/en-US/kb/windows-sso) — accessed 2026-09-30.
12. [Git: credential helpers](https://git-scm.com/docs/gitcredentials) — accessed 2026-09-30.
13. [Git Credential Manager: credential stores](https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/credstores.md) — accessed 2026-09-30.
14. [Git Credential Manager: usage](https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/usage.md) — accessed 2026-09-30.
15. [GitHub CLI: logout](https://cli.github.com/manual/gh_auth_logout) — accessed 2026-09-30.
16. [GitHub CLI: login](https://cli.github.com/manual/gh_auth_login) — accessed 2026-09-30.
17. [GitHub CLI: config directory](https://cli.github.com/manual/gh_help_environment) — accessed 2026-09-30.
18. [npm: logout](https://docs.npmjs.com/cli/v11/commands/npm-logout) — accessed 2026-09-30.
19. [npm: config](https://docs.npmjs.com/cli/v11/commands/npm-config) — accessed 2026-09-30.
20. [Docker: login](https://docs.docker.com/reference/cli/docker/login/) — accessed 2026-09-30.
21. [Docker: logout](https://docs.docker.com/reference/cli/docker/logout/) — accessed 2026-09-30.
22. [Docker: CLI config](https://docs.docker.com/reference/cli/docker/) — accessed 2026-09-30.
23. [Microsoft: Azure CLI Windows install](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows) — accessed 2026-09-30.
24. [Microsoft: MSAL Azure CLI cache](https://learn.microsoft.com/en-us/cli/azure/msal-based-azure-cli) — accessed 2026-09-30.
25. [Microsoft: Azure CLI reference](https://learn.microsoft.com/en-us/cli/azure/reference-index) — accessed 2026-09-30.
26. [AWS: CLI config files](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html) — accessed 2026-09-30.
27. [AWS: IAM Identity Center cache](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso-tutorial.html) — accessed 2026-09-30.
28. [AWS: aws sso logout](https://docs.aws.amazon.com/cli/latest/reference/sso/logout.html) — accessed 2026-09-30.
29. [AWS: aws login/logout](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sign-in.html) — accessed 2026-09-30.
30. [Google Cloud: gcloud authentication](https://docs.cloud.google.com/sdk/docs/authenticate) — accessed 2026-09-30.
31. [Google Cloud: gcloud auth revoke](https://docs.cloud.google.com/sdk/gcloud/reference/auth/revoke) — accessed 2026-09-30.
32. [Google Cloud: configurations](https://docs.cloud.google.com/sdk/docs/configurations) — accessed 2026-09-30.
33. [Kubernetes: kubeconfig](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/) — accessed 2026-09-30.
34. [Kubernetes: kubectl config unset](https://kubernetes.io/docs/reference/kubectl/generated/kubectl_config/kubectl_config_unset/) — accessed 2026-09-30.
35. [Microsoft: user profile hive](https://learn.microsoft.com/en-us/windows/win32/shell/about-user-profiles) — accessed 2026-09-30.
36. [Microsoft: registry functions](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-functions) — accessed 2026-09-30.
37. [Microsoft: hive privileges](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_se_exports) — accessed 2026-09-30.
38. [Microsoft: Win32_UserProfile](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/ee886409%28v%3Dvs.85%29) — accessed 2026-09-30.
39. [Microsoft: system snapshots](https://learn.microsoft.com/en-us/windows/win32/toolhelp/snapshots-of-the-system) — accessed 2026-09-30.
40. [Microsoft: ProcessIdToSessionId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-processidtosessionid) — accessed 2026-09-30.
41. [Microsoft: least privilege and elevated helpers](https://learn.microsoft.com/en-us/windows/win32/secbp/running-with-administrator-privileges) — accessed 2026-09-30.
42. [Microsoft: Task Scheduler security contexts](https://learn.microsoft.com/en-us/windows/win32/taskschd/security-contexts-for-running-tasks) — accessed 2026-09-30.
43. [Microsoft: COM elevation moniker](https://learn.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker) — accessed 2026-09-30.
44. [Microsoft: named-pipe security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights) — accessed 2026-09-30.
45. [Microsoft: named-pipe impersonation](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-impersonatenamedpipeclient) — accessed 2026-09-30.
