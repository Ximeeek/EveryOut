# Windows/Microsoft accounts and developer tools

Phase 26 of EveryOut preserves the V1 offline architecture. All twelve entries are
**non-executable research candidates**, not evidence that a tool or account is installed.
The Rust research planner builds previews with no actions and explicit blockers. Unresolved
roots and adapter names grant no filesystem, credential, registry or process capabilities.
No CLI, credential inventory or deletion fallback is enabled by this phase.

**WARNING: Browsers and Office may silently sign in again through Windows SSO after local
cleanup. Full logout may require disconnecting the account from Windows. This is a separate
user decision; EveryOut never disconnects Windows accounts or alters the Windows sign-in identity.**
The engine includes this warning in the category preview and text/JSON report, even for empty
or blocked selections. Its existing separate, run-bound category confirmation remains mandatory;
confirmation cannot waive candidate status, unknown ownership or preservation conflicts.

## Catalog

Location and loss statements below follow the [Windows dossier §§1–4](../research/02-windows-identity-and-multi-account.md).
Primary links describe vendor behavior, not an approved V1 execution contract. Confidence is
low for automated cleanup in every row; exact shipping versions, ownership and preservation
remain unverified. Cache path hypotheses are explicitly identified.

| Name                                                        | Where the session lives                                                                                        | Cleaning method                                                                                                                                                                                  | True logout available?                                                                                                                                                                                 | Risk of permanent data loss and which                                                                                                                                   | Confidence of the information                           |
| ----------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| <a id="microsoft-credentials"></a>Microsoft app credentials | Credential Manager target metadata via cmdkey /list; exact app-only target unresolved                          | Blocked: `windows-sign-in-ownership-unproven`. Documented command: `cmdkey /delete:<reviewed-target>`; no deletion fallback.                                                                     | Local target removal; no remote revocation. [Vendor source](https://learn.microsoft.com/windows-server/administration/windows-commands/cmdkey)                                                         | Selected saved credential; unknown Windows-sign-in relationship; no mutation authorized.                                                                                | Low; research candidate, shipping execution unverified. |
| <a id="tokenbroker"></a>Microsoft TokenBroker               | %LOCALAPPDATA%/Microsoft/TokenBroker (observed, unsupported deletion contract)                                 | Blocked: `s5-broker-cache-deletion-unsupported`. Documented command: `none`; no deletion fallback.                                                                                               | Supported app sign-out or manual Windows account disconnect only. [Vendor source](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam)                        | Shared broker state and unrelated app access; complete effects unknown; no mutation authorized.                                                                         | Low; research candidate, shipping execution unverified. |
| <a id="identitycache"></a>Microsoft IdentityCache           | %LOCALAPPDATA%/Microsoft/IdentityCache (hypothesis)                                                            | Blocked: `s5-broker-cache-deletion-unsupported`. Documented command: `none`; no deletion fallback.                                                                                               | Supported app sign-out or manual Windows account disconnect only. [Vendor source](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam)                        | Shared identity state; complete effects unknown; no mutation authorized.                                                                                                | Low; research candidate, shipping execution unverified. |
| <a id="oneauth"></a>Microsoft OneAuth                       | %LOCALAPPDATA%/Microsoft/OneAuth (hypothesis)                                                                  | Blocked: `s5-broker-cache-deletion-unsupported`. Documented command: `none`; no deletion fallback.                                                                                               | Supported app sign-out or manual Windows account disconnect only. [Vendor source](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-wam)                        | Shared app authentication state; complete effects unknown; no mutation authorized.                                                                                      | Low; research candidate, shipping execution unverified. |
| <a id="git-credentials"></a>Git Credential Manager          | Windows Credential Manager by default; .gcm/dpapi_store or .gcm/store for alternative configured stores        | Blocked: `credential-helper-and-target-scope-unreviewed`. Documented command: `git credential reject / git credential-manager erase`; no deletion fallback.                                      | Local helper erase; provider-specific remote revocation separate. [Vendor source](https://github.com/git-ecosystem/git-credential-manager/blob/main/docs/credstores.md)                                | Selected hosted Git credential; broad removal also affects unrelated credentials; .gitconfig contains identity, aliases and helper preferences; no mutation authorized. | Low; research candidate, shipping execution unverified. |
| <a id="github-cli"></a>GitHub CLI                           | OS credential store or gh configuration when plaintext storage is used                                         | Blocked: `cli-offline-version-and-account-scope-unreviewed`. Documented command: `gh auth logout --hostname <host> --user <user>`; no deletion fallback.                                         | Local only; does not revoke tokens. [Vendor source](https://cli.github.com/manual/gh_auth_logout)                                                                                                      | Selected CLI authorization; broad configuration deletion loses settings and other accounts; no mutation authorized.                                                     | Low; research candidate, shipping execution unverified. |
| <a id="npm"></a>npm                                         | %USERPROFILE%/.npmrc; userconfig and registry overrides possible                                               | Blocked: `remote-revocation-prohibited-in-v1`. Documented command: `npm logout`; no deletion fallback.                                                                                           | Token auth revoked remotely; legacy auth cleared locally; V1 never invokes this command. [Vendor source](https://docs.npmjs.com/cli/v11/commands/npm-logout/)                                          | Registry tokens, scope mappings, proxies and other npm preferences if .npmrc is deleted; no mutation authorized.                                                        | Low; research candidate, shipping execution unverified. |
| <a id="docker"></a>Docker                                   | %USERPROFILE%/.docker/config.json and configured credential helpers; Docker Desktop may use Credential Manager | Blocked: `credential-helper-and-target-scope-unreviewed`. Documented command: `docker logout <registry>`; no deletion fallback.                                                                  | Documented registry logout; remote revocation not established. [Vendor source](https://docs.docker.com/reference/cli/docker/logout/)                                                                   | Registry credentials, helpers, proxy and CLI preferences if config.json is deleted; no mutation authorized.                                                             | Low; research candidate, shipping execution unverified. |
| <a id="azure-cli"></a>Azure CLI                             | %USERPROFILE%/.azure/msal_token_cache.bin (Windows encrypted); config directory overrides possible             | Blocked: `cli-offline-version-and-account-scope-unreviewed`. Documented command: `az logout --username <account>`; no deletion fallback.                                                         | Local subscription access removed; remote effect unverified. [Vendor source](https://learn.microsoft.com/en-us/cli/azure/msal-based-azure-cli)                                                         | Selected auth cache; broad .azure deletion loses configuration, extensions, history and subscription metadata; no mutation authorized.                                  | Low; research candidate, shipping execution unverified. |
| <a id="aws-cli"></a>AWS CLI                                 | %USERPROFILE%/.aws/credentials and config; sso/cache and login/cache; overrides possible                       | Blocked: `cli-offline-version-and-account-scope-unreviewed`. Documented command: `aws sso logout / aws logout`; no deletion fallback.                                                            | Cached sessions removed; long-lived IAM keys not revoked; offline invocation not reviewed. [Vendor source](https://docs.aws.amazon.com/cli/latest/reference/sso/logout.html)                           | SSO logout affects multiple profiles; deleting .aws loses regions, profiles, role settings and static credentials; no mutation authorized.                              | Low; research candidate, shipping execution unverified. |
| <a id="gcloud"></a>Google Cloud CLI                         | %APPDATA%/gcloud; CLOUDSDK_CONFIG override; named configurations and credentials                               | Blocked: `remote-revocation-prohibited-in-v1`. Documented command: `gcloud auth revoke <account>`; no deletion fallback.                                                                         | User credentials revoked on authorization servers; service/external account removal local only; command blocked in V1. [Vendor source](https://docs.cloud.google.com/sdk/gcloud/reference/auth/revoke) | Local credentials, named configurations, project/account defaults and preferences on broad deletion; no mutation authorized.                                            | Low; research candidate, shipping execution unverified. |
| <a id="kubectl"></a>kubectl                                 | %USERPROFILE%/.kube/config or KUBECONFIG; credentials, certificates, contexts and exec plugins                 | Blocked: `mixed-credential-and-key-store-preservation-unreviewed`. Documented command: `none (kubectl config unset users.<name> edits configuration, not generic logout)`; no deletion fallback. | No generic logout; IdP/cluster revocation separate. [Vendor source](https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/)                                             | Contexts, endpoints, certificates, namespace defaults and auth setup; credentials may stay valid; no mutation authorized.                                               | Low; research candidate, shipping execution unverified. |

## V1 refusal reasons and reopening requirements

- **npm and gcloud:** token-based npm logout ends the token session on the registry server;
  gcloud user-account revoke contacts Google's authorization servers. These violate the offline
  and no-remote-revocation contract and remain unavailable in V1. Legacy npm authentication and
  service/external gcloud accounts do not authorize executing the same unreviewed command.
  A future distinct local-only adapter would need a reviewed scope and preservation contract;
  the documented server-revoking commands cannot be enabled under the present architecture.
- **Microsoft app credentials:** cmdkey metadata listing and deletion by exact target name are
  the research recommendation; CredEnumerateW/CredRead are excluded. No target pattern is
  ownership proof. Before any adapter can delete, S5 must establish independently versioned
  app-only target ownership, explicit Windows-sign-in exclusion, locale-safe bounded metadata
  discovery, and preservation of unrelated canaries. No production targets are enumerated here.
- **TokenBroker, IdentityCache, OneAuth:** direct deletion has no reviewed public contract.
  S5 remains pending. Completion of experiments alone is insufficient: a supported safe deletion
  contract, sign-in exclusion, shared-owner evidence and reviewed implementation are required.
  WAM, PRT, Windows Hello, device registration and account disconnect remain protected.
- **Git/GCM and Docker:** helpers are configurable and may execute additional programs.
  Review a pinned Windows version, fixed helper identity, exact target/account ownership,
  offline behavior, stdout/stderr handling, environment overrides and permanent effects.
  Do not delete .gitconfig, .docker/config.json or whole credential stores as a fallback.
- **GitHub CLI, Azure CLI and AWS CLI:** a documented local effect is not proof that every
  installed version runs offline without reading/outputting secrets or touching other accounts.
  Review a pinned version's source, allowed executable location, fixed arguments, account
  metadata discovery, configuration overrides, helpers/telemetry and output suppression.
  GitHub CLI documents local-only logout; Azure's remote effect is unresolved; AWS SSO logout
  spans profiles and does not revoke long-lived IAM keys. No such adapter is adopted yet.
- **kubectl:** no generic logout exists. Kubeconfig mixes session state, certificates and
  contexts, and may execute credential plugins. No content parsing, plugin execution or broad
  deletion is authorized. An independently reviewed local scope must preserve key material.

After review, an eligible local adapter still needs an immutable plan, ownership revalidation,
separate category and loss confirmations, metadata-only verification and fixture/VM validation.
CLI adapter tests must use a fake executable with fixed argv and suppressed output; credential
integration tests must create and remove only test-namespaced targets in a disposable lab.
A fake CLI test cannot validate a real CLI's offline behavior. This phase intentionally has no
subprocess/deletion path, so those original success-path tests are deferred with the adapters.
Current tests prove refusal, no capability binding and unchanged temporary fixtures instead;
they do not touch real credentials, tools, registry state or authenticated accounts.

## Revised phase 26 acceptance

- Twelve manifests with sources, artifact confidence, loss descriptions and blockers validate.
- Rust research previews contain no executable actions and cannot become ValidatedPlan.
- Changed flags, roots, methods, preservation or missing category confirmation cannot promote
  Windows/dev manifests; category scope validation is candidate-only.
- The engine's category confirmation is required and run-bound; fixture tests retain both checks.
- SSO warning appears in research plans, prepared engine plans and text/JSON category reports.
- Windows sign-in and all broker/device state are excluded by absence of mutation capabilities;
  this is not a claim of a successful live S5 experiment.
- Workspace build/test/clippy/fmt and frontend checks pass; only phase files are committed.

The original requirement for executable providers and fake-CLI success is replaced by the
explicit blocked-candidate scope above until the stated evidence gates are met. UI, network
revocation and all-accounts mode remain outside this phase.
