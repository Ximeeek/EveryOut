# Application manifest examples

The [desktop catalog](../../docs/catalog/apps-other.md) adds 17 research candidates under
`communication/`, `messengers/`, `mail/`, `vpn/`, `authenticators/`, `wallets/` and
`password-managers/`. All start unchecked with low confidence. Five use typed unresolved roots
which cannot bind filesystem paths. The fixed desktop scopes declare local history, vault,
authenticator, wallet-key and device-trust losses; Thunderbird's mixed profile reset is a
non-waivable password-preservation conflict.

The [gaming catalog](../../docs/catalog/apps-gaming.md) adds seven real-product research entries
under `gaming/`. All remain unverified candidates; fixture deletion is not proof of product logout.

The Electron/CEF, WebView2 and Store entries are synthetic candidate manifests used by tests.
They are not real catalog support and cannot execute as distributed. Actual application entries
require version-specific ownership, storage, preservation and loss evidence in later phases.

See the [generic application provider contract](../../docs/architecture/21-application-providers.md)
for allowed storage families, package-family addressing, preserved encryption metadata and PWA
ownership. Each manifest binds one reviewed AppData root; additional scopes need separate review.
