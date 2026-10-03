# EveryOut

EveryOut is a Windows desktop application, currently in the pre-alpha design phase, intended to log the user out locally from apps and browser sessions with one click. The application is designed to delete session data; using it can remove access to accounts and destroy local-only data, so review its behavior carefully before use.

**Status:** pre-alpha — design phase

**License:** GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

Project documentation will appear in [`docs/`](docs/).

## Trust and verification

Before running a release, compare its SHA-256 with the published checksums and, when signed,
verify the declared publisher and signature. Follow the
[source and build verification procedure](docs/oss/reproducible-builds.md) and
[code signing policy](docs/oss/code-signing.md). Signing provider approval and complete bit
reproducibility remain unverified; do not assume a download is signed. [HYPOTHESIS]

Signing does not guarantee immediate SmartScreen reputation. New signed builds can still warn,
and unsigned builds can be blocked by device policy.
[VERIFIED: https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation, accessed 2026-10-03]
Report suspected [antivirus/EDR false positives](docs/oss/false-positives.md) without sharing
session data; report vulnerabilities privately under [SECURITY.md](SECURITY.md).
