# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/Ximeeek/EveryOut/security/advisories/new).
Do not open a public issue for an unpatched vulnerability. Include the affected version or
commit, the impact, and enough steps to reproduce the issue safely. Do not attach real session
data, credentials, tokens, or cookies.

## Supported versions

| Version     | Supported          |
| ----------- | ------------------ |
| Pre-release | Latest `main` only |

## Scope and guarantees

EveryOut is intended to operate locally on Windows to delete or invalidate app and browser
sessions. Its central security requirement is that it does not read, copy, decrypt, or transmit
secrets. The wipe operation is designed to make no network requests. These are design guarantees
that implementations and contributions must preserve; the project is currently pre-alpha, so
review the current code and release notes before relying on a build.

Reports about behavior that violates these guarantees are in scope. Please avoid public disclosure
until maintainers have had a reasonable opportunity to investigate and coordinate a fix.

## Coordinated disclosure

Report vulnerabilities through the private advisory channel above. Include an affected commit
or release hash, impact and a synthetic reproduction; never supply real session contents.
Maintainers should acknowledge, investigate, agree on a disclosure plan with the reporter and
coordinate a fix and advisory. Do not publish exploit details before that coordination. No fixed
response or remediation deadline is promised. These are project policy obligations. [HYPOTHESIS]

## Antivirus and EDR detections

Use the [false-positive handling procedure](docs/oss/false-positives.md) and the linked issue form
for suspected file misclassification. If evidence suggests secret access, unexpected networking,
binary tampering or another vulnerability, use private coordinated disclosure instead. Never
upload profiles, tokens, cookies or dumps, or disable protection to investigate. [HYPOTHESIS]

The [code signing policy](docs/oss/code-signing.md),
[release checklist](docs/oss/release-process.md) and
[verification procedure](docs/oss/reproducible-builds.md) define proposed release gates;
provider approval and complete bit reproducibility remain unverified. [HYPOTHESIS]
