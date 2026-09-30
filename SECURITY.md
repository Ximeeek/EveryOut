# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through [GitHub Security Advisories](https://github.com/Ximeeek/EveryOut/security/advisories/new).
Do not open a public issue for an unpatched vulnerability. Include the affected version or
commit, the impact, and enough steps to reproduce the issue safely. Do not attach real session
data, credentials, tokens, or cookies.

## Supported versions

| Version | Supported |
| --- | --- |
| Pre-release | Latest `main` only |

## Scope and guarantees

EveryOut is intended to operate locally on Windows to delete or invalidate app and browser
sessions. Its central security requirement is that it does not read, copy, decrypt, or transmit
secrets. The wipe operation is designed to make no network requests. These are design guarantees
that implementations and contributions must preserve; the project is currently pre-alpha, so
review the current code and release notes before relying on a build.

Reports about behavior that violates these guarantees are in scope. Please avoid public disclosure
until maintainers have had a reasonable opportunity to investigate and coordinate a fix.
