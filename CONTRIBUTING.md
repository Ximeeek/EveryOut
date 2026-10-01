# Contributing to EveryOut

Thank you for your interest in EveryOut. The project is in pre-alpha design, so discuss
substantial changes in an issue before investing in an implementation.

## Development workflow

1. Check the open issues and existing documentation before proposing a change.
2. For substantial work, open an issue to agree on the expected behavior and risks.
3. Create a focused branch using `<type>/<kebab-case-description>`. Allowed branch types are
   `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, and `ci`.
4. Keep changes focused, document user-visible behavior, and include a practical verification
   procedure in your pull request.
5. Open a pull request against `main` and complete the pull request template. Address review
   feedback before asking for another review.

Provider and catalog additions must be made through the relevant manifest files. Do not add
provider or catalog entries as one-off hard-coded behavior. Include evidence for the session
location, the supported logout or invalidation behavior, and any data-loss implications.

## Commit messages

Use [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/) with a required
lowercase scope: `<type>(<scope>): <imperative description>`. Keep the subject lowercase, at most
72 characters, imperative, and without a trailing period.

Every commit must have a detailed body after one blank line. The body is required even for small
changes and should be the bulk of the message. Explain what changed, grouped by area or file, why
it changed, and notable decisions or trade-offs. Wrap body lines near 100 characters. Add
`Refs:` or `BREAKING CHANGE:` footers only when relevant.

Examples:

```text
docs(contributing): define manifest-based provider contributions

Explain that provider and catalog additions belong in manifests, and list the evidence a
contributor should include. This gives reviewers a consistent way to assess session handling
before provider support is implemented.
```

```text
fix(providers): preserve browser profile paths with spaces

Quote profile paths when resolving browser session locations so installations under paths
containing spaces are handled correctly. Keep the lookup local and avoid reading credential
stores as part of the change.
```

```text
feat(ui): explain which sessions a wipe will invalidate

Show the selected apps and the expected sign-out or local-data consequences before the user
confirms a wipe. This makes irreversible effects visible at the point of decision.
```

## Running the app

Install Rust using the version pinned in [`rust-toolchain.toml`](rust-toolchain.toml), including
the MSVC toolchain, Node.js (LTS), pnpm, Microsoft C++ Build Tools with the **Desktop development
with C++** workload, and the Microsoft Edge WebView2 Runtime.

From the repository root, run:

```powershell
pnpm install
pnpm tauri dev
pnpm tauri build
```

`pnpm tauri dev` starts the Vite development server and desktop app. `pnpm tauri build` creates a
release application bundle.

## Quality checks

Run the same checks used by CI from the repository root before opening a pull request:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --nocapture
pnpm install --frozen-lockfile
pnpm lint
pnpm typecheck
pnpm format:check
pnpm build
pnpm commitlint --from <base> --to <head>
```

Replace `<base>` and `<head>` with the commit IDs at the start and end of the range to check.
Every commit needs a body with at least 20 characters of description.

## Pull requests

- Keep each pull request focused and describe its motivation and user impact.
- Link related issues and explain how reviewers can verify the change.
- Call out data loss, provider-specific behavior, security implications, and limitations.
- Update documentation and manifests with behavior changes; do not silently broaden the wipe
  scope.
- Wait for review and resolve requested changes before merging. Maintainers handle merging.

## Security and session data

EveryOut's central design principle is that the app deletes and invalidates sessions but **never
reads, copies, decrypts, or transmits secrets**. This is a design requirement for all contributions,
including providers, diagnostics, logging, and error handling. Wiping must not use the network;
keep the operation local. Do not add code or documentation that asks users to submit passwords,
tokens, cookies, or other secret session contents. See [SECURITY.md](SECURITY.md) to report a
vulnerability privately.
