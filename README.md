# EveryOut

EveryOut is the open-source project for SessionWipe, a Windows desktop application intended to log the user out locally from apps and browser sessions with one click. The application is designed to delete session data; using it can remove access to accounts and destroy local-only data, so review its behavior carefully before use.

**Status:** pre-alpha — design phase

**License:** GNU General Public License v3.0 or later. See [LICENSE](LICENSE).

Project documentation is indexed in [`docs/`](docs/).

## Development

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) using the version pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml), with the MSVC toolchain for Windows.
- [Node.js](https://nodejs.org/) (LTS) and [pnpm](https://pnpm.io/installation).
- [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with
  the **Desktop development with C++** workload.
- [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/).

### Commands

Run these commands from the repository root:

```powershell
pnpm install
pnpm tauri dev
pnpm tauri build
```

The first command installs the locked frontend dependencies. `pnpm tauri dev` starts the Vite
development server and desktop app; `pnpm tauri build` builds a release application bundle.
