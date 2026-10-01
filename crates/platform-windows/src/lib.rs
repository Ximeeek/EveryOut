//! Current-user, metadata-only platform capabilities. No content reader is exposed.
#![deny(unsafe_op_in_unsafe_fn)]

use everyout_core_model::{ActionStatus, ErrorKind};

#[cfg(windows)]
mod filesystem;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
mod registry;
#[cfg(windows)]
mod resolver;

#[cfg(windows)]
pub use filesystem::{AllowedRoot, Metadata, SafePath};
#[cfg(windows)]
pub use registry::{RegistryRoot, RegistryTarget};
#[cfg(all(windows, feature = "test-fixtures"))]
pub use resolver::FixtureFolders;
#[cfg(windows)]
pub use resolver::{CurrentUserFolders, RootResolver};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnownFolder {
    LocalAppData,
    RoamingAppData,
}

/// Stable, path-free diagnostics; already-completed mutations are counted on failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlatformError {
    pub kind: ErrorKind,
    pub os_code: Option<u32>,
    pub applied: usize,
}
impl PlatformError {
    pub(crate) fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            os_code: None,
            applied: 0,
        }
    }
}
impl std::fmt::Display for PlatformError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "platform-{:?}", self.kind)
    }
}
impl std::error::Error for PlatformError {}
pub type Result<T> = std::result::Result<T, PlatformError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mutation {
    pub status: ActionStatus,
    pub objects: usize,
}

/// Conservative Windows grammar, independent of ambient environment variables.
/// Empty components, aliases, ADS, device names and wildcard expansion are refused.
pub(crate) fn components(input: &str) -> Result<Vec<String>> {
    if input.is_empty()
        || input
            .chars()
            .any(|c| c.is_control() || ":*?<>|\"%~".contains(c))
    {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    input
        .split(['/', '\\'])
        .map(|part| {
            let stem = part.split('.').next().unwrap_or_default().to_uppercase();
            let device = matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            ) || ["COM", "LPT"].iter().any(|prefix| {
                stem.strip_prefix(prefix).is_some_and(|n| {
                    matches!(
                        n,
                        "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                    )
                })
            });
            if part.is_empty()
                || part == "."
                || part == ".."
                || part.ends_with(['.', ' '])
                || device
                || part.encode_utf16().count() > 255
            {
                Err(PlatformError::new(ErrorKind::ScopeViolation))
            } else {
                Ok(part.to_owned())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_windows_escape_and_alias_grammar() {
        for path in [
            "",
            "..",
            "a/../b",
            "/root",
            "C:\\x",
            "\\\\server\\share",
            "\\\\?\\C:\\x",
            "a:stream",
            "%APPDATA%",
            "x//y",
            "x/./y",
            "name.",
            "name ",
            "NUL.txt",
            "COM¹",
            "x*",
            "SHORT~1",
        ] {
            assert_eq!(
                components(path).unwrap_err().kind,
                ErrorKind::ScopeViolation,
                "{path}"
            );
        }
        assert_eq!(
            components("żółć space\\nested").unwrap(),
            ["żółć space", "nested"]
        );
    }
}
