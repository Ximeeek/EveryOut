//! Trusted manifests and bounded provider execution; only Firefox profiles.ini paths may be read.
#![forbid(unsafe_code)]

#[cfg(windows)]
pub mod executor;
mod firefox;
pub mod manifest;
#[cfg(windows)]
pub mod platform;
pub mod validation;
pub use manifest::*;
pub use validation::{load_manifest, ManifestError, ManifestErrorKind};
