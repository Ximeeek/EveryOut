//! Trusted manifest configuration parsed from memory; no discovery or system I/O.
#![forbid(unsafe_code)]

#[cfg(windows)]
pub mod executor;
pub mod manifest;
#[cfg(windows)]
pub mod platform;
pub mod validation;
pub use manifest::*;
pub use validation::{load_manifest, ManifestError, ManifestErrorKind};
