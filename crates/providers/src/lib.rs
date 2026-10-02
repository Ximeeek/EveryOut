//! Trusted manifests and bounded provider execution; only Firefox profiles.ini paths may be read.
#![forbid(unsafe_code)]

pub mod application;
#[cfg(windows)]
pub mod executor;
mod firefox;
pub mod gaming;
#[cfg(windows)]
mod identity;
pub mod manifest;
#[cfg(windows)]
pub mod platform;
#[cfg(windows)]
pub mod steam;
pub mod validation;
pub use manifest::*;
pub use validation::{load_manifest, ManifestError, ManifestErrorKind};
