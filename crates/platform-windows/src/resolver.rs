use crate::{AllowedRoot, KnownFolder, PlatformError, Result};
use everyout_core_model::ErrorKind;
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf, ptr};
use windows_sys::Win32::{
    System::Com::CoTaskMemFree,
    UI::Shell::{FOLDERID_LocalAppData, FOLDERID_RoamingAppData, SHGetKnownFolderPath},
};

/// Returns a capability, never a caller-provided absolute-path string. Shipping
/// implementations resolve the current unelevated user's OS known folders.
pub trait RootResolver {
    fn resolve(&self, folder: KnownFolder) -> Result<AllowedRoot>;
}
pub struct CurrentUserFolders;
impl RootResolver for CurrentUserFolders {
    fn resolve(&self, folder: KnownFolder) -> Result<AllowedRoot> {
        let id = match folder {
            KnownFolder::LocalAppData => &FOLDERID_LocalAppData,
            KnownFolder::RoamingAppData => &FOLDERID_RoamingAppData,
        };
        let mut value = ptr::null_mut();
        // SAFETY: a fixed known-folder ID, no other-user token and no CREATE flag.
        // The OS owns a null-terminated allocated result on success.
        let status = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &mut value) };
        if status < 0 {
            if !value.is_null() {
                // SAFETY: any allocation returned by this API uses the COM allocator.
                unsafe {
                    CoTaskMemFree(value.cast());
                }
            }
            return Err(PlatformError {
                kind: ErrorKind::Io,
                os_code: Some(status as u32),
                applied: 0,
            });
        }
        let mut length = 0;
        // SAFETY: SHGetKnownFolderPath returned an allocated null-terminated string.
        while unsafe { *value.add(length) } != 0 {
            length += 1;
        }
        // SAFETY: measured string length; ownership is released after copying metadata.
        let path = PathBuf::from(OsString::from_wide(unsafe {
            std::slice::from_raw_parts(value, length)
        }));
        // SAFETY: release exactly the allocation returned by SHGetKnownFolderPath.
        unsafe {
            CoTaskMemFree(value.cast());
        }
        AllowedRoot::absolute(&path)
    }
}

/// This harness-only resolver cannot adopt an existing arbitrary directory.
/// Its immutable root is freshly created and owned, with no production fallback.
#[cfg(feature = "test-fixtures")]
pub struct FixtureFolders {
    root: Option<AllowedRoot>,
    directory: tempfile::TempDir,
}
#[cfg(feature = "test-fixtures")]
impl FixtureFolders {
    pub fn create() -> Result<Self> {
        let directory = tempfile::Builder::new()
            .prefix("everyout-platform-")
            .tempdir()
            .map_err(|e| crate::native::error(e.raw_os_error().unwrap_or(1) as u32))?;
        let root = AllowedRoot::absolute(directory.path())?;
        Ok(Self {
            root: Some(root),
            directory,
        })
    }
    /// Only for seeding and observing synthetic fixtures outside the adapter.
    pub fn path(&self) -> &std::path::Path {
        self.directory.path()
    }
}
#[cfg(feature = "test-fixtures")]
impl RootResolver for FixtureFolders {
    fn resolve(&self, _folder: KnownFolder) -> Result<AllowedRoot> {
        Ok(self.root.as_ref().expect("fixture is alive").clone())
    }
}
#[cfg(feature = "test-fixtures")]
impl Drop for FixtureFolders {
    fn drop(&mut self) {
        // Release the immutable root before TempDir removes the owned fixture.
        self.root.take();
    }
}
