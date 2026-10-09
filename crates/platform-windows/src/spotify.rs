//! Fixed desktop exception, reviewed on Spotify 1.2.98.301. Credential values
//! never leave this module. Unknown builds and unknown autologin keys fail closed.
use crate::{
    native::{self, Handle, Identity},
    PlatformError, Result,
};
use everyout_core_model::ErrorKind;
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, ptr};
use windows_sys::Win32::Storage::FileSystem::*;
use zeroize::Zeroizing;

const PREFS_LIMIT: u64 = 64 * 1024;
// Reviewed executable had a valid Spotify AB Authenticode signature.
const BUILD_SHA256: [u8; 32] = [
    0x76, 0x26, 0x1c, 0x1e, 0xd0, 0xad, 0xba, 0xba, 0x3a, 0xcf, 0x09, 0x0f, 0x3a, 0x26, 0xae, 0x02,
    0x4f, 0x4b, 0xd8, 0xe5, 0x7f, 0xf0, 0x56, 0xe3, 0x91, 0x53, 0xca, 0x13, 0x96, 0xb7, 0x67, 0x78,
];

pub(crate) fn reviewed_build(root: &Handle) -> Result<()> {
    let exe = native::open_checked_child(
        root,
        OsStr::new("Spotify.exe"),
        Some(false),
        false,
        FILE_READ_DATA,
    )?;
    let size = exe.info()?.size;
    if size == 0 || size > 64 * 1024 * 1024 {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 16384];
    let mut remaining = size;
    while remaining != 0 {
        let length = remaining.min(buffer.len() as u64) as usize;
        read_exact(&exe, &mut buffer[..length])?;
        hash.update(&buffer[..length]);
        remaining -= length as u64;
    }
    if hash.finalize().as_slice() != BUILD_SHA256 {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    Ok(())
}

pub(crate) fn saved_login(root: &Handle, identity: Option<Identity>, apply: bool) -> Result<bool> {
    // The checked object is held without write/delete sharing throughout the
    // read, rewrite, flush and verification. Never reopen an ambient path.
    let file = native::open_checked_child(
        root,
        OsStr::new("prefs"),
        Some(false),
        false,
        FILE_READ_DATA | if apply { FILE_WRITE_DATA } else { 0 },
    )?;
    let info = file.info()?;
    if Some(info.identity) != identity {
        return Err(PlatformError::new(ErrorKind::StalePlan));
    }
    if info.size > PREFS_LIMIT {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    let mut original = Zeroizing::new(vec![0u8; info.size as usize]);
    read_exact(&file, &mut original)?;
    let filtered = Zeroizing::new(strip_autologin(&original)?);
    if *original == *filtered {
        return Ok(false);
    }
    if !apply {
        return Ok(true);
    }
    // In-place writes preserve object identity and ACLs. Restore original bytes
    // on any I/O or read-back failure; no reusable credentials are written to a
    // backup file. Power interruption remains a file-write limitation.
    let write = rewrite(&file, &filtered).and_then(|()| {
        seek_start(&file)?;
        let mut actual = Zeroizing::new(vec![0u8; filtered.len()]);
        read_exact(&file, &mut actual)?;
        if *actual != *filtered || file.info()?.size != filtered.len() as u64 {
            return Err(PlatformError::new(ErrorKind::Io));
        }
        Ok(())
    });
    if let Err(error) = write {
        if rewrite(&file, &original).is_err() {
            return Err(PlatformError {
                applied: 1,
                ..error
            });
        }
        return Err(error);
    }
    Ok(true)
}

fn strip_autologin(bytes: &[u8]) -> Result<Vec<u8>> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| PlatformError::new(ErrorKind::Unsupported))?;
    let mut output = Vec::with_capacity(bytes.len());
    let text = if let Some(text) = text.strip_prefix('\u{feff}') {
        output.extend_from_slice(b"\xef\xbb\xbf");
        text
    } else {
        text
    };
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\r', '\n']);
        if body.contains(['\r', '\0'])
            || (body.trim_start().starts_with("autologin.") && !body.starts_with("autologin."))
        {
            return Err(PlatformError::new(ErrorKind::Unsupported));
        }
        let key = body.split_once('=').map(|(key, _)| key).unwrap_or(body);
        if key.starts_with("autologin.") {
            if !body.contains('=')
                || !matches!(
                    key,
                    "autologin.username"
                        | "autologin.saved_credentials"
                        | "autologin.canonical_username"
                        | "autologin.blob"
                )
            {
                return Err(PlatformError::new(ErrorKind::Unsupported));
            }
        } else {
            output.extend_from_slice(line.as_bytes());
        }
    }
    Ok(output)
}

fn read_exact(file: &Handle, bytes: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        let mut count = 0;
        // SAFETY: synchronous, checked handle and bounded writable slice.
        if unsafe {
            ReadFile(
                file.0,
                bytes[offset..].as_mut_ptr(),
                (bytes.len() - offset) as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(native::last_error());
        }
        if count == 0 {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        offset += count as usize;
    }
    Ok(())
}
fn seek_start(file: &Handle) -> Result<()> {
    // SAFETY: retained synchronous file handle; offset zero is within the file.
    if unsafe { SetFilePointerEx(file.0, 0, ptr::null_mut(), FILE_BEGIN) } == 0 {
        return Err(native::last_error());
    }
    Ok(())
}
fn rewrite(file: &Handle, bytes: &[u8]) -> Result<()> {
    seek_start(file)?;
    let mut offset = 0;
    while offset < bytes.len() {
        let mut count = 0;
        // SAFETY: retained, exclusively writable file and bounded readable slice.
        if unsafe {
            WriteFile(
                file.0,
                bytes[offset..].as_ptr(),
                (bytes.len() - offset) as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(native::last_error());
        }
        if count == 0 {
            return Err(PlatformError::new(ErrorKind::Io));
        }
        offset += count as usize;
    }
    // SAFETY: position follows the completed write; retain ACL and file identity.
    if unsafe { SetEndOfFile(file.0) } == 0 || unsafe { FlushFileBuffers(file.0) } == 0 {
        return Err(native::last_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn preserves_every_non_login_byte_and_removes_duplicate_fields() {
        let bytes = b"\xef\xbb\xbfapp.last-launched-version=x\r\nautologin.username=fake\r\n# comment\nautologin.blob=fake\nautologin.blob=duplicate\nstorage.last-location=fake\nautologin.saved_credentials=fake\nautologin.canonical_username=fake";
        let expected =
            b"\xef\xbb\xbfapp.last-launched-version=x\r\n# comment\nstorage.last-location=fake\n";
        assert_eq!(strip_autologin(bytes).unwrap(), expected);
        assert_eq!(strip_autologin(expected).unwrap(), expected);
    }
    #[test]
    fn rejects_unknown_login_fields_and_invalid_encoding_before_writing() {
        for bytes in [
            b"autologin.future=fake".as_slice(),
            b"autologin.blob",
            &[0xff],
        ] {
            assert_eq!(
                strip_autologin(bytes).unwrap_err().kind,
                ErrorKind::Unsupported
            );
        }
        assert_eq!(
            strip_autologin(b"# autologin.blob=fake\n").unwrap(),
            b"# autologin.blob=fake\n"
        );
    }
    #[test]
    fn real_handles_preserve_identity_settings_and_canaries() {
        use crate::{AllowedRoot, FixtureFolders, KnownFolder, RootResolver};
        use std::fs;
        let fixture = FixtureFolders::create().unwrap();
        let root: AllowedRoot = fixture.resolve(KnownFolder::RoamingAppData).unwrap();
        let prefs = fixture.path().join("prefs");
        let original = b"setting=fake\r\nautologin.blob=fake\r\nstorage.last-location=fake\n";
        fs::write(&prefs, original).unwrap();
        fs::write(fixture.path().join("cache-canary"), b"preserve").unwrap();
        let bound = native::child(root.handle(), OsStr::new("prefs"), Some(false), false).unwrap();
        let identity = Some(bound.info().unwrap().identity);
        drop(bound);
        assert!(saved_login(root.handle(), identity, false).unwrap());
        assert_eq!(fs::read(&prefs).unwrap(), original);
        assert!(saved_login(root.handle(), identity, true).unwrap());
        assert_eq!(
            fs::read(&prefs).unwrap(),
            b"setting=fake\r\nstorage.last-location=fake\n"
        );
        assert!(!saved_login(root.handle(), identity, false).unwrap());
        assert!(!saved_login(root.handle(), identity, true).unwrap());
        assert_eq!(
            fs::read(fixture.path().join("cache-canary")).unwrap(),
            b"preserve"
        );
        fs::write(&prefs, b"autologin.future=fake\nsetting=fake").unwrap();
        assert_eq!(
            saved_login(root.handle(), identity, true).unwrap_err().kind,
            ErrorKind::Unsupported
        );
        assert_eq!(
            fs::read(&prefs).unwrap(),
            b"autologin.future=fake\nsetting=fake"
        );
    }
    #[test]
    fn rejects_substitution_oversize_and_unreviewed_executable() {
        use crate::{FixtureFolders, KnownFolder, RootResolver};
        use std::fs;
        let fixture = FixtureFolders::create().unwrap();
        let root = fixture.resolve(KnownFolder::RoamingAppData).unwrap();
        fs::write(
            fixture.path().join("Spotify.exe"),
            b"unreviewed synthetic build",
        )
        .unwrap();
        assert_eq!(
            root.spotify_reviewed_build().unwrap_err().kind,
            ErrorKind::Unsupported
        );
        let prefs = fixture.path().join("prefs");
        fs::write(&prefs, b"autologin.blob=fake").unwrap();
        let handle = native::child(root.handle(), OsStr::new("prefs"), Some(false), false).unwrap();
        let identity = Some(handle.info().unwrap().identity);
        drop(handle);
        fs::rename(&prefs, fixture.path().join("old-prefs")).unwrap();
        fs::write(&prefs, b"replacement=fake").unwrap();
        assert_eq!(
            saved_login(root.handle(), identity, true).unwrap_err().kind,
            ErrorKind::StalePlan
        );
        let handle = native::child(root.handle(), OsStr::new("prefs"), Some(false), false).unwrap();
        let identity = Some(handle.info().unwrap().identity);
        drop(handle);
        fs::write(&prefs, vec![b'x'; PREFS_LIMIT as usize + 1]).unwrap();
        assert_eq!(
            saved_login(root.handle(), identity, true).unwrap_err().kind,
            ErrorKind::Unsupported
        );
        assert_eq!(fs::metadata(&prefs).unwrap().len(), PREFS_LIMIT + 1);
    }
}
