use crate::{PlatformError, Result};
use everyout_core_model::ErrorKind;
use std::{
    ffi::{OsStr, OsString},
    mem::{offset_of, size_of},
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            NtCreateFile, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN,
            FILE_OPEN_REPARSE_POINT, FILE_SYNCHRONOUS_IO_NONALERT,
        },
    },
    Win32::{Foundation::*, Storage::FileSystem::*, System::IO::IO_STATUS_BLOCK},
};

pub(crate) fn wide(input: impl AsRef<OsStr>) -> Vec<u16> {
    input.as_ref().encode_wide().chain(Some(0)).collect()
}
pub(crate) fn error(code: u32) -> PlatformError {
    let kind = match code {
        ERROR_ACCESS_DENIED => ErrorKind::AccessDenied,
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_USER_MAPPED_FILE => {
            ErrorKind::Locked
        }
        ERROR_CANT_ACCESS_FILE | ERROR_REPARSE_TAG_INVALID | ERROR_REPARSE_POINT_ENCOUNTERED => {
            ErrorKind::ScopeViolation
        }
        _ => ErrorKind::Io,
    };
    PlatformError {
        kind,
        os_code: Some(code),
        applied: 0,
    }
}
pub(crate) fn last_error() -> PlatformError {
    // SAFETY: GetLastError has no arguments; called immediately after failed Windows I/O.
    error(unsafe { GetLastError() })
}
pub(crate) fn absent(e: &PlatformError) -> bool {
    matches!(e.os_code, Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND))
}
pub(crate) struct Handle(pub(crate) HANDLE);
pub(crate) fn duplicate(handle: &Handle) -> Result<Handle> {
    let mut copy = ptr::null_mut();
    // SAFETY: duplicate a valid same-process owned handle, retaining identical rights.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle.0,
            GetCurrentProcess(),
            &mut copy,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(last_error());
    }
    Ok(Handle(copy))
}
impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this RAII wrapper owns exactly one successful open.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Identity {
    pub(crate) volume: u32,
    pub(crate) index: u64,
}
pub(crate) struct Info {
    pub identity: Identity,
    pub directory: bool,
    pub size: u64,
    pub modified_ticks: u64,
}
impl Handle {
    pub(crate) fn info(&self) -> Result<Info> {
        let mut data = BY_HANDLE_FILE_INFORMATION::default();
        // SAFETY: valid owned handle and writable structure of the documented size.
        if unsafe { GetFileInformationByHandle(self.0, &mut data) } == 0 {
            return Err(last_error());
        }
        if data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 || data.nNumberOfLinks > 1 {
            return Err(PlatformError::new(ErrorKind::ScopeViolation));
        }
        Ok(Info {
            identity: Identity {
                volume: data.dwVolumeSerialNumber,
                index: (u64::from(data.nFileIndexHigh) << 32) | u64::from(data.nFileIndexLow),
            },
            directory: data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            size: (u64::from(data.nFileSizeHigh) << 32) | u64::from(data.nFileSizeLow),
            modified_ticks: (u64::from(data.ftLastWriteTime.dwHighDateTime) << 32)
                | u64::from(data.ftLastWriteTime.dwLowDateTime),
        })
    }
    pub(crate) fn delete(&self, dry_run: bool) -> Result<()> {
        self.info()?;
        if dry_run {
            return Ok(());
        }
        let info = FILE_DISPOSITION_INFO { DeleteFile: true };
        // SAFETY: the target is the checked open object, not a reopened path. No POSIX
        // deletion, attribute override or security bypass flags are requested.
        if unsafe {
            SetFileInformationByHandle(
                self.0,
                FileDispositionInfo,
                (&info as *const FILE_DISPOSITION_INFO).cast(),
                size_of::<FILE_DISPOSITION_INFO>() as u32,
            )
        } == 0
        {
            return Err(last_error());
        }
        Ok(())
    }
    pub(crate) fn children(&self) -> Result<Vec<(OsString, bool)>> {
        self.enumerate_children(true).map(|(entries, _)| entries)
    }
    pub(crate) fn discovery_children(&self) -> Result<(Vec<(OsString, bool)>, bool)> {
        self.enumerate_children(false)
    }
    fn enumerate_children(&self, reject_reparse: bool) -> Result<(Vec<(OsString, bool)>, bool)> {
        self.info()?;
        let mut result = Vec::new();
        let mut omitted = false;
        let mut count = 0;
        let mut buffer = vec![0u64; 8192];
        let mut class = FileIdBothDirectoryRestartInfo;
        loop {
            // SAFETY: aligned, writable 64 KiB buffer; directory handle has only
            // FILE_LIST_DIRECTORY/attributes rights, never file-content rights.
            if unsafe {
                GetFileInformationByHandleEx(
                    self.0,
                    class,
                    buffer.as_mut_ptr().cast(),
                    (buffer.len() * 8) as u32,
                )
            } == 0
            {
                let e = last_error();
                if e.os_code == Some(ERROR_NO_MORE_FILES) {
                    break;
                }
                return Err(e);
            }
            class = FileIdBothDirectoryInfo;
            let bytes = buffer.len() * 8;
            let mut offset = 0;
            loop {
                let name_offset = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
                if offset + size_of::<FILE_ID_BOTH_DIR_INFO>() > bytes {
                    return Err(PlatformError::new(ErrorKind::Io));
                }
                // SAFETY: checked structure bounds; Windows supplies NextEntryOffset and
                // FileNameLength, validated below before forming the filename slice.
                let entry = unsafe {
                    ptr::read_unaligned(
                        buffer
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset)
                            .cast::<FILE_ID_BOTH_DIR_INFO>(),
                    )
                };
                let length = entry.FileNameLength as usize;
                if !length.is_multiple_of(2) || offset + name_offset + length > bytes {
                    return Err(PlatformError::new(ErrorKind::Io));
                }
                // SAFETY: UTF-16 length and buffer bounds validated above; offset is aligned.
                let name = OsString::from_wide(unsafe {
                    std::slice::from_raw_parts(
                        buffer
                            .as_ptr()
                            .cast::<u8>()
                            .add(offset + name_offset)
                            .cast::<u16>(),
                        length / 2,
                    )
                });
                if name != "." && name != ".." {
                    count += 1;
                    if count > 10_000 {
                        return Err(PlatformError::new(ErrorKind::Unsupported));
                    }
                    if entry.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        if reject_reparse {
                            return Err(PlatformError::new(ErrorKind::ScopeViolation));
                        }
                        omitted = true;
                    } else {
                        result.push((name, entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0));
                    }
                }
                if entry.NextEntryOffset == 0 {
                    break;
                }
                let next = entry.NextEntryOffset as usize;
                if next < name_offset + length || !next.is_multiple_of(8) || offset + next >= bytes
                {
                    return Err(PlatformError::new(ErrorKind::Io));
                }
                offset += next;
            }
        }
        Ok((result, omitted))
    }
}

/// Open exactly one component relative to an already checked directory object.
/// Generic file opens never receive FILE_READ_DATA; the directory right is only
/// requested together with FILE_DIRECTORY_FILE, so type substitution fails closed.
pub(crate) fn child(
    parent: &Handle,
    name: &OsStr,
    directory: Option<bool>,
    delete: bool,
) -> Result<Handle> {
    open_child(parent, name, directory, delete, false)
}

fn open_child(
    parent: &Handle,
    name: &OsStr,
    directory: Option<bool>,
    delete: bool,
    profile_config: bool,
) -> Result<Handle> {
    open_checked_child(
        parent,
        name,
        directory,
        delete,
        if profile_config { FILE_READ_DATA } else { 0 },
    )
}

// Compiled executable metadata readers and fixed adapters may request content rights.
// Runtime pins request read sharing rights without consuming payloads. Generic filesystem
// metadata callers continue through child(), which passes zero content access.
pub(crate) fn open_checked_child(
    parent: &Handle,
    name: &OsStr,
    directory: Option<bool>,
    delete: bool,
    content_access: u32,
) -> Result<Handle> {
    open_child_with_sharing(parent, name, directory, delete, content_access, false)
}
/// Read-only runtime observation can coexist with a writer, but never with deletion.
/// Uses the same handle-relative no-reparse grammar and physical identity checks.
pub(crate) fn runtime_child(parent: &Handle, name: &OsStr, directory: bool) -> Result<Handle> {
    // Attribute-only handles do not enforce share-delete exclusion on Windows.
    // Request read access solely to pin the representative object; no payload reads.
    open_child_with_sharing(
        parent,
        name,
        Some(directory),
        false,
        if directory { 0 } else { FILE_READ_DATA },
        true,
    )
}
fn open_child_with_sharing(
    parent: &Handle,
    name: &OsStr,
    directory: Option<bool>,
    delete: bool,
    content_access: u32,
    runtime_observation: bool,
) -> Result<Handle> {
    parent.info()?;
    let mut name = wide(name);
    let length = (name.len() - 1) * 2;
    if length > u16::MAX as usize {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let unicode = UNICODE_STRING {
        Length: length as u16,
        MaximumLength: length as u16,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.0,
        ObjectName: &unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        ..Default::default()
    };
    let options = FILE_OPEN_REPARSE_POINT
        | if directory == Some(true) || content_access != 0 {
            FILE_SYNCHRONOUS_IO_NONALERT
        } else {
            0
        }
        | match directory {
            Some(true) => FILE_DIRECTORY_FILE,
            Some(false) => FILE_NON_DIRECTORY_FILE,
            None => 0,
        };
    let access = FILE_READ_ATTRIBUTES
        | if directory == Some(true) || content_access != 0 {
            SYNCHRONIZE
        } else {
            0
        }
        | if directory == Some(true) {
            FILE_LIST_DIRECTORY
        } else {
            0
        }
        | if delete { DELETE } else { 0 }
        | content_access;
    let mut handle = ptr::null_mut();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: parent is alive, the name is a single validated component, the Unicode
    // string/buffers live for the synchronous open. FILE_OPEN cannot create anything.
    let sharing = FILE_SHARE_READ
        | if (directory == Some(true) || runtime_observation) && !delete {
            FILE_SHARE_WRITE
        } else {
            0
        };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut io,
            ptr::null(),
            0,
            sharing,
            FILE_OPEN,
            options,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        // SAFETY: pure status-code translation, no object access.
        return Err(error(unsafe { RtlNtStatusToDosError(status) }));
    }
    let handle = Handle(handle);
    handle.info()?;
    Ok(handle)
}

pub(crate) fn metadata_path(handle: &Handle) -> Result<std::path::PathBuf> {
    handle.info()?;
    let mut buffer = vec![0u16; 32768];
    // SAFETY: retained checked handle and bounded UTF-16 output, no filesystem mutation.
    let len =
        unsafe { GetFinalPathNameByHandleW(handle.0, buffer.as_mut_ptr(), buffer.len() as u32, 0) };
    if len == 0 || len as usize >= buffer.len() {
        return Err(last_error());
    }
    let path = String::from_utf16(&buffer[..len as usize])
        .map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))?;
    let path = path.strip_prefix("\\\\?\\").unwrap_or(&path);
    Ok(std::path::PathBuf::from(path))
}

/// Sole content exception: fixed non-secret configuration, bounded and opened
/// relative to a retained root without write/delete sharing or redirect traversal.
pub(crate) fn firefox_profiles_ini(parent: &Handle) -> Result<String> {
    let handle = open_child(parent, OsStr::new("profiles.ini"), Some(false), false, true)?;
    let info = handle.info()?;
    if info.size > 64 * 1024 {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    let mut bytes = vec![0u8; info.size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let mut count = 0;
        // SAFETY: synchronous fixed config handle and bounded writable buffer.
        // Session-artifact handles never receive content rights.
        if unsafe {
            ReadFile(
                handle.0,
                bytes[offset..].as_mut_ptr(),
                (bytes.len() - offset) as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(last_error());
        }
        if count == 0 {
            return Err(PlatformError::new(ErrorKind::StalePlan));
        }
        offset += count as usize;
    }
    String::from_utf8(bytes).map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))
}

pub(crate) fn directory_path(handle: &Handle) -> Result<String> {
    let mut buffer = vec![0u16; 32768];
    // SAFETY: metadata-only path query for a retained directory capability.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            handle.0,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    } as usize;
    if count == 0 {
        return Err(last_error());
    }
    if count >= buffer.len() {
        return Err(PlatformError::new(ErrorKind::ScopeViolation));
    }
    String::from_utf16(&buffer[..count]).map_err(|_| PlatformError::new(ErrorKind::ScopeViolation))
}
