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
    volume: u32,
    index: u64,
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
        self.info()?;
        let mut result = Vec::new();
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
                    if entry.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(PlatformError::new(ErrorKind::ScopeViolation));
                    }
                    result.push((name, entry.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0));
                    if result.len() > 10_000 {
                        return Err(PlatformError::new(ErrorKind::Unsupported));
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
        Ok(result)
    }
}

/// Open exactly one component relative to an already checked directory object.
/// A file never receives FILE_READ_DATA; the overlapping directory right is only
/// requested together with FILE_DIRECTORY_FILE, so type substitution fails closed.
pub(crate) fn child(
    parent: &Handle,
    name: &OsStr,
    directory: Option<bool>,
    delete: bool,
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
        | if directory == Some(true) {
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
        | if directory == Some(true) {
            SYNCHRONIZE
        } else {
            0
        }
        | if directory == Some(true) {
            FILE_LIST_DIRECTORY
        } else {
            0
        }
        | if delete { DELETE } else { 0 };
    let mut handle = ptr::null_mut();
    let mut io = IO_STATUS_BLOCK::default();
    // SAFETY: parent is alive, the name is a single validated component, the Unicode
    // string/buffers live for the synchronous open. FILE_OPEN cannot create anything.
    let sharing = FILE_SHARE_READ
        | if directory == Some(true) && !delete {
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
