//! Static executable metadata only; no module loading or executable invocation.
use super::*;
use crate::native::{open_checked_child, wide, Handle};
use sha2::{Digest, Sha256};
use std::{ffi::OsStr, mem::size_of, ptr};
use windows_sys::Win32::{
    Security::{Cryptography::*, WinTrust::*},
    Storage::FileSystem::*,
};

fn text(value: String) -> Option<String> {
    let value = value.trim_matches('\0').trim().to_owned();
    (!value.is_empty() && value.len() <= 512 && !value.chars().any(char::is_control))
        .then_some(value)
}
fn version(path: &Path) -> PeMetadata {
    let path = wide(path);
    // SAFETY: local pinned executable path; size query reads version resources only.
    let size = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), ptr::null_mut()) };
    if size == 0 || size > 1024 * 1024 {
        return PeMetadata::default();
    }
    let mut data = vec![0u64; (size as usize).div_ceil(8)];
    if unsafe { GetFileVersionInfoW(path.as_ptr(), 0, size, data.as_mut_ptr().cast()) } == 0 {
        return PeMetadata::default();
    }
    let mut translations = ptr::null_mut();
    let mut len = 0;
    if unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            wide("\\VarFileInfo\\Translation").as_ptr(),
            &mut translations,
            &mut len,
        )
    } == 0
        || translations.is_null()
        || !(4..=256).contains(&len)
    {
        return PeMetadata::default();
    }
    // API returns language/code-page pairs within this live resource buffer.
    let translations =
        unsafe { std::slice::from_raw_parts(translations.cast::<u16>(), len as usize / 2) };
    let get = |name: &str| {
        translations.as_chunks::<2>().0.iter().find_map(|pair| {
            let query = wide(format!(
                "\\StringFileInfo\\{:04x}{:04x}\\{name}",
                pair[0], pair[1]
            ));
            let mut value = ptr::null_mut();
            let mut length = 0;
            if unsafe {
                VerQueryValueW(
                    data.as_ptr().cast(),
                    query.as_ptr(),
                    &mut value,
                    &mut length,
                )
            } == 0
                || value.is_null()
                || length == 0
                || length > 513
            {
                return None;
            }
            text(
                String::from_utf16(unsafe {
                    std::slice::from_raw_parts(value.cast::<u16>(), length as usize)
                })
                .ok()?,
            )
        })
    };
    PeMetadata {
        executable_header: false,
        product_name: get("ProductName"),
        company_name: get("CompanyName"),
        file_description: get("FileDescription"),
        product_version: get("ProductVersion"),
        file_version: get("FileVersion"),
        original_filename: get("OriginalFilename"),
    }
}
fn signature(path: &Path) -> SignatureMetadata {
    let path = wide(path);
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        ..Default::default()
    };
    let mut data = WINTRUST_DATA {
        cbStruct: size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 { pFile: &mut file },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: fixed Authenticode policy, no UI/network retrieval, pinned local file.
    let status = unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        )
    };
    let mut result = SignatureMetadata {
        status: match status as u32 {
            0 => SignatureStatus::Valid,
            0x800b0100 => SignatureStatus::Unsigned,
            // Definite integrity/signature failures, unlike unavailable/offline trust policy.
            0x80096010 | 0x800b0004 => SignatureStatus::Invalid,
            _ => SignatureStatus::Unknown,
        },
        ..Default::default()
    };
    if status == 0 && !data.hWVTStateData.is_null() {
        let provider = unsafe { WTHelperProvDataFromStateData(data.hWVTStateData) };
        if !provider.is_null() {
            let signer = unsafe { WTHelperGetProvSignerFromChain(provider, 0, 0, 0) };
            if !signer.is_null() && unsafe { (*signer).csCertChain } > 0 {
                let cert = unsafe { (*(*signer).pasCertChain).pCert };
                if !cert.is_null() {
                    let mut name = [0u16; 513];
                    let count = unsafe {
                        CertGetNameStringW(
                            cert,
                            CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0,
                            ptr::null(),
                            name.as_mut_ptr(),
                            name.len() as u32,
                        )
                    };
                    if count > 1 && count <= name.len() as u32 {
                        result.publisher = String::from_utf16(&name[..count as usize - 1])
                            .ok()
                            .and_then(text);
                    }
                    let cert = unsafe { &*cert };
                    if cert.cbCertEncoded > 0
                        && cert.cbCertEncoded < 1024 * 1024
                        && !cert.pbCertEncoded.is_null()
                    {
                        result.certificate_sha256 = Some(format!(
                            "{:x}",
                            Sha256::digest(unsafe {
                                std::slice::from_raw_parts(
                                    cert.pbCertEncoded,
                                    cert.cbCertEncoded as usize,
                                )
                            })
                        ));
                    }
                }
            }
        }
    }
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: release the provider's state on every outcome, no mutation of the target.
    unsafe {
        WinVerifyTrust(
            ptr::null_mut(),
            &mut action,
            (&mut data as *mut WINTRUST_DATA).cast(),
        );
    }
    result
}
pub(super) fn collect(binding: &ExecutableBinding) -> (PeMetadata, SignatureMetadata) {
    if binding.revalidate().is_err() {
        return Default::default();
    }
    let mut result = (
        version(&binding.canonical_path),
        signature(&binding.canonical_path),
    );
    result.0.executable_header = executable_header(binding).unwrap_or(false);
    if binding.revalidate().is_err() {
        Default::default()
    } else {
        result
    }
}
fn executable_header(binding: &ExecutableBinding) -> Result<bool> {
    let root = AllowedRoot::absolute(binding.canonical_path.parent().expect("parent"))?;
    let file = open_checked_child(
        root.handle(),
        binding.canonical_path.file_name().expect("file"),
        Some(false),
        false,
        FILE_READ_DATA,
    )?;
    if PhysicalIdentity::from_native(file.info()?.identity) != binding.physical {
        return Err(PlatformError::new(ErrorKind::StalePlan));
    }
    let mut header = [0u8; 64];
    let mut read = 0;
    if unsafe {
        ReadFile(
            file.0,
            header.as_mut_ptr(),
            header.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(native::last_error());
    }
    if read != 64 || &header[..2] != b"MZ" {
        return Ok(false);
    }
    let offset = u32::from_le_bytes(header[60..64].try_into().expect("offset"));
    if !(64..=1024 * 1024).contains(&offset) || u64::from(offset) + 24 > file.info()?.size {
        return Ok(false);
    }
    if unsafe { SetFilePointerEx(file.0, offset as i64, ptr::null_mut(), FILE_BEGIN) } == 0 {
        return Err(native::last_error());
    }
    let mut pe = [0u8; 24];
    if unsafe {
        ReadFile(
            file.0,
            pe.as_mut_ptr(),
            pe.len() as u32,
            &mut read,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(native::last_error());
    }
    // Image must carry an executable image COFF flag, not just a renamed data file.
    Ok(read == 24 && &pe[..4] == b"PE\0\0" && u16::from_le_bytes([pe[22], pe[23]]) & 0x0002 != 0)
}
pub(super) fn executable_hash(binding: &ExecutableBinding) -> Result<String> {
    binding.revalidate()?;
    let root = AllowedRoot::absolute(binding.canonical_path.parent().expect("parent"))?;
    let file = open_checked_child(
        root.handle(),
        binding
            .canonical_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("")),
        Some(false),
        false,
        FILE_READ_DATA,
    )?;
    if PhysicalIdentity::from_native(file.info()?.identity) != binding.physical {
        return Err(PlatformError::new(ErrorKind::StalePlan));
    }
    let digest = hash(&file)?;
    // Keep this read pin while checking that cached PE/version metadata still describes it.
    binding.revalidate()?;
    Ok(digest)
}
fn hash(file: &Handle) -> Result<String> {
    let size = file.info()?.size;
    if size == 0 || size > 256 * 1024 * 1024 {
        return Err(PlatformError::new(ErrorKind::Unsupported));
    }
    let mut digest = Sha256::new();
    let mut remaining = size;
    let mut buffer = [0u8; 16384];
    while remaining > 0 {
        let count = remaining.min(buffer.len() as u64) as u32;
        let mut read = 0;
        if unsafe {
            ReadFile(
                file.0,
                buffer.as_mut_ptr(),
                count,
                &mut read,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(native::last_error());
        }
        if read == 0 || read > count {
            return Err(PlatformError::new(ErrorKind::Io));
        }
        digest.update(&buffer[..read as usize]);
        remaining -= read as u64;
    }
    Ok(format!("{:x}", digest.finalize()))
}
