use everyout_identity_probe::{DirectorySummary, directory_summary, parse_targets};
use serde::Serialize;
use std::os::windows::{ffi::OsStringExt, process::CommandExt};
use std::{
    path::{Path, PathBuf},
    process::Command,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_ITEMS, ERROR_SUCCESS},
    Globalization::{GetOEMCP, MultiByteToWideChar},
    Storage::FileSystem::GetDriveTypeW,
    System::{Registry::*, SystemInformation::GetSystemDirectoryW},
};

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: each successful open owns exactly this handle.
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn open(parent: HKEY, name: &str, view: u32) -> Result<Key, u32> {
    let name = wide(name);
    let mut key = ptr::null_mut();
    // SAFETY: live terminated input and valid output storage; read access only.
    let status = unsafe { RegOpenKeyExW(parent, name.as_ptr(), 0, KEY_READ | view, &mut key) };
    if status == ERROR_SUCCESS {
        Ok(Key(key))
    } else {
        Err(status)
    }
}
fn names(key: &Key) -> Result<Vec<String>, &'static str> {
    let mut result = Vec::new();
    for index in 0..100_000 {
        let mut buffer = [0u16; 256];
        let mut len = buffer.len() as u32;
        // SAFETY: buffers and size pointers are valid for this call.
        let status = unsafe {
            RegEnumKeyExW(
                key.0,
                index,
                buffer.as_mut_ptr(),
                &mut len,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if status == ERROR_NO_MORE_ITEMS {
            return Ok(result);
        }
        if status != ERROR_SUCCESS {
            return Err("profile enumeration incomplete");
        }
        result
            .push(String::from_utf16(&buffer[..len as usize]).map_err(|_| "invalid profile key")?);
    }
    Err("profile enumeration limit exceeded")
}
fn profile_path(key: &Key) -> Result<String, &'static str> {
    // Read this one approved metadata field, never arbitrary registry values.
    let value = wide("ProfileImagePath");
    let mut data = [0u16; 32768];
    let mut bytes = (data.len() * 2) as u32;
    let mut kind = 0;
    // SAFETY: aligned output buffer and byte size agree; value name is terminated.
    let status = unsafe {
        RegQueryValueExW(
            key.0,
            value.as_ptr(),
            ptr::null(),
            &mut kind,
            data.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status != ERROR_SUCCESS
        || ![REG_SZ, REG_EXPAND_SZ].contains(&kind)
        || bytes < 2
        || !bytes.is_multiple_of(2)
    {
        return Err("profile path metadata unavailable");
    }
    let units = &data[..bytes as usize / 2];
    if units.last() != Some(&0) || units[..units.len() - 1].contains(&0) {
        return Err("invalid profile path metadata");
    }
    // Keep REG_EXPAND_SZ literal: never expand against the helper's user environment.
    String::from_utf16(&units[..units.len() - 1]).map_err(|_| "invalid profile path encoding")
}

#[derive(Serialize)]
pub struct Profile {
    sid: String,
    profile_image_path: Option<String>,
    path_state: &'static str,
    hive_state: &'static str,
}
fn profiles() -> Result<Vec<Profile>, &'static str> {
    let list = open(
        HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        KEY_WOW64_64KEY,
    )
    .map_err(|_| "ProfileList unavailable")?;
    let mut profiles = Vec::new();
    for sid in names(&list)? {
        let path = open(list.0, &sid, 0)
            .ok()
            .and_then(|key| profile_path(&key).ok());
        let hive_state = match open(HKEY_USERS, &sid, 0) {
            Ok(_) => "loaded_observed",
            Err(ERROR_FILE_NOT_FOUND) => "unloaded_observed",
            Err(_) => "unknown",
        };
        profiles.push(Profile {
            sid,
            path_state: if path.is_some() {
                "literal_registry_metadata"
            } else {
                "unavailable"
            },
            profile_image_path: path,
            hive_state,
        });
    }
    profiles.sort_by(|a, b| a.sid.cmp(&b.sid));
    Ok(profiles)
}
fn system_cmdkey() -> Result<PathBuf, &'static str> {
    let mut buffer = [0u16; 32768];
    // SAFETY: valid output array; reported capacity matches allocation.
    let len = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if len == 0 || len >= buffer.len() {
        return Err("system directory unavailable");
    }
    Ok(PathBuf::from(std::ffi::OsString::from_wide(&buffer[..len])).join("cmdkey.exe"))
}
fn decode(bytes: &[u8]) -> Result<String, &'static str> {
    let length = i32::try_from(bytes.len()).map_err(|_| "cmdkey output too large")?;
    if length == 0 {
        return Err("empty cmdkey output");
    }
    // SAFETY: code page query and length-only conversion do not dereference output.
    let cp = unsafe { GetOEMCP() };
    let size = unsafe { MultiByteToWideChar(cp, 0, bytes.as_ptr(), length, ptr::null_mut(), 0) };
    if size <= 0 {
        return Err("cmdkey encoding unsupported");
    }
    let mut text = vec![0u16; size as usize];
    // SAFETY: source and destination capacities agree with conversion lengths.
    if unsafe { MultiByteToWideChar(cp, 0, bytes.as_ptr(), length, text.as_mut_ptr(), size) }
        != size
    {
        return Err("cmdkey decoding failed");
    }
    String::from_utf16(&text).map_err(|_| "cmdkey encoding invalid")
}
fn targets() -> Result<Vec<String>, &'static str> {
    // Absolute Windows executable, fixed read-only argument, no shell or PATH lookup.
    let output = Command::new(system_cmdkey()?)
        .arg("/list")
        .creation_flags(0x08000000)
        .output()
        .map_err(|_| "cmdkey launch failed")?;
    if !output.status.success() {
        return Err("cmdkey inventory failed");
    }
    if output.stdout.len() > 4 * 1024 * 1024 {
        return Err("cmdkey output too large");
    }
    // Raw metadata contains usernames. It stays local in memory and is never printed.
    parse_targets(&decode(&output.stdout)?).map_err(|_| "cmdkey layout unsupported")
}
fn local_root() -> Result<PathBuf, &'static str> {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or("LOCALAPPDATA unavailable")?;
    use std::path::{Component, Prefix};
    if root
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("invalid local root");
    }
    match root.components().next() {
        Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_)) && root.is_absolute() =>
        {
            let drive = format!("{}\\", prefix.as_os_str().to_string_lossy());
            // SAFETY: live terminated drive root; query only.
            if unsafe { GetDriveTypeW(wide(&drive).as_ptr()) } != 3 {
                return Err("non-fixed local root");
            }
        }
        _ => return Err("invalid local root"),
    }
    Ok(root)
}
#[derive(Serialize)]
pub struct Report {
    schema_version: u32,
    credential_scope: &'static str,
    microsoft_candidate_targets: Vec<String>,
    directories: Vec<DirectorySummary>,
    profiles: Vec<Profile>,
}
pub fn inspect() -> Result<Report, &'static str> {
    let root = local_root()?;
    let microsoft_candidate_targets = targets()?;
    let profiles = profiles()?;
    let directories = ["TokenBroker", "IdentityCache", "OneAuth"]
        .into_iter()
        .map(|store| directory_summary(store, &root.join(Path::new("Microsoft")).join(store)))
        .collect();
    Ok(Report {
        schema_version: 1,
        credential_scope: "process user only; no other-user credential coverage",
        microsoft_candidate_targets,
        directories,
        profiles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decodes_ascii_fixture_without_executing_inventory() {
        assert_eq!(
            decode(b"Target: MicrosoftOffice_fixture").unwrap(),
            "Target: MicrosoftOffice_fixture"
        );
        assert!(decode(b"").is_err());
    }
}
