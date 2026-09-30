//! Fixed-path metadata observations only; no payload reader or recursive tree walk.
use serde::Serialize;
use std::{
    fs, io,
    path::{Component, Path},
};

#[derive(Debug, Default, Clone, Copy)]
pub struct Evidence {
    pub identity: bool,
    pub runtime: bool,
    pub storage: bool,
    pub ownership: bool,
    pub plausible_owner: bool,
    pub conflict: bool,
    pub excluded: bool,
}
#[derive(Debug, Serialize)]
pub struct Score {
    pub points: u8,
    pub confidence: &'static str,
    pub signals: Vec<&'static str>,
    pub actionable: bool,
}
pub fn score(e: Evidence) -> Score {
    let signals: Vec<_> = [
        (e.identity, "identity"),
        (e.runtime, "runtime_packaging"),
        (e.storage, "storage_layout"),
        (e.ownership, "ownership"),
    ]
    .into_iter()
    .filter_map(|(yes, name)| yes.then_some(name))
    .collect();
    let points = u8::from(e.identity) * 4
        + u8::from(e.runtime) * 2
        + u8::from(e.storage) * 2
        + u8::from(e.ownership) * 3;
    let confidence = if e.excluded || e.conflict || signals.len() < 2 {
        "suppressed"
    } else if points >= 9 && signals.len() >= 3 && e.identity && e.ownership {
        "high"
    } else if points >= 5 && e.plausible_owner {
        "medium"
    } else {
        "low"
    };
    Score {
        points,
        confidence,
        signals,
        actionable: false,
    }
}
fn invalid() -> io::Error {
    io::Error::other("unsafe or incomplete metadata")
}
fn redirected(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
/// Check ancestors in root-to-leaf order before probing; missing paths remain absent.
pub fn safe_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid());
    }
    #[cfg(windows)]
    {
        use std::{os::windows::ffi::OsStrExt, path::Prefix};
        let Some(Component::Prefix(prefix)) = path.components().next() else {
            return Err(invalid());
        };
        if !matches!(prefix.kind(), Prefix::Disk(_)) {
            return Err(invalid());
        }
        let drive: Vec<u16> = prefix.as_os_str().encode_wide().chain([92, 0]).collect();
        // SAFETY: live terminated drive path; query before filesystem access.
        if unsafe { windows_sys::Win32::Storage::FileSystem::GetDriveTypeW(drive.as_ptr()) } != 3 {
            return Err(invalid());
        }
    }
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    for ancestor in ancestors {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if redirected(&meta) => return Err(invalid()),
            Ok(_) => (),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        }
    }
    Ok(())
}
#[derive(Debug, Serialize)]
pub struct Observation {
    pub signal_path: &'static str,
    pub state: &'static str,
    pub bytes: Option<u64>,
}
fn observe(root: &Path, relative: &'static str, directory: bool) -> Observation {
    let path = root.join(relative);
    let result = safe_path(&path).and_then(|()| fs::symlink_metadata(&path));
    match result {
        Ok(meta)
            if !redirected(&meta)
                && (if directory {
                    meta.is_dir()
                } else {
                    meta.is_file()
                }) =>
        {
            Observation {
                signal_path: relative,
                state: "present",
                bytes: (!directory).then_some(meta.len()),
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Observation {
            signal_path: relative,
            state: "absent",
            bytes: None,
        },
        _ => Observation {
            signal_path: relative,
            state: "unknown",
            bytes: None,
        },
    }
}
pub fn storage(root: &Path) -> (bool, Vec<Observation>) {
    let observations: Vec<_> = [
        ("Cookies", false),
        ("Network/Cookies", false),
        ("Local Storage", true),
        ("Session Storage", true),
        ("IndexedDB", true),
        ("Local State", false),
    ]
    .into_iter()
    .map(|(p, d)| observe(root, p, d))
    .collect();
    // Two cookie locations remain one artifact.
    let present = |i: usize| observations[i].state == "present";
    let cookies = present(0) || present(1);
    let count = usize::from(cookies) + (2..6).filter(|&i| present(i)).count();
    (count >= 3 && (cookies || present(4)), observations)
}
pub fn runtime(root: &Path) -> (bool, Vec<Observation>) {
    let observations = vec![
        observe(root, "resources/app.asar", false),
        observe(root, "resources/app", true),
    ];
    (
        observations.iter().any(|o| o.state == "present"),
        observations,
    )
}
pub fn excluded(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "everyout",
        "microsoft",
        "packages",
        "temp",
        "crashdumps",
        "application data",
        "windows",
        "edgewebview",
    ]
    .contains(&name.as_str())
        || [
            "everyout",
            "microsoft.aad.brokerplugin",
            "microsoft.accountscontrol",
            "microsoft.windows.cloudexperiencehost",
            "microsoft.windows.shellexperiencehost",
            "microsoft.win32webviewhost",
            "microsoft.windowsappruntime",
        ]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}
#[derive(Serialize)]
pub struct Candidate {
    pub id: String,
    pub root_class: &'static str,
    pub layout_index: usize,
    pub installation_state: &'static str,
    pub score: Score,
    pub observations: Vec<Observation>,
    pub limitations: Vec<&'static str>,
}
pub fn candidate(
    id: String,
    root_class: &'static str,
    layout_index: usize,
    root: &Path,
    install: Option<&Path>,
    mapped_package: bool,
) -> Candidate {
    let (storage, mut observations) = storage(root);
    let mut e = Evidence {
        storage,
        ..Default::default()
    };
    let installation_state = installation_state(install);
    let root_present = safe_path(root).is_ok()
        && fs::symlink_metadata(root).is_ok_and(|m| m.is_dir() && !redirected(&m));
    if let Some(install) = install
        && mapped_package
        && installation_state == "existing"
        && root_present
    {
        e.identity = true;
        e.ownership = true;
        e.plausible_owner = true;
        let (runtime, runtime_observations) = runtime(install);
        e.runtime = runtime;
        observations.extend(runtime_observations);
    }
    let mut limitations = vec!["identity is not authentication or a safe wipe scope"];
    if !e.identity {
        limitations.push("installation identity uncorroborated; registry value reads blocked");
    }
    if !e.ownership {
        limitations.push("exclusive root ownership unknown");
    }
    if observations.iter().any(|o| o.state == "unknown") {
        limitations.push("incomplete metadata coverage");
    }
    Candidate {
        id,
        root_class,
        layout_index,
        installation_state,
        score: score(e),
        observations,
        limitations,
    }
}

pub fn installation_state(install: Option<&Path>) -> &'static str {
    let Some(install) = install else {
        return "unknown";
    };
    if safe_path(install).is_err() {
        return "unknown";
    }
    match fs::symlink_metadata(install) {
        Ok(meta) if meta.is_dir() && !redirected(&meta) => "existing",
        Err(error) if error.kind() == io::ErrorKind::NotFound => "residue",
        _ => "unknown",
    }
}
