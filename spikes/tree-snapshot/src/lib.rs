//! Offline lab inventory. The capture path has no file-content reader.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub path: String,
    pub size: u64,
    pub modified_ns: Option<String>,
    pub created_ns: Option<String>,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub entries: Vec<Entry>,
}

#[derive(Debug, Serialize)]
pub struct Change {
    pub before: Entry,
    pub after: Entry,
}

#[derive(Debug, Serialize)]
pub struct Diff {
    pub added: Vec<Entry>,
    pub removed: Vec<Entry>,
    pub changed: Vec<Change>,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn redirected(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
    }
    #[cfg(not(windows))]
    {
        metadata.file_type().is_symlink()
    }
}

fn timestamp(time: io::Result<SystemTime>) -> Option<String> {
    time.ok()
        .map(|value| match value.duration_since(UNIX_EPOCH) {
            Ok(delta) => delta.as_nanos().to_string(),
            Err(error) => format!("-{}", error.duration().as_nanos()),
        })
}

fn checked_root(root: &Path) -> io::Result<PathBuf> {
    // Reject ambiguous traversal, network/device paths and redirected ancestors before walking.
    if root.components().any(|part| part == Component::ParentDir) {
        return Err(invalid("parent traversal is unsupported"));
    }
    let absolute = std::path::absolute(root)?;
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::path::Prefix;
        if !matches!(
            absolute.components().next(),
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_))
        ) {
            return Err(invalid("only local drive paths are supported"));
        }
        // A drive letter may be a mapped network share. Check before any filesystem I/O.
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn GetDriveTypeW(root: *const u16) -> u32;
        }
        let drive = absolute.components().next().unwrap().as_os_str();
        let drive_root: Vec<u16> = drive.encode_wide().chain([b'\\' as u16, 0]).collect();
        // SAFETY: drive_root is a live, NUL-terminated UTF-16 drive root.
        let drive_type = unsafe { GetDriveTypeW(drive_root.as_ptr()) };
        if !matches!(drive_type, 2 | 3 | 6) {
            return Err(invalid("network or unknown drive is unsupported"));
        }
    }
    for ancestor in absolute.ancestors() {
        if redirected(&fs::symlink_metadata(ancestor)?) {
            return Err(invalid("redirected root or ancestor is unsupported"));
        }
    }
    if !fs::symlink_metadata(&absolute)?.is_dir() {
        return Err(invalid("root must be a directory"));
    }
    Ok(absolute)
}

/// Validate the explicitly supplied metadata document location before diff opens it.
pub fn snapshot_path(path: &Path) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    checked_root(
        absolute
            .parent()
            .ok_or_else(|| invalid("missing snapshot parent"))?,
    )?;
    let metadata = fs::symlink_metadata(&absolute)?;
    if redirected(&metadata) || !metadata.is_file() {
        return Err(invalid(
            "snapshot must be a regular, nonredirected local file",
        ));
    }
    Ok(absolute)
}

/// Capture paths, sizes and timestamps only. All errors abort the complete snapshot.
pub fn capture(root: &Path) -> io::Result<Snapshot> {
    let root = checked_root(root)?;
    let mut entries = Vec::new();
    let mut pending = vec![(root.clone(), 0_usize)];
    while let Some((directory, depth)) = pending.pop() {
        if depth > 256 {
            return Err(invalid("tree depth limit exceeded"));
        }
        if redirected(&fs::symlink_metadata(&directory)?) {
            return Err(invalid("redirected directory is unsupported"));
        }
        for item in fs::read_dir(&directory)? {
            let path = item?.path();
            let metadata = fs::symlink_metadata(&path)?;
            if redirected(&metadata) || !(metadata.is_file() || metadata.is_dir()) {
                return Err(invalid("redirected or special entry is unsupported"));
            }
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| invalid("root mismatch"))?;
            let mut name = relative
                .to_str()
                .ok_or_else(|| invalid("non-Unicode path is unsupported"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if metadata.is_dir() {
                name.push('/');
                pending.push((path, depth + 1));
            }
            entries.push(Entry {
                path: name,
                size: if metadata.is_file() {
                    metadata.len()
                } else {
                    0
                },
                modified_ns: timestamp(metadata.modified()),
                created_ns: timestamp(metadata.created()),
            });
            if entries.len() > 1_000_000 {
                return Err(invalid("entry limit exceeded"));
            }
        }
    }
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let snapshot = Snapshot {
        version: 1,
        entries,
    };
    validate(&snapshot)?;
    Ok(snapshot)
}

pub fn validate(snapshot: &Snapshot) -> io::Result<()> {
    if snapshot.version != 1 || snapshot.entries.len() > 1_000_000 {
        return Err(invalid("unsupported snapshot version or size"));
    }
    let mut names = BTreeMap::new();
    for entry in &snapshot.entries {
        let name = entry.path.strip_suffix('/').unwrap_or(&entry.path);
        if name.is_empty()
            || name.contains(['\\', ':'])
            || name
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || names.insert(name, ()).is_some()
        {
            return Err(invalid("invalid or duplicate relative path"));
        }
        if entry.path.ends_with('/') && entry.size != 0 {
            return Err(invalid("directory size must be zero"));
        }
        for value in [&entry.modified_ns, &entry.created_ns]
            .into_iter()
            .flatten()
        {
            let digits = value.strip_prefix('-').unwrap_or(value);
            if digits.is_empty() || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
                return Err(invalid("invalid timestamp"));
            }
        }
    }
    Ok(())
}

/// Compare previously generated metadata JSON, never the source trees or payloads.
pub fn compare(before: &Snapshot, after: &Snapshot) -> io::Result<Diff> {
    validate(before)?;
    validate(after)?;
    let old: BTreeMap<_, _> = before
        .entries
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect();
    let new: BTreeMap<_, _> = after
        .entries
        .iter()
        .map(|entry| (&entry.path, entry))
        .collect();
    let mut diff = Diff {
        added: vec![],
        removed: vec![],
        changed: vec![],
    };
    for (path, entry) in &old {
        match new.get(path) {
            None => diff.removed.push((*entry).clone()),
            Some(current) if entry != current => diff.changed.push(Change {
                before: (*entry).clone(),
                after: (*current).clone(),
            }),
            _ => {}
        }
    }
    for (path, entry) in &new {
        if !old.contains_key(path) {
            diff.added.push((*entry).clone());
        }
    }
    Ok(diff)
}
