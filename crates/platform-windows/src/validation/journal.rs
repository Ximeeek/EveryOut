use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
};
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, FILE_FLAG_OPEN_REPARSE_POINT, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

/// Config metadata only. The retained directory chain rejects ancestor reparses
/// and prevents replacement while the atomic, write-through journal is committed.
pub struct JournalStore {
    directory: PathBuf,
    _root: AllowedRoot,
}
impl JournalStore {
    pub fn open(directory: &Path) -> Result<Self> {
        // The parent must already be a trusted application config directory.
        let parent = directory
            .parent()
            .ok_or_else(|| error(ErrorKind::ScopeViolation))?;
        let _parent = AllowedRoot::absolute(parent)?;
        match fs::create_dir(directory) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(error(ErrorKind::Io)),
        }
        let root = AllowedRoot::absolute(directory)?;
        Ok(Self {
            directory: root.metadata_path()?,
            _root: root,
        })
    }
    fn path(&self, id: &str, extension: &str) -> Result<PathBuf> {
        if id.len() != 32 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(error(ErrorKind::ScopeViolation));
        }
        Ok(self.directory.join(format!("{id}.{extension}")))
    }
    fn write<T: serde::Serialize>(&self, id: &str, extension: &str, value: &T) -> Result<()> {
        self._root.metadata_path()?;
        let path = self.path(id, extension)?;
        let bytes = serde_json::to_vec_pretty(value).map_err(|_| error(ErrorKind::Io))?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err(error(ErrorKind::Unsupported));
        }
        let mut file =
            tempfile::NamedTempFile::new_in(&self.directory).map_err(|_| error(ErrorKind::Io))?;
        file.write_all(&bytes)
            .and_then(|_| file.as_file().sync_all())
            .map_err(|_| error(ErrorKind::Io))?;
        // Close the flushed temporary file before replacement. A retained write
        // handle can prolong Windows/filter-driver sharing conflicts on rename.
        let temporary = file.into_temp_path();
        let source = native::wide(&temporary);
        let target = native::wide(&path);
        // Same-volume atomic replacement for metadata only, durably flushed before
        // return. COPY_ALLOWED is intentionally absent. Payloads never enter here.
        for attempt in 0..=10 {
            self._root.metadata_path()?;
            if let Ok(m) = fs::symlink_metadata(&path) {
                if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    return Err(error(ErrorKind::ScopeViolation));
                }
            }
            if unsafe {
                MoveFileExW(
                    source.as_ptr(),
                    target.as_ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            } != 0
            {
                return Ok(());
            }
            let failure = native::last_error();
            if attempt == 10 || !matches!(failure.kind, ErrorKind::Locked | ErrorKind::AccessDenied)
            {
                return Err(failure);
            }
            // Metadata replacement only. The caller must not advance to any
            // payload mutation until this durable write succeeds.
            thread::sleep(Duration::from_millis(25));
        }
        unreachable!()
    }
    pub fn save(&self, journal: &ValidationJournal) -> Result<()> {
        self.write(&journal.session_id, "journal", journal)
    }
    pub fn save_rule(&self, rule: &LocalValidatedRule) -> Result<()> {
        if !rule.qualified() {
            return Err(error(ErrorKind::Unsupported));
        }
        self.write(&rule.id, "rule", rule)
    }
    pub fn mark_stale(&self, id: &str) -> Result<()> {
        let mut rule = self
            .rules()?
            .into_iter()
            .find(|r| r.id == id)
            .ok_or_else(|| error(ErrorKind::StalePlan))?;
        rule.stale = true;
        self.write(id, "rule", &rule)
    }
    fn load<T: serde::de::DeserializeOwned>(&self, extension: &str) -> Result<Vec<T>> {
        self._root.metadata_path()?;
        let mut result = vec![];
        let entries = fs::read_dir(&self.directory).map_err(|_| error(ErrorKind::Io))?;
        for (i, entry) in entries.enumerate() {
            if i >= 512 {
                return Err(error(ErrorKind::Unsupported));
            }
            let path = entry.map_err(|_| error(ErrorKind::Io))?.path();
            if !path.extension().is_some_and(|e| e == extension) {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| error(ErrorKind::ScopeViolation))?;
            self.path(stem, extension)?;
            let metadata = fs::symlink_metadata(&path).map_err(|_| error(ErrorKind::Io))?;
            if !metadata.is_file()
                || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
                || metadata.len() > 4 * 1024 * 1024
            {
                return Err(error(ErrorKind::ScopeViolation));
            }
            let mut file = fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(|_| error(ErrorKind::Io))?;
            if file
                .metadata()
                .map_err(|_| error(ErrorKind::Io))?
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT
                != 0
            {
                return Err(error(ErrorKind::ScopeViolation));
            }
            let mut bytes = vec![];
            Read::by_ref(&mut file)
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| error(ErrorKind::Io))?;
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(error(ErrorKind::Unsupported));
            }
            result.push(serde_json::from_slice(&bytes).map_err(|_| error(ErrorKind::Io))?);
        }
        Ok(result)
    }
    pub fn journals(&self) -> Result<Vec<ValidationJournal>> {
        self.load("journal")
    }
    pub fn rules(&self) -> Result<Vec<LocalValidatedRule>> {
        self.load("rule")
    }
    pub fn pending(&self) -> Result<bool> {
        Ok(self
            .journals()?
            .iter()
            .any(|j| j.stage != JournalStage::Completed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "00000000000000000000000000000000";

    #[test]
    fn atomic_metadata_write_waits_for_temporary_reader_and_preserves_old_on_failure() {
        let directory = tempfile::tempdir().unwrap();
        let store = JournalStore::open(&directory.path().join("validation")).unwrap();
        store.write(ID, "rule", &vec![1u8]).unwrap();
        let path = store.path(ID, "rule").unwrap();
        let reader = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .open(&path)
            .unwrap();
        assert!(store.write(ID, "rule", &vec![2u8]).is_err());
        assert_eq!(store.load::<Vec<u8>>("rule").unwrap(), vec![vec![1]]);
        let release = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            drop(reader);
        });
        store.write(ID, "rule", &vec![3u8]).unwrap();
        release.join().unwrap();
        assert_eq!(store.load::<Vec<u8>>("rule").unwrap(), vec![vec![3]]);
    }
}
