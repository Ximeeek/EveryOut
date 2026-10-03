use crate::dto::{CommandError, Settings};
use std::{fs, io::Write, path::PathBuf};

/// Only a host-resolved app-config directory (or an owned fixture in tests).
pub struct SettingsStore {
    path: PathBuf,
}
impl SettingsStore {
    pub fn catalog_directory(&self) -> Result<PathBuf, CommandError> {
        let parent = self.path.parent().ok_or(CommandError::SettingsIo)?;
        fs::create_dir_all(parent).map_err(|_| CommandError::SettingsIo)?;
        Ok(parent.join("catalog-v1"))
    }
    pub fn new(directory: PathBuf) -> Self {
        Self {
            path: directory.join("settings.json"),
        }
    }
    pub fn reports_directory(&self) -> Result<PathBuf, CommandError> {
        Ok(self
            .path
            .parent()
            .ok_or(CommandError::ReportIo)?
            .join("reports"))
    }
    pub fn load(&self) -> Result<Settings, CommandError> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| CommandError::SettingsIo),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Settings::default()),
            Err(_) => Err(CommandError::SettingsIo),
        }
    }
    pub fn save(&self, settings: &Settings) -> Result<(), CommandError> {
        fs::create_dir_all(self.path.parent().ok_or(CommandError::SettingsIo)?)
            .map_err(|_| CommandError::SettingsIo)?;
        // A completed write is required before the in-memory choice changes.
        let bytes = serde_json::to_vec_pretty(settings).map_err(|_| CommandError::SettingsIo)?;
        let mut temporary =
            tempfile::NamedTempFile::new_in(self.path.parent().ok_or(CommandError::SettingsIo)?)
                .map_err(|_| CommandError::SettingsIo)?;
        temporary
            .write_all(&bytes)
            .and_then(|()| temporary.as_file().sync_all())
            .map_err(|_| CommandError::SettingsIo)?;
        temporary
            .persist(&self.path)
            .map_err(|_| CommandError::SettingsIo)?;
        Ok(())
    }
}
