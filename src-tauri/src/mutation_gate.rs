//! One admission boundary per desktop config, shared by apply and recovery.
use crate::dto::CommandError;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};
#[derive(Default)]
struct Gate {
    recovery: bool,
    validation: bool,
    wipe: bool,
}
#[derive(Clone)]
pub(crate) struct Admission(Arc<Mutex<Gate>>);
impl Admission {
    pub fn for_directory(path: &Path) -> Result<Self, CommandError> {
        static REGISTRY: OnceLock<Mutex<HashMap<PathBuf, Weak<Mutex<Gate>>>>> = OnceLock::new();
        let mut registry = REGISTRY
            .get_or_init(Default::default)
            .lock()
            .map_err(|_| CommandError::WorkerUnavailable)?;
        let gate = registry.entry(path.to_path_buf()).or_default();
        if let Some(gate) = gate.upgrade() {
            return Ok(Self(gate));
        }
        let new = Arc::new(Mutex::new(Gate::default()));
        *gate = Arc::downgrade(&new);
        Ok(Self(new))
    }
    pub fn begin_wipe(&self) -> Result<(), CommandError> {
        let mut gate = self.0.lock().map_err(|_| CommandError::WorkerUnavailable)?;
        if gate.recovery || gate.validation || gate.wipe {
            return Err(CommandError::Busy);
        }
        gate.wipe = true;
        Ok(())
    }
    pub fn end_wipe(&self) {
        if let Ok(mut gate) = self.0.lock() {
            gate.wipe = false;
        }
    }
    pub fn begin_validation(&self, recovery: bool) -> Result<(), CommandError> {
        let mut gate = self.0.lock().map_err(|_| CommandError::WorkerUnavailable)?;
        if gate.wipe || gate.validation || gate.recovery && !recovery {
            return Err(CommandError::Busy);
        }
        gate.validation = true;
        Ok(())
    }
    pub fn end_validation(&self) {
        if let Ok(mut gate) = self.0.lock() {
            gate.validation = false;
        }
    }
    pub fn recovery(&self, blocked: bool) {
        if let Ok(mut gate) = self.0.lock() {
            gate.recovery = blocked;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn shared_config_blocks_wipe_until_recovery_and_validation_finish() {
        let fixture = everyout_test_support::FixtureTree::empty().unwrap();
        let native = Admission::for_directory(fixture.path()).unwrap();
        let validation = Admission::for_directory(fixture.path()).unwrap();
        validation.recovery(true);
        assert!(native.begin_wipe().is_err());
        assert!(validation.begin_validation(false).is_err());
        validation.begin_validation(true).unwrap();
        validation.recovery(false);
        assert!(native.begin_wipe().is_err());
        validation.end_validation();
        native.begin_wipe().unwrap();
        assert!(validation.begin_validation(false).is_err());
        native.end_wipe();
        validation.begin_validation(false).unwrap();
        assert!(native.begin_wipe().is_err());
        validation.end_validation();
        native.begin_wipe().unwrap();
        native.end_wipe();
    }
}
