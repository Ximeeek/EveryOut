//! Bounded Restart Manager resource observation. Never shutdown/restart/force.
use super::*;
use crate::native::{runtime_child, wide, Handle};
use std::{ffi::OsStr, ptr};
use windows_sys::Win32::{Foundation::*, System::RestartManager::*};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_ticks: u64,
}
#[derive(Debug, Clone, Default)]
pub struct RuntimeUsage {
    pub processes: Vec<ProcessIdentity>,
    pub shared: bool,
    pub coverage: Vec<String>,
}
/// At most eight candidates, four files each, 32 resources per scan.
#[derive(Debug, Default)]
pub struct UsageBudget {
    candidates: usize,
    resources: usize,
}
/// Native read-only observer boundary; fixtures supply deterministic usage instead of live apps.
pub trait RuntimeObserver {
    fn observe(&mut self, candidate: &SafePath, snapshot: &Win32Snapshot) -> RuntimeUsage;
}
impl RuntimeObserver for UsageBudget {
    fn observe(&mut self, candidate: &SafePath, snapshot: &Win32Snapshot) -> RuntimeUsage {
        self.corroborate(candidate, snapshot)
    }
}
struct Session(u32);
impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            RmEndSession(self.0);
        }
    }
}
struct Resource {
    _handles: Vec<Handle>,
    path: PathBuf,
}
fn resource(root: &AllowedRoot, relative: &str) -> Result<Resource> {
    let parts = crate::components(relative)?;
    let mut handles = Vec::new();
    let mut parent = root.handle();
    for (i, part) in parts.iter().enumerate() {
        handles.push(runtime_child(
            parent,
            OsStr::new(part),
            i + 1 < parts.len(),
        )?);
        parent = handles.last().expect("resource component");
    }
    let path = native::metadata_path(handles.last().expect("file resource"))?;
    Ok(Resource {
        _handles: handles,
        path,
    })
}
impl UsageBudget {
    pub fn corroborate(&mut self, candidate: &SafePath, snapshot: &Win32Snapshot) -> RuntimeUsage {
        if self.candidates >= 8 || self.resources >= 32 {
            return RuntimeUsage {
                coverage: vec!["restart-manager-budget-exhausted".into()],
                ..Default::default()
            };
        }
        self.candidates += 1;
        let mut result = RuntimeUsage::default();
        let Ok(path) = candidate.canonical_metadata_path() else {
            result
                .coverage
                .push("restart-manager-candidate-unavailable".into());
            return result;
        };
        let directory = candidate.probe_shallow().is_ok_and(|m| m.is_directory);
        let Ok(root) = AllowedRoot::absolute(if directory {
            &path
        } else {
            path.parent().expect("candidate parent")
        }) else {
            return result;
        };
        let hints = if directory {
            vec![
                "LOCK",
                "leveldb/LOCK",
                "Local Storage/leveldb/LOCK",
                "Network/Cookies",
                "Cookies",
                "state.db",
                "config/loginusers.vdf",
                "loginusers.vdf",
                "EBWebView/Default/Network/Cookies",
                "Default/Network/Cookies",
            ]
        } else {
            vec![path.file_name().and_then(|n| n.to_str()).unwrap_or("")]
        };
        let resources: Vec<_> = hints
            .iter()
            .filter_map(|name| resource(&root, name).ok())
            .take(4.min(32 - self.resources))
            .collect();
        self.resources += resources.len();
        if resources.is_empty() {
            result
                .coverage
                .push("restart-manager-no-representative-files".into());
            return result;
        }
        let mut key = [0u16; 33];
        let mut handle = 0;
        if unsafe { RmStartSession(&mut handle, 0, key.as_mut_ptr()) } != ERROR_SUCCESS {
            result
                .coverage
                .push("restart-manager-session-unavailable".into());
            return result;
        }
        let session = Session(handle);
        let paths: Vec<_> = resources.iter().map(|r| wide(&r.path)).collect();
        let pointers: Vec<_> = paths.iter().map(|p| p.as_ptr()).collect();
        if unsafe {
            RmRegisterResources(
                session.0,
                pointers.len() as u32,
                pointers.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
            )
        } != ERROR_SUCCESS
        {
            result
                .coverage
                .push("restart-manager-register-unavailable".into());
            return result;
        }
        let mut needed = 0;
        let mut count = 0;
        let mut reasons = 0;
        let status = unsafe {
            RmGetList(
                session.0,
                &mut needed,
                &mut count,
                ptr::null_mut(),
                &mut reasons,
            )
        };
        if status == ERROR_SUCCESS && needed == 0 {
            return result;
        }
        if status != ERROR_MORE_DATA || needed > 64 {
            result
                .coverage
                .push("restart-manager-list-incomplete".into());
            return result;
        }
        let mut owners = vec![RM_PROCESS_INFO::default(); needed as usize];
        count = needed;
        if unsafe {
            RmGetList(
                session.0,
                &mut needed,
                &mut count,
                owners.as_mut_ptr(),
                &mut reasons,
            )
        } != ERROR_SUCCESS
        {
            result
                .coverage
                .push("restart-manager-list-incomplete".into());
            return result;
        }
        let Ok((observer_pid, observer_start)) = crate::process::observer_start_identity() else {
            result
                .coverage
                .push("restart-manager-observer-identity-unavailable".into());
            return result;
        };
        let observer = ProcessIdentity {
            pid: observer_pid,
            creation_ticks: observer_start,
        };
        for owner in owners.iter().take(count as usize) {
            let id = ProcessIdentity {
                pid: owner.Process.dwProcessId,
                creation_ticks: (u64::from(owner.Process.ProcessStartTime.dwHighDateTime) << 32)
                    | u64::from(owner.Process.ProcessStartTime.dwLowDateTime),
            };
            // Our read-only pin itself can appear in the resource list. Exclude precisely
            // this process object, never a basename, publisher, child or PID without start time.
            if id == observer {
                continue;
            }
            let app = snapshot
                .applications
                .iter()
                .find(|a| a.processes.contains(&id));
            let verified = app.is_some_and(|a| {
                crate::process::observe_current_user(id.pid)
                    .ok()
                    .flatten()
                    .is_some_and(|p| {
                        p.pid() == id.pid
                            && p.creation_ticks() == id.creation_ticks
                            && ExecutableBinding::capture(p.image_path())
                                .is_ok_and(|b| b.physical == a.executable.physical)
                            && a.executable.revalidate().is_ok()
                    })
            });
            if verified {
                result.processes.push(id);
            } else {
                result.shared = true;
                result
                    .coverage
                    .push("restart-manager-unrelated-or-unresolved-owner".into());
            }
        }
        if candidate.physical_chain().is_err()
            || resources
                .iter()
                .any(|r| r._handles.iter().any(|h| h.info().is_err()))
        {
            return RuntimeUsage {
                coverage: vec!["restart-manager-resource-binding-stale".into()],
                ..Default::default()
            };
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FixtureFolders, KnownFolder, RootResolver};
    #[test]
    fn representative_resources_pin_files_and_never_register_directories() {
        let fixture = FixtureFolders::create().unwrap();
        std::fs::create_dir(fixture.path().join("candidate")).unwrap();
        std::fs::create_dir(fixture.path().join("candidate/LOCK")).unwrap();
        std::fs::write(
            fixture.path().join("candidate/state.db"),
            b"unread synthetic bytes",
        )
        .unwrap();
        let root = fixture
            .resolve(KnownFolder::LocalAppData)
            .unwrap()
            .discovery_descendant("candidate")
            .unwrap();
        assert!(resource(&root, "LOCK").is_err());
        let bound = resource(&root, "state.db").unwrap();
        assert!(std::fs::rename(&bound.path, bound.path.with_extension("old")).is_err());
        assert_eq!(
            std::fs::read(&bound.path).unwrap(),
            b"unread synthetic bytes"
        );
    }
    #[test]
    fn empty_candidates_exhaust_a_fixed_budget_without_registering_appdata() {
        let fixture = FixtureFolders::create().unwrap();
        std::fs::create_dir(fixture.path().join("candidate")).unwrap();
        let candidate = fixture
            .resolve(KnownFolder::LocalAppData)
            .unwrap()
            .path("candidate")
            .unwrap();
        let mut budget = UsageBudget::default();
        for _ in 0..8 {
            let usage = budget.corroborate(&candidate, &Win32Snapshot::default());
            assert!(usage.processes.is_empty());
        }
        assert_eq!(budget.resources, 0);
        assert_eq!(budget.candidates, 8);
        assert!(budget
            .corroborate(&candidate, &Win32Snapshot::default())
            .coverage
            .iter()
            .any(|c| c == "restart-manager-budget-exhausted"));
    }
}
