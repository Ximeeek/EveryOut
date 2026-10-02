//! Steam exception operates only on caller-held capabilities and exact names.
//! Installation discovery remains blocked; this module cannot adopt absolute paths.
use crate::executor::ProcessGate;
use everyout_core_model::{ErrorKind, ProcessClosePolicy, Support};
use everyout_platform_windows::{
    AllowedRoot, Mutation, RegistryRoot, RegistryTarget, Result, SafePath,
};

pub const FILES: [&str; 2] = ["config/loginusers.vdf", "config/config.vdf"];
pub const VALUES: [&str; 2] = ["AutoLoginUser", "RememberPassword"];
pub const LOSS_CONFIRMATION: &str = "review-steam-login-trust-settings-offline-loss";

pub fn registry_targets() -> [RegistryTarget; 2] {
    VALUES.map(|name| RegistryTarget::Value(name.into()))
}

/// Fixed files plus non-directory ssfn* entries at one level only. No recursive glob.
pub struct SteamCleanup<'a> {
    root: &'a AllowedRoot,
    registry: &'a RegistryRoot,
    support: Support,
    processes: &'a dyn ProcessGate,
    guard_names: Vec<String>,
    files: Vec<SafePath>,
}
pub struct Outcome {
    /// Stable effect label; no opaque filenames or registry payloads enter reports.
    pub effect: &'static str,
    pub result: Result<Mutation>,
}
fn guard_names(root: &AllowedRoot) -> std::result::Result<Vec<String>, ErrorKind> {
    let (entries, omitted) = root.discovery_children().map_err(|e| e.kind)?;
    if omitted {
        return Err(ErrorKind::ScopeViolation);
    }
    Ok(entries
        .into_iter()
        .filter_map(|(name, directory)| {
            (!directory && name.to_ascii_lowercase().starts_with("ssfn")).then_some(name)
        })
        .collect())
}
impl<'a> SteamCleanup<'a> {
    /// The trusted caller must establish exclusive installation ownership, version
    /// coverage and support. Distributed Steam research never supplies validated support.
    pub fn discover(
        root: &'a AllowedRoot,
        registry: &'a RegistryRoot,
        support: Support,
        processes: &'a dyn ProcessGate,
    ) -> std::result::Result<Self, ErrorKind> {
        let names = guard_names(root)?;
        let files = FILES
            .iter()
            .copied()
            .chain(names.iter().map(String::as_str))
            .map(|name| root.path(name).map_err(|e| e.kind))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        processes.preview()?;
        Ok(Self {
            root,
            registry,
            support,
            processes,
            guard_names: names,
            files,
        })
    }
    /// Preview never closes processes or mutates files/registry.
    pub fn dry_run(&self) -> Vec<Outcome> {
        self.perform(true)
    }
    pub fn apply(
        &self,
        confirmed_loss: bool,
        policy: ProcessClosePolicy,
    ) -> std::result::Result<Vec<Outcome>, ErrorKind> {
        if self.support != Support::Validated {
            return Err(ErrorKind::Unsupported);
        }
        if !confirmed_loss {
            return Err(ErrorKind::ScopeViolation);
        }
        // Forced shutdown needs the engine's separate unsaved-work review. This
        // research adapter has no such approval capability and cannot request it.
        if policy != ProcessClosePolicy::Ask {
            return Err(ErrorKind::Unsupported);
        }
        if guard_names(self.root)? != self.guard_names {
            return Err(ErrorKind::StalePlan);
        }
        self.processes.close(policy)?;
        self.processes.revalidate()?;
        if guard_names(self.root)? != self.guard_names {
            return Err(ErrorKind::StalePlan);
        }
        Ok(self.perform(false))
    }
    fn perform(&self, dry_run: bool) -> Vec<Outcome> {
        let mut results = Vec::new();
        for (index, path) in self.files.iter().enumerate() {
            let effect = match index {
                0 => "remembered-accounts",
                1 => "mixed-client-configuration",
                _ => "steam-guard-machine-trust",
            };
            let result = if !dry_run {
                self.processes
                    .revalidate()
                    .map_err(|kind| everyout_platform_windows::PlatformError {
                        kind,
                        os_code: None,
                        applied: 0,
                    })
                    .and_then(|()| path.delete_file(false))
            } else {
                path.delete_file(true)
            };
            results.push(Outcome { effect, result });
        }
        for name in VALUES {
            let result = if !dry_run {
                self.processes
                    .revalidate()
                    .map_err(|kind| everyout_platform_windows::PlatformError {
                        kind,
                        os_code: None,
                        applied: 0,
                    })
                    .and_then(|()| self.registry.delete_value(name, false))
            } else {
                self.registry.delete_value(name, true)
            };
            results.push(Outcome {
                effect: "registry-auto-login",
                result,
            });
        }
        results
    }
}
