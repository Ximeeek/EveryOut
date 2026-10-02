//! Reviewed profiles.ini adapter: only ProfileN Path/IsRelative fields are retained.
//! No prefs, account, extension, session or database payload is parsed.
#[cfg(any(windows, test))]
use everyout_core_model::ErrorKind;
#[cfg(any(windows, test))]
use std::collections::HashSet;

pub(crate) const ADAPTER: &str = "firefox-profiles-ini";

#[cfg(any(windows, test))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Location {
    pub path: String,
    pub relative: bool,
}

#[cfg(any(windows, test))]
pub(crate) fn locations(input: &str) -> Result<Vec<Location>, ErrorKind> {
    if input.len() > 64 * 1024 || input.contains('\0') {
        return Err(ErrorKind::ScopeViolation);
    }
    let mut result = Vec::new();
    let mut sections = HashSet::new();
    let mut profile = false;
    let mut path = None;
    let mut relative = None;
    let finish = |profile: bool,
                  path: &mut Option<String>,
                  relative: &mut Option<bool>,
                  result: &mut Vec<Location>|
     -> Result<(), ErrorKind> {
        if profile {
            result.push(Location {
                path: path
                    .take()
                    .filter(|p| !p.is_empty())
                    .ok_or(ErrorKind::ScopeViolation)?,
                relative: relative.take().ok_or(ErrorKind::ScopeViolation)?,
            });
            if result.len() > 100 {
                return Err(ErrorKind::ScopeViolation);
            }
        }
        Ok(())
    };
    for line in input.trim_start_matches('\u{feff}').lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with([';', '#']) {
            continue;
        }
        if line.starts_with('[') {
            finish(profile, &mut path, &mut relative, &mut result)?;
            let section = line
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .ok_or(ErrorKind::ScopeViolation)?;
            profile = section
                .strip_prefix("Profile")
                .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()));
            if profile && !sections.insert(section) {
                return Err(ErrorKind::ScopeViolation);
            }
            continue;
        }
        if !profile {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(ErrorKind::ScopeViolation)?;
        match key.trim() {
            "Path" => {
                if path.replace(value.trim().to_owned()).is_some() {
                    return Err(ErrorKind::ScopeViolation);
                }
            }
            "IsRelative" => {
                let value = match value.trim() {
                    "1" => true,
                    "0" => false,
                    _ => return Err(ErrorKind::ScopeViolation),
                };
                if relative.replace(value).is_some() {
                    return Err(ErrorKind::ScopeViolation);
                }
            }
            _ => {} // Names, defaults and install/account metadata are not retained.
        }
    }
    finish(profile, &mut path, &mut relative, &mut result)?;
    if result.is_empty() {
        return Err(ErrorKind::ScopeViolation);
    }
    Ok(result)
}

#[cfg(windows)]
pub(crate) fn discover(
    root: &everyout_platform_windows::AllowedRoot,
) -> Result<Vec<String>, ErrorKind> {
    let input = root.firefox_profiles_ini().map_err(|e| e.kind)?;
    let mut paths = Vec::new();
    let mut chains: Vec<Vec<everyout_platform_windows::PhysicalIdentity>> = Vec::new();
    for location in locations(&input)? {
        let path = if location.relative {
            location.path.replace('\\', "/")
        } else {
            root.firefox_relative_profile(&location.path)
                .map_err(|e| e.kind)?
        };
        let candidate = root.path(&path).map_err(|e| e.kind)?;
        let metadata = candidate.probe_shallow().map_err(|e| e.kind)?;
        if !metadata.exists || !metadata.is_directory {
            return Err(ErrorKind::ScopeViolation);
        }
        let chain = candidate
            .physical_chain()
            .map_err(|e| e.kind)?
            .ok_or(ErrorKind::StalePlan)?;
        if chains.contains(&chain) {
            continue;
        }
        if chains
            .iter()
            .any(|other| other.starts_with(&chain) || chain.starts_with(other))
        {
            return Err(ErrorKind::OwnershipConflict);
        }
        chains.push(chain);
        paths.push(path);
    }
    paths.sort_by_key(|p| p.to_lowercase());
    Ok(paths)
}

pub(crate) fn extension_id(id: &str) -> bool {
    if let Some(guid) = id.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
        return guid.len() == 36
            && guid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            });
    }
    let Some((name, domain)) = id.split_once('@') else {
        return false;
    };
    !domain.is_empty()
        && name.len() + domain.len() <= 254
        && name
            .bytes()
            .chain(domain.bytes())
            .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_location_fields_are_retained_including_additional_profiles() {
        let input = "\u{feff}[General]\nStartWithLastProfile=1\n[Profile0]\nName=ignored\nDefault=1\nPath=Profiles/a.default\nIsRelative=1\n[InstallABC]\nDefault=ignored\n[Profile2]\nPath=C:\\fixture\\extra\nIsRelative=0\n";
        assert_eq!(
            locations(input).unwrap(),
            vec![
                Location {
                    path: "Profiles/a.default".into(),
                    relative: true
                },
                Location {
                    path: "C:\\fixture\\extra".into(),
                    relative: false
                },
            ]
        );
    }
    #[test]
    fn malformed_ambiguous_or_unbounded_configuration_is_refused() {
        for input in [
            "",
            "[Profile0]\nPath=x",
            "[Profile0]\nPath=x\nIsRelative=2",
            "[Profile0]\nPath=x\nPath=y\nIsRelative=1",
            "[Profile0]\nPath=x\nIsRelative=1\n[Profile0]\nPath=y\nIsRelative=1",
            "[Profile0]\nPath=x\0\nIsRelative=1",
        ] {
            assert_eq!(locations(input), Err(ErrorKind::ScopeViolation));
        }
        assert!(locations(&"x".repeat(65537)).is_err());
        let input: String = (0..101)
            .map(|i| format!("[Profile{i}]\nPath=Profiles/p{i}\nIsRelative=1\n"))
            .collect();
        assert!(locations(&input).is_err());
    }
    #[test]
    fn gecko_ids_are_single_bounded_components() {
        for id in [
            "{446900e4-71c2-419f-a6a7-df9c091e268b}",
            "authenticator@mymindstorm",
            "webextension@metamask.io",
            "@example",
        ] {
            assert!(extension_id(id));
        }
        for id in ["../outside@x", "a@b@c", "{bad}", "a@:x", "a@", "a/b@x"] {
            assert!(!extension_id(id));
        }
    }
}
