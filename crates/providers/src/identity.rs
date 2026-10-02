//! Unverified metadata signals only; no configuration or account payload reads.
//! Presence never establishes sign-in, active sync, or absence of a Sync chain.
use everyout_core_model::ProfileId;
use everyout_platform_windows::AllowedRoot;

pub(crate) const WARNING: &str = "Sync or automatic sign-in can recreate data or access after this wipe. Local deletion does not remove server data or guarantee a lasting sign-out.";

pub(crate) struct Observation {
    pub profile: ProfileId,
    pub summary: String,
}

/// Fixed research candidates, not a vendor/version identity-removal allowlist.
pub(crate) fn observe(root: &AllowedRoot, browser: &str, profiles: &[String]) -> Vec<Observation> {
    let signals: &[&str] = match browser {
        "chrome" | "edge" | "brave" | "opera" | "vivaldi" => {
            &["Sync Data", "Accounts", "Account Web Data"]
        }
        "firefox" => &["signedInUser.json"],
        _ => return vec![],
    };
    let mut result = vec![];
    for (index, profile) in profiles.iter().enumerate() {
        let id = ProfileId(format!("{browser}-profile-{index}"));
        for signal in signals {
            let path = if profile.is_empty() {
                signal.to_string()
            } else {
                format!("{profile}/{signal}")
            };
            // No recursion, parsing, content logging, or payload read handle.
            let state = match root.path(&path).and_then(|p| p.probe_shallow()) {
                Ok(metadata) if metadata.exists => "present",
                Ok(_) => "absent",
                Err(_) => "unknown",
            };
            result.push(Observation {
                profile: id.clone(),
                summary: format!("identity-sync-metadata: {}; {signal}={state}; unverified; sign-in=unknown; sync-active=unknown", id.0),
            });
        }
    }
    result
}
