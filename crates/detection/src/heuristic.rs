use everyout_core_model::Confidence;
use serde::Serialize;

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Score {
    pub points: u8,
    pub confidence: Option<Confidence>,
    pub signals: Vec<String>,
}
/// UNVERIFIED thresholds copied from architecture 03, not calibrated probabilities.
/// Independent families count once; missing identity/ownership cannot pass high.
pub fn score(e: Evidence) -> Score {
    let signals: Vec<_> = [
        (e.identity, "identity"),
        (e.runtime, "runtime-packaging"),
        (e.storage, "storage-layout"),
        (e.ownership, "ownership"),
    ]
    .into_iter()
    .filter(|(present, _)| *present)
    .map(|(_, signal)| signal.to_owned())
    .collect();
    let points = u8::from(e.identity) * 4
        + u8::from(e.runtime) * 2
        + u8::from(e.storage) * 2
        + u8::from(e.ownership) * 3;
    let confidence = if e.excluded || signals.len() < 2 {
        None
    } else if e.conflict {
        Some(Confidence::Low)
    } else if points >= 9 && signals.len() >= 3 && e.identity && e.ownership {
        Some(Confidence::High)
    } else if points >= 5 && e.plausible_owner {
        Some(Confidence::Medium)
    } else {
        Some(Confidence::Low)
    };
    Score {
        points,
        confidence,
        signals,
    }
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
