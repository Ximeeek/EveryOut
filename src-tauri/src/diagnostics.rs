//! Bounded development diagnostics. Session contents and account identities are never logged.
use crate::dto::{ReportDto, WipeEvent};

#[cfg(debug_assertions)]
mod dev {
    use super::*;
    use std::{
        io::Write,
        path::PathBuf,
        sync::{Mutex, OnceLock},
    };

    static LOG: OnceLock<Mutex<PathBuf>> = OnceLock::new();
    const MAX_BYTES: u64 = 4 * 1024 * 1024;

    pub fn initialize(directory: &std::path::Path) {
        let directory = directory.join("dev-logs");
        if std::fs::create_dir_all(&directory).is_ok() {
            let path = directory.join("cleanup.jsonl");
            eprintln!("EveryOut development diagnostics: {}", path.display());
            let _ = LOG.set(Mutex::new(path));
        }
    }

    pub fn record(event: &str, details: serde_json::Value) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let line =
            serde_json::json!({"timestamp_ms": timestamp, "event": event, "details": details});
        eprintln!("[EveryOut dev] {line}");
        if let Some(path) = LOG.get().and_then(|log| log.lock().ok()) {
            let truncate = std::fs::metadata(&*path).is_ok_and(|m| m.len() >= MAX_BYTES);
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .append(!truncate)
                .truncate(truncate)
                .open(&*path)
            {
                let _ = writeln!(file, "{line}");
            }
        }
    }

    pub fn report(event: &str, report: &ReportDto) {
        let items: Vec<_> = report.accounts.iter().flat_map(|a| &a.sections)
            .flat_map(|s| &s.items).map(|item| serde_json::json!({
                "provider": item.provider, "status": item.status,
                "process_count": item.processes.len(), "issues": item.issues,
                "limitations": item.limitations,
                "authentication": item.authentication,
                "decision": item.decision,
                "actions": item.actions.iter().enumerate().map(|(index, action)| serde_json::json!({
                    "index": index, "outcome": action.outcome,
                    "verification": action.verification, "locked": action.locked,
                    "issues": action.issues,
                })).collect::<Vec<_>>(),
            })).collect();
        record(
            event,
            serde_json::json!({
                "mode": report.mode, "account_mode": report.account_mode,
                "process_policy": report.process_close_policy, "items": items,
            }),
        );
    }
}

pub fn initialize(directory: &std::path::Path) {
    #[cfg(debug_assertions)]
    dev::initialize(directory);
    #[cfg(not(debug_assertions))]
    let _ = directory;
}

pub fn record(event: &str, details: serde_json::Value) {
    #[cfg(debug_assertions)]
    dev::record(event, details);
    #[cfg(not(debug_assertions))]
    let _ = (event, details);
}

pub fn report(event: &str, report: &ReportDto) {
    #[cfg(debug_assertions)]
    dev::report(event, report);
    #[cfg(not(debug_assertions))]
    let _ = (event, report);
}

pub fn wipe_event(event: &WipeEvent) {
    #[cfg(debug_assertions)]
    match event {
        WipeEvent::Progress {
            stage, category, ..
        } => record(
            "cleanup-stage",
            serde_json::json!({"stage": stage, "category": category}),
        ),
        WipeEvent::Item { item, .. } => record(
            "cleanup-item",
            serde_json::json!({
                "provider": item.provider, "status": item.status,
                "issues": item.issues,
                "actions": item.actions.iter().map(|a| serde_json::json!({
                    "outcome": a.outcome, "verification": a.verification,
                    "locked": a.locked, "issues": a.issues,
                })).collect::<Vec<_>>(),
            }),
        ),
        WipeEvent::Finished { report: result, .. } => report("cleanup-finished", result),
        WipeEvent::Failed { error, .. } => {
            record("cleanup-failed", serde_json::json!({"error": error}))
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = event;
}
