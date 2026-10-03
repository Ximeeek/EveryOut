use crate::{application::opaque, dto::*};
use std::{fs, io::Write, path::Path};

/// Export only the retained native projection. JavaScript cannot supply content or a path.
pub fn export(
    directory: &Path,
    report: &ReportDto,
    format: ExportFormat,
) -> Result<String, CommandError> {
    fs::create_dir_all(directory).map_err(|_| CommandError::ReportIo)?;
    let (extension, content) = match format {
        ExportFormat::Json => (
            "json",
            serde_json::to_string_pretty(report).map_err(|_| CommandError::ReportIo)?,
        ),
        ExportFormat::Text => ("txt", text(report)),
    };
    let mut temporary =
        tempfile::NamedTempFile::new_in(directory).map_err(|_| CommandError::ReportIo)?;
    temporary
        .write_all(content.as_bytes())
        .and_then(|()| temporary.as_file().sync_all())
        .map_err(|_| CommandError::ReportIo)?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CommandError::ReportIo)?
        .as_nanos();
    let name = format!("everyout-{timestamp}-{}.{}", opaque("report"), extension);
    let path = directory.join(&name);
    temporary
        .persist_noclobber(path)
        .map_err(|_| CommandError::ReportIo)?;
    Ok(format!("reports/{name}"))
}
fn text(report: &ReportDto) -> String {
    let mut output = format!("EveryOut local session report\nMode: {:?}; accounts: {:?}\nLocal effects only; Windows remains signed in. Sync or silent sign-in may restore access.\n", report.mode, report.account_mode);
    for account in &report.accounts {
        output.push_str(&format!("\nAccount: {}\n", account.account));
        for section in &account.sections {
            output.push_str(&format!("\n{:?}: {:?}\n", section.category, section.status));
            for warning in &section.warnings {
                output.push_str(&format!("Warning: {warning}\n"));
            }
            for item in &section.items {
                output.push_str(&format!(
                    "{}: {:?}; identity {:?}; sync {:?}; SSO {:?}\n",
                    item.instance, item.status, item.identity, item.sync, item.silent_sso
                ));
                for action in &item.actions {
                    output.push_str(&format!(
                        "  {}: {:?}; verification {:?}; bytes {:?}\n",
                        action.path, action.outcome, action.verification, action.bytes
                    ));
                    for issue in &action.issues {
                        output.push_str(&format!("  Issue: {issue}\n"));
                    }
                }
                output.push_str("What remains: preserved and unsupported data; remote sessions are not revoked.\n");
                for limitation in item.limitations.iter().chain(&item.issues) {
                    output.push_str(&format!("  {limitation}\n"));
                }
            }
        }
        for issue in account.limitations.iter().chain(&account.issues) {
            output.push_str(&format!("Account coverage: {issue}\n"));
        }
        if account.residual_hive {
            output.push_str("Temporary account hive remains; manual recovery is required.\n");
        }
    }
    for skipped in &report.skipped {
        output.push_str(&format!(
            "\nAccount: {}; {:?}; {}: Skipped by choice; cleanup not requested.\n",
            skipped.account, skipped.category, skipped.name
        ));
    }
    output
}
#[cfg(test)]
mod tests {
    use super::*;
    use everyout_core_model::{ExecutionMode, ProcessClosePolicy};
    #[test]
    fn exports_native_projection_without_content_or_destination_from_ui() {
        let fixture = everyout_test_support::FixtureTree::empty().unwrap();
        let report = ReportDto::current(&[], ProcessClosePolicy::Ask, ExecutionMode::Apply);
        for format in [ExportFormat::Json, ExportFormat::Text] {
            let name = export(fixture.path(), &report, format).unwrap();
            let content =
                fs::read_to_string(fixture.path().join(name.strip_prefix("reports/").unwrap()))
                    .unwrap();
            assert!(content.contains("not-requested") || content.contains("NotRequested"));
            assert!(!content.contains(fixture.path().to_str().unwrap()));
            if matches!(format, ExportFormat::Json) {
                assert!(serde_json::from_str::<serde_json::Value>(&content).is_ok());
            }
        }
    }
}
