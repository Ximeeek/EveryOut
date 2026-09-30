//! Metadata only: no credential API, file content reader or mutation operations.
use serde::Serialize;
use std::{fs, io, path::Path};

pub fn microsoft_target(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    [
        "microsoftaccount:",
        "windowslive:",
        "microsoftoffice",
        "msteams",
        "onedrive",
        "adal:",
        "msal:",
        "sso_pop_",
    ]
    .iter()
    .any(|pattern| lower.contains(pattern))
}

/// cmdkey is localized and not a structured API. Only reviewed target labels are supported.
/// Unknown layouts fail closed rather than claiming that no credentials exist.
pub fn parse_targets(output: &str) -> Result<Vec<String>, &'static str> {
    let mut header = false;
    let mut empty_marker = false;
    let mut target_count = 0;
    let mut targets = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        // English and Polish fixtures; other locales require a reviewed fixture first.
        if [
            "Currently stored credentials:",
            "Aktualnie przechowywane poświadczenia:",
        ]
        .contains(&line)
        {
            header = true;
        }
        if ["* NONE *", "* BRAK *"].contains(&line) {
            empty_marker = true;
            continue;
        }
        if let Some((label, target)) = line.split_once(':')
            && ["Target", "Obiekt docelowy"].contains(&label.trim())
        {
            target_count += 1;
            let target = target.trim();
            if target.is_empty() {
                return Err("empty target");
            }
            if microsoft_target(target) {
                targets.push(target.to_owned());
            }
        }
    }
    if target_count == 0 && !(header && empty_marker) {
        return Err("unsupported cmdkey layout");
    }
    if target_count > 0 && empty_marker {
        return Err("inconsistent cmdkey layout");
    }
    targets.sort();
    targets.dedup();
    Ok(targets)
}

#[derive(Debug, Serialize)]
pub struct DirectorySummary {
    pub store: &'static str,
    pub state: &'static str,
    pub bytes: Option<u64>,
    pub files: Option<u64>,
}

fn reparse(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

fn safe_ancestors(path: &Path) -> io::Result<()> {
    for ancestor in path.ancestors() {
        let meta = fs::symlink_metadata(ancestor)?;
        if reparse(&meta) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
    }
    Ok(())
}

fn sum(path: &Path, depth: usize, entries: &mut u64) -> io::Result<(u64, u64)> {
    if depth > 128 || *entries >= 100_000 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    *entries += 1;
    let meta = fs::symlink_metadata(path)?;
    if reparse(&meta) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if meta.is_file() {
        return Ok((meta.len(), 1));
    }
    if !meta.is_dir() {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (mut bytes, mut files) = (0u64, 0u64);
    for item in fs::read_dir(path)? {
        let (size, count) = sum(&item?.path(), depth + 1, entries)?;
        bytes = bytes.checked_add(size).ok_or(io::ErrorKind::InvalidData)?;
        files += count;
    }
    Ok((bytes, files))
}

pub fn directory_summary(store: &'static str, root: &Path) -> DirectorySummary {
    let result = safe_ancestors(root).and_then(|()| sum(root, 0, &mut 0));
    let (state, bytes, files) = match result {
        Ok((bytes, files)) => ("present", Some(bytes), Some(files)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => ("missing_or_changed", None, None),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            ("access_denied", None, None)
        }
        Err(_) => ("unsafe_or_incomplete", None, None),
    };
    DirectorySummary {
        store,
        state,
        bytes,
        files,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filters_targets_without_username_or_other_fields() {
        let input = "Currently stored credentials:\n Target: LegacyGeneric:target=MicrosoftAccount:user=test@example.invalid\n User: DO_NOT_EXPORT\n Target: Domain:target=server\n Target: LegacyGeneric:target=MicrosoftOffice16_Data:fixture\n";
        let targets = parse_targets(input).unwrap();
        assert_eq!(targets.len(), 2);
        assert!(
            !targets
                .iter()
                .any(|t| t.contains("DO_NOT_EXPORT") || t.contains("server"))
        );
    }
    #[test]
    fn handles_polish_unicode_and_deduplicates() {
        let text = "Aktualnie przechowywane poświadczenia:\n Obiekt docelowy: WindowsLive:target=żółć\n Obiekt docelowy: WindowsLive:target=żółć";
        assert_eq!(
            parse_targets(text).unwrap(),
            vec!["WindowsLive:target=żółć"]
        );
    }
    #[test]
    fn unsupported_layout_and_empty_target_are_errors() {
        assert!(parse_targets("Unrecognized localized output").is_err());
        assert!(parse_targets("Target: ").is_err());
        assert!(parse_targets("").is_err());
        assert!(parse_targets("Currently stored credentials:").is_err());
        assert!(
            parse_targets("Currently stored credentials:\n Cible: MicrosoftOffice_fixture")
                .is_err()
        );
        assert!(parse_targets("Target: MicrosoftOffice_fixture\n* NONE *").is_err());
        assert!(
            parse_targets("Currently stored credentials:\n* NONE *")
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn matches_are_candidates_only() {
        assert!(microsoft_target(
            "LegacyGeneric:target=mIcRoSoFtOfFiCe16_fixture"
        ));
        assert!(!microsoft_target("git:https://example.invalid"));
        assert!(!microsoft_target("Microsoft unrelated"));
    }
}
