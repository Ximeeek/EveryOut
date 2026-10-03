//! Fixed gaming research scopes; citations do not establish logout completeness.
use crate::{ApplicationKind, CleaningMethod, Manifest, Ownership, Root};
use everyout_core_model::{ArtifactKind, Category, Scope};

pub fn valid_scope(m: &Manifest) -> bool {
    if m.application != Some(ApplicationKind::GamingLauncher)
        || m.category != Category::Application
        || m.identity.browser_id.is_some()
        || m.identity.package_id.is_some()
        || m.identity.installation_id.as_deref() != Some(m.id.as_str())
        || m.profiles.is_some()
        || m.extensions.is_some()
        || m.sources
            .as_ref()
            .is_none_or(|s| s.is_empty() || s.iter().any(|u| !u.starts_with("https://")))
        || !m
            .preserve
            .artifact_families
            .iter()
            .any(|f| f == "encryption-key-metadata")
    {
        return false;
    }
    let expected: &[(&str, &str)] = match m.id.as_str() {
        "steam" => &[
            ("installation", "Steam"),
            ("registry", "Software/Valve/Steam"),
        ],
        "epic-games-launcher" => &[("local", "EpicGamesLauncher")],
        "battle-net" => &[("roaming", "Battle.net")],
        "riot-client" => &[("local", "Riot Games/Riot Client")],
        "ea-app" => &[("local", "Electronic Arts/EA Desktop")],
        "ubisoft-connect" => &[("local", "Ubisoft Game Launcher")],
        "gog-galaxy" => &[
            ("local", "GOG.com/Galaxy"),
            ("registry", "Software/GOG.com/Galaxy"),
        ],
        _ => return false,
    };
    if m.roots.len() != expected.len()
        || m.roots
            .iter()
            .zip(expected)
            .any(|(root, (base, relative))| {
                let actual = match root {
                    Root::LocalAppData { .. } => "local",
                    Root::RoamingAppData { .. } => "roaming",
                    Root::Registry { .. } => "registry",
                    Root::ReviewedInstallation { .. } => "installation",
                    Root::Unresolved { .. } | Root::UserProfile { .. } => return true,
                };
                actual != *base || root.relative().replace('\\', "/") != *relative
            })
    {
        return false;
    }
    m.evidence.iter().all(|e| {
        e.source
            .as_ref()
            .is_none_or(|u| m.sources.as_ref().unwrap().contains(u))
    }) && m.session_locations.iter().all(|a| {
        let path = a.relative.replace('\\', "/");
        let allowed: &[(&str, ArtifactKind)] = match m.id.as_str() {
            "steam" => &[
                ("config/loginusers.vdf", ArtifactKind::File),
                ("config/config.vdf", ArtifactKind::File),
                ("ssfn", ArtifactKind::File),
                ("AutoLoginUser", ArtifactKind::RegistryValue),
                ("RememberPassword", ArtifactKind::RegistryValue),
            ],
            "epic-games-launcher" => &[
                (
                    "Saved/Config/WindowsEditor/GameUserSettings.ini",
                    ArtifactKind::File,
                ),
                ("Saved/webcache", ArtifactKind::Directory),
                ("Saved/webcache_4147", ArtifactKind::Directory),
                ("Saved/webcache_4430", ArtifactKind::Directory),
            ],
            "battle-net" => &[("Battle.net.config", ArtifactKind::File)],
            "riot-client" => &[
                ("Data/Cookies", ArtifactKind::Directory),
                ("Data/Sessions", ArtifactKind::Directory),
            ],
            "ea-app" => &[("CEF/BrowserCache/EADesktop/Cookies", ArtifactKind::File)],
            "ubisoft-connect" => &[
                ("ConnectSecureStorage.dat", ArtifactKind::File),
                ("user.dat", ArtifactKind::File),
            ],
            "gog-galaxy" => &[
                ("Configuration/config.json", ArtifactKind::File),
                ("refreshToken", ArtifactKind::RegistryValue),
            ],
            _ => return false,
        };
        let root = m.roots.iter().find(|r| r.id() == a.root);
        let registry = a.kind == ArtifactKind::RegistryValue;
        a.scope == Scope::OsUser
            && a.ownership == Ownership::Application
            && allowed.contains(&(path.as_str(), a.kind))
            && root.is_some_and(|r| matches!(r, Root::Registry { .. }) == registry)
            && a.evidence.as_ref().is_some_and(|e| !e.is_empty())
            && a.confidence
                .as_deref()
                .is_some_and(|c| matches!(c, "verified" | "unverified"))
            && (a.name_prefix.is_none()
                || (m.id == "steam" && path == "ssfn" && a.name_prefix.as_deref() == Some("ssfn")))
    }) && m.cleaning_methods.iter().all(|method| match method {
        CleaningMethod::DeleteFileFamily { companions, .. } => companions.is_empty(),
        CleaningMethod::DeleteDirectoryFamily { exclusions, .. } => exclusions.is_empty(),
        CleaningMethod::DeleteRegistryTarget { .. } => true,
        CleaningMethod::ExceptionAdapter { adapter_id, .. } => {
            m.id == "steam" && adapter_id == "steam-ssfn-files"
        }
        _ => false,
    })
}
