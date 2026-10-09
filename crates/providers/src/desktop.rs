//! Fixed desktop research scopes. Unknown locations grant no path authority.
use crate::{ApplicationKind, CleaningMethod, Manifest, Ownership, Root};
use everyout_core_model::*;

pub fn valid_scope(m: &Manifest) -> bool {
    if m.application != Some(ApplicationKind::DesktopClient)
        || m.category != Category::Application
        || m.identity.browser_id.is_some()
        || m.identity.package_id.is_some()
        || m.identity.installation_id.as_deref() != Some(m.id.as_str())
        || m.roots.len() != 1
        || m.profiles.is_some()
        || m.extensions.is_some()
        || m.sources
            .as_ref()
            .is_none_or(|s| s.is_empty() || s.iter().any(|u| !u.starts_with("https://")))
        || m.evidence.iter().any(|e| {
            e.source
                .as_ref()
                .is_none_or(|u| !m.sources.as_ref().unwrap().contains(u))
        })
        || m.risks.confirmations.is_empty()
    {
        return false;
    }
    let (base, root, targets): (&str, &str, &[(&str, ArtifactKind)]) = match m.id.as_str() {
        "discord" => (
            "roaming",
            "discord",
            &[("Local Storage", ArtifactKind::Directory)],
        ),
        "spotify" => ("roaming", "Spotify", &[("prefs", ArtifactKind::File)]),
        "slack" => (
            "roaming",
            "Slack",
            &[("Local Storage", ArtifactKind::Directory)],
        ),
        "microsoft-teams" => (
            "local",
            "Packages/MSTeams_8wekyb3d8bbwe",
            &[("LocalCache/Microsoft/MSTeams", ArtifactKind::Directory)],
        ),
        "telegram-desktop" => (
            "roaming",
            "Telegram Desktop",
            &[("tdata", ArtifactKind::Directory)],
        ),
        "signal-desktop" => (
            "roaming",
            "Signal",
            &[
                ("sql", ArtifactKind::Directory),
                ("attachments.noindex", ArtifactKind::Directory),
            ],
        ),
        "thunderbird" => (
            "roaming",
            "Thunderbird",
            &[("Profiles", ArtifactKind::Directory)],
        ),
        "ente-auth" => (
            "roaming",
            "Ente Technologies, Inc",
            &[("Ente Auth", ArtifactKind::Directory)],
        ),
        "winauth" => ("roaming", "WinAuth", &[("winauth.xml", ArtifactKind::File)]),
        "exodus" => (
            "roaming",
            "Exodus",
            &[("exodus.wallet", ArtifactKind::Directory)],
        ),
        "electrum" => (
            "roaming",
            "Electrum",
            &[("wallets", ArtifactKind::Directory)],
        ),
        "bitwarden" => ("roaming", "Bitwarden", &[("data.json", ArtifactKind::File)]),
        "whatsapp-desktop" | "outlook" | "proton-vpn" | "nordvpn" | "onepassword" => (
            "unresolved",
            "unresolved",
            &[("unresolved", ArtifactKind::Directory)],
        ),
        _ => return false,
    };
    let r = &m.roots[0];
    let actual = match r {
        Root::LocalAppData { .. } => "local",
        Root::RoamingAppData { .. } => "roaming",
        Root::Unresolved { .. } => "unresolved",
        _ => return false,
    };
    if actual != base || r.relative().replace('\\', "/") != root {
        return false;
    }
    let required: &[RiskFlag] = match m.id.as_str() {
        "signal-desktop" => &[
            RiskFlag::LocalOnlyDocuments,
            RiskFlag::DraftsOrOfflineMessages,
        ],
        "thunderbird" => &[
            RiskFlag::LocalOnlyDocuments,
            RiskFlag::DraftsOrOfflineMessages,
            RiskFlag::SavedPasswordsPasskeysAutofillHistory,
        ],
        "ente-auth" | "winauth" | "bitwarden" | "onepassword" => &[RiskFlag::VaultOr2faRecovery],
        "exodus" | "electrum" => &[RiskFlag::WalletOrKeyMaterial],
        _ => &[],
    };
    if required.iter().any(|f| !m.risks.flags.contains(f))
        || (!required.is_empty() && m.risks.permanent_data_loss != LossAssessment::Known)
        || !m
            .risks
            .confirmations
            .contains(&ConfirmationId(format!("review-{}-permanent-loss", m.id)))
        || (m.support == Support::Validated
            && (base == "unresolved"
                || m.confidence.level != Confidence::High
                || m.session_locations
                    .iter()
                    .any(|a| a.confidence.as_deref() != Some("verified"))))
    {
        return false;
    }
    m.session_locations.iter().all(|a| {
        a.root == r.id()
            && a.scope == Scope::OsUser
            && a.ownership == Ownership::Application
            && a.name_prefix.is_none()
            && targets.contains(&(a.relative.replace('\\', "/").as_str(), a.kind))
            && a.evidence.as_ref().is_some_and(|e| !e.is_empty())
            && matches!(a.confidence.as_deref(), Some("verified" | "unverified"))
    }) && m.cleaning_methods.iter().all(|method| {
        if base == "unresolved" {
            matches!(method, CleaningMethod::ExceptionAdapter { adapter_id, .. }
                if adapter_id == "unresolved-session-scope" && m.support == Support::Candidate)
        } else {
            match method {
                CleaningMethod::DeleteFileFamily { companions, .. } => companions.is_empty(),
                CleaningMethod::DeleteDirectoryFamily { exclusions, .. } => exclusions.is_empty(),
                CleaningMethod::ExceptionAdapter { adapter_id, .. } => {
                    m.id == "spotify"
                        && adapter_id == "spotify-saved-login-v1"
                        && m.support == Support::Candidate
                        && m.session_locations.len() == 1
                        && m.session_locations[0].method == method.id()
                }
                _ => false,
            }
        }
    })
}
