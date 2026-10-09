//! Non-executable research providers. Names and documented locations grant no authority.
use crate::{CleaningMethod, Manifest, Ownership, Root};
use everyout_core_model::*;

pub const IDS: [&str; 12] = [
    "microsoft-credentials",
    "tokenbroker",
    "identitycache",
    "oneauth",
    "git-credentials",
    "github-cli",
    "npm",
    "docker",
    "azure-cli",
    "aws-cli",
    "gcloud",
    "kubectl",
];

/// These codes are stable, public explanations, never credential target names.
pub fn blocker(id: &str) -> Option<&'static str> {
    Some(match id {
        "microsoft-credentials" => "windows-sign-in-ownership-unproven",
        "tokenbroker" | "identitycache" | "oneauth" => "s5-broker-cache-deletion-unsupported",
        "git-credentials" | "docker" => "credential-helper-and-target-scope-unreviewed",
        "github-cli" | "azure-cli" | "aws-cli" => {
            "cli-offline-version-and-account-scope-unreviewed"
        }
        "npm" | "gcloud" => "remote-revocation-prohibited-in-v1",
        "kubectl" => "mixed-credential-and-key-store-preservation-unreviewed",
        _ => return None,
    })
}

pub fn refusal_reason(id: &str) -> Option<&'static str> {
    Some(match id {
        "npm" => "npm logout may invalidate a token on the registry server; V1 requires offline local operations and prohibits remote revocation.",
        "gcloud" => "gcloud auth revoke revokes user credentials on authorization servers; V1 cannot invoke it or infer a local-only account type by reading credentials.",
        "microsoft-credentials" => "An exact target name does not prove app-only ownership or exclusion of the Windows sign-in identity. S5 ownership evidence is missing.",
        "tokenbroker" | "identitycache" | "oneauth" => "Direct broker-cache deletion has no reviewed supported contract. S5 and Windows-sign-in/shared-owner preservation evidence are required.",
        "git-credentials" | "docker" => "Configured credential helpers and exact target ownership have not been reviewed for offline, secret-free execution. No broad-store fallback is allowed.",
        "github-cli" | "azure-cli" | "aws-cli" => "A documented local logout effect does not validate the installed version, account scope, environment overrides or helper/telemetry behavior. No offline adapter has been reviewed.",
        "kubectl" => "There is no generic logout. Kubeconfig mixes credentials, certificates and contexts and can invoke plugins; preservation and local target scope are unresolved.",
        _ => return None,
    })
}

/// Candidate-only allowlist. Promotion needs a separately reviewed implementation;
/// changing manifest flags or replacing an unresolved root can never activate it.
pub fn valid_scope(m: &Manifest) -> bool {
    let Some(reason) = blocker(&m.id) else {
        return false;
    };
    m.category == Category::WindowsMicrosoftAndDevTools
        && m.support == Support::Candidate
        && m.application.is_none()
        && m.profiles.is_none()
        && m.extensions.is_none()
        && m.identity.installation_id.as_deref() == Some(m.id.as_str())
        && m.identity.browser_id.is_none()
        && m.identity.package_id.is_none()
        && m.identity.process_names.is_empty()
        && m.roots.len() == 1
        && matches!(&m.roots[0], Root::Unresolved { id, scope: Scope::OsUser, owner }
            if id == "data" && owner == &m.id)
        && m.session_locations.len() == 1
        && m.session_locations.iter().all(|a| {
            a.id == "unresolved-session"
                && a.root == "data"
                && a.relative == "unresolved"
                && a.scope == Scope::OsUser
                && a.kind == ArtifactKind::Directory
                && a.method == "blocked-windows-dev"
                && a.ownership
                    == if IDS[..4].contains(&m.id.as_str()) {
                        Ownership::SharedIdentity
                    } else {
                        Ownership::DeveloperTool
                    }
                && a.confidence.as_deref() == Some("unverified")
        })
        && m.cleaning_methods.len() == 1
        && matches!(&m.cleaning_methods[0], CleaningMethod::ExceptionAdapter {
            id, adapter_id, blockers, effects
        } if id == "blocked-windows-dev" && adapter_id == "unresolved-windows-dev-scope"
            && blockers == &[reason.to_string(), "no-reviewed-offline-adapter".into()]
            && effects == &["no-authorized-mutation"])
        && m.risks.permanent_data_loss == LossAssessment::Unknown
        && m.risks.flags.contains(&RiskFlag::Unknown)
        && m.risks
            .confirmations
            .contains(&ConfirmationId("review-windows-dev-category".into()))
        && m.confidence.status.as_deref() == Some("unverified")
        && [
            "windows-sign-in",
            "wam-prt-device-registration",
            "password-stores",
            "passkeys",
            "key-material",
            "unlisted-settings",
        ]
        .iter()
        .all(|f| m.preserve.artifact_families.iter().any(|a| a == f))
        && m.sources
            .as_ref()
            .is_some_and(|s| !s.is_empty() && s.iter().all(|u| u.starts_with("https://")))
        && m.evidence.iter().all(|e| {
            e.source.as_ref().is_none_or(|s| {
                m.sources
                    .as_ref()
                    .is_some_and(|sources| sources.contains(s))
            })
        })
}

/// Explicit research preview, not installed-tool discovery or an execution capability.
/// There are no paths, owners, credential inventories or process operations to resolve.
pub fn research_plan(m: &Manifest, selection: Selection) -> Result<ProposedPlan, ErrorKind> {
    if !valid_scope(m) {
        return Err(ErrorKind::InvalidManifest);
    }
    if selection.account_mode != AccountMode::Current {
        return Err(ErrorKind::Unsupported);
    }
    let mut limitations = m.limitations.clone();
    limitations.push(refusal_reason(&m.id).unwrap().into());
    limitations.push(everyout_engine::WINDOWS_DEV_SSO_WARNING.into());
    Ok(ProposedPlan {
        scope_evidence: crate::evidence::catalog(m),
        plan_id: PlanId(format!("{}-research-only", m.id)),
        provider_id: ProviderId(m.id.clone()),
        manifest_revision: m.revision,
        support: Support::Candidate,
        selection,
        actions: vec![],
        risks: m.risks.clone(),
        blockers: m.cleaning_methods[0].blockers().to_vec(),
        confirmations: m.risks.confirmations.clone(),
        limitations,
    })
}
