//! One projection shared by discovery, current-account providers and account helpers.
use crate::{CleaningMethod, Manifest};
use everyout_core_model::*;

pub fn catalog(m: &Manifest) -> ScopeEvidence {
    if m.support == Support::Validated {
        let mut evidence = ScopeEvidence::reviewed_catalog(m.risks.permanent_data_loss);
        if m.session_locations
            .iter()
            .any(|artifact| artifact.confidence.as_deref() != Some("verified"))
        {
            evidence.authentication_scope = EvidenceState::new(
                AuthenticationScope::Unknown,
                "catalog-declaration",
                "unverified-catalog-artifact",
            );
        }
        return evidence;
    }
    let framework_hint = m.limitations.iter().any(|s| s.contains("framework"))
        || matches!(
            m.application,
            Some(crate::ApplicationKind::ElectronCef | crate::ApplicationKind::Webview2)
        );
    ScopeEvidence {
        application_identity: EvidenceState::new(
            ApplicationIdentity::Weak,
            "catalog-declaration",
            "application-registration-uncorroborated",
        ),
        storage_ownership: EvidenceState::new(
            StorageOwnership::Unknown,
            "catalog-declaration",
            "exclusive-owner-unresolved",
        ),
        authentication_scope: EvidenceState::new(
            if framework_hint {
                AuthenticationScope::FrameworkHint
            } else {
                AuthenticationScope::Unknown
            },
            if framework_hint {
                "framework-inference"
            } else {
                "missing-evidence"
            },
            "no-authentication-proof",
        ),
        preservation: EvidenceState::new(
            if m.risks.permanent_data_loss == LossAssessment::Known
                && !m.risks.flags.contains(&RiskFlag::Unknown)
            {
                PreservationState::KnownLosses
            } else {
                PreservationState::Unknown
            },
            "catalog-declaration",
            "catalog-preservation-assessment",
        ),
        ..Default::default()
    }
}
pub fn decision(m: &Manifest, evidence: ScopeEvidence, additional: &[String]) -> DecisionTrace {
    let blockers: Vec<_> = m
        .cleaning_methods
        .iter()
        .flat_map(|method| method.blockers())
        .chain(additional)
        .cloned()
        .collect();
    evidence.decide(
        m.support,
        &blockers,
        m.risks.permanent_data_loss,
        &m.risks.flags,
        &m.risks.confirmations,
    )
}

#[cfg(windows)]
pub fn assess(
    m: &Manifest,
    resolver: &dyn everyout_platform_windows::RootResolver,
) -> DecisionTrace {
    use everyout_platform_windows::{AllowedRoot, KnownFolder};
    let mut evidence = catalog(m);
    let reviewed_spotify = m.id == "spotify"
        && crate::desktop::valid_scope(m)
        && m.session_locations.len() == 1
        && m.session_locations[0].confidence.as_deref() == Some("verified")
        && m.cleaning_methods.len() == 1
        && matches!(&m.cleaning_methods[0],
            CleaningMethod::ExceptionAdapter { adapter_id, .. } if adapter_id == "spotify-saved-login-v1");
    let mut blockers = Vec::new();
    if reviewed_spotify {
        let root = AllowedRoot::from_manifest(resolver, KnownFolder::RoamingAppData, "Spotify");
        match root.and_then(|root| {
            root.spotify_reviewed_build()?;
            Ok(root)
        }) {
            Ok(root) => {
                evidence = spotify_local_evidence();
                if root
                    .path("prefs")
                    .and_then(|path| path.spotify_saved_login())
                    .is_err()
                {
                    evidence.authentication_scope = EvidenceState::new(
                        AuthenticationScope::Unknown,
                        "provider-adapter",
                        "spotify-login-format-not-reviewed",
                    );
                    evidence.preservation = EvidenceState::new(
                        PreservationState::Unknown,
                        "provider-adapter",
                        "spotify-login-format-not-reviewed",
                    );
                    blockers.push("spotify-login-format-not-reviewed".into());
                }
            }
            Err(error) => {
                evidence.version_applicability = EvidenceState::new(
                    if error.kind == ErrorKind::Unsupported {
                        VersionApplicability::Stale
                    } else {
                        VersionApplicability::Unknown
                    },
                    "runtime-executable-hash",
                    "spotify-build-not-reviewed",
                );
                blockers.push("spotify-build-not-reviewed".into());
            }
        }
    }
    decision(m, evidence, &blockers)
}

#[cfg(windows)]
fn spotify_local_evidence() -> ScopeEvidence {
    // Historical local review covers saved login only. It is not a new VM record,
    // remote-session validation or compatibility evidence for other executables.
    let mut authentication_scope = EvidenceState::new(
        AuthenticationScope::Validated,
        "user-observed-result",
        "spotify-existing-local-saved-login-closure",
    );
    authentication_scope.provenance.push(EvidenceProvenance {
        source: "provider-adapter".into(),
        reason_code: "spotify-four-fixed-login-fields".into(),
    });
    ScopeEvidence {
        application_identity: EvidenceState::new(
            ApplicationIdentity::Exact,
            "runtime-executable-hash",
            "spotify-pinned-executable-match",
        ),
        storage_ownership: EvidenceState::new(
            StorageOwnership::Exclusive,
            "provider-adapter",
            "spotify-fixed-root-physical-binding",
        ),
        authentication_scope,
        preservation: EvidenceState::new(
            PreservationState::Validated,
            "provider-adapter",
            "spotify-unrelated-preference-bytes-preserved",
        ),
        version_applicability: EvidenceState::new(
            VersionApplicability::Current,
            "runtime-executable-hash",
            "spotify-pinned-executable-match",
        ),
        authority: OperationAuthority::SpotifySavedLogin,
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn pinned_spotify_projection_preserves_existing_review_without_inventing_vm_evidence() {
        let m = crate::load_manifest(include_str!(
            "../../../catalog/apps/communication/spotify.json"
        ))
        .unwrap();
        let evidence = spotify_local_evidence();
        let trace = decision(&m, evidence.clone(), &[]);
        assert!(trace.action_allowed);
        assert_eq!(trace.support, Support::Candidate);
        assert_eq!(
            evidence.authentication_scope.state,
            AuthenticationScope::Validated
        );
        assert!(evidence
            .authentication_scope
            .provenance
            .iter()
            .any(|p| p.source == "user-observed-result"));
        assert!(!evidence
            .authentication_scope
            .provenance
            .iter()
            .any(|p| p.source == "product-validation-record"));
        let blocked = decision(&m, evidence, &["spotify-login-format-not-reviewed".into()]);
        assert!(!blocked.action_allowed);
    }
}
