use everyout_core_model::*;
use everyout_providers::{load_manifest, Manifest, Root};
use serde_json::{json, Value};

const CATALOG: [(&str, &str); 17] = [
    (
        "communication",
        include_str!("../../../catalog/apps/communication/discord.json"),
    ),
    (
        "communication",
        include_str!("../../../catalog/apps/communication/spotify.json"),
    ),
    (
        "communication",
        include_str!("../../../catalog/apps/communication/slack.json"),
    ),
    (
        "communication",
        include_str!("../../../catalog/apps/communication/microsoft-teams.json"),
    ),
    (
        "messengers",
        include_str!("../../../catalog/apps/messengers/telegram-desktop.json"),
    ),
    (
        "messengers",
        include_str!("../../../catalog/apps/messengers/whatsapp-desktop.json"),
    ),
    (
        "messengers",
        include_str!("../../../catalog/apps/messengers/signal-desktop.json"),
    ),
    (
        "mail",
        include_str!("../../../catalog/apps/mail/thunderbird.json"),
    ),
    (
        "mail",
        include_str!("../../../catalog/apps/mail/outlook.json"),
    ),
    (
        "vpn",
        include_str!("../../../catalog/apps/vpn/proton-vpn.json"),
    ),
    (
        "vpn",
        include_str!("../../../catalog/apps/vpn/nordvpn.json"),
    ),
    (
        "authenticators",
        include_str!("../../../catalog/apps/authenticators/ente-auth.json"),
    ),
    (
        "authenticators",
        include_str!("../../../catalog/apps/authenticators/winauth.json"),
    ),
    (
        "wallets",
        include_str!("../../../catalog/apps/wallets/exodus.json"),
    ),
    (
        "wallets",
        include_str!("../../../catalog/apps/wallets/electrum.json"),
    ),
    (
        "password-managers",
        include_str!("../../../catalog/apps/password-managers/bitwarden.json"),
    ),
    (
        "password-managers",
        include_str!("../../../catalog/apps/password-managers/onepassword.json"),
    ),
];

#[test]
fn catalog_requires_evidence_loss_assessments_and_bounded_scopes() {
    for (_, input) in CATALOG {
        let m = load_manifest(input).unwrap();
        assert_eq!(m.support, Support::Candidate);
        let reviewed_login = m.id == "spotify";
        assert_eq!(
            m.confidence.level,
            if reviewed_login {
                Confidence::High
            } else {
                Confidence::Low
            }
        );
        assert_eq!(
            m.confidence.status.as_deref(),
            Some(if reviewed_login {
                "verified"
            } else {
                "unverified"
            })
        );
        assert!(!m.sources.as_ref().unwrap().is_empty());
        assert!(m.session_locations.iter().all(|a| a.confidence.as_deref()
            == Some(if reviewed_login {
                "verified"
            } else {
                "unverified"
            })
            && a.evidence.as_ref().is_some_and(|e| !e.is_empty())));
        assert!(!m.risks.affected_data.is_empty());
        assert_eq!(
            m.risks.confirmations,
            [ConfirmationId(format!("review-{}-permanent-loss", m.id))]
        );
        for (pointer, replacement) in [
            ("/support", json!("validated")),
            ("/session_locations/0/relative", json!("../outside")),
            ("/session_locations/0/relative", json!("Local State")),
            ("/session_locations/0/relative", json!("arbitrary")),
            ("/session_locations/0/evidence", json!([])),
            ("/risks/confirmations", json!([])),
            (
                "/risks/confirmations",
                json!(["review-another-provider-permanent-loss"]),
            ),
            ("/sources", json!([])),
            ("/identity/installation_id", json!("other-owner")),
        ] {
            let mut bad: Value = serde_json::from_str(input).unwrap();
            *bad.pointer_mut(pointer).unwrap() = replacement;
            assert!(
                load_manifest(&bad.to_string()).is_err(),
                "{}: {pointer}",
                m.id
            );
        }
        let mut bad: Value = serde_json::from_str(input).unwrap();
        bad["roots"][0] = json!({"id":"data", "base":"roaming-app-data", "relative":"Other", "owner":m.id,"scope":"os-user"});
        assert!(load_manifest(&bad.to_string()).is_err());
        if m.risks.permanent_data_loss == LossAssessment::Known {
            for field in ["flags", "affected_data"] {
                let mut bad: Value = serde_json::from_str(input).unwrap();
                bad["risks"][field] = json!([]);
                assert!(load_manifest(&bad.to_string()).is_err());
            }
        }
    }
}

#[test]
fn recovery_sensitive_entries_cannot_hide_specific_permanent_losses() {
    for (category, input) in CATALOG {
        let m = load_manifest(input).unwrap();
        let expected = match category {
            "wallets" => Some(RiskFlag::WalletOrKeyMaterial),
            "authenticators" | "password-managers" => Some(RiskFlag::VaultOr2faRecovery),
            _ if m.id == "signal-desktop" => Some(RiskFlag::LocalOnlyDocuments),
            _ => None,
        };
        if let Some(flag) = expected {
            assert_eq!(m.risks.permanent_data_loss, LossAssessment::Known);
            assert!(m.risks.flags.contains(&flag));
            let mut bad: Value = serde_json::from_str(input).unwrap();
            bad["risks"]["flags"] = serde_json::to_value(
                m.risks
                    .flags
                    .iter()
                    .filter(|f| **f != flag)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
            assert!(load_manifest(&bad.to_string()).is_err());
        }
    }
}

#[cfg(windows)]
fn synthetic(input: &str) -> Value {
    let mut m: Value = serde_json::from_str(input).unwrap();
    m["support"] = json!("validated");
    m["compatibility"]["product_versions"] = json!("synthetic-only-v1");
    m["confidence"]["version_coverage"] = json!("synthetic-only-v1");
    m["confidence"]["status"] = json!("verified");
    m["confidence"]["level"] = json!("high");
    m["open_spikes"] = json!([]);
    let flags = m["risks"]["flags"].as_array_mut().unwrap();
    flags.retain(|f| f != "unknown");
    m["risks"]["permanent_data_loss"] = json!("known");
    for a in m["session_locations"].as_array_mut().unwrap() {
        a["confidence"] = json!("verified");
    }
    for method in m["cleaning_methods"].as_array_mut().unwrap() {
        method["blockers"] = json!([]);
    }
    m
}

#[cfg(windows)]
mod windows {
    use super::*;
    use everyout_engine::*;
    use everyout_platform_windows::FixtureFolders;
    use everyout_providers::{
        executor::{ManifestExecutor, ProcessGate},
        platform::PlatformManifest,
    };
    use std::{cell::Cell, fs, path::PathBuf};

    #[derive(Default)]
    struct Gate(Cell<usize>);
    impl ProcessGate for Gate {
        fn preview(&self) -> Result<Vec<ProcessPreview>, ErrorKind> {
            Ok(vec![])
        }
        fn close(&self, _: ProcessClosePolicy) -> Result<(), ErrorKind> {
            self.0.set(self.0.get() + 1);
            Ok(())
        }
        fn revalidate(&self) -> Result<(), ErrorKind> {
            Ok(())
        }
    }
    fn seed(folders: &FixtureFolders, m: &Manifest) -> Vec<PathBuf> {
        let root = folders.path().join(m.roots[0].relative());
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("unlisted-canary"), b"preserve invented bytes").unwrap();
        m.session_locations
            .iter()
            .map(|a| {
                let p = root.join(&a.relative);
                if a.kind == ArtifactKind::Directory {
                    fs::create_dir_all(&p).unwrap();
                    fs::write(p.join("opaque"), b"invented fixture bytes").unwrap();
                } else {
                    fs::create_dir_all(p.parent().unwrap()).unwrap();
                    fs::write(&p, b"invented fixture bytes").unwrap();
                }
                p
            })
            .collect()
    }
    fn prepare<'a>(
        engine: &Engine<'a>,
        provider: &'a ManifestExecutor<'a>,
        id: &str,
    ) -> PreparedRun<'a> {
        let inventory = engine
            .scan(&[provider], Category::Application, &mut |_| {})
            .unwrap();
        engine
            .prepare(
                inventory,
                Category::Application,
                &[InstanceId(format!("{id}-installation"))],
                ProcessClosePolicy::Ask,
                &mut |_| {},
            )
            .unwrap()
    }
    fn approval(run: &PreparedRun<'_>, flags: bool, ids: bool) -> Approval {
        let mut approval = Approval::default();
        for item in &run.preview().sections[0].items {
            if let Some(plan) = &item.plan {
                if flags {
                    approval
                        .confirmed_risks
                        .push(run.confirm_risks(&item.instance, &plan.risks.flags));
                }
                if ids {
                    approval
                        .confirmations
                        .extend(plan.risks.confirmations.clone());
                }
            }
        }
        approval
    }
    #[test]
    fn candidates_stay_unchecked_and_cannot_mutate_even_with_loss_approval() {
        for (_, input) in CATALOG {
            let m = load_manifest(input).unwrap();
            let folders = FixtureFolders::create().unwrap();
            let gate = Gate::default();
            if matches!(m.roots[0], Root::Unresolved { .. }) {
                let before = folders.snapshot().unwrap();
                assert_eq!(
                    ManifestExecutor::load(
                        input,
                        &folders,
                        UserId("fixture".into()),
                        InstallationId("fixture".into()),
                        &gate
                    )
                    .err(),
                    Some(ErrorKind::Unsupported)
                );
                assert!(PlatformManifest::load(input)
                    .unwrap()
                    .file("session-0", None, &folders)
                    .is_err());
                assert!(load_manifest(&synthetic(input).to_string()).is_err());
                assert_eq!(before, folders.snapshot().unwrap());
                continue;
            }
            seed(&folders, &m);
            let provider = ManifestExecutor::load(
                input,
                &folders,
                UserId("fixture".into()),
                InstallationId("fixture".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture".into()), &provider);
            let inventory = engine
                .scan(&[&provider], Category::Application, &mut |_| {})
                .unwrap();
            assert!(
                inventory
                    .default_selection(Category::Application)
                    .is_empty(),
                "{}",
                m.id
            );
            let before = folders.snapshot().unwrap();
            let run = prepare(&engine, &provider, &m.id);
            assert_eq!(before, folders.snapshot().unwrap());
            let accepted = approval(&run, true, true);
            let report = engine.apply(run, accepted, &|| false, &mut |_| {});
            assert_eq!(report.sections[0].aggregate, AggregateStatus::Blocked);
            assert_eq!(before, folders.snapshot().unwrap());
            assert_eq!(gate.0.get(), 0);
        }
    }
    #[test]
    fn resolvable_synthetic_scopes_require_both_loss_tokens_and_matching_confirmation() {
        for (_, input) in CATALOG {
            let m = load_manifest(input).unwrap();
            if matches!(m.roots[0], Root::Unresolved { .. }) {
                continue;
            }
            if m.id == "spotify" {
                // A synthetic promotion cannot replace the compiled executable pin.
                assert!(load_manifest(&synthetic(input).to_string()).is_err());
                continue;
            }
            let reviewed = synthetic(input);
            if m.id == "thunderbird" {
                assert!(load_manifest(&reviewed.to_string()).is_err());
                continue;
            }
            // Clearing support/version/blocker gates cannot hide an unverified location.
            let mut unverified = reviewed.clone();
            unverified["session_locations"][0]["confidence"] = json!("unverified");
            assert!(load_manifest(&unverified.to_string()).is_err());
            let mut weak = reviewed.clone();
            weak["confidence"]["level"] = json!("low");
            assert!(load_manifest(&weak.to_string()).is_err());
            let folders = FixtureFolders::create().unwrap();
            let targets = seed(&folders, &m);
            let gate = Gate::default();
            let provider = ManifestExecutor::load(
                &reviewed.to_string(),
                &folders,
                UserId("fixture".into()),
                InstallationId("fixture".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture".into()), &provider);
            let before = folders.snapshot().unwrap();
            for (flags, ids, wrong) in [
                (false, false, false),
                (true, false, false),
                (false, true, false),
                (true, false, true),
            ] {
                let run = prepare(&engine, &provider, &m.id);
                let plan = run.preview().sections[0].items[0].plan.as_ref().unwrap();
                assert_eq!(
                    plan.risks.flags,
                    m.risks
                        .flags
                        .iter()
                        .filter(|f| **f != RiskFlag::Unknown)
                        .copied()
                        .collect::<Vec<_>>()
                );
                assert!(run.preview().sections[0].counts.would_apply > 0);
                assert_eq!(before, folders.snapshot().unwrap());
                let mut accepted = approval(&run, flags, ids);
                if wrong {
                    accepted.confirmations.push(ConfirmationId(
                        "review-another-provider-permanent-loss".into(),
                    ));
                }
                let report = engine.apply(run, accepted, &|| false, &mut |_| {});
                assert_eq!(
                    report.sections[0].aggregate,
                    AggregateStatus::Blocked,
                    "{}",
                    m.id
                );
                assert_eq!(before, folders.snapshot().unwrap());
                assert_eq!(gate.0.get(), 0);
            }
            let run = prepare(&engine, &provider, &m.id);
            let accepted = approval(&run, true, true);
            let report = engine.apply(run, accepted, &|| false, &mut |_| {});
            assert_eq!(
                report.sections[0].aggregate,
                AggregateStatus::CompleteLocalScope,
                "{}",
                m.id
            );
            assert!(targets.iter().all(|p| !p.exists()));
            assert!(folders
                .path()
                .join(m.roots[0].relative())
                .join("unlisted-canary")
                .exists());
            assert_eq!(gate.0.get(), 1);
        }
    }
    #[test]
    fn each_category_exercises_engine_loss_contract_in_an_explicit_synthetic_carrier() {
        let mut covered = std::collections::HashSet::new();
        for (category, input) in CATALOG {
            if !covered.insert(category) {
                continue;
            }
            let research = load_manifest(input).unwrap();
            // This is a separate synthetic Electron fixture, not a promoted product path.
            let mut carrier: Value = serde_json::from_str(include_str!(
                "../../../catalog/apps/example-electron-cef.json"
            ))
            .unwrap();
            carrier["risks"] = serde_json::to_value(&research.risks).unwrap();
            carrier["risks"]["evidence"] = json!(["fixture-evidence"]);
            if category == "mail" {
                // Actual Thunderbird credentials remain hard-blocked; demonstrate a
                // hypothetical separable mail-session store with local message loss.
                carrier["risks"]["flags"] =
                    json!(["local-only-documents", "drafts-or-offline-messages"]);
            }
            let reviewed = synthetic(&carrier.to_string());
            let m = load_manifest(&reviewed.to_string()).unwrap();
            let folders = FixtureFolders::create().unwrap();
            let targets = seed(&folders, &m);
            let gate = Gate::default();
            let provider = ManifestExecutor::load(
                &reviewed.to_string(),
                &folders,
                UserId("fixture".into()),
                InstallationId("fixture".into()),
                &gate,
            )
            .unwrap();
            let engine = Engine::new(UserId("fixture".into()), &provider);
            let before = folders.snapshot().unwrap();
            let run = prepare(&engine, &provider, &m.id);
            assert!(run.preview().sections[0].counts.would_apply > 0);
            assert_eq!(before, folders.snapshot().unwrap());
            let report = engine.apply(run, Approval::default(), &|| false, &mut |_| {});
            assert_eq!(report.sections[0].aggregate, AggregateStatus::Blocked);
            assert_eq!(before, folders.snapshot().unwrap());
            assert_eq!(gate.0.get(), 0);
            let run = prepare(&engine, &provider, &m.id);
            let accepted = approval(&run, true, true);
            let report = engine.apply(run, accepted, &|| false, &mut |_| {});
            assert_eq!(
                report.sections[0].aggregate,
                AggregateStatus::CompleteLocalScope,
                "{category}"
            );
            assert!(targets.iter().all(|p| !p.exists()));
        }
        assert_eq!(covered.len(), 7);
    }
}
