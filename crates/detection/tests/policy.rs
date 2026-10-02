use everyout_core_model::{Category, Confidence, DetectionOrigin};
use everyout_detection::{
    classification::{classify, Claim},
    heuristic::{excluded, score, Evidence},
};
use everyout_providers::Ownership;

#[test]
fn unverified_score_gates_require_independent_families_and_ownership() {
    for bits in 0u8..16 {
        let e = Evidence {
            identity: bits & 1 != 0,
            runtime: bits & 2 != 0,
            storage: bits & 4 != 0,
            ownership: bits & 8 != 0,
            plausible_owner: true,
            ..Default::default()
        };
        let result = score(e);
        if bits.count_ones() < 2 {
            assert_eq!(result.confidence, None);
        }
        if result.confidence == Some(Confidence::High) {
            assert!(result.points >= 9 && e.identity && e.ownership && bits.count_ones() >= 3);
        }
        assert_eq!(result.signals.len(), bits.count_ones() as usize);
        assert!(!DetectionOrigin::Heuristic.default_selected(true));
    }
    let full = Evidence {
        identity: true,
        runtime: true,
        storage: true,
        ownership: true,
        plausible_owner: true,
        ..Default::default()
    };
    assert_eq!(score(full).confidence, Some(Confidence::High));
    assert_eq!(
        score(Evidence {
            conflict: true,
            ..full
        })
        .confidence,
        Some(Confidence::Low)
    );
    assert_eq!(
        score(Evidence {
            excluded: true,
            ..full
        })
        .confidence,
        None
    );
    assert_eq!(
        score(Evidence {
            ownership: false,
            ..full
        })
        .confidence,
        Some(Confidence::Medium)
    );
    assert_eq!(
        score(Evidence {
            runtime: true,
            storage: true,
            ..Default::default()
        })
        .confidence,
        Some(Confidence::Low)
    );
    assert_eq!(
        score(Evidence {
            identity: true,
            storage: true,
            ..Default::default()
        })
        .confidence,
        Some(Confidence::Low)
    );
}
#[test]
fn classification_uses_owner_and_handles_browser_aliases_and_sso() {
    let claim = |owner: &str, ownership| Claim {
        owner: owner.into(),
        ownership,
    };
    assert_eq!(
        classify(&[
            claim("browser", Ownership::BrowserProfile),
            claim("browser", Ownership::Application)
        ]),
        Some(("browser".into(), Category::Browser))
    );
    for owner in [
        "webview2-host",
        "independent-store-app",
        "microsoft-desktop-app",
    ] {
        assert_eq!(
            classify(&[claim(owner, Ownership::Application)]),
            Some((owner.into(), Category::Application))
        );
    }
    for ownership in [Ownership::SharedIdentity, Ownership::DeveloperTool] {
        assert_eq!(
            classify(&[claim("reviewed-provider", ownership)]),
            Some((
                "reviewed-provider".into(),
                Category::WindowsMicrosoftAndDevTools
            ))
        );
    }
    assert_eq!(classify(&[]), None);
    assert_eq!(
        classify(&[
            claim("browser", Ownership::BrowserProfile),
            claim("different-host", Ownership::Application)
        ]),
        None
    );
    assert_eq!(
        classify(&[
            claim("host-a", Ownership::Application),
            claim("host-b", Ownership::Application)
        ]),
        None
    );
}
#[test]
fn exclusion_list_and_selection_preserve_open_gates() {
    for name in [
        "EveryOut",
        "EveryOutLab_synthetic",
        "Microsoft",
        "Temp",
        "EdgeWebView",
        "Microsoft.AAD.BrokerPlugin_opaque",
        "Microsoft.WindowsAppRuntime_opaque",
    ] {
        assert!(excluded(name));
    }
    assert!(!excluded("independent-host"));
    assert!(DetectionOrigin::KnownProvider.default_selected(true));
    assert!(!DetectionOrigin::KnownProvider.default_selected(false));
    assert!(!DetectionOrigin::Heuristic.default_selected(true));
}
