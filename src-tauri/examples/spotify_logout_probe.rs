//! Opt-in live verification of the pinned Spotify adapter through CurrentSession.
//! Default is read-only. No other provider, account or arbitrary target is accepted.
use everyout_core_model::*;
use everyout_lib::{application::CurrentSession, dto::*};
use everyout_platform_windows::{AllowedRoot, CurrentUserFolders, KnownFolder};
use everyout_providers::executor::{ManifestExecutor, WindowsProcessGate};

fn main() -> Result<(), String> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let apply = match arguments.as_slice() {
        [] => false,
        [flag] if flag == "--apply-reviewed-spotify" => true,
        _ => return Err("Use no arguments for preview, or --apply-reviewed-spotify to apply and close only the reviewed Spotify processes.".into()),
    };
    let root =
        AllowedRoot::from_manifest(&CurrentUserFolders, KnownFolder::RoamingAppData, "Spotify")
            .map_err(|e| e.to_string())?;
    let executable = root
        .spotify_reviewed_executable()
        .map_err(|e| e.to_string())?;
    let gate =
        WindowsProcessGate::reviewed_installation(vec!["Spotify.exe".into()], vec![executable])
            .map_err(|e| format!("{e:?}"))?;
    let provider = ManifestExecutor::load(
        include_str!("../../catalog/apps/communication/spotify.json"),
        &CurrentUserFolders,
        UserId("current-account".into()),
        InstallationId("spotify".into()),
        &gate,
    )
    .map_err(|e| format!("{e:?}"))?;
    let mut session = CurrentSession::new(&provider, vec![(Category::Application, &provider)]);
    let inventory = session.scan().map_err(|e| format!("{e:?}"))?;
    let plan = session
        .build_plan(
            SelectionRequest {
                inventory_id: inventory.inventory_id,
                items: vec!["spotify-installation".into()],
                skipped: None,
                profiles: vec![],
            },
            if apply {
                ProcessClosePolicy::HardKillAfter2s
            } else {
                ProcessClosePolicy::Ask
            },
        )
        .map_err(|e| format!("{e:?}"))?;
    let items: Vec<_> = plan
        .report
        .accounts
        .iter()
        .flat_map(|a| &a.sections)
        .flat_map(|s| &s.items)
        .collect();
    if items.len() != 1 || items[0].provider.as_deref() != Some("spotify") {
        return Err("Unexpected review scope".into());
    }
    if !apply {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan.report).map_err(|e| e.to_string())?
        );
        return Ok(());
    }
    if items[0]
        .actions
        .iter()
        .any(|action| action.outcome == ActionStatus::Blocked)
    {
        return Err("Reviewed operation is blocked; no apply requested".into());
    }
    let request = ExecuteRequest {
        plan_id: plan.plan_id,
        confirmed_risks: vec![RiskAcceptance {
            account: "current-account".into(),
            instance: items[0].instance.clone(),
            flags: items[0].risks.clone(),
            confirmations: items[0].confirmations.clone(),
        }],
        category_tokens: vec![],
        force_close_accounts: vec!["current-account".into()],
    };
    let report = session
        .execute(request, &|| false, &mut |_| {})
        .map_err(|e| format!("{e:?}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?
    );
    if report
        .accounts
        .iter()
        .flat_map(|a| &a.sections)
        .flat_map(|s| &s.items)
        .any(|i| i.status != AggregateStatus::CompleteLocalScope)
    {
        return Err("Live operation did not complete the reviewed local scope".into());
    }
    Ok(())
}
