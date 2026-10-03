//! Optional VM-only manual driver. Automated tests never invoke this binary.
#[cfg(windows)]
fn run() -> Result<(), &'static str> {
    use everyout_core_model::AccountMode;
    use everyout_elevated_helper::{launch, protocol::Command, LaunchOutcome};
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[0] != "--disposable-vm" {
        return Err(
            "usage: --disposable-vm <recorded-sha256> <current|finish|all-accounts-preview|parent-loss|timeout>",
        );
    }
    let mode = match args[2].as_str() {
        "current" => AccountMode::Current,
        "finish" | "all-accounts-preview" | "parent-loss" | "timeout" => AccountMode::AllAccounts,
        _ => return Err("unknown lab scenario"),
    };
    let hash = &args[1];
    if !everyout_elevated_helper::protocol::nonce_valid(hash) {
        return Err("invalid recorded digest");
    }
    let mut digest = [0; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hash[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid digest")?;
    }
    match launch(mode, true, digest) {
        LaunchOutcome::CurrentAccount => println!("current-account: no helper requested"),
        LaunchOutcome::Fallback(fallback) => println!(
            "fallback: {:?}; fresh current-scope review required",
            fallback.reason
        ),
        LaunchOutcome::Elevated(mut client) => {
            println!("authenticated helper; all-account work requires separate plan review");
            match args[2].as_str() {
                "parent-loss" => std::process::exit(0),
                "timeout" => std::thread::sleep(std::time::Duration::from_secs(35)),
                "all-accounts-preview" => {
                    let response = client
                        .request(Command::EnumerateProfiles)
                        .map_err(|_| "inventory failed")?;
                    let data = response.data.ok_or("profile metadata unavailable")?;
                    let mut json = data.report;
                    for page in 1..data.pages {
                        json.push_str(
                            &client
                                .request(Command::ReadReport { page })
                                .map_err(|_| "report page failed")?
                                .data
                                .ok_or("missing page")?
                                .report,
                        );
                    }
                    let inventory: serde_json::Value =
                        serde_json::from_str(&json).map_err(|_| "invalid inventory")?;
                    let accounts = inventory["accounts"].as_array().ok_or("missing accounts")?;
                    let mut selections = Vec::new();
                    for account in accounts {
                        let id = account["account"].as_str().ok_or("invalid account id")?;
                        for (provider, revision) in [
                            ("example-electron-cef", 1),
                            ("chrome", 2),
                            ("microsoft-credentials", 1),
                        ] {
                            selections.push(everyout_elevated_helper::protocol::Selection {
                                provider_id: provider.into(),
                                revision,
                                account_id: id.into(),
                            });
                        }
                    }
                    let response = client
                        .request(Command::Plan { selections })
                        .map_err(|_| "planning failed")?;
                    println!(
                        "plan: {:?}; candidate providers remain blocked",
                        response.status
                    );
                    let data = response.data.ok_or("plan unavailable")?;
                    let id = data.plan_id.ok_or("plan id unavailable")?;
                    let response = client
                        .request(Command::Execute {
                            plan_id: id,
                            dry_run: true,
                        })
                        .map_err(|_| "dry run failed")?;
                    println!("dry run: {:?}", response.status);
                    if let Some(data) = response.data {
                        let mut report = data.report;
                        for page in 1..data.pages {
                            report.push_str(
                                &client
                                    .request(Command::ReadReport { page })
                                    .map_err(|_| "report failed")?
                                    .data
                                    .ok_or("missing report page")?
                                    .report,
                            );
                        }
                        println!("{report}");
                    }
                    client
                        .request(Command::Finish)
                        .map_err(|_| "finish failed")?;
                }
                _ => {
                    let response = client
                        .request(Command::EnumerateProfiles)
                        .map_err(|_| "IPC failed")?;
                    println!("enumerate: {:?}", response.status);
                    let response = client
                        .request(Command::Finish)
                        .map_err(|_| "finish failed")?;
                    println!("finish: {:?}", response.status);
                }
            }
        }
    }
    Ok(())
}
fn main() {
    #[cfg(windows)]
    if let Err(reason) = run() {
        eprintln!("{reason}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    std::process::exit(1);
}
