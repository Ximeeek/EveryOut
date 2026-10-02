//! Optional VM-only manual driver. Automated tests never invoke this binary.
#[cfg(windows)]
fn run() -> Result<(), &'static str> {
    use everyout_core_model::AccountMode;
    use everyout_elevated_helper::{launch, protocol::Command, LaunchOutcome};
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || args[0] != "--disposable-vm" {
        return Err(
            "usage: --disposable-vm <recorded-sha256> <current|finish|parent-loss|timeout>",
        );
    }
    let mode = match args[2].as_str() {
        "current" => AccountMode::Current,
        "finish" | "parent-loss" | "timeout" => AccountMode::AllAccounts,
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
            println!("authenticated helper; foreign-account operations remain blocked");
            match args[2].as_str() {
                "parent-loss" => std::process::exit(0),
                "timeout" => std::thread::sleep(std::time::Duration::from_secs(35)),
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
