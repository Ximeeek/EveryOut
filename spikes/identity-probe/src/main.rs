#[cfg(windows)]
mod windows;

fn main() {
    if std::env::args_os().skip(1).collect::<Vec<_>>() != ["inspect-lab"] {
        eprintln!("usage: everyout-identity-probe inspect-lab (disposable VM only)");
        std::process::exit(1);
    }
    #[cfg(windows)]
    match windows::inspect() {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(_) => {
                eprintln!("serialization failed");
                std::process::exit(1);
            }
        },
        Err(category) => {
            eprintln!("identity-probe failed: {category}");
            std::process::exit(1);
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("Windows is required");
        std::process::exit(1);
    }
}
