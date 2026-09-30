#[cfg(windows)]
mod windows;
fn main() {
    if std::env::args_os().skip(1).collect::<Vec<_>>() != ["scan-lab"] {
        eprintln!("usage: everyout-heuristic-scan scan-lab (disposable VM only)");
        std::process::exit(1);
    }
    #[cfg(windows)]
    {
        match windows::scan()
            .and_then(|r| serde_json::to_string_pretty(&r).map_err(|_| "serialization"))
        {
            Ok(json) => println!("{json}"),
            Err(category) => {
                eprintln!("heuristic-scan failed: {category}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(not(windows))]
    {
        eprintln!("Windows required");
        std::process::exit(1);
    }
}
