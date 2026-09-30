#[cfg(windows)]
mod windows;
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let options = match everyout_process_close::parse(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("process-close refused: {error}");
            std::process::exit(1);
        }
    };
    let start = std::time::Instant::now();
    let result = {
        #[cfg(windows)]
        {
            windows::close(&options)
        }
        #[cfg(not(windows))]
        {
            let _ = options;
            Err("Windows required")
        }
    };
    match result {
        Ok((json, exited)) => {
            println!("{json}");
            if !exited {
                std::process::exit(2);
            }
        }
        Err(error) => {
            println!(
                "{}",
                serde_json::json!({"schema_version":1, "outcome":"refused_or_failed", "category":error, "elapsed_ms":start.elapsed().as_millis(), "partial_close_possible":true})
            );
            eprintln!("process-close refused/failed: {error}");
            std::process::exit(1);
        }
    }
}
