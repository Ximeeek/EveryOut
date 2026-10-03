#![cfg_attr(windows, windows_subsystem = "windows")]
fn main() {
    #[cfg(windows)]
    if everyout_elevated_helper::helper_main().is_err() {
        // Fixed failure exit only: no raw arguments, SID, nonce or OS text in logs.
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    std::process::exit(1);
}
