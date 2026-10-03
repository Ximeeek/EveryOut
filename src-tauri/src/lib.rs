#[cfg(test)]
mod acl_tests;
pub mod application;
pub mod bindings;
pub mod bridge;
mod commands;
pub mod dto;
mod native;
pub mod reports;
pub mod settings;
use tauri::Manager;
include!(concat!(env!("OUT_DIR"), "/helper_pin.rs"));

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let state = bridge::Bridge::start(app.path().app_config_dir()?, HELPER_PIN)
                .map_err(|e| std::io::Error::other(format!("application initialization: {e:?}")))?;
            app.manage(state);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::scan,
            commands::build_plan,
            commands::dry_run,
            commands::execute,
            commands::cancel,
            commands::get_settings,
            commands::set_settings,
            commands::get_last_report,
            commands::close_reviewed,
            commands::export_report,
            commands::enable_all_accounts_mode
        ])
        .run(tauri::generate_context!())
        .expect("failed to run EveryOut");
}
