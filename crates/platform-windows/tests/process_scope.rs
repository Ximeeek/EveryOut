#![cfg(windows)]
use everyout_core_model::ErrorKind;
use everyout_platform_windows::process::enumerate_current_user_matches;

#[test]
fn unrelated_processes_cannot_make_a_selected_scope_unavailable() {
    let inventory =
        enumerate_current_user_matches(&["everyout-nonexistent-process-fixture.exe".into()])
            .unwrap();
    assert!(inventory.processes.is_empty());
    assert!(inventory.unavailable.is_empty());
    assert_eq!(
        enumerate_current_user_matches(&[]).err().unwrap().kind,
        ErrorKind::ScopeViolation
    );
    let executable = std::env::current_exe().unwrap();
    let name = executable
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .to_ascii_uppercase();
    let inventory = enumerate_current_user_matches(std::slice::from_ref(&name)).unwrap();
    assert!(inventory.unavailable.is_empty());
    assert!(inventory
        .processes
        .iter()
        .any(|p| p.pid() == std::process::id()));
    assert!(inventory
        .processes
        .iter()
        .all(|p| p.matches(std::slice::from_ref(&name), &[])));
}
