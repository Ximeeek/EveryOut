use crate::{bridge::Bridge, commands, dto::Settings, settings::SettingsStore};
use tauri::{
    ipc::{CallbackFn, InvokeBody},
    test::{get_ipc_response, mock_builder, INVOKE_KEY},
    webview::InvokeRequest,
    WebviewWindowBuilder,
};

#[test]
fn command_acl_allows_only_local_main_window() {
    let fixture = everyout_test_support::FixtureTree::empty().unwrap();
    let (bridge, _worker) =
        Bridge::channel(SettingsStore::new(fixture.path().into()), None).unwrap();
    let app = mock_builder()
        .manage(bridge)
        .invoke_handler(tauri::generate_handler![commands::get_settings])
        .build(tauri::generate_context!())
        .unwrap();
    let main = WebviewWindowBuilder::new(&app, "main", Default::default())
        .build()
        .unwrap();
    let foreign = WebviewWindowBuilder::new(&app, "foreign", Default::default())
        .build()
        .unwrap();
    let request = |url: &str| InvokeRequest {
        cmd: "get_settings".into(),
        callback: CallbackFn(0),
        error: CallbackFn(1),
        url: url.parse().unwrap(),
        body: InvokeBody::default(),
        headers: Default::default(),
        invoke_key: INVOKE_KEY.into(),
    };
    assert_eq!(
        get_ipc_response(&main, request("http://tauri.localhost"))
            .unwrap()
            .deserialize::<Settings>()
            .unwrap(),
        Settings::default()
    );
    assert!(get_ipc_response(&foreign, request("http://tauri.localhost")).is_err());
    assert!(get_ipc_response(&main, request("https://example.com")).is_err());
    let capability: serde_json::Value =
        serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
    assert_eq!(capability["permissions"].as_array().unwrap().len(), 11);
    assert!(capability["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .all(|p| p.as_str().unwrap().starts_with("allow-")));
}
