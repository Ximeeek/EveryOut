use crate::{bridge::Bridge, dto::*};
use tauri::{ipc::Channel, State};
async fn background<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, CommandError> + Send + 'static,
) -> Result<T, CommandError> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|_| CommandError::WorkerUnavailable)?
}
#[tauri::command]
pub async fn scan(state: State<'_, Bridge>) -> Result<ScanDto, CommandError> {
    let state = state.inner().clone();
    background(move || state.scan()).await
}
#[tauri::command]
pub async fn build_plan(
    state: State<'_, Bridge>,
    selection: SelectionRequest,
) -> Result<PlanDto, CommandError> {
    let state = state.inner().clone();
    background(move || state.build_plan(selection)).await
}
#[tauri::command]
pub async fn dry_run(state: State<'_, Bridge>, plan_id: String) -> Result<PlanDto, CommandError> {
    let state = state.inner().clone();
    background(move || state.dry_run(plan_id)).await
}
#[tauri::command]
pub async fn execute(
    state: State<'_, Bridge>,
    request: ExecuteRequest,
    on_event: Channel<WipeEvent>,
) -> Result<RunStarted, CommandError> {
    let state = state.inner().clone();
    background(move || {
        let cancel = state.clone();
        let run = request.plan_id.clone();
        state.execute(
            request,
            Box::new(move |event| {
                if on_event.send(event).is_err() {
                    let _ = cancel.cancel(&run);
                }
            }),
        )
    })
    .await
}
#[tauri::command]
pub fn cancel(state: State<'_, Bridge>, run_id: String) -> Result<(), CommandError> {
    state.cancel(&run_id)
}
#[tauri::command]
pub fn get_settings(state: State<'_, Bridge>) -> Result<Settings, CommandError> {
    state.get_settings()
}
#[tauri::command]
pub async fn set_settings(
    state: State<'_, Bridge>,
    settings: Settings,
) -> Result<Settings, CommandError> {
    let state = state.inner().clone();
    background(move || state.set_settings(settings)).await
}
#[tauri::command]
pub fn get_last_report(state: State<'_, Bridge>) -> Result<Option<ReportDto>, CommandError> {
    state.get_last_report()
}
#[tauri::command]
pub async fn enable_all_accounts_mode(
    state: State<'_, Bridge>,
) -> Result<ModeResult, CommandError> {
    let state = state.inner().clone();
    background(move || state.enable_all_accounts_mode()).await
}

#[tauri::command]
pub async fn close_reviewed(
    state: State<'_, Bridge>,
    request: ExecuteRequest,
) -> Result<ReportDto, CommandError> {
    let state = state.inner().clone();
    background(move || state.close_reviewed(request)).await
}
#[tauri::command]
pub async fn export_report(
    state: State<'_, Bridge>,
    format: ExportFormat,
) -> Result<String, CommandError> {
    let state = state.inner().clone();
    background(move || state.export_report(format)).await
}
