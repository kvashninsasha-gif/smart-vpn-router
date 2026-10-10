#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
mod ai;
mod ai_runtime;
mod diagnostics;
mod file_actions;
mod local_recovery;
mod metrics;
#[cfg(any(target_os = "macos", test))]
mod network_cli;
mod setup_check;
mod setup_plan;
#[cfg(target_os = "macos")]
mod update_install;
mod updates;
#[cfg(any(windows, test))]
mod windows_proxy_auto;
use serde::Serialize;
use smart_vpn_engine::{
    latency,
    routing::{self, Rule},
    servers::{self, ImportReport},
    settings::{connection_plan, ConnectionPlan, Profile, Settings, Subscription, Vault},
    statistics,
    vpn::CoreProcess,
};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tauri::{
    menu::{Menu, MenuItem, Submenu},
    tray::TrayIconBuilder,
    Emitter, Manager,
};
struct ActiveCore {
    #[cfg(windows)]
    proxy_session: Option<windows_proxy_auto::Session>,
    local: Option<CoreProcess>,
    proxy_port: u16,
    api_port: u16,
    secret: String,
    logs: Arc<Mutex<Vec<String>>>,
}
impl ActiveCore {
    fn local(core: CoreProcess) -> Self {
        Self {
            #[cfg(windows)]
            proxy_session: None,
            proxy_port: core.proxy_port,
            api_port: core.api_port,
            secret: core.secret.clone(),
            logs: core.logs.clone(),
            local: Some(core),
        }
    }
    fn remote(status: smart_vpn_engine::network_helper::Status) -> Self {
        Self {
            #[cfg(windows)]
            proxy_session: None,
            local: None,
            proxy_port: status.proxy_port,
            api_port: status.api_port,
            secret: status.secret,
            logs: Arc::new(Mutex::new(vec![])),
        }
    }
    fn alive(&mut self) -> bool {
        #[cfg(windows)]
        if self.proxy_session.as_mut().is_some_and(|p| !p.alive()) {
            return false;
        }
        match &mut self.local {
            Some(core) => core.alive(),
            None => smart_vpn_engine::network_helper::request(
                &smart_vpn_engine::network_helper::Request::Status,
            )
            .is_ok_and(|r| r.status.wanted),
        }
    }
}
#[cfg(windows)]
impl Drop for ActiveCore {
    fn drop(&mut self) {
        if let Some(mut proxy) = self.proxy_session.take() {
            let _ = proxy.stop();
        }
    }
}
#[derive(Clone)]
struct State {
    installing: Arc<std::sync::atomic::AtomicBool>,
    profile: Arc<Mutex<Profile>>,
    vault: Arc<Vault>,
    core: Arc<Mutex<Option<ActiveCore>>>,
    binary: PathBuf,
    status: Arc<Mutex<String>>,
    gate: Arc<Mutex<()>>,
    measurements: Arc<Mutex<()>>,
    proxy_error: Arc<Mutex<Option<String>>>,
    wanted: Arc<smart_vpn_engine::lifecycle::ConnectionIntent>,
}
#[derive(Serialize)]
struct Snapshot {
    profile: Profile,
    status: String,
    proxy_port: Option<u16>,
    core_version: String,
    connection_plan: ConnectionPlan,
    logs: Vec<String>,
    helper_available: bool,
    platform: &'static str,
}
fn edit<T>(s: &State, f: impl FnOnce(&mut Profile) -> Result<T, String>) -> Result<T, String> {
    let _operation = s
        .gate
        .lock()
        .map_err(|_| smart_vpn_engine::text("message_311"))?;
    if s.installing.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("Выполняется установка обновления.".into());
    }
    let mut current = s
        .profile
        .lock()
        .map_err(|_| smart_vpn_engine::text("message_312"))?;
    let mut next = current.clone();
    let value = f(&mut next)?;
    s.vault.save(&next)?;
    *current = next;
    Ok(value)
}
#[tauri::command]
fn snapshot(s: tauri::State<State>) -> Snapshot {
    let (proxy_port, logs) = {
        let core = s.core.lock().unwrap();
        (
            core.as_ref().map(|c| c.proxy_port),
            core.as_ref()
                .map(|c| c.logs.lock().unwrap().clone())
                .unwrap_or_default(),
        )
    };
    let profile = s.profile.lock().unwrap().clone();
    let helper_available = smart_vpn_engine::network_helper::ready();
    Snapshot {
        connection_plan: smart_vpn_engine::settings::connection_plan_with_helper(
            &profile,
            helper_available,
        ),
        profile,
        status: s.status.lock().unwrap().clone(),
        proxy_port,
        core_version: "1.14.2".into(),
        logs,
        helper_available,
        platform: std::env::consts::OS,
    }
}
#[tauri::command]
async fn windows_proxy_status(
    state: tauri::State<'_, State>,
) -> Result<smart_vpn_engine::windows_proxy::Status, String> {
    let configured = state
        .profile
        .lock()
        .map_err(|_| "Не удалось прочитать настройки")?
        .settings
        .proxy_port;
    let port = state
        .core
        .lock()
        .map_err(|_| "Не удалось прочитать состояние")?
        .as_ref()
        .map_or(configured, |c| c.proxy_port);
    tauri::async_runtime::spawn_blocking(move || smart_vpn_engine::windows_proxy::read(port))
        .await
        .map_err(|_| "Не удалось проверить прокси Windows".to_string())?
}
#[tauri::command]
fn open_windows_proxy_settings() -> Result<(), String> {
    smart_vpn_engine::windows_proxy::open_settings()
}
#[derive(Serialize)]
struct RuntimeSnapshot {
    status: String,
    proxy_port: Option<u16>,
    logs: Option<Vec<String>>,
    connection_error: Option<String>,
    active_server_id: Option<String>,
}
#[tauri::command]
async fn runtime(
    include_logs: bool,
    s: tauri::State<'_, State>,
) -> Result<RuntimeSnapshot, String> {
    let s = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let tun = s.profile.lock().unwrap().settings.tun;
        let mut core = s.core.lock().unwrap();
        let mut connection_error = s
            .proxy_error
            .lock()
            .map_err(|_| "Не удалось прочитать состояние прокси")?
            .clone();
        let mut active_server_id = None;
        if tun || core.as_ref().is_some_and(|c| c.local.is_none()) {
            match smart_vpn_engine::network_helper::request(
                &smart_vpn_engine::network_helper::Request::Status,
            ) {
                Ok(response) => {
                    active_server_id = response.status.active_server_id.clone();
                    connection_error = diagnostics::connection_error(
                        response.status.connection_state(),
                        response.status.error.clone(),
                        connection_error,
                    );
                    if !response.status.compatible() {
                        connection_error = Some(smart_vpn_engine::text("helper_upgrade").into());
                    }
                    *s.status.lock().unwrap() = response.status.connection_state().into();
                    if response.status.running && response.status.compatible() {
                        *s.proxy_error
                            .lock()
                            .map_err(|_| "Не удалось обновить состояние подключения")? = None;
                        if let Some(core) = core.as_mut() {
                            core.proxy_port = response.status.proxy_port;
                            core.api_port = response.status.api_port;
                            core.secret = response.status.secret;
                        } else {
                            *core = Some(ActiveCore::remote(response.status));
                        }
                    } else if response.status.stopped()
                        && core.as_ref().is_some_and(|c| c.local.is_none())
                    {
                        *core = None;
                    }
                }
                Err(error) => {
                    connection_error = Some(error);
                    *s.status.lock().unwrap() = if smart_vpn_engine::network_helper::installed()
                        || core.as_ref().is_some_and(|c| c.local.is_none())
                    {
                        "unknown"
                    } else {
                        "disconnected"
                    }
                    .into();
                }
            }
            if include_logs {
                if let Ok(response) = smart_vpn_engine::network_helper::request(
                    &smart_vpn_engine::network_helper::Request::Logs,
                ) {
                    if let Some(c) = core.as_ref() {
                        *c.logs.lock().unwrap() = response.logs;
                    }
                }
            }
        }
        let result = RuntimeSnapshot {
            status: s.status.lock().unwrap().clone(),
            proxy_port: core.as_ref().map(|c| c.proxy_port),
            logs: include_logs.then(|| {
                core.as_ref()
                    .map(|c| c.logs.lock().unwrap().clone())
                    .unwrap_or_default()
            }),
            connection_error,
            active_server_id,
        };
        drop(core);
        if result.status == "connected" {
            if let Some(id) = result.active_server_id.as_ref() {
                let needs_update = s.profile.lock().unwrap().selected.as_ref() != Some(id);
                if needs_update {
                    edit(&s, |p| {
                        if p.settings.tun && p.servers.iter().any(|server| &server.id == id) {
                            p.selected = Some(id.clone());
                        }
                        Ok(())
                    })?;
                }
            }
        }
        Ok(result)
    })
    .await
    .map_err(|_| smart_vpn_engine::text("helper_ipc").to_string())?
}
#[tauri::command]
fn import_servers(text: String, s: tauri::State<State>) -> Result<ImportReport, String> {
    import_servers_state(text, &s)
}
fn import_servers_state(text: String, s: &State) -> Result<ImportReport, String> {
    if text.len() > 4_000_000 {
        return Err(smart_vpn_engine::text("message_313").into());
    }
    edit(s, |p| {
        let r = servers::import(&text, &mut p.servers);
        if p.selected.is_none() {
            p.selected = p.servers.first().map(|s| s.id.clone())
        }
        Ok(r)
    })
}
#[tauri::command]
fn select_server(id: String, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_314").into());
    }
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        if !p.servers.iter().any(|s| s.id == id) {
            return Err(smart_vpn_engine::text("message_315").into());
        }
        p.selected = Some(id);
        Ok(())
    })
}
#[tauri::command]
fn delete_server(id: String, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_316").into());
    }
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        p.servers.retain(|s| s.id != id);
        if p.selected.as_ref() == Some(&id) {
            p.selected = p.servers.first().map(|s| s.id.clone())
        }
        Ok(())
    })
}
#[tauri::command]
fn favorite(id: String, s: tauri::State<State>) -> Result<(), String> {
    edit(&s, |p| {
        let v = p
            .servers
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(smart_vpn_engine::text("message_315"))?;
        v.favorite = !v.favorite;
        Ok(())
    })
}
#[tauri::command]
fn rename_server(
    id: String,
    name: String,
    group: String,
    s: tauri::State<State>,
) -> Result<(), String> {
    if name.trim().is_empty() || name.len() > 200 || group.len() > 100 {
        return Err(smart_vpn_engine::text("message_317").into());
    }
    edit(&s, |p| {
        let v = p
            .servers
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(smart_vpn_engine::text("message_315"))?;
        v.name = name.trim().into();
        v.group = group.trim().into();
        Ok(())
    })
}
#[tauri::command]
fn server_uri(id: String, s: tauri::State<State>) -> Result<String, String> {
    s.profile
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|v| v.id == id)
        .ok_or(smart_vpn_engine::text("message_315").into())
        .and_then(|v| v.uri())
}
#[tauri::command]
fn save_rules(rules: Vec<Rule>, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_318").into());
    }
    routing::validate(&rules)?;
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        p.rules = rules;
        Ok(())
    })
}
#[tauri::command]
fn set_metric_settings(
    enabled: bool,
    interval_seconds: u64,
    s: tauri::State<State>,
) -> Result<(), String> {
    edit(&s, |p| {
        p.settings.auto_metrics = enabled;
        p.settings.metric_interval = interval_seconds;
        p.settings.validate()
    })
}
#[tauri::command]
fn save_settings(settings: Settings, s: tauri::State<State>) -> Result<(), String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_319").into());
    }
    settings.validate()?;
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        p.settings = settings;
        Ok(())
    })
}
#[tauri::command]
fn check_route(domain: String, s: tauri::State<State>) -> Result<routing::Decision, String> {
    let p = s.profile.lock().unwrap();
    routing::decide(&domain, &p.settings.mode, &p.rules)
}
fn disconnect(s: &State) -> Result<(), String> {
    let ticket = s.wanted.cancel();
    disconnect_for_ticket(s, ticket)
}
fn disconnect_for_ticket(s: &State, ticket: u64) -> Result<(), String> {
    let _guard = s.gate.lock().unwrap();
    disconnect_locked(s, ticket)
}
fn disconnect_locked(s: &State, ticket: u64) -> Result<(), String> {
    if !s.wanted.current(ticket) {
        return Err(smart_vpn_engine::text("connection_cancelled").into());
    }
    let active_remote = s
        .core
        .lock()
        .unwrap()
        .as_ref()
        .is_some_and(|c| c.local.is_none());
    let result = (|| {
        #[cfg(windows)]
        if let Some(proxy) = s
            .core
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|c| c.proxy_session.as_mut())
        {
            proxy.stop()?;
        }
        if let Some(local) = s
            .core
            .lock()
            .unwrap()
            .as_mut()
            .and_then(|c| c.local.as_mut())
        {
            local.stop_checked()?;
        }
        if active_remote || smart_vpn_engine::network_helper::installed() {
            smart_vpn_engine::network_helper::require_current()?;
            let response = smart_vpn_engine::network_helper::request(
                &smart_vpn_engine::network_helper::Request::Stop,
            )?;
            if !response.status.stopped() {
                return Err(smart_vpn_engine::text("helper_stop_unconfirmed").into());
            }
        }
        Ok(())
    })();
    if result.is_ok() {
        *s.core.lock().unwrap() = None;
        *s.status.lock().unwrap() = "disconnected".into();
        *s.proxy_error
            .lock()
            .map_err(|_| "Не удалось очистить состояние подключения")? = None;
    } else {
        *s.status.lock().unwrap() = "unknown".into();
    }
    result
}

fn connect_for_ticket(s: &State, ticket: u64, manual: bool) -> Result<u16, String> {
    let _guard = s.gate.lock().unwrap();
    finish_connect_locked(s, ticket, manual)
}
fn finish_connect_locked(s: &State, ticket: u64, manual: bool) -> Result<u16, String> {
    if !s.wanted.current(ticket) {
        return Err(smart_vpn_engine::text("connection_cancelled").into());
    }
    let result = connect_locked(s, ticket);
    if manual {
        if result.is_err() {
            if s.wanted.current(ticket) {
                *s.proxy_error
                    .lock()
                    .map_err(|_| "Не удалось сохранить ошибку подключения")? =
                    result.as_ref().err().cloned();
            }
            s.wanted.fail_current(ticket);
        } else {
            s.wanted.finish_current(ticket);
        }
    }
    result
}
fn connect_locked(s: &State, ticket: u64) -> Result<u16, String> {
    if s.installing.load(std::sync::atomic::Ordering::SeqCst) {
        return Err("Выполняется установка обновления.".into());
    }
    if !s.wanted.current(ticket) || !s.wanted.load(std::sync::atomic::Ordering::SeqCst) {
        return Err(smart_vpn_engine::text("connection_cancelled").into());
    }
    *s.proxy_error
        .lock()
        .map_err(|_| "Не удалось подготовить подключение")? = None;
    {
        let mut core = s.core.lock().unwrap();
        if let Some(c) = core.as_mut() {
            if c.alive() {
                return Ok(c.proxy_port);
            }
        }
        *core = None;
    }
    let p = s.profile.lock().unwrap().clone();
    if !p.settings.tun && connection_plan(&p) == ConnectionPlan::NeedsProxyConsent {
        return Err(smart_vpn_engine::text("proxy_setup_needed").into());
    }
    let server = p
        .servers
        .iter()
        .find(|v| Some(&v.id) == p.selected.as_ref())
        .ok_or(smart_vpn_engine::text("message_320"))?;
    *s.status.lock().unwrap() = "connecting".into();
    let result = (|| {
        let core = if p.settings.tun {
            smart_vpn_engine::network_helper::require_current()?;
            let response = smart_vpn_engine::network_helper::request(
                &smart_vpn_engine::network_helper::Request::Start(Box::new(
                    smart_vpn_engine::network_helper::StartRequest {
                        server: server.clone(),
                        reserves: latency::recovery_order(&p.servers, &server.id, &p.settings)
                            .iter()
                            .filter(|id| *id != &server.id)
                            .filter_map(|id| {
                                p.servers
                                    .iter()
                                    .find(|candidate| &candidate.id == id)
                                    .cloned()
                            })
                            .collect(),
                        settings: p.settings.clone(),
                        rules: p.rules.clone(),
                    },
                )),
            )?;
            ActiveCore::remote(response.status)
        } else {
            diagnostics::verify_core(s)?;
            ActiveCore::local(CoreProcess::start_on_port(
                &s.binary,
                server,
                &p.settings,
                &p.rules,
                p.settings.proxy_port,
            )?)
        };
        let c = latency::client(core.proxy_port)?;
        c.get("https://www.gstatic.com/generate_204")
            .send()
            .map_err(|e| smart_vpn_engine::vpn::friendly_error(&e.to_string()))?
            .error_for_status()
            .map_err(|_| smart_vpn_engine::text("message_321"))?;
        if !s.wanted.current(ticket) || !s.wanted.load(std::sync::atomic::Ordering::SeqCst) {
            if core.local.is_none() {
                let _ = smart_vpn_engine::network_helper::request(
                    &smart_vpn_engine::network_helper::Request::Stop,
                );
            }
            return Err(smart_vpn_engine::text("connection_cancelled").into());
        }
        let port = core.proxy_port;
        #[cfg(windows)]
        let mut core = core;
        #[cfg(windows)]
        if p.settings.windows_proxy_auto == Some(true) {
            core.proxy_session = Some(windows_proxy_auto::Session::start(port)?);
        }
        if !s.wanted.current(ticket) {
            return Err(smart_vpn_engine::text("connection_cancelled").into());
        }
        *s.proxy_error.lock().unwrap() = None;
        *s.core.lock().unwrap() = Some(core);
        Ok(port)
    })();
    *s.status.lock().unwrap() = if result.is_ok() {
        "connected"
    } else {
        if p.settings.tun && smart_vpn_engine::network_helper::installed() {
            "unknown"
        } else {
            "disconnected"
        }
    }
    .into();
    result
}
#[tauri::command]
fn prepare_proxy(
    expected_selected: String,
    windows_proxy_auto: Option<bool>,
    s: tauri::State<State>,
) -> Result<(), String> {
    edit(&s, |profile| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        *profile = smart_vpn_engine::settings::prepare_proxy(profile, &expected_selected)?;
        if cfg!(windows) {
            profile.settings.windows_proxy_auto = Some(windows_proxy_auto.unwrap_or(false));
        }
        Ok(())
    })
}
#[tauri::command]
async fn install_network_helper(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let resources = app
            .path()
            .resource_dir()
            .map_err(|_| smart_vpn_engine::text("helper_package"))?;
        tauri::async_runtime::spawn_blocking(move || {
            let package = smart_vpn_engine::network_helper::create_installer(&resources)?;
            std::process::Command::new("/usr/bin/open")
                .arg(package)
                .status()
                .map_err(|_| smart_vpn_engine::text("helper_package"))?;
            Ok(())
        })
        .await
        .map_err(|_| smart_vpn_engine::text("helper_package"))?
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = app;
        Err(smart_vpn_engine::text("helper_macos_only").into())
    }
}
#[tauri::command]
async fn test_recovery() -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(|| {
        smart_vpn_engine::network_helper::request(
            &smart_vpn_engine::network_helper::Request::TestRecovery,
        )
        .map(|_| ())
    })
    .await
    .map_err(|_| smart_vpn_engine::text("helper_ipc"))?
}
#[tauri::command]
fn prepare_tun(s: tauri::State<State>) -> Result<(), String> {
    smart_vpn_engine::network_helper::require_current()?;
    edit(&s, |profile| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        profile.settings.tun = true;
        profile.settings.kill_switch = true;
        Ok(())
    })
}
#[tauri::command]
async fn connect(s: tauri::State<'_, State>) -> Result<u16, String> {
    let state = s.inner().clone();
    let ticket = state.wanted.request()?;
    tauri::async_runtime::spawn_blocking(move || connect_for_ticket(&state, ticket, true))
        .await
        .map_err(|_| smart_vpn_engine::text("message_322"))?
}
#[tauri::command]
async fn stop(s: tauri::State<'_, State>) -> Result<(), String> {
    let state = s.inner().clone();
    let ticket = state.wanted.cancel();
    tauri::async_runtime::spawn_blocking(move || disconnect_for_ticket(&state, ticket))
        .await
        .map_err(|_| smart_vpn_engine::text("message_322"))?
}
fn test_impl(s: &State, id: &str, speed: bool) -> Result<latency::Measurement, String> {
    let _measurement = s
        .measurements
        .lock()
        .map_err(|_| smart_vpn_engine::text("message_323"))?;
    let server = s
        .profile
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|v| v.id == id)
        .cloned()
        .ok_or(smart_vpn_engine::text("message_315"))?;
    let result =
        diagnostics::verify_core(s).and_then(|_| latency::measure(&s.binary, &server, speed));
    edit(s, |p| {
        let Some(v) = p.servers.iter_mut().find(|v| v.id == id) else {
            return Ok(());
        };
        match &result {
            Ok(m) => {
                v.latency_ms = Some(m.latency_ms);
                if m.download_mbps.is_some() {
                    v.download_mbps = m.download_mbps
                }
                v.status = if m.latency_ms > 500 {
                    "slow"
                } else {
                    "available"
                }
                .into();
                v.successes = v.successes.saturating_add(1);
                v.last_error = None
            }
            Err(e) => {
                v.failures = v.failures.saturating_add(1);
                v.status = "unavailable".into();
                v.last_error = Some(e.clone());
                v.latency_ms = None;
                v.download_mbps = None
            }
        }
        Ok(())
    })?;
    result
}
#[tauri::command]
async fn test_server(
    id: String,
    speed: bool,
    s: tauri::State<'_, State>,
) -> Result<latency::Measurement, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || test_impl(&state, &id, speed))
        .await
        .map_err(|_| smart_vpn_engine::text("message_323"))?
}
#[tauri::command]
async fn test_all(app: tauri::AppHandle, s: tauri::State<'_, State>) -> Result<(), String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let ids: Vec<_> = state
            .profile
            .lock()
            .unwrap()
            .servers
            .iter()
            .map(|v| v.id.clone())
            .collect();
        for id in ids {
            let _ = test_impl(&state, &id, false);
            let _ = app.emit("servers-updated", ());
        }
        Ok(())
    })
    .await
    .map_err(|_| smart_vpn_engine::text("message_323"))?
}
#[tauri::command]
fn auto_select(s: tauri::State<State>) -> Result<String, String> {
    if s.core.lock().unwrap().is_some() {
        return Err(smart_vpn_engine::text("message_324").into());
    }
    edit(&s, |p| {
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        let id = latency::select(&p.servers, &p.settings)
            .ok_or(smart_vpn_engine::text("message_325"))?;
        p.selected = Some(id.clone());
        Ok(id)
    })
}
#[tauri::command]
async fn traffic(s: tauri::State<'_, State>) -> Result<statistics::Traffic, String> {
    let Some((port, secret)) = s
        .core
        .lock()
        .unwrap()
        .as_ref()
        .map(|c| (c.api_port, c.secret.clone()))
    else {
        return Ok(statistics::Traffic::default());
    };
    tauri::async_runtime::spawn_blocking(move || statistics::read(port, &secret))
        .await
        .map_err(|_| smart_vpn_engine::text("message_326"))?
}
#[tauri::command]
fn add_subscription(name: String, url: String, s: tauri::State<State>) -> Result<(), String> {
    smart_vpn_engine::subscriptions::validate_url(&url)?;
    edit(&s, |p| {
        if p.subscriptions.iter().any(|v| v.url == url) {
            return Err(smart_vpn_engine::text("message_327").into());
        }
        p.subscriptions.push(Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            url,
            updated_at: None,
            server_count: 0,
        });
        Ok(())
    })
}
#[tauri::command]
fn edit_subscription(
    id: String,
    name: String,
    url: String,
    s: tauri::State<State>,
) -> Result<(), String> {
    edit(&s, |p| {
        if s.core
            .lock()
            .map_err(|_| "Не удалось проверить подключение")?
            .is_some()
        {
            return Err(smart_vpn_engine::text("disconnect_first").into());
        }
        smart_vpn_engine::subscriptions::edit(p, &id, &name, &url)
    })
}
fn update_sub(s: &State, id: &str) -> Result<ImportReport, String> {
    let url = s
        .profile
        .lock()
        .unwrap()
        .subscriptions
        .iter()
        .find(|v| v.id == id)
        .map(|v| v.url.clone())
        .ok_or(smart_vpn_engine::text("message_328"))?;
    let text = smart_vpn_engine::subscriptions::fetch(&url)?;
    let mut imported = vec![];
    let report = servers::import(&text, &mut imported);
    if report.added == 0 || !report.errors.is_empty() {
        return Err(smart_vpn_engine::text("message_329").into());
    }
    edit(s, |p| {
        smart_vpn_engine::subscriptions::source_is_current(p, id, &url)?;
        if s.core.lock().unwrap().is_some() {
            return Err(smart_vpn_engine::text("message_330").into());
        }
        for item in &mut imported {
            item.subscription = Some(id.into());
            if let Some(old) = p.servers.iter().find(|old| {
                old.subscription.as_deref() == Some(id) && old.fingerprint() == item.fingerprint()
            }) {
                let name = item.name.clone();
                *item = old.clone();
                item.name = name;
            }
        }
        p.servers.retain(|v| v.subscription.as_deref() != Some(id));
        for item in imported {
            if !p
                .servers
                .iter()
                .any(|old| old.fingerprint() == item.fingerprint())
            {
                p.servers.push(item)
            }
        }
        let count = p
            .servers
            .iter()
            .filter(|v| v.subscription.as_deref() == Some(id))
            .count();
        if !p.servers.iter().any(|v| Some(&v.id) == p.selected.as_ref()) {
            p.selected = p.servers.first().map(|v| v.id.clone())
        }
        let sub = p
            .subscriptions
            .iter_mut()
            .find(|v| v.id == id)
            .ok_or(smart_vpn_engine::text("message_328"))?;
        sub.server_count = count;
        sub.updated_at = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        );
        Ok(report)
    })
}
#[tauri::command]
async fn update_subscription(
    id: String,
    s: tauri::State<'_, State>,
) -> Result<ImportReport, String> {
    let state = s.inner().clone();
    tauri::async_runtime::spawn_blocking(move || update_sub(&state, &id))
        .await
        .map_err(|_| smart_vpn_engine::text("message_331"))?
}
#[tauri::command]
fn delete_subscription(id: String, s: tauri::State<State>) -> Result<(), String> {
    edit(&s, |p| {
        p.subscriptions.retain(|v| v.id != id);
        for v in &mut p.servers {
            if v.subscription.as_deref() == Some(&id) {
                v.subscription = None;
            }
        }
        Ok(())
    })
}
fn write_private(path: &std::path::Path, text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options
        .open(path)
        .map_err(|_| smart_vpn_engine::text("message_336"))?;
    f.write_all(text.as_bytes())
        .and_then(|_| f.sync_all())
        .map_err(|_| smart_vpn_engine::text("message_337").into())
}
fn main() {
    if std::env::args().nth(1).as_deref() == Some("--foxvpn-ai-worker") {
        if ai_runtime::worker().is_err() {
            std::process::exit(1);
        }
        return;
    }
    #[cfg(target_os = "macos")]
    if let Some(result) = network_cli::run(&std::env::args().nth(1).unwrap_or_default()) {
        match result {
            Ok(report) => {
                println!("{report}");
                return;
            }
            Err(error) => {
                eprintln!("{error}");
                std::process::exit(1);
            }
        }
    }
    #[cfg(windows)]
    if std::env::args().nth(1).as_deref() == Some("--foxvpn-proxy-guardian") {
        std::process::exit(if windows_proxy_auto::guardian().is_ok() {
            0
        } else {
            1
        });
    }
    // Recover even if loading the encrypted profile or creating the UI fails.
    #[cfg(windows)]
    let proxy_recovery_error = windows_proxy_auto::Session::recover().err();
    let strings: serde_json::Value =
        serde_json::from_str(include_str!("../../../../locales/ru.json")).expect("Russian locale");
    let t = move |key: &str| strings[key].as_str().unwrap().to_string();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .setup(move |app| {
            #[cfg(any(target_os = "macos", windows))]
            app.handle()
                .plugin(tauri_plugin_updater::Builder::new().build())?;
            let app_updates =
                updates::AppUpdates::new(app.handle()).map_err(std::io::Error::other)?;
            let pending_helper = updates::pending_helper(app.handle(), &app_updates);
            app.manage(app_updates);
            let vault = Arc::new(Vault::new("ru.smartvpn.router"));
            let profile = vault.load().map_err(std::io::Error::other)?;
            profile.validate().map_err(std::io::Error::other)?;
            let resource = app
                .path()
                .resource_dir()?
                .join("core")
                .join(if cfg!(windows) {
                    "sing-box.exe"
                } else {
                    "sing-box"
                });
            let binary = if resource.exists() {
                resource
            } else {
                PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../core/sing-box")
            };
            let state = State {
                installing: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                profile: Arc::new(Mutex::new(profile.clone())),
                vault,
                core: Arc::new(Mutex::new(None)),
                binary,
                status: Arc::new(Mutex::new("disconnected".into())),
                gate: Arc::new(Mutex::new(())),
                measurements: Arc::new(Mutex::new(())),
                proxy_error: Arc::new(Mutex::new({
                    #[cfg(windows)]
                    {
                        proxy_recovery_error
                    }
                    #[cfg(not(windows))]
                    {
                        None
                    }
                })),
                wanted: Arc::new(smart_vpn_engine::lifecycle::ConnectionIntent::default()),
            };
            if let Ok(response) = smart_vpn_engine::network_helper::request(
                &smart_vpn_engine::network_helper::Request::Status,
            ) {
                *state.status.lock().unwrap() = response.status.connection_state().into();
                if response.status.wanted && response.status.running && response.status.compatible()
                {
                    *state.core.lock().unwrap() = Some(ActiveCore::remote(response.status));
                    *state.status.lock().unwrap() = "connected".into();
                    state
                        .wanted
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            } else if smart_vpn_engine::network_helper::installed() && profile.settings.tun {
                *state.status.lock().unwrap() = "unknown".into();
            }
            app.manage(state.clone());
            app.manage(ai::Assistant::default());
            app.manage(setup_plan::Plans::default());
            metrics::start(state.clone(), app.handle().clone());
            let show = MenuItem::with_id(app, "show", t("open_app"), true, None::<&str>)?;
            let connect = MenuItem::with_id(app, "connect", t("connect"), true, None::<&str>)?;
            let stop = MenuItem::with_id(app, "stop", t("disconnect"), true, None::<&str>)?;
            let tests = MenuItem::with_id(app, "tests", t("test_all"), true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", t("exit"), true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &connect, &stop, &tests, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .tooltip("foxVPN")
                .on_menu_event(|app, e| {
                    let state = app.state::<State>().inner().clone();
                    match e.id.as_ref() {
                        "show" => {
                            if let Some(w) = app.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        }
                        "connect" => {
                            let plan = connection_plan(&state.profile.lock().unwrap());
                            if plan != ConnectionPlan::Ready
                                && !state.profile.lock().unwrap().settings.tun
                            {
                                if let Some(window) = app.get_webview_window("main") {
                                    let _ = window.show();
                                    let _ = window.set_focus();
                                }
                                let _ = app.emit("connection-setup-required", plan);
                                return;
                            }
                            let Ok(ticket) = state.wanted.request() else {
                                return;
                            };
                            let handle = app.clone();
                            tauri::async_runtime::spawn_blocking(move || {
                                if let Err(error) = connect_for_ticket(&state, ticket, true) {
                                    let _ = handle.emit("connection-error", error);
                                }
                                let _ = handle.emit("servers-updated", ());
                            });
                        }
                        "stop" => {
                            let ticket = state.wanted.cancel();
                            let handle = app.clone();
                            tauri::async_runtime::spawn_blocking(move || {
                                if let Err(error) = disconnect_for_ticket(&state, ticket) {
                                    let _ = handle.emit("operation-error", error);
                                }
                                let _ = handle.emit("servers-updated", ());
                            });
                        }
                        "tests" => {
                            let handle = app.clone();
                            tauri::async_runtime::spawn_blocking(move || {
                                let ids: Vec<_> = state
                                    .profile
                                    .lock()
                                    .unwrap()
                                    .servers
                                    .iter()
                                    .map(|v| v.id.clone())
                                    .collect();
                                for id in ids {
                                    let _ = test_impl(&state, &id, false);
                                    let _ = handle.emit("servers-updated", ());
                                }
                            });
                        }
                        "quit" => {
                            if state.installing.load(std::sync::atomic::Ordering::SeqCst) {
                                if let Some(w) = app.get_webview_window("main") {
                                    let _ = w.show();
                                    let _ = w.set_focus();
                                }
                                return;
                            }
                            let ticket = state.wanted.close();
                            if let Err(error) = disconnect_for_ticket(&state, ticket) {
                                state.wanted.reopen();
                                let _ = app.emit("operation-error", error);
                            } else {
                                app.exit(0)
                            }
                        }
                        _ => (),
                    }
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            // Native menu strings remain Russian, including macOS application menu.
            let close =
                MenuItem::with_id(app, "hide", t("hide_window"), true, Some("CmdOrCtrl+W"))?;
            let exit = MenuItem::with_id(app, "exit-app", t("exit"), true, Some("CmdOrCtrl+Q"))?;
            let open = MenuItem::with_id(app, "show-app", t("open_app"), true, None::<&str>)?;
            let app_menu = Submenu::with_items(app, "foxVPN", true, &[&open, &close, &exit])?;
            app.set_menu(Menu::with_items(app, &[&app_menu])?)?;
            let startup_plan = smart_vpn_engine::settings::connection_plan_with_helper(
                &profile,
                smart_vpn_engine::network_helper::ready(),
            );
            if profile.settings.start_minimized
                && !(profile.settings.auto_connect && startup_plan != ConnectionPlan::Ready)
            {
                if let Some(w) = app.get_webview_window("main") {
                    w.hide()?;
                }
            }
            let handle = app.handle().clone();
            let startup_ticket = if !pending_helper
                && profile.settings.auto_connect
                && startup_plan == ConnectionPlan::Ready
            {
                state.wanted.request_startup()
            } else {
                None
            };
            std::thread::spawn(move || {
                if let Some(ticket) = startup_ticket {
                    if let Err(error) = connect_for_ticket(&state, ticket, true) {
                        let _ = handle.emit("connection-error", error);
                    }
                }
                let mut recovery = local_recovery::Worker::new();
                let mut last_sub = std::time::Instant::now();
                loop {
                    let running = state.wanted.load(std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_secs(if running {
                        2
                    } else {
                        10
                    }));
                    let settings = state.profile.lock().unwrap().settings.clone();
                    recovery.tick(&state, &handle);
                    if settings.subscription_interval > 0
                        && last_sub.elapsed().as_secs() >= settings.subscription_interval
                    {
                        last_sub = std::time::Instant::now();
                        if state.core.lock().unwrap().is_none() {
                            let subscriptions = state.profile.lock().unwrap().subscriptions.clone();
                            for sub in &subscriptions {
                                let _ = update_sub(&state, &sub.id);
                            }
                            let _ = handle.emit("servers-updated", ());
                        }
                    }
                }
            });
            Ok(())
        })
        .on_menu_event(|app, e| match e.id.as_ref() {
            "show-app" => {
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                    let _ = w.set_focus();
                }
            }
            "hide" => {
                if app
                    .state::<State>()
                    .installing
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    return;
                }
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.hide();
                }
            }
            "exit-app" => {
                if app
                    .state::<State>()
                    .installing
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                    return;
                }
                let state = app.state::<State>();
                let ticket = state.wanted.close();
                if let Err(error) = disconnect_for_ticket(&state, ticket) {
                    state.wanted.reopen();
                    let _ = app.emit("operation-error", error);
                } else {
                    app.exit(0)
                }
            }
            _ => (),
        })
        .on_window_event(|window, e| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = e {
                api.prevent_close();
                if !window
                    .state::<State>()
                    .installing
                    .load(std::sync::atomic::Ordering::SeqCst)
                {
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            updates::update_state,
            updates::update_preferences,
            updates::check_app_update,
            updates::skip_app_update,
            updates::install_app_update,
            updates::cancel_app_update,
            snapshot,
            windows_proxy_status,
            open_windows_proxy_settings,
            diagnostics::connection_diagnostics,
            setup_check::setup_check,
            setup_plan::prepare_setup_plan,
            setup_plan::apply_setup_plan,
            setup_plan::undo_setup_plan,
            setup_plan::cancel_setup_plan,
            ai::ai_state,
            ai::ai_download,
            ai::ai_cancel,
            ai::ai_explain,
            runtime,
            install_network_helper,
            prepare_tun,
            test_recovery,
            import_servers,
            select_server,
            delete_server,
            favorite,
            rename_server,
            server_uri,
            save_rules,
            save_settings,
            set_metric_settings,
            check_route,
            connect,
            prepare_proxy,
            stop,
            test_server,
            test_all,
            auto_select,
            traffic,
            add_subscription,
            edit_subscription,
            update_subscription,
            delete_subscription,
            file_actions::import_file,
            file_actions::export_backup,
            file_actions::import_backup,
            file_actions::export_config
        ])
        .build(tauri::generate_context!())
        .unwrap_or_else(|_| panic!("{}", smart_vpn_engine::text("message_345")))
        .run(|app, event| {
            #[cfg(target_os = "macos")]
            if matches!(&event, tauri::RunEvent::Reopen { .. }) {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            if let tauri::RunEvent::ExitRequested { code, api, .. } = event {
                let installing = app
                    .state::<State>()
                    .installing
                    .load(std::sync::atomic::Ordering::SeqCst);
                if !updates::exit_allowed(installing, code) {
                    api.prevent_exit();
                    if let Some(w) = app.get_webview_window("main") {
                        let _ = w.show();
                        let _ = w.set_focus();
                    }
                } else if code.is_none() {
                    // Dock/system Quit also requires a positive VPN stop. The
                    // confirmed app.exit(0) below is allowed on the second event.
                    api.prevent_exit();
                    let state = app.state::<State>().inner().clone();
                    let ticket = state.wanted.close();
                    let handle = app.clone();
                    tauri::async_runtime::spawn_blocking(move || {
                        if let Err(error) = disconnect_for_ticket(&state, ticket) {
                            state.wanted.reopen();
                            let _ = handle.emit("operation-error", error);
                            if let Some(w) = handle.get_webview_window("main") {
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                        } else {
                            handle.exit(0);
                        }
                    });
                } else {
                    app.state::<ai::Assistant>().shutdown();
                }
            }
        });
}
