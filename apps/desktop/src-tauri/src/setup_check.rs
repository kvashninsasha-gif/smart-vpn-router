//! Read-only guided checks. Repairs use the existing consent-gated commands.
use super::{diagnostics, State};
use serde::Serialize;
use smart_vpn_engine::{latency, network_helper, servers::Server};
use tauri::Emitter;

#[derive(Serialize)]
pub struct Item {
    pub(crate) label: &'static str,
    pub(crate) ok: bool,
    message: String,
}
#[derive(Serialize)]
pub struct Candidate {
    id: String,
    name: String,
    latency_ms: u64,
}
#[derive(Serialize)]
pub struct Report {
    pub(crate) items: Vec<Item>,
    pub(crate) action: &'static str,
    selected: Option<String>,
    pub(crate) recommendation: Option<Candidate>,
    pub(crate) tested: usize,
    pub(crate) total: usize,
    changed: bool,
    pub(crate) check_id: String,
}
#[allow(clippy::too_many_arguments)]
fn action(
    core: bool,
    server: bool,
    active: bool,
    tun: bool,
    helper: network_helper::Probe,
    windows: bool,
    proxy_matches: bool,
    healthy: bool,
) -> &'static str {
    if !core {
        "reinstall"
    } else if !server {
        "add_server"
    } else if tun && !windows && helper != network_helper::Probe::Ready {
        if helper == network_helper::Probe::Starting {
            "wait_helper"
        } else {
            "helper"
        }
    } else if active {
        if windows && healthy && !proxy_matches {
            "windows_proxy"
        } else {
            "none"
        }
    } else if healthy {
        "connect"
    } else {
        "none"
    }
}
fn item(items: &mut Vec<Item>, label: &'static str, ok: bool, message: impl Into<String>) {
    items.push(Item {
        label,
        ok,
        message: message.into(),
    });
}
#[cfg(any(windows, test))]
fn manual_proxy_is_unambiguous(matches: bool, flags: Option<u32>) -> bool {
    matches && flags.is_some_and(|v| v & (4 | 8) == 0)
}
#[tauri::command]
pub async fn setup_check(
    app: tauri::AppHandle,
    state: tauri::State<'_, State>,
) -> Result<Report, String> {
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _measurement = state.measurements.lock().map_err(|_| "Проверка показателей уже занята")?;
        let initial_stamp = super::ai::stamp(&state)?;
        let profile = state.profile.lock().map_err(|_| "Не удалось прочитать настройки")?.clone();
        let ticket = state.wanted.ticket();
        let active = state.status.lock().map_err(|_| "Не удалось прочитать состояние")?.as_str() != "disconnected";
        let current = state.core.lock().map_err(|_| "Не удалось прочитать подключение")?
            .as_ref().map(|c| (c.proxy_port, c.secret.clone()));
        let mut items = vec![];
        let core = diagnostics::verify_core(&state).is_ok();
        item(&mut items, "Компонент VPN", core, if core { "Целостность ядра подтверждена" }
            else { "Ядро отсутствует или не прошло проверку. Переустановите проверенную сборку foxVPN" });
        let helper = network_helper::probe(std::time::Duration::ZERO);
        if cfg!(target_os = "macos") {
            item(&mut items, "Сетевой компонент macOS", helper == network_helper::Probe::Ready,
                match helper {
                    network_helper::Probe::Ready => "Компонент соответствует приложению",
                    network_helper::Probe::Missing => "Компонент не установлен. Для VPN всего Mac нужна установка",
                    network_helper::Probe::Stale => "Компонент требует обновления для этой сборки",
                    network_helper::Probe::Starting => "Компонент запускается. Повторите проверку позднее",
                });
            if profile.settings.tun && helper == network_helper::Probe::Ready && active {
                if let Ok(response) = network_helper::request(&network_helper::Request::Status) {
                    item(&mut items, "Системный DNS", response.status.dns_active,
                        if response.status.dns_active { "Компонент сообщает, что системный DNS настроен" }
                        else { "Компонент не подтверждает активный системный DNS. Проверьте настройки" });
                }
            }
        }
        let mut healthy = false;
        let mut successes: Vec<Server> = vec![];
        let mut tested = 0;
        if active {
            if let Some((port, _)) = &current {
                let _ = app.emit("setup-check-progress", "Проверяем текущее соединение…");
                healthy = latency::client(*port).and_then(|c| c.get("https://www.gstatic.com/generate_204")
                    .send().map(|r| r.status().as_u16() == 204).map_err(|_| "Контрольный HTTPS-запрос не прошёл".into()))
                    .unwrap_or(false);
            }
            item(&mut items, "Текущее соединение", healthy, if healthy {
                "Контрольный HTTPS-запрос через текущий локальный порт прошёл. Подключение не прерывалось"
            } else { "Контрольный запрос не прошёл или состояние неизвестно. Переподключение не выполнялось" });
        } else if core && profile.settings.mode == smart_vpn_engine::routing::Mode::Direct {
            healthy = latency::probe_without_proxy().unwrap_or(false);
            item(&mut items, "Режим напрямую", healthy, "Контрольный HTTPS-запрос без локального прокси. Маршруты ОС сохраняются; VPN-серверы не проверялись");
        } else if core {
            let mut candidates: Vec<_> = profile.servers.iter()
                .filter(|s| !profile.settings.favorites_only || s.favorite).cloned().collect();
            candidates.sort_by_key(|s| Some(&s.id) != profile.selected.as_ref());
            for server in candidates.into_iter().take(3) {
                if !state.wanted.current(ticket) || state.core.lock().map_err(|_| "Не удалось прочитать состояние")?.is_some() { break; }
                diagnostics::verify_core(&state)?;
                tested += 1;
                let _ = app.emit("setup-check-progress", format!("Проверяем сервер {tested} из максимум 3…"));
                if let Ok(measurement) = latency::measure(&state.binary, &server, false) {
                    let mut checked = server;
                    checked.latency_ms = Some(measurement.latency_ms);
                    checked.status = "available".into();
                    successes.push(checked);
                }
            }
            healthy = successes.iter().any(|s| Some(&s.id) == profile.selected.as_ref());
            item(&mut items, "Доступность серверов", !successes.is_empty(),
                format!("Проверено {tested}; доступно {}. Проверка без скачивания файла для замера скорости", successes.len()));
        }
        let port = current.as_ref().map_or(profile.settings.proxy_port, |c| c.0);
        let proxy_matches = if cfg!(windows) {
            match smart_vpn_engine::windows_proxy::read(port) {
                Ok(status) => {
                    #[cfg(windows)]
                    let matches = manual_proxy_is_unambiguous(status.matches,
                        smart_vpn_engine::windows_proxy::configuration().ok().map(|c| c.flags));
                    #[cfg(not(windows))]
                    let matches = status.matches;
                    item(&mut items, "Прокси Windows", matches,
                        if matches { "Ручной прокси указывает на foxVPN; расширения браузера могут переопределять маршрут" }
                        else { "Прокси Windows не указывает однозначно на foxVPN: адрес не совпадает либо автоматические параметры переопределяют маршрут. Можно настроить Windows с согласия" });
                    matches
                }
                Err(_) => { item(&mut items, "Прокси Windows", false, "Не удалось прочитать параметры Windows"); false }
            }
        } else { true };
        let latest = state.profile.lock().map_err(|_| "Не удалось прочитать настройки")?.clone();
        let latest_current = state.core.lock().map_err(|_| "Не удалось прочитать состояние")?
            .as_ref().map(|c| (c.proxy_port, c.secret.clone()));
        let selected_config = |p: &smart_vpn_engine::settings::Profile| p.servers.iter().find(|s| Some(&s.id) == p.selected.as_ref()).and_then(|s| s.uri().ok());
        let changed = super::ai::stamp(&state)? != initial_stamp || !state.wanted.current(ticket) || latest.selected != profile.selected || latest_current != current
            || selected_config(&latest) != selected_config(&profile)
            || serde_json::to_value(&latest.settings).ok() != serde_json::to_value(&profile.settings).ok()
            || serde_json::to_value(&latest.rules).ok() != serde_json::to_value(&profile.rules).ok();
        successes.retain(|s| latest.servers.iter().any(|v| v.id == s.id && v.favorite == s.favorite && v.uri().ok() == s.uri().ok()));
        let recommendation = if !active && !changed {
            latency::select(&successes, &profile.settings).and_then(|id| successes.iter().find(|s| s.id == id))
                .map(|s| Candidate { id: s.id.clone(), name: s.name.clone(), latency_ms: s.latency_ms.unwrap_or_default() })
        } else { None };
        if changed { item(&mut items, "Актуальность проверки", false, "Подключение или выбранный сервер изменились. Повторите проверку"); }
        let server = latest.servers.iter().any(|s| Some(&s.id) == latest.selected.as_ref());
        let next = if changed { "none" } else { action(core, server, active, profile.settings.tun, helper,
            cfg!(windows), proxy_matches, healthy) };
        let report = Report { items, action: next, selected: latest.selected, recommendation, tested,
            total: profile.servers.len(), changed, check_id: if changed { String::new() } else { uuid::Uuid::new_v4().to_string() } };
        if !changed { super::ai::remember(&app, &report, initial_stamp)?; }
        Ok(report)
    }).await.map_err(|_| "Не удалось завершить проверку")?
}
#[cfg(test)]
pub(crate) fn private_fixture_report() -> Report {
    Report {
        items: vec![Item {
            label: "Компонент VPN",
            ok: true,
            message: "PRIVATE_TOKEN PRIVATE_URI".into(),
        }],
        action: "connect",
        selected: Some("PRIVATE_SERVER_ID".into()),
        recommendation: Some(Candidate {
            id: "PRIVATE_OTHER_ID".into(),
            name: "PRIVATE_SERVER_NAME".into(),
            latency_ms: 99,
        }),
        tested: 3,
        total: 200,
        changed: false,
        check_id: "public-check".into(),
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use network_helper::Probe::*;
    #[test]
    fn pac_and_auto_detection_do_not_count_as_confirmed_manual_proxy() {
        assert!(manual_proxy_is_unambiguous(true, Some(3)));
        assert!(!manual_proxy_is_unambiguous(true, Some(11)));
        assert!(!manual_proxy_is_unambiguous(true, Some(7)));
        assert!(!manual_proxy_is_unambiguous(true, None));
        assert!(!manual_proxy_is_unambiguous(false, Some(3)));
    }
    #[test]
    fn plans_repairs_without_connecting_or_stopping_active_sessions() {
        assert_eq!(
            action(false, true, false, false, Missing, true, false, true),
            "reinstall"
        );
        assert_eq!(
            action(true, false, false, true, Missing, false, false, false),
            "add_server"
        );
        assert_eq!(
            action(true, true, false, true, Stale, false, false, true),
            "helper"
        );
        assert_eq!(
            action(true, true, false, true, Starting, false, false, true),
            "wait_helper"
        );
        assert_eq!(
            action(true, true, true, false, Missing, true, false, true),
            "windows_proxy"
        );
        assert_eq!(
            action(true, true, true, false, Missing, true, false, false),
            "none"
        );
        assert_eq!(
            action(true, true, true, true, Ready, false, true, true),
            "none"
        );
        assert_eq!(
            action(true, true, false, true, Ready, false, true, true),
            "connect"
        );
        assert_eq!(
            action(true, true, false, false, Missing, true, false, false),
            "none"
        );
    }
}
