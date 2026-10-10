//! Typed, consented configuration tools. Model text never becomes executable input.
use super::{ai, diagnostics, setup_check::Report, State};
use serde::{Deserialize, Serialize};
use smart_vpn_engine::{
    latency, network_helper,
    routing::{self, Mode, Rule},
    settings::{Profile, Settings},
};
use std::{
    net::TcpListener,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager};

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Patch {
    mode: Option<Mode>,
    tun: Option<bool>,
    kill_switch: Option<bool>,
    proxy_port: Option<u16>,
    dns_protection: Option<bool>,
    dns_provider: Option<String>,
    dns_transport: Option<String>,
    auto_connect: Option<bool>,
    start_minimized: Option<bool>,
    restore: Option<bool>,
    health_interval: Option<u64>,
    auto_metrics: Option<bool>,
    metric_interval: Option<u64>,
    failover: Option<bool>,
    favorites_only: Option<bool>,
    strategy: Option<String>,
    subscription_interval: Option<u64>,
    windows_proxy_auto: Option<bool>,
}
impl Patch {
    fn apply(&self, s: &mut Settings) {
        macro_rules! set { ($($key:ident),+) => { $(if let Some(value) = &self.$key { s.$key = value.clone(); })+ }; }
        set!(
            mode,
            tun,
            kill_switch,
            proxy_port,
            dns_protection,
            dns_provider,
            dns_transport,
            auto_connect,
            start_minimized,
            restore,
            health_interval,
            auto_metrics,
            metric_interval,
            failover,
            favorites_only,
            strategy,
            subscription_interval
        );
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    #[serde(default)]
    patch: Patch,
    #[serde(default)]
    rules: Option<Vec<Rule>>,
    #[serde(default = "yes")]
    select_recommended: bool,
    #[serde(default = "yes")]
    connect_after: bool,
}
fn yes() -> bool {
    true
}
#[derive(Clone)]
struct Check {
    report: Report,
    stamp: String,
    time: Instant,
}
struct Draft {
    id: String,
    before: Profile,
    after: Profile,
    stamp: String,
    time: Instant,
    active: bool,
    connect: bool,
    view: Plan,
}
struct Undo {
    id: String,
    before: Profile,
    applied: String,
    ticket: u64,
    active: bool,
}
#[derive(Clone, Default)]
pub struct Plans {
    check: Arc<Mutex<Option<Check>>>,
    draft: Arc<Mutex<Option<Draft>>>,
    undo: Arc<Mutex<Option<Undo>>>,
    busy: Arc<AtomicBool>,
}
struct Busy(Plans);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.busy.store(false, Ordering::SeqCst);
    }
}
fn fresh(
    id: &str,
    expected: &str,
    stamp: &str,
    current: &str,
    time: Instant,
) -> Result<(), String> {
    if id != expected || stamp != current || time.elapsed() > Duration::from_secs(120) {
        return Err("План или проверка устарели. Повторите проверку".into());
    }
    Ok(())
}
impl Plans {
    pub(crate) fn is_busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }
    fn acquire(&self) -> Result<Busy, String> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "Настройка уже выполняется")?;
        Ok(Busy(self.clone()))
    }
}
#[derive(Clone, Serialize)]
pub struct Plan {
    id: String,
    changes: Vec<String>,
    steps: Vec<String>,
    blockers: Vec<String>,
    reconnect: bool,
}
#[derive(Serialize)]
pub struct Outcome {
    connected: bool,
    verified: bool,
    undo_id: String,
    message: String,
}
pub fn remember(app: &tauri::AppHandle, report: &Report, stamp: String) -> Result<(), String> {
    *app.state::<Plans>()
        .check
        .lock()
        .map_err(|_| "Не удалось сохранить проверку")? = Some(Check {
        report: report.clone(),
        stamp,
        time: Instant::now(),
    });
    Ok(())
}
fn configured(p: &Profile) -> Result<String, String> {
    // Names and measurements do not invalidate undo; configuration and server credentials do.
    let servers: Vec<_> = p
        .servers
        .iter()
        .map(|s| Ok((&s.id, s.uri()?)))
        .collect::<Result<_, String>>()?;
    let bytes = serde_json::to_vec(&(
        &p.settings,
        &p.selected,
        &p.rules,
        servers,
        &p.subscriptions,
    ))
    .map_err(|_| "Не удалось проверить настройки")?;
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(bytes)))
}
fn free_port(preferred: u16, owned: Option<u16>) -> Result<u16, String> {
    if owned == Some(preferred) || TcpListener::bind(("127.0.0.1", preferred)).is_ok() {
        return Ok(preferred);
    }
    let socket =
        TcpListener::bind(("127.0.0.1", 0)).map_err(|_| "Не найден свободный локальный порт")?;
    socket
        .local_addr()
        .map(|v| v.port())
        .map_err(|_| "Не найден свободный локальный порт".into())
}
fn item(report: &Report, name: &str) -> Option<bool> {
    report.items.iter().find(|i| i.label == name).map(|i| i.ok)
}
fn changed_settings(a: &Settings, b: &Settings) -> Vec<String> {
    let mut result = vec![];
    macro_rules! changed { ($($field:ident => $label:literal),+) => { $(if a.$field!=b.$field { result.push(format!("{}: {} → {}",$label,
        serde_json::to_string(&a.$field).unwrap_or_default(),serde_json::to_string(&b.$field).unwrap_or_default())); })+ }; }
    changed!(mode=>"Режим маршрутизации",tun=>"VPN всего Mac",kill_switch=>"Защита при обрыве",
        proxy_port=>"Локальный порт",dns_protection=>"Защита DNS",dns_provider=>"Провайдер DNS",dns_transport=>"Транспорт DNS",
        auto_connect=>"Подключение при запуске",start_minimized=>"Свёрнутый запуск",restore=>"Восстановление соединения",
        health_interval=>"Интервал проверки, секунд",auto_metrics=>"Автоматические замеры",metric_interval=>"Интервал замеров, секунд",
        failover=>"Резервные серверы",favorites_only=>"Только избранные",strategy=>"Стратегия выбора",subscription_interval=>"Обновление подписок, секунд",
        proxy_acknowledged=>"Согласие на локальный прокси",windows_proxy_auto=>"Автоматический прокси Windows");
    result
}
fn build(
    before: &Profile,
    report: &Report,
    options: &Options,
    windows: bool,
    helper: bool,
    active: bool,
    owned_port: Option<u16>,
) -> Result<(Profile, Plan), String> {
    let mut after = before.clone();
    options.patch.apply(&mut after.settings);
    if let Some(rules) = &options.rules {
        routing::validate(rules)?;
        after.rules = rules.clone();
    }
    if windows {
        if options.patch.tun == Some(true) || options.patch.kill_switch == Some(true) {
            return Err(
                "Windows поддерживает локальный прокси; TUN и Kill Switch здесь недоступны".into(),
            );
        }
        after.settings.tun = false;
        after.settings.kill_switch = false;
        after.settings.proxy_acknowledged = true;
        after.settings.windows_proxy_auto = Some(
            options
                .patch
                .windows_proxy_auto
                .unwrap_or(before.settings.windows_proxy_auto.unwrap_or(true)),
        );
    } else if !after.settings.tun {
        if after.settings.kill_switch {
            return Err("Защита при обрыве требует системного VPN Mac. Её отключение должно быть выбрано явно".into());
        }
        after.settings.proxy_acknowledged = true;
    }
    if !windows && options.patch.windows_proxy_auto.is_some() {
        return Err("Параметр прокси Windows недоступен на Mac".into());
    }
    after.settings.validate()?;
    if options.select_recommended && !active {
        if let Some(id) = latency::select(&report.verified, &after.settings) {
            after.selected = Some(id);
        }
    }
    let mut blockers = vec![];
    if item(report, "Компонент VPN") != Some(true) {
        blockers.push("Ядро не прошло проверку. Сначала переустановите проверенную сборку".into());
    }
    if options.connect_after
        && !after
            .servers
            .iter()
            .any(|s| Some(&s.id) == after.selected.as_ref())
    {
        blockers.push(
            "Добавьте свой VPN-сервер и повторите проверку. Помощник не создаёт ключи доступа"
                .into(),
        );
    }
    if after.settings.tun && !helper {
        blockers.push(
            "Сначала установите или обновите сетевой компонент macOS, затем повторите проверку"
                .into(),
        );
    }
    after.settings.proxy_port = free_port(after.settings.proxy_port, owned_port)?;
    after.validate()?;
    let mut changes = changed_settings(&before.settings, &after.settings);
    if before.selected != after.selected {
        let name = after
            .servers
            .iter()
            .find(|s| Some(&s.id) == after.selected.as_ref())
            .map_or("не выбран", |s| s.name.as_str());
        changes.push(format!("Выбрать проверенный сервер: {name}"));
    }
    if serde_json::to_value(&before.rules).ok() != serde_json::to_value(&after.rules).ok() {
        changes.push(format!(
            "Правила маршрутизации: {} → {} записей",
            before.rules.len(),
            after.rules.len()
        ));
    }
    let modifies = configured(before)? != configured(&after)?;
    let healthy = item(report, "Текущее соединение") == Some(true);
    let reconnect = active && (modifies || !healthy || !options.connect_after);
    let mut steps = vec![];
    if options.select_recommended && active {
        steps.push("Сохранить текущий сервер. Для сравнения других серверов сначала отключите VPN и повторите проверку".into());
    }
    if reconnect {
        steps.push("Остановить текущее соединение и восстановить прежние системные параметры. На время настройки соединение прервётся".into());
    }
    if modifies {
        steps.push("Сохранить выбранные параметры в защищённом профиле".into());
    }
    if options.connect_after {
        if !active || reconnect {
            steps.push("Запустить выбранное подключение".into());
        }
        steps.push("Проверить HTTPS через подключение; для Windows также проверить адрес системного прокси".into());
    } else {
        steps.push("Сохранить настройки без подключения".into());
    }
    if windows
        && after.settings.windows_proxy_auto == Some(true)
        && before.settings.windows_proxy_auto != Some(true)
    {
        steps.push("При подключении включить прокси Windows. Прежние параметры будут сохранены и восстановлены при отключении".into());
    }
    Ok((
        after,
        Plan {
            id: uuid::Uuid::new_v4().to_string(),
            changes,
            steps,
            blockers,
            reconnect,
        },
    ))
}
#[tauri::command]
pub async fn prepare_setup_plan(
    app: tauri::AppHandle,
    plans: tauri::State<'_, Plans>,
    state: tauri::State<'_, State>,
    check_id: String,
    options: Options,
) -> Result<Plan, String> {
    let plans = plans.inner().clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = plans.acquire()?;
        let _gate = state.gate.lock().map_err(|_| "Настройки заняты")?;
        if state.installing.load(Ordering::SeqCst) {
            return Err("Дождитесь обновления приложения".into());
        }
        let stamp = ai::stamp(&state)?;
        let check = plans
            .check
            .lock()
            .map_err(|_| "Проверка недоступна")?
            .clone()
            .ok_or("Сначала выполните проверку подключения")?;
        fresh(
            &check.report.check_id,
            &check_id,
            &check.stamp,
            &stamp,
            check.time,
        )?;
        let before = state
            .profile
            .lock()
            .map_err(|_| "Не удалось прочитать настройки")?
            .clone();
        let active = state
            .status
            .lock()
            .map_err(|_| "Не удалось прочитать состояние")?
            .as_str()
            != "disconnected";
        let owned = state
            .core
            .lock()
            .map_err(|_| "Не удалось прочитать состояние")?
            .as_ref()
            .map(|c| c.proxy_port);
        let helper = network_helper::ready();
        let (after, view) = build(
            &before,
            &check.report,
            &options,
            cfg!(windows),
            helper,
            active,
            owned,
        )?;
        // Switching from proxy to TUN still needs an authenticated component.
        if after.settings.tun && helper {
            network_helper::require_current()?;
        }
        *plans
            .draft
            .lock()
            .map_err(|_| "Не удалось сохранить план")? = Some(Draft {
            id: view.id.clone(),
            before,
            after,
            stamp,
            time: Instant::now(),
            active,
            connect: options.connect_after,
            view: view.clone(),
        });
        let _ = app.emit(
            "setup-plan-progress",
            "План готов. Изменения ещё не применялись",
        );
        Ok(view)
    })
    .await
    .map_err(|_| "Не удалось подготовить план")?
}

trait Backend {
    fn current(&self) -> bool;
    fn stop(&mut self) -> Result<(), String>;
    fn save(&mut self, p: &Profile) -> Result<(), String>;
    fn start(&mut self) -> Result<(), String>;
    fn verify(&mut self) -> Result<(), String>;
}
/// Every failed stage restores configuration; restoration failure is reported explicitly.
fn transact(
    b: &mut impl Backend,
    before: &Profile,
    after: &Profile,
    active: bool,
    reconnect: bool,
    connect: bool,
) -> Result<(), String> {
    let mut touched = false;
    let modifies = configured(before)? != configured(after)?;
    let result = (|| {
        if !b.current() {
            return Err("Действие отменено или состояние изменилось".into());
        }
        if reconnect {
            b.stop()?;
            touched = true;
        }
        if !b.current() {
            return Err("Действие отменено".into());
        }
        if modifies || reconnect {
            touched = true;
            b.save(after)?;
        }
        if connect {
            if !active || reconnect {
                touched = true;
                b.start()?;
            }
            b.verify()?;
        }
        if !b.current() {
            return Err("Действие отменено".into());
        }
        Ok(())
    })();
    if let Err(error) = result {
        if !touched {
            return Err(error);
        }
        let was_current = b.current();
        let stopped = b.stop();
        // Never restore/restart while stopping a possibly live tunnel failed.
        if let Err(stop) = stopped {
            return Err(format!("{error}. Остановка не подтверждена: {stop}. Настройки не восстанавливались; выполните проверку"));
        }
        if let Err(save) = b.save(before) {
            return Err(format!(
                "{error}. Не удалось вернуть прежние настройки: {save}"
            ));
        }
        if active && was_current {
            if let Err(start) = b.start().and_then(|_| b.verify()) {
                return Err(format!(
                    "{error}. Прежние настройки возвращены, подключение не восстановлено: {start}"
                ));
            }
        }
        return Err(format!("{error}. Прежние настройки возвращены"));
    }
    Ok(())
}
struct Live<'a> {
    state: &'a State,
    ticket: u64,
}
impl Backend for Live<'_> {
    fn current(&self) -> bool {
        self.state.wanted.current(self.ticket) && !self.state.installing.load(Ordering::SeqCst)
    }
    fn stop(&mut self) -> Result<(), String> {
        super::disconnect_locked(self.state, self.state.wanted.ticket())
    }
    fn save(&mut self, p: &Profile) -> Result<(), String> {
        p.validate()?;
        self.state.vault.save(p)?;
        *self
            .state
            .profile
            .lock()
            .map_err(|_| "Не удалось сохранить настройки")? = p.clone();
        Ok(())
    }
    fn start(&mut self) -> Result<(), String> {
        if !self.current() {
            return Err("Действие отменено".into());
        }
        super::finish_connect_locked(self.state, self.ticket, false).map(|_| ())
    }
    fn verify(&mut self) -> Result<(), String> {
        if !self.current() {
            return Err("Действие отменено".into());
        }
        let port = self
            .state
            .core
            .lock()
            .map_err(|_| "Нет подключения")?
            .as_ref()
            .map(|c| c.proxy_port)
            .ok_or("Подключение не запущено")?;
        let ok = latency::client(port)?
            .get("https://www.gstatic.com/generate_204")
            .send()
            .map(|r| r.status().as_u16() == 204)
            .unwrap_or(false);
        if !ok {
            return Err("Контрольный HTTPS-запрос не прошёл".into());
        }
        #[cfg(windows)]
        if self
            .state
            .profile
            .lock()
            .map_err(|_| "Не удалось прочитать настройки")?
            .settings
            .windows_proxy_auto
            == Some(true)
            && !smart_vpn_engine::windows_proxy::read(port)?.matches
        {
            return Err("Прокси Windows не подтвердил новые параметры".into());
        }
        if self
            .state
            .profile
            .lock()
            .map_err(|_| "Не удалось прочитать настройки")?
            .settings
            .tun
        {
            let s = network_helper::request(&network_helper::Request::Status)?.status;
            if !s.compatible() || !s.running || !s.core_alive || !s.dns_active {
                return Err("Системный VPN/DNS не подтвердил подключение".into());
            }
            if self
                .state
                .profile
                .lock()
                .map_err(|_| "Не удалось прочитать настройки")?
                .settings
                .kill_switch
                && !s.kill_switch
            {
                return Err("Защита при обрыве не подтвердилась".into());
            }
        }
        Ok(())
    }
}
#[tauri::command]
pub async fn apply_setup_plan(
    app: tauri::AppHandle,
    plans: tauri::State<'_, Plans>,
    state: tauri::State<'_, State>,
    plan_id: String,
    approved: bool,
) -> Result<Outcome, String> {
    if !approved {
        return Err("Подтвердите конкретный план изменений".into());
    }
    let plans = plans.inner().clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = plans.acquire()?;
        let _measure = state
            .measurements
            .lock()
            .map_err(|_| "Дождитесь завершения проверки")?;
        let _gate = state.gate.lock().map_err(|_| "Настройки заняты")?;
        if state.installing.load(Ordering::SeqCst) {
            return Err("Дождитесь обновления приложения".into());
        }
        let mut stored = plans.draft.lock().map_err(|_| "План недоступен")?;
        let draft = stored.as_ref().ok_or("Сначала подготовьте план")?;
        fresh(
            &draft.id,
            &plan_id,
            &draft.stamp,
            &ai::stamp(&state)?,
            draft.time,
        )?;
        if !draft.view.blockers.is_empty() {
            return Err(draft.view.blockers.join(". "));
        }
        let draft = stored.take().ok_or("План недоступен")?;
        drop(stored);
        diagnostics::verify_core(&state)?;
        let owned = state
            .core
            .lock()
            .map_err(|_| "Нет состояния подключения")?
            .as_ref()
            .map(|c| c.proxy_port);
        if free_port(draft.after.settings.proxy_port, owned)? != draft.after.settings.proxy_port {
            return Err("Порт заняли после подготовки плана. Подготовьте новый план".into());
        }
        let ticket = state.wanted.request()?;
        let _ = app.emit(
            "setup-plan-progress",
            "Применяем подтверждённый план и проверяем результат…",
        );
        let result = transact(
            &mut Live {
                state: &state,
                ticket,
            },
            &draft.before,
            &draft.after,
            draft.active,
            draft.view.reconnect,
            draft.connect,
        );
        if let Err(error) = result {
            if state
                .core
                .lock()
                .map_err(|_| "Нет состояния подключения")?
                .is_some()
            {
                state.wanted.finish_current(ticket);
            } else {
                state.wanted.fail_current(ticket);
            }
            let _ = app.emit("servers-updated", ());
            return Err(error);
        }
        state.wanted.finish_current(ticket);
        if !draft.connect {
            state.wanted.fail_current(ticket);
        }
        let id = uuid::Uuid::new_v4().to_string();
        *plans
            .undo
            .lock()
            .map_err(|_| "Не удалось сохранить возврат настроек")? = Some(Undo {
            id: id.clone(),
            before: draft.before,
            applied: configured(&draft.after)?,
            ticket,
            active: draft.active,
        });
        let _ = app.emit("servers-updated", ());
        Ok(Outcome {
            connected: draft.connect,
            verified: draft.connect,
            undo_id: id,
            message: if draft.connect {
                "Настройки применены; подключение и контрольный HTTPS-запрос подтверждены"
            } else {
                "Настройки сохранены без подключения"
            }
            .into(),
        })
    })
    .await
    .map_err(|_| "Не удалось завершить настройку")?
}
#[tauri::command]
pub async fn undo_setup_plan(
    app: tauri::AppHandle,
    plans: tauri::State<'_, Plans>,
    state: tauri::State<'_, State>,
    undo_id: String,
    approved: bool,
) -> Result<(), String> {
    if !approved {
        return Err("Подтвердите возврат прежних настроек".into());
    }
    let plans = plans.inner().clone();
    let state = state.inner().clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _busy=plans.acquire()?;let _measure=state.measurements.lock().map_err(|_|"Дождитесь проверки")?;let _gate=state.gate.lock().map_err(|_|"Настройки заняты")?;
        if state.installing.load(Ordering::SeqCst){return Err("Дождитесь обновления приложения".into());}
        let mut saved=plans.undo.lock().map_err(|_|"Возврат недоступен")?;
        let undo=saved.as_ref().ok_or("Прежние настройки недоступны после перезапуска приложения")?;
        let current=state.profile.lock().map_err(|_|"Не удалось прочитать настройки")?.clone();
        if undo.id!=undo_id||configured(&current)?!=undo.applied||!state.wanted.current(undo.ticket){return Err("После настройки состояние изменилось. Автоматический возврат отменён, чтобы сохранить ваши изменения".into());}
        let undo=saved.take().ok_or("Возврат недоступен")?;drop(saved);
        let active=state.core.lock().map_err(|_|"Нет состояния")?.is_some();let ticket=state.wanted.request()?;
        let result=transact(&mut Live {state:&state,ticket},&current,&undo.before,active,active,undo.active);
        state.wanted.finish_current(ticket);
        if state.core.lock().map_err(|_|"Нет состояния подключения")?.is_none(){state.wanted.fail_current(ticket);}
        let _=app.emit("servers-updated",());result
    }).await.map_err(|_|"Не удалось вернуть настройки")?
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        log: Vec<&'static str>,
        fail: &'static str,
        current: bool,
    }
    impl Backend for Fake {
        fn current(&self) -> bool {
            self.current
        }
        fn stop(&mut self) -> Result<(), String> {
            self.log.push("stop");
            if self.fail == "stop" {
                Err("stop failed".into())
            } else {
                Ok(())
            }
        }
        fn save(&mut self, _: &Profile) -> Result<(), String> {
            self.log.push("save");
            if self.fail == "save" {
                self.fail = "";
                return Err("save failed".into());
            }
            Ok(())
        }
        fn start(&mut self) -> Result<(), String> {
            self.log.push("start");
            if self.fail == "cancel" {
                self.current = false;
            }
            if self.fail == "start" {
                self.fail = "";
                return Err("start failed".into());
            }
            Ok(())
        }
        fn verify(&mut self) -> Result<(), String> {
            self.log.push("verify");
            if self.fail == "verify" {
                self.fail = "";
                Err("verify failed".into())
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn success_is_verified_and_failure_restores_then_verifies_previous_connection() {
        let p = Profile::default();
        let mut b = Fake {
            log: vec![],
            fail: "",
            current: true,
        };
        transact(&mut b, &p, &p, true, true, true).unwrap();
        assert_eq!(b.log, vec!["stop", "save", "start", "verify"]);
        b.log.clear();
        b.fail = "verify";
        assert!(transact(&mut b, &p, &p, true, true, true)
            .unwrap_err()
            .contains("Прежние настройки возвращены"));
        assert_eq!(
            b.log,
            vec!["stop", "save", "start", "verify", "stop", "save", "start", "verify"]
        );
    }
    #[test]
    fn cancellation_and_unconfirmed_stop_do_not_write_configuration() {
        let p = Profile::default();
        let mut b = Fake {
            log: vec![],
            fail: "stop",
            current: true,
        };
        assert!(transact(&mut b, &p, &p, true, true, true).is_err());
        assert_eq!(b.log, vec!["stop"]);
        b.log.clear();
        b.current = false;
        assert!(transact(&mut b, &p, &p, false, false, true).is_err());
        assert!(b.log.is_empty());
    }
    #[test]
    fn plans_cover_all_supported_settings_and_reject_invented_tools() {
        let o:Options=serde_json::from_value(serde_json::json!({"patch":{"mode":"vpn","dns_provider":"quad9","dns_transport":"tls","auto_connect":true,"start_minimized":true,"restore":true,"health_interval":45,"auto_metrics":false,"metric_interval":1200,"failover":true,"favorites_only":false,"strategy":"latency","subscription_interval":3600},"connect_after":false})).unwrap();
        let p = Profile::default();
        let r = super::super::setup_check::private_fixture_report();
        let (after, view) = build(&p, &r, &o, true, false, false, None).unwrap();
        assert!(!after.settings.tun && !after.settings.kill_switch);
        assert_eq!(after.settings.windows_proxy_auto, Some(true));
        assert_eq!(after.settings.dns_provider, "quad9");
        assert_eq!(after.settings.metric_interval, 1200);
        assert!(!view.changes.is_empty());
        assert!(serde_json::from_value::<Options>(serde_json::json!({"shell":"whoami"})).is_err());
        assert!(
            serde_json::from_value::<Options>(serde_json::json!({"patch":{"exec":"whoami"}}))
                .is_err()
        );
    }
    #[test]
    fn unsupported_windows_tun_and_unapproved_mac_downgrade_are_rejected() {
        let p = Profile::default();
        let r = super::super::setup_check::private_fixture_report();
        let options =
            |patch| serde_json::from_value::<Options>(serde_json::json!({"patch":patch})).unwrap();
        assert!(build(
            &p,
            &r,
            &options(serde_json::json!({"tun":true})),
            true,
            false,
            false,
            None
        )
        .is_err());
        assert!(build(
            &p,
            &r,
            &options(serde_json::json!({"tun":false})),
            false,
            true,
            false,
            None
        )
        .is_err());
    }
    #[test]
    fn occupied_port_has_a_concrete_preview_and_rules_are_validated() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        assert_ne!(free_port(port, None).unwrap(), port);
        assert_eq!(free_port(port, Some(port)).unwrap(), port);
        let r = super::super::setup_check::private_fixture_report();
        let p = Profile::default();
        let o:Options=serde_json::from_value(serde_json::json!({"rules":[{"domain":"invalid/path","route":"vpn"}],"connect_after":false})).unwrap();
        assert!(build(&p, &r, &o, true, false, false, None).is_err());
    }
    #[test]
    fn stale_or_forged_plans_are_rejected() {
        let t = Instant::now();
        assert!(fresh("id", "id", "stamp", "stamp", t).is_ok());
        assert!(fresh("id", "forged", "stamp", "stamp", t).is_err());
        assert!(fresh("id", "id", "stamp", "changed", t).is_err());
        assert!(fresh("id", "id", "stamp", "stamp", t - Duration::from_secs(121)).is_err());
    }
    #[test]
    fn verification_of_unchanged_active_session_never_disconnects_it_on_failure() {
        let p = Profile::default();
        let mut b = Fake {
            log: vec![],
            fail: "verify",
            current: true,
        };
        assert!(transact(&mut b, &p, &p, true, false, true).is_err());
        assert_eq!(b.log, vec!["verify"]);
    }
    #[test]
    fn failed_save_restores_configuration_before_any_new_connection() {
        let p = Profile::default();
        let mut after = p.clone();
        after.settings.dns_provider = "google".into();
        let mut b = Fake {
            log: vec![],
            fail: "save",
            current: true,
        };
        assert!(transact(&mut b, &p, &after, false, false, true).is_err());
        assert_eq!(b.log, vec!["save", "stop", "save"]);
    }
    #[test]
    fn failed_start_and_cancelled_start_restore_without_restarting_over_user_intent() {
        let p = Profile::default();
        let mut b = Fake {
            log: vec![],
            fail: "start",
            current: true,
        };
        assert!(transact(&mut b, &p, &p, false, false, true).is_err());
        assert_eq!(b.log, vec!["start", "stop", "save"]);
        b.log.clear();
        b.fail = "cancel";
        assert!(transact(&mut b, &p, &p, false, false, true).is_err());
        assert_eq!(b.log, vec!["start", "verify", "stop", "save"]);
    }
    #[test]
    fn changed_user_configuration_invalidates_undo() {
        let mut p = Profile::default();
        let before = configured(&p).unwrap();
        p.settings.auto_connect = true;
        assert_ne!(configured(&p).unwrap(), before);
    }
}
