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
        atomic::{AtomicBool, AtomicU8, Ordering},
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
    operation: Arc<AtomicU8>,
    cancel: Arc<Mutex<bool>>,
    operation_id: Arc<Mutex<String>>,
}
struct Busy(Plans);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.operation.store(0, Ordering::SeqCst);
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
    fn request_cancel(&self, operation_id: &str) -> Result<(), String> {
        let mut cancel = self
            .cancel
            .lock()
            .map_err(|_| "Не удалось запросить отмену")?;
        if !self.is_busy()
            || !matches!(self.operation.load(Ordering::SeqCst), 2 | 3)
            || self
                .operation_id
                .lock()
                .map_err(|_| "Настройка недоступна")?
                .as_str()
                != operation_id
        {
            return Err("Настройка ещё не началась или уже завершилась".into());
        }
        *cancel = true;
        Ok(())
    }
    fn acquire(&self, operation: u8, operation_id: &str) -> Result<Busy, String> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "Настройка уже выполняется")?;
        let guard = Busy(self.clone());
        let mut cancel = self
            .cancel
            .lock()
            .map_err(|_| "Не удалось начать настройку")?;
        *cancel = false;
        *self
            .operation_id
            .lock()
            .map_err(|_| "Не удалось начать настройку")? = operation_id.into();
        self.operation.store(operation, Ordering::SeqCst);
        Ok(guard)
    }
}
#[derive(Clone, Serialize)]
pub struct Plan {
    id: String,
    changes: Vec<String>,
    steps: Vec<String>,
    blockers: Vec<String>,
    reconnect: bool,
    scope: String,
    rule_changes: Vec<RuleChange>,
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
    smart_vpn_engine::settings::configuration_digest(p)
}
/// A plan changes configuration, never overwrites newer measurements or
/// subscription timestamps. Credentials/identity must still match for copying.
fn with_observations(desired: &Profile, latest: &Profile) -> Result<Profile, String> {
    let mut target = desired.clone();
    let observations: std::collections::HashMap<_, _> =
        latest.servers.iter().map(|s| (s.id.as_str(), s)).collect();
    for server in &mut target.servers {
        if let Some(current) = observations.get(server.id.as_str()) {
            if server.uri()? == current.uri()? {
                server.latency_ms = current.latency_ms;
                server.download_mbps = current.download_mbps;
                server.status = current.status.clone();
                server.successes = current.successes;
                server.failures = current.failures;
                server.last_error = current.last_error.clone();
            }
        }
    }
    for sub in &mut target.subscriptions {
        if let Some(current) = latest
            .subscriptions
            .iter()
            .find(|s| s.id == sub.id && s.url == sub.url)
        {
            sub.updated_at = current.updated_at;
            sub.server_count = current.server_count;
        }
    }
    Ok(target)
}
#[derive(Clone, Debug, Serialize)]
pub struct RuleChange {
    domain: String,
    previous_route: Option<String>,
    next_route: Option<String>,
    previous_position: Option<usize>,
    next_position: Option<usize>,
}
fn rule_key(rule: &Rule) -> Result<String, String> {
    let wildcard = rule.domain.starts_with("*.");
    let domain = routing::normalize(rule.domain.strip_prefix("*.").unwrap_or(&rule.domain))?;
    Ok(if wildcard {
        format!("*.{domain}")
    } else {
        domain
    })
}
fn rule_changes(before: &[Rule], after: &[Rule]) -> Result<Vec<RuleChange>, String> {
    use std::collections::BTreeMap;
    let map = |rules: &[Rule]| -> Result<BTreeMap<String, (usize, String)>, String> {
        rules
            .iter()
            .enumerate()
            .map(|(i, r)| Ok((rule_key(r)?, (i + 1, r.route.clone()))))
            .collect()
    };
    let old = map(before)?;
    let new = map(after)?;
    let mut result = vec![];
    // Keep the displayed order aligned with the effective priority of new rules.
    for (i, rule) in after.iter().enumerate() {
        let domain = rule_key(rule)?;
        let prior = old.get(&domain);
        if prior.is_none_or(|(position, route)| *position != i + 1 || route != &rule.route) {
            result.push(RuleChange {
                domain,
                previous_route: prior.map(|v| v.1.clone()),
                next_route: Some(rule.route.clone()),
                previous_position: prior.map(|v| v.0),
                next_position: Some(i + 1),
            });
        }
    }
    for (i, rule) in before.iter().enumerate() {
        let domain = rule_key(rule)?;
        if !new.contains_key(&domain) {
            result.push(RuleChange {
                domain,
                previous_route: Some(rule.route.clone()),
                next_route: None,
                previous_position: Some(i + 1),
                next_position: None,
            });
        }
    }
    Ok(result)
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
    let rule_changes = rule_changes(&before.rules, &after.rules)?;
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
    let scope = if windows {
        "Локальный прокси Windows: только совместимые приложения"
    } else if after.settings.tun {
        "Системный VPN всего Mac"
    } else {
        "Локальный прокси Mac: только настроенные приложения"
    }
    .to_string();
    Ok((
        after,
        Plan {
            id: uuid::Uuid::new_v4().to_string(),
            changes,
            steps,
            blockers,
            reconnect,
            scope,
            rule_changes,
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
        let _busy = plans.acquire(1, &check_id)?;
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
    fn complete(&mut self) -> Result<(), String> {
        if self.current() {
            Ok(())
        } else {
            Err("Действие отменено".into())
        }
    }
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
        b.complete()
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
fn verify_proxy_port(port: u16, url: &str) -> Result<(), String> {
    let ok = latency::client(port)?
        .get(url)
        .send()
        .map(|r| r.status().as_u16() == 204)
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err("Контрольный запрос через подключение не прошёл".into())
    }
}
struct Live<'a> {
    state: &'a State,
    plans: &'a Plans,
    ticket: u64,
}
impl Backend for Live<'_> {
    fn current(&self) -> bool {
        self.plans.cancel.lock().is_ok_and(|cancel| !*cancel)
            && self.state.wanted.current(self.ticket)
            && !self.state.installing.load(Ordering::SeqCst)
    }
    fn complete(&mut self) -> Result<(), String> {
        let cancel = self
            .plans
            .cancel
            .lock()
            .map_err(|_| "Не удалось завершить настройку")?;
        if *cancel
            || !self.state.wanted.current(self.ticket)
            || self.state.installing.load(Ordering::SeqCst)
        {
            return Err("Действие отменено".into());
        }
        self.plans.operation.store(0, Ordering::SeqCst);
        Ok(())
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
        verify_proxy_port(port, "https://www.gstatic.com/generate_204")?;
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
pub fn cancel_setup_plan(
    plans: tauri::State<'_, Plans>,
    operation_id: String,
) -> Result<(), String> {
    plans.request_cancel(&operation_id)
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
        let _busy = plans.acquire(2, &plan_id)?;
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
        let before = state
            .profile
            .lock()
            .map_err(|_| "Не удалось прочитать настройки")?
            .clone();
        let after = with_observations(&draft.after, &before)?;
        let ticket = state.wanted.request()?;
        let _ = app.emit(
            "setup-plan-progress",
            "Применяем подтверждённый план и проверяем результат…",
        );
        let result = transact(
            &mut Live {
                state: &state,
                plans: &plans,
                ticket,
            },
            &before,
            &after,
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
            before,
            applied: configured(&after)?,
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
        let _busy=plans.acquire(3, &undo_id)?;let _measure=state.measurements.lock().map_err(|_|"Дождитесь проверки")?;let _gate=state.gate.lock().map_err(|_|"Настройки заняты")?;
        if state.installing.load(Ordering::SeqCst){return Err("Дождитесь обновления приложения".into());}
        let mut saved=plans.undo.lock().map_err(|_|"Возврат недоступен")?;
        let undo=saved.as_ref().ok_or("Прежние настройки недоступны после перезапуска приложения")?;
        let current=state.profile.lock().map_err(|_|"Не удалось прочитать настройки")?.clone();
        if undo.id!=undo_id||configured(&current)?!=undo.applied||!state.wanted.current(undo.ticket){return Err("После настройки состояние изменилось. Автоматический возврат отменён, чтобы сохранить ваши изменения".into());}
        let undo=saved.take().ok_or("Возврат недоступен")?;drop(saved);
        let active=state.core.lock().map_err(|_|"Нет состояния")?.is_some();let ticket=state.wanted.request()?;
        let restored=with_observations(&undo.before,&current)?;
        let result=transact(&mut Live {state:&state,plans:&plans,ticket},&current,&restored,active,active,undo.active);
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
    fn fixture_profile() -> Profile {
        let mut p = Profile::default();
        let server=smart_vpn_engine::servers::Server::parse("vless://11111111-1111-4111-8111-111111111111@127.0.0.1:9?security=none&type=tcp#public-config-test").unwrap();
        p.selected = Some(server.id.clone());
        p.servers.push(server);
        p.subscriptions
            .push(smart_vpn_engine::settings::Subscription {
                id: "public-sub".into(),
                name: "Public".into(),
                url: "https://example.com/public".into(),
                updated_at: None,
                server_count: 1,
            });
        p.settings.tun = false;
        p.settings.kill_switch = false;
        p.settings.mode = Mode::Direct;
        p.settings.proxy_acknowledged = true;
        p.settings.windows_proxy_auto = Some(false);
        p
    }
    fn fixture_state(profile: Profile, path: std::path::PathBuf) -> State {
        State {
            installing: Arc::new(AtomicBool::new(false)),
            profile: Arc::new(Mutex::new(profile)),
            vault: Arc::new(smart_vpn_engine::settings::Vault::test_fixture(
                path, [42; 32],
            )),
            core: Arc::new(Mutex::new(None)),
            binary: std::path::PathBuf::from("unused-public-fixture"),
            status: Arc::new(Mutex::new("disconnected".into())),
            gate: Arc::new(Mutex::new(())),
            measurements: Arc::new(Mutex::new(())),
            proxy_error: Arc::new(Mutex::new(None)),
            wanted: Arc::new(smart_vpn_engine::lifecycle::ConnectionIntent::default()),
        }
    }
    #[test]
    fn subscriptions_and_every_user_server_field_invalidate_freshness_and_undo() {
        let dir = tempfile::tempdir().unwrap();
        let base = fixture_profile();
        let state = fixture_state(base.clone(), dir.path().join("profile.enc"));
        let stamp = ai::stamp(&state).unwrap();
        let digest = configured(&base).unwrap();
        let mut variants = vec![];
        let mut p = base.clone();
        p.subscriptions[0].url = "https://example.org/new".into();
        variants.push(p);
        let mut p = base.clone();
        p.subscriptions[0].name = "Changed".into();
        variants.push(p);
        let mut p = base.clone();
        p.subscriptions.clear();
        variants.push(p);
        let mut p = base.clone();
        p.servers[0].favorite = true;
        variants.push(p);
        let mut p = base.clone();
        p.servers[0].group = "New group".into();
        variants.push(p);
        let mut p = base.clone();
        p.servers[0].name = "New name".into();
        variants.push(p);
        let mut p = base.clone();
        p.servers[0].subscription = Some("public-sub".into());
        variants.push(p);
        let mut p = base.clone();
        p.servers[0]
            .params
            .insert("sni".into(), "example.com".into());
        variants.push(p);
        for p in variants {
            assert_ne!(configured(&p).unwrap(), digest);
            *state.profile.lock().unwrap() = p;
            assert!(fresh(
                "id",
                "id",
                &stamp,
                &ai::stamp(&state).unwrap(),
                Instant::now()
            )
            .is_err());
        }
    }
    #[test]
    fn apply_and_undo_keep_latest_observations_without_expiring_unchanged_configuration() {
        let original = fixture_profile();
        let mut latest = original.clone();
        latest.servers[0].latency_ms = Some(21);
        latest.servers[0].download_mbps = Some(12.5);
        latest.servers[0].successes = 42;
        latest.servers[0].failures = 2;
        latest.servers[0].status = "available".into();
        latest.servers[0].last_error = Some("public observation".into());
        latest.subscriptions[0].updated_at = Some(123);
        latest.subscriptions[0].server_count = 4;
        assert_eq!(configured(&original).unwrap(), configured(&latest).unwrap());
        let dir = tempfile::tempdir().unwrap();
        let state = fixture_state(original.clone(), dir.path().join("profile.enc"));
        let stamp = ai::stamp(&state).unwrap();
        *state.profile.lock().unwrap() = latest.clone();
        assert_eq!(stamp, ai::stamp(&state).unwrap());
        let mut goal = original.clone();
        goal.settings.dns_provider = "google".into();
        let after = with_observations(&goal, &latest).unwrap();
        assert_eq!(after.settings.dns_provider, "google");
        assert_eq!(after.servers[0].latency_ms, Some(21));
        assert_eq!(after.servers[0].successes, 42);
        assert_eq!(after.subscriptions[0].updated_at, Some(123));
        let mut newest = after;
        newest.servers[0].latency_ms = Some(33);
        newest.subscriptions[0].updated_at = Some(456);
        let restored = with_observations(&original, &newest).unwrap();
        assert_eq!(restored.settings.dns_provider, "cloudflare");
        assert_eq!(restored.servers[0].latency_ms, Some(33));
        assert_eq!(restored.subscriptions[0].updated_at, Some(456));
    }
    #[test]
    fn rule_preview_exposes_routes_additions_removals_idn_wildcards_and_priority() {
        let rules = |pairs: &[(&str, &str)]| {
            pairs
                .iter()
                .map(|(d, r)| Rule {
                    domain: (*d).into(),
                    route: (*r).into(),
                })
                .collect::<Vec<_>>()
        };
        let before = rules(&[
            ("example.com", "vpn"),
            ("*.example.ru", "direct"),
            ("пример.рф", "vpn"),
        ]);
        let after = rules(&[
            ("*.example.ru", "direct"),
            ("example.com", "direct"),
            ("new.example.com", "vpn"),
        ]);
        let changes = rule_changes(&before, &after).unwrap();
        assert_eq!(changes.len(), 4);
        assert_eq!(changes[0].domain, "*.example.ru");
        assert_eq!(changes[0].previous_position, Some(2));
        assert_eq!(changes[0].next_position, Some(1));
        assert_eq!(changes[1].previous_route.as_deref(), Some("vpn"));
        assert_eq!(changes[1].next_route.as_deref(), Some("direct"));
        assert!(changes[2].previous_route.is_none());
        assert!(changes[3].next_route.is_none());
        assert!(changes[3].domain.starts_with("xn--"));
        let mut p = fixture_profile();
        p.rules = rules(&[("example.com", "vpn")]);
        let options:Options=serde_json::from_value(serde_json::json!({"rules":[{"domain":"example.com","route":"direct"}],"connect_after":false})).unwrap();
        let (_, view) = build(
            &p,
            &super::super::setup_check::private_fixture_report(),
            &options,
            false,
            true,
            false,
            None,
        )
        .unwrap();
        assert_eq!(view.rule_changes[0].domain, "example.com");
        assert_eq!(view.rule_changes[0].next_route.as_deref(), Some("direct"));
        let large = rules(
            &(0..5000)
                .map(|_| ("unused.example", "vpn"))
                .collect::<Vec<_>>(),
        );
        let before = large
            .iter()
            .enumerate()
            .map(|(i, r)| Rule {
                domain: format!("{i}.example.com"),
                route: r.route.clone(),
            })
            .collect::<Vec<_>>();
        let mut after = before.clone();
        after.reverse();
        assert_eq!(rule_changes(&before, &after).unwrap().len(), 5000);
    }
    #[test]
    fn preview_reports_actual_scope_and_never_silently_upgrades_or_downgrades_it() {
        let p = fixture_profile();
        let report = super::super::setup_check::private_fixture_report();
        let options: Options = serde_json::from_value(
            serde_json::json!({"patch":{"mode":"vpn"},"connect_after":false}),
        )
        .unwrap();
        let (after, plan) = build(&p, &report, &options, false, true, false, None).unwrap();
        assert!(!after.settings.tun);
        assert!(plan.scope.contains("прокси Mac"));
        let options: Options = serde_json::from_value(
            serde_json::json!({"patch":{"mode":"vpn","tun":true},"connect_after":false}),
        )
        .unwrap();
        let (after, plan) = build(&p, &report, &options, false, false, false, None).unwrap();
        assert!(after.settings.tun);
        assert!(plan.scope.contains("всего Mac"));
        assert!(!plan.blockers.is_empty());
    }
    #[test]
    fn cancellation_before_mutation_does_not_change_existing_connection_intent() {
        let dir = tempfile::tempdir().unwrap();
        let profile = fixture_profile();
        let state = fixture_state(profile.clone(), dir.path().join("profile.enc"));
        let ticket = state.wanted.request().unwrap();
        state.wanted.finish_current(ticket);
        let plans = Plans::default();
        let busy = plans.acquire(2, "public-operation").unwrap();
        plans.request_cancel("public-operation").unwrap();
        let live = Live {
            state: &state,
            plans: &plans,
            ticket,
        };
        assert!(!live.current());
        assert!(state.wanted.current(ticket));
        assert!(state.wanted.load(Ordering::SeqCst));
        drop(busy);
        assert!(!plans.is_busy());
        let _busy = plans.acquire(2, "public-operation").unwrap();
        assert!(!*plans.cancel.lock().unwrap());
    }
    struct StoredCore {
        state: State,
        plans: Plans,
        ticket: u64,
        probe: String,
    }
    impl Backend for StoredCore {
        fn current(&self) -> bool {
            Live {
                state: &self.state,
                plans: &self.plans,
                ticket: self.ticket,
            }
            .current()
        }
        fn complete(&mut self) -> Result<(), String> {
            Live {
                state: &self.state,
                plans: &self.plans,
                ticket: self.ticket,
            }
            .complete()
        }
        fn save(&mut self, p: &Profile) -> Result<(), String> {
            Live {
                state: &self.state,
                plans: &self.plans,
                ticket: self.ticket,
            }
            .save(p)
        }
        fn start(&mut self) -> Result<(), String> {
            let p = self.state.profile.lock().unwrap().clone();
            let server = p
                .servers
                .iter()
                .find(|s| Some(&s.id) == p.selected.as_ref())
                .unwrap();
            let core = smart_vpn_engine::vpn::CoreProcess::start_on_port(
                &self.state.binary,
                server,
                &p.settings,
                &p.rules,
                p.settings.proxy_port,
            )?;
            *self.state.core.lock().unwrap() = Some(super::super::ActiveCore::local(core));
            *self.state.status.lock().unwrap() = "connected".into();
            Ok(())
        }
        fn stop(&mut self) -> Result<(), String> {
            let mut owned = self.state.core.lock().unwrap();
            if let Some(c) = owned.as_mut().and_then(|c| c.local.as_mut()) {
                c.stop_checked()?;
            }
            *owned = None;
            *self.state.status.lock().unwrap() = "disconnected".into();
            Ok(())
        }
        fn verify(&mut self) -> Result<(), String> {
            let port = self.state.core.lock().unwrap().as_ref().unwrap().proxy_port;
            verify_proxy_port(port, &self.probe)
        }
    }
    #[test]
    fn transaction_with_real_core_and_encrypted_profile_handles_failure_and_preserves_new_data() {
        let Ok(binary) = std::env::var("SMARTVPN_TEST_CORE") else {
            return;
        };
        use std::io::{Read, Write};
        use std::net::TcpListener;
        let http = TcpListener::bind("127.0.0.1:0").unwrap();
        http.set_nonblocking(true).unwrap();
        let address = http.local_addr().unwrap();
        let responder = std::thread::spawn(move || {
            for status in [204, 503, 204] {
                let deadline = Instant::now() + Duration::from_secs(30);
                let mut stream = loop {
                    match http.accept() {
                        Ok((s, _)) => break s,
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            std::thread::sleep(Duration::from_millis(10))
                        }
                        Err(e) => panic!("public test listener: {e}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = vec![];
                let mut bytes = [0u8; 1024];
                while !request.windows(4).any(|s| s == b"\r\n\r\n") {
                    let count = stream.read(&mut bytes).unwrap();
                    assert!(count > 0 && request.len() < 8192);
                    request.extend_from_slice(&bytes[..count]);
                }
                assert!(String::from_utf8_lossy(&request).contains("/public-transaction"));
                write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("vault/profile.enc");
        let mut p = fixture_profile();
        p.settings.proxy_port = smart_vpn_engine::vpn::free_port().unwrap();
        p.servers[0].latency_ms = Some(31);
        p.subscriptions[0].updated_at = Some(100);
        let mut state = fixture_state(p.clone(), file.clone());
        state.binary = binary.into();
        state.vault.save(&p).unwrap();
        let ticket = state.wanted.request().unwrap();
        let mut backend = StoredCore {
            state,
            plans: Plans::default(),
            ticket,
            probe: format!("http://{address}/public-transaction"),
        };
        let mut desired = p.clone();
        desired.settings.dns_provider = "google".into();
        let desired = with_observations(&desired, &p).unwrap();
        transact(&mut backend, &p, &desired, false, false, true).unwrap();
        assert_eq!(
            backend.state.vault.load().unwrap().settings.dns_provider,
            "google"
        );
        let before = backend.state.profile.lock().unwrap().clone();
        let mut failing = before.clone();
        failing.settings.dns_provider = "quad9".into();
        assert!(transact(&mut backend, &before, &failing, true, true, true).is_err());
        let persisted = backend.state.vault.load().unwrap();
        assert_eq!(persisted.settings.dns_provider, "google");
        assert_eq!(persisted.servers[0].latency_ms, Some(31));
        assert!(backend
            .state
            .core
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .local
            .as_mut()
            .unwrap()
            .alive());
        assert!(!std::fs::read(&file)
            .unwrap()
            .windows(36)
            .any(|b| b == b"11111111-1111-4111-8111-111111111111"));
        let mut current = persisted;
        current.servers[0].latency_ms = Some(77);
        current.subscriptions[0].updated_at = Some(200);
        let restored = with_observations(&p, &current).unwrap();
        transact(&mut backend, &current, &restored, true, true, false).unwrap();
        let saved = backend.state.vault.load().unwrap();
        assert_eq!(saved.settings.dns_provider, "cloudflare");
        assert_eq!(saved.servers[0].latency_ms, Some(77));
        assert_eq!(saved.subscriptions[0].updated_at, Some(200));
        assert!(backend.state.core.lock().unwrap().is_none());
        responder.join().unwrap();
    }
    #[test]
    fn cancellation_is_rejected_after_the_transaction_commit_point() {
        let dir = tempfile::tempdir().unwrap();
        let state = fixture_state(fixture_profile(), dir.path().join("profile.enc"));
        let ticket = state.wanted.request().unwrap();
        let plans = Plans::default();
        let _busy = plans.acquire(2, "public-operation").unwrap();
        let mut live = Live {
            state: &state,
            plans: &plans,
            ticket,
        };
        live.complete().unwrap();
        assert!(plans.request_cancel("public-operation").is_err());
        assert!(!*plans.cancel.lock().unwrap());
    }
    #[test]
    fn poisoned_cancellation_state_releases_the_operation_guard() {
        let plans = Plans::default();
        let copy = plans.clone();
        let _ = std::thread::spawn(move || {
            let _lock = copy.cancel.lock().unwrap();
            panic!("public poison fixture");
        })
        .join();
        assert!(plans.acquire(2, "public-operation").is_err());
        assert!(!plans.is_busy());
    }
    #[test]
    fn a_late_cancel_from_an_older_plan_cannot_cancel_a_newer_operation() {
        let plans = Plans::default();
        let old = plans.acquire(2, "older-plan").unwrap();
        drop(old);
        let _new = plans.acquire(2, "newer-plan").unwrap();
        assert!(plans.request_cancel("older-plan").is_err());
        assert!(!*plans.cancel.lock().unwrap());
        plans.request_cancel("newer-plan").unwrap();
        assert!(*plans.cancel.lock().unwrap());
    }
}
