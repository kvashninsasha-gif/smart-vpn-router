//! Optional local explanations. The model has no repair/execution authority.
use super::{
    ai_runtime::{self, Action, Facts, Job, Platform},
    setup_check::Report,
    State,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tauri::{Emitter, Manager};

struct Check {
    id: String,
    facts: Facts,
    stamp: String,
    time: Instant,
}
struct DownloadDigest {
    hash: Sha256,
    bytes: u64,
}
impl DownloadDigest {
    fn new() -> Self {
        Self {
            hash: Sha256::new(),
            bytes: 0,
        }
    }
    fn add(&mut self, chunk: &[u8], limit: u64) -> Result<(), String> {
        let size = self
            .bytes
            .checked_add(chunk.len() as u64)
            .ok_or("Модель слишком велика")?;
        if size > limit {
            return Err("Модель превысила допустимый размер".into());
        }
        self.hash.update(chunk);
        self.bytes = size;
        Ok(())
    }
    fn finish(self, size: u64, sha: &str) -> Result<(), String> {
        if self.bytes != size || format!("{:x}", self.hash.finalize()) != sha {
            return Err("Модель не прошла проверку размера и SHA256. Повторите загрузку".into());
        }
        Ok(())
    }
}
#[derive(Clone, Default)]
pub struct Assistant {
    phase: Arc<AtomicU8>,
    cancel: Arc<AtomicBool>,
    closing: Arc<AtomicBool>,
    bytes: Arc<AtomicU64>,
    check: Arc<Mutex<Option<Check>>>,
    child: Arc<Mutex<Option<Child>>>,
}
struct Busy(Assistant);
impl Drop for Busy {
    fn drop(&mut self) {
        self.0.phase.store(0, Ordering::SeqCst);
    }
}
impl Assistant {
    fn acquire(&self, phase: u8) -> Result<Busy, String> {
        if self.closing.load(Ordering::SeqCst) {
            return Err("Приложение завершается".into());
        }
        self.phase
            .compare_exchange(0, phase, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "Помощник уже выполняет действие")?;
        self.cancel.store(false, Ordering::SeqCst);
        Ok(Busy(self.clone()))
    }
    fn interrupted(&self) -> bool {
        self.cancel.load(Ordering::SeqCst) || self.closing.load(Ordering::SeqCst)
    }
    pub fn shutdown(&self) {
        self.closing.store(true, Ordering::SeqCst);
        self.cancel.store(true, Ordering::SeqCst);
        if let Ok(mut child) = self.child.lock() {
            if let Some(c) = child.as_mut() {
                let _ = c.kill();
            }
        }
    }
}
#[derive(Serialize)]
pub struct Info {
    model: &'static str,
    available: bool,
    phase: &'static str,
    downloaded: u64,
    total: u64,
}
fn directory(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_local_data_dir()
        .map(|p| p.join("local-ai"))
        .map_err(|_| "Не найдено хранилище модели".into())
}
fn available(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file() && m.len() == ai_runtime::MODEL_BYTES)
}
#[tauri::command]
pub fn ai_state(app: tauri::AppHandle, ai: tauri::State<'_, Assistant>) -> Result<Info, String> {
    Ok(Info {
        model: "Qwen3-0.6B",
        available: available(&directory(&app)?.join(ai_runtime::MODEL_NAME)),
        phase: match ai.phase.load(Ordering::SeqCst) {
            1 => "download",
            2 => "thinking",
            _ => "idle",
        },
        downloaded: ai.bytes.load(Ordering::SeqCst),
        total: ai_runtime::MODEL_BYTES,
    })
}
#[derive(Clone, Serialize)]
struct Progress {
    stage: &'static str,
    downloaded: u64,
    total: u64,
}
fn progress(app: &tauri::AppHandle, ai: &Assistant, stage: &'static str) {
    let _ = app.emit(
        "ai-progress",
        Progress {
            stage,
            downloaded: ai.bytes.load(Ordering::SeqCst),
            total: ai_runtime::MODEL_BYTES,
        },
    );
}
fn private_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|_| "Не удалось создать хранилище модели")?;
    if !std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir()) {
        return Err("Небезопасное хранилище модели".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| "Не удалось защитить хранилище")?;
    }
    Ok(())
}
async fn cancellable<T>(
    future: impl std::future::Future<Output = T>,
    ai: &Assistant,
) -> Result<T, String> {
    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(15), future) =>
            result.map_err(|_| "Загрузка остановилась. Проверьте интернет и повторите".into()),
        _ = async { loop { if ai.interrupted() { break; } tokio::time::sleep(Duration::from_millis(100)).await; } } =>
            Err("Загрузка отменена".into()),
    }
}
async fn fetch(app: &tauri::AppHandle, ai: &Assistant, dir: &Path) -> Result<(), String> {
    private_dir(dir)?;
    let target = dir.join(ai_runtime::MODEL_NAME);
    if ai_runtime::verify_model(&target).is_ok() {
        return Ok(());
    }
    if std::fs::symlink_metadata(&target).is_ok_and(|m| !m.is_file()) {
        return Err("Небезопасный файл модели. Загрузка остановлена".into());
    }
    ai.bytes.store(0, Ordering::SeqCst);
    progress(app, ai, "download");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(1200))
        .https_only(true)
        .build()
        .map_err(|_| "Не удалось начать загрузку")?;
    let mut response = cancellable(client.get(ai_runtime::MODEL_URL).send(), ai)
        .await?
        .and_then(|r| r.error_for_status())
        .map_err(|_| "Не удалось скачать модель. Проверьте интернет и повторите")?;
    if response
        .content_length()
        .is_some_and(|n| n != ai_runtime::MODEL_BYTES)
    {
        return Err("Сервер вернул неверный размер модели".into());
    }
    let mut temp = tempfile::Builder::new()
        .prefix(".foxvpn-model-")
        .tempfile_in(dir)
        .map_err(|_| "Не удалось создать файл загрузки. Проверьте свободное место")?;
    let mut digest = DownloadDigest::new();
    let mut last = Instant::now();
    loop {
        if ai.interrupted() {
            return Err("Загрузка отменена".into());
        }
        let chunk = cancellable(response.chunk(), ai)
            .await?
            .map_err(|_| "Загрузка прервалась. Можно повторить")?;
        let Some(chunk) = chunk else {
            break;
        };
        digest.add(&chunk, ai_runtime::MODEL_BYTES)?;
        temp.write_all(&chunk)
            .map_err(|_| "Не удалось сохранить модель. Проверьте свободное место")?;
        ai.bytes.store(digest.bytes, Ordering::SeqCst);
        if last.elapsed() >= Duration::from_millis(250) {
            progress(app, ai, "download");
            last = Instant::now();
        }
    }
    progress(app, ai, "verify");
    if ai.interrupted() {
        return Err("Загрузка отменена".into());
    }
    digest.finish(ai_runtime::MODEL_BYTES, ai_runtime::MODEL_SHA)?;
    temp.as_file()
        .sync_all()
        .map_err(|_| "Не удалось сохранить модель")?;
    // Only this fixed optional public model is replaced, never a user-selected file.
    if target.exists() {
        std::fs::remove_file(&target).map_err(|_| "Не удалось заменить повреждённую модель")?;
    }
    temp.persist_noclobber(&target)
        .map_err(|_| "Не удалось завершить сохранение модели")?;
    progress(app, ai, "ready");
    Ok(())
}
#[tauri::command]
pub async fn ai_download(
    app: tauri::AppHandle,
    ai: tauri::State<'_, Assistant>,
    state: tauri::State<'_, State>,
    consent: bool,
) -> Result<(), String> {
    if !consent {
        return Err("Для загрузки модели нужно ваше согласие".into());
    }
    if state.installing.load(Ordering::SeqCst) {
        return Err("Дождитесь обновления приложения".into());
    }
    let ai = ai.inner().clone();
    let busy = ai.acquire(1)?;
    let dir = directory(&app)?;
    let _busy = busy;
    let result = fetch(&app, &ai, &dir).await;
    progress(&app, &ai, "idle");
    result
}
#[tauri::command]
pub fn ai_cancel(ai: tauri::State<'_, Assistant>) {
    ai.cancel.store(true, Ordering::SeqCst);
}

pub fn stamp(state: &State) -> Result<String, String> {
    let profile = state
        .profile
        .lock()
        .map_err(|_| "Не удалось прочитать настройки")?
        .clone();
    let status = state
        .status
        .lock()
        .map_err(|_| "Не удалось прочитать состояние")?
        .clone();
    let value = serde_json::to_vec(&(
        state.wanted.ticket(),
        status,
        profile.selected,
        profile.settings,
        profile.rules,
        profile.servers,
    ))
    .map_err(|_| "Не удалось проверить актуальность")?;
    Ok(format!("{:x}", Sha256::digest(value)))
}
fn facts_from_report(report: &Report) -> Facts {
    let item = |label: &str| report.items.iter().find(|v| v.label == label).map(|v| v.ok);
    Facts {
        platform: if cfg!(target_os = "macos") {
            Platform::Macos
        } else if cfg!(windows) {
            Platform::Windows
        } else {
            Platform::Other
        },
        core_ok: item("Компонент VPN").unwrap_or(false),
        helper_ok: item("Сетевой компонент macOS"),
        connection_ok: item("Текущее соединение").or_else(|| item("Режим напрямую")),
        dns_ok: item("Системный DNS"),
        proxy_ok: item("Прокси Windows"),
        servers_available: item("Доступность серверов"),
        tested: report.tested.min(3) as u8,
        has_servers: report.total > 0,
        has_recommendation: report.recommendation.is_some(),
        action: Action::from_check(report.action),
    }
}
pub fn remember(app: &tauri::AppHandle, report: &Report, stamp: String) -> Result<(), String> {
    let facts = facts_from_report(report);
    *app.state::<Assistant>()
        .check
        .lock()
        .map_err(|_| "Не удалось сохранить проверку")? = Some(Check {
        id: report.check_id.clone(),
        facts,
        stamp,
        time: Instant::now(),
    });
    Ok(())
}
fn checked_facts(check: &Check, id: &str, current: &str) -> Result<Facts, String> {
    if check.id != id || check.stamp != current || check.time.elapsed() > Duration::from_secs(120) {
        return Err("Результаты устарели. Повторите проверку подключения".into());
    }
    Ok(check.facts.clone())
}
#[derive(Serialize)]
pub struct Explanation {
    text: String,
    advice: &'static str,
    elapsed_ms: u64,
}
struct Worker(Assistant);
impl Drop for Worker {
    fn drop(&mut self) {
        if let Ok(mut child) = self.0.child.lock() {
            if let Some(mut c) = child.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }
}
fn run_worker(ai: &Assistant, job: Job) -> Result<String, String> {
    if ai.interrupted() {
        return Err("Объяснение отменено".into());
    }
    let mut command = Command::new(std::env::current_exe().map_err(|_| "Не найдено приложение")?);
    command
        .arg("--foxvpn-ai-worker")
        .arg(std::process::id().to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command
        .spawn()
        .map_err(|_| "Не удалось запустить помощника")?;
    let input = child.stdin.take().ok_or("Не удалось передать результаты")?;
    let output = child.stdout.take().ok_or("Не удалось получить ответ")?;
    *ai.child.lock().map_err(|_| "Помощник недоступен")? = Some(child);
    let _worker = Worker(ai.clone());
    // Writer owns and closes stdin. Only a small bounded private JSON job is sent.
    let data = serde_json::to_vec(&job).map_err(|_| "Не удалось подготовить результаты")?;
    let writer = std::thread::spawn(move || {
        let mut input = input;
        input.write_all(&data)
    });
    let reader = std::thread::spawn(move || {
        let mut data = vec![];
        output.take(8193).read_to_end(&mut data).map(|_| data)
    });
    let started = Instant::now();
    let status = loop {
        if ai.interrupted() {
            return Err("Объяснение отменено".into());
        }
        if started.elapsed() > Duration::from_secs(90) {
            return Err("Помощник отвечал слишком долго. Повторите позже".into());
        }
        let done = ai
            .child
            .lock()
            .map_err(|_| "Помощник недоступен")?
            .as_mut()
            .ok_or("Помощник остановлен")?
            .try_wait()
            .map_err(|_| "Не удалось проверить помощника")?;
        if let Some(status) = done {
            break status;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    writer
        .join()
        .map_err(|_| "Не удалось передать результаты")?
        .map_err(|_| "Не удалось передать результаты")?;
    let data = reader
        .join()
        .map_err(|_| "Не удалось получить ответ")?
        .map_err(|_| "Не удалось получить ответ")?;
    if !status.success() || data.len() > 8192 {
        return Err(
            "Модель не дала ответа или повреждена. Повторите загрузку; обычная проверка доступна"
                .into(),
        );
    }
    serde_json::from_slice::<String>(&data).map_err(|_| "Некорректный ответ модели".into())
}
#[tauri::command]
pub async fn ai_explain(
    app: tauri::AppHandle,
    ai: tauri::State<'_, Assistant>,
    state: tauri::State<'_, State>,
    check_id: String,
) -> Result<Explanation, String> {
    if state.installing.load(Ordering::SeqCst) {
        return Err("Дождитесь обновления приложения".into());
    }
    let current = stamp(&state)?;
    let facts = {
        let check = ai
            .check
            .lock()
            .map_err(|_| "Не удалось прочитать проверку")?;
        let check = check
            .as_ref()
            .ok_or("Сначала запустите проверку подключения")?;
        checked_facts(check, &check_id, &current)?
    };
    let state = state.inner().clone();
    let ai = ai.inner().clone();
    let busy = ai.acquire(2)?;
    let model = directory(&app)?.join(ai_runtime::MODEL_NAME);
    tauri::async_runtime::spawn_blocking(move || {
        let _busy = busy;
        let start = Instant::now();
        progress(&app, &ai, "thinking");
        let text = run_worker(
            &ai,
            Job {
                model,
                facts: facts.clone(),
            },
        );
        progress(&app, &ai, "idle");
        let text = text?;
        if state.installing.load(Ordering::SeqCst) || stamp(&state)? != current {
            return Err("Состояние изменилось во время ответа. Повторите проверку".into());
        }
        Ok(Explanation {
            text,
            advice: facts.action.advice(),
            elapsed_ms: start.elapsed().as_millis() as u64,
        })
    })
    .await
    .map_err(|_| "Не удалось завершить объяснение")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_operation_at_a_time_cancel_and_shutdown_do_not_touch_vpn() {
        let ai = Assistant::default();
        let busy = ai.acquire(1).unwrap();
        assert!(ai.acquire(2).is_err());
        ai.cancel.store(true, Ordering::SeqCst);
        assert!(ai.interrupted());
        drop(busy);
        let busy = ai.acquire(2).unwrap();
        assert!(!ai.interrupted());
        drop(busy);
        ai.shutdown();
        assert!(ai.acquire(1).is_err());
    }
    #[test]
    fn presence_check_rejects_links_and_partial_models() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(ai_runtime::MODEL_NAME);
        std::fs::write(&path, b"partial").unwrap();
        assert!(!available(&path));
        #[cfg(unix)]
        {
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(path, &link).unwrap();
            assert!(!available(&link));
        }
    }
    #[test]
    fn interrupted_oversized_and_modified_downloads_are_not_publishable() {
        let bytes = b"public model fixture";
        let sha = format!("{:x}", Sha256::digest(bytes));
        let mut good = DownloadDigest::new();
        good.add(&bytes[..4], bytes.len() as u64).unwrap();
        good.add(&bytes[4..], bytes.len() as u64).unwrap();
        assert!(good.finish(bytes.len() as u64, &sha).is_ok());
        let mut partial = DownloadDigest::new();
        partial.add(&bytes[..4], bytes.len() as u64).unwrap();
        assert!(partial.finish(bytes.len() as u64, &sha).is_err());
        let mut oversize = DownloadDigest::new();
        assert!(oversize.add(bytes, 4).is_err());
        let mut changed = DownloadDigest::new();
        changed.add(bytes, bytes.len() as u64).unwrap();
        assert!(changed.finish(bytes.len() as u64, &"0".repeat(64)).is_err());
    }
    #[test]
    fn explanations_require_matching_fresh_backend_snapshot() {
        let facts = ai_runtime::tests::fixture();
        let mut check = Check {
            id: "id".into(),
            stamp: "settings".into(),
            time: Instant::now(),
            facts,
        };
        assert!(checked_facts(&check, "id", "settings").is_ok());
        assert!(checked_facts(&check, "fake", "settings").is_err());
        assert!(checked_facts(&check, "id", "changed-settings").is_err());
        check.time -= Duration::from_secs(121);
        assert!(checked_facts(&check, "id", "settings").is_err());
    }
    #[test]
    fn model_receives_no_private_report_strings_or_server_identity() {
        let report = super::super::setup_check::private_fixture_report();
        let facts = facts_from_report(&report);
        let serialized = serde_json::to_string(&facts).unwrap();
        assert!(!serialized.contains("PRIVATE_"));
        assert!(!ai_runtime::prompt(&facts).unwrap().contains("PRIVATE_"));
        assert!(facts.core_ok && facts.has_recommendation);
    }
    #[tokio::test]
    async fn stalled_network_operation_can_be_cancelled() {
        let ai = Assistant::default();
        ai.cancel.store(true, Ordering::SeqCst);
        assert!(cancellable(std::future::pending::<()>(), &ai)
            .await
            .is_err());
    }
}
