use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex,
    },
};
use tauri::{Emitter, Manager};

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Preferences {
    auto_check: bool,
    skipped_version: Option<String>,
    pending_version: Option<String>,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            auto_check: true,
            skipped_version: None,
            pending_version: None,
        }
    }
}
pub struct AppUpdates {
    path: PathBuf,
    busy: AtomicBool,
    #[cfg(any(target_os = "macos", windows))]
    offer: Mutex<Option<tauri_plugin_updater::Update>>,
    #[cfg(any(target_os = "macos", windows))]
    cancel: Mutex<Option<std::sync::Arc<tokio::sync::Notify>>>,
}
impl AppUpdates {
    pub fn new(app: &tauri::AppHandle) -> Result<Self, String> {
        Ok(Self {
            path: app
                .path()
                .app_config_dir()
                .map_err(|_| "Не найден каталог настроек обновления.")?
                .join("updates.json"),
            busy: AtomicBool::new(false),
            #[cfg(any(target_os = "macos", windows))]
            offer: Mutex::new(None),
            #[cfg(any(target_os = "macos", windows))]
            cancel: Mutex::new(None),
        })
    }
    fn read(&self) -> Result<Preferences, String> {
        if !self.path.exists() {
            return Ok(Preferences::default());
        }
        use std::io::Read;
        let mut bytes = Vec::new();
        fs::File::open(&self.path)
            .and_then(|file| file.take(8193).read_to_end(&mut bytes))
            .map_err(|_| "Не удалось прочитать настройки обновления.")?;
        if bytes.len() > 8192 {
            return Err(
                "Повреждены настройки обновления. Автопроверка отключена до исправления.".into(),
            );
        }
        serde_json::from_slice(&bytes).map_err(|_| {
            "Повреждены настройки обновления. Автопроверка отключена до исправления.".into()
        })
    }
    fn write(&self, value: &Preferences) -> Result<(), String> {
        let parent = self
            .path
            .parent()
            .ok_or("Нет каталога настроек обновления.")?;
        fs::create_dir_all(parent)
            .map_err(|_| "Не удалось создать каталог настроек обновления.")?;
        let temp = parent.join(format!("updates-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            use std::io::Write;
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temp)?;
            file.write_all(&serde_json::to_vec(value).map_err(std::io::Error::other)?)?;
            file.sync_all()?;
            fs::rename(&temp, &self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temp);
            return Err("Не удалось сохранить настройки обновления.".into());
        }
        Ok(())
    }
    fn acquire(&self) -> Result<Busy<'_>, String> {
        self.busy
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| "Уже выполняется операция обновления.")?;
        Ok(Busy(self))
    }
}
struct Busy<'a>(&'a AppUpdates);
impl Drop for Busy<'_> {
    fn drop(&mut self) {
        #[cfg(any(target_os = "macos", windows))]
        {
            *self.0.cancel.lock().unwrap() = None;
        }
        self.0.busy.store(false, Ordering::SeqCst);
    }
}
#[derive(Serialize)]
pub struct Info {
    supported: bool,
    platform: &'static str,
    current: String,
    auto_check: bool,
    skipped_version: Option<String>,
    helper_required: bool,
    /// The installed component is current but its daemon is still starting or
    /// restarting. This must not be presented as "update the component".
    helper_starting: bool,
    error: Option<String>,
}
pub fn exit_allowed(installing: bool, code: Option<i32>) -> bool {
    !installing || code == Some(tauri::RESTART_EXIT_CODE)
}
async fn mark_installing(state: &crate::State) -> Result<(), String> {
    let state = state.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let _gate = state
            .gate
            .lock()
            .map_err(|_| "Не удалось дождаться настройки")?;
        state.installing.store(true, Ordering::SeqCst);
        Ok(())
    })
    .await
    .map_err(|_| "Не удалось начать установку")?
}
#[tauri::command]
pub async fn update_state(
    app: tauri::AppHandle,
    state: tauri::State<'_, AppUpdates>,
) -> Result<Info, String> {
    let _busy = state.acquire()?;
    let result = state.read();
    let error = result.as_ref().err().cloned();
    let mut prefs = result.unwrap_or(Preferences {
        auto_check: false,
        ..Preferences::default()
    });
    let current = app.package_info().version.to_string();
    let pending = prefs.pending_version.as_deref() == Some(&current);
    let migration = pending || smart_vpn_engine::network_helper::installed();
    let component = if migration {
        // The package restarts the daemon, so a check that runs right after an
        // install waits briefly instead of reporting an outdated component.
        tauri::async_runtime::spawn_blocking(|| {
            smart_vpn_engine::network_helper::probe(smart_vpn_engine::network_helper::START_WAIT)
        })
        .await
        .unwrap_or(smart_vpn_engine::network_helper::Probe::Starting)
    } else {
        smart_vpn_engine::network_helper::Probe::Ready
    };
    let ready = component == smart_vpn_engine::network_helper::Probe::Ready;
    #[cfg(target_os = "macos")]
    if ready {
        let is_current = smart_vpn_engine::component_update::macos::public_binding()
            .and_then(|b| {
                smart_vpn_engine::network_helper::self_hash().map(|hash| b.current == hash)
            })
            .unwrap_or(false);
        if is_current {
            let _ = tauri::async_runtime::spawn_blocking(|| {
                for _ in 0..20 {
                    if smart_vpn_engine::network_helper::request(
                        &smart_vpn_engine::network_helper::Request::FinalizeUpdate,
                    )
                    .is_ok()
                    {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            })
            .await;
        }
    }
    if pending && ready {
        prefs.pending_version = None;
        let _ = state.write(&prefs);
    }
    Ok(Info {
        supported: cfg!(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(windows, target_arch = "x86_64")
        )),
        platform: std::env::consts::OS,
        current,
        auto_check: prefs.auto_check,
        skipped_version: prefs.skipped_version,
        helper_required: cfg!(target_os = "macos")
            && matches!(
                component,
                smart_vpn_engine::network_helper::Probe::Stale
                    | smart_vpn_engine::network_helper::Probe::Missing
            ),
        helper_starting: cfg!(target_os = "macos")
            && component == smart_vpn_engine::network_helper::Probe::Starting,
        error,
    })
}
pub fn pending_helper(app: &tauri::AppHandle, state: &AppUpdates) -> bool {
    state.read().is_ok_and(|p| {
        p.pending_version.as_deref() == Some(&app.package_info().version.to_string())
    })
}
#[tauri::command]
pub fn update_preferences(enabled: bool, state: tauri::State<AppUpdates>) -> Result<(), String> {
    let _busy = state.acquire()?;
    let mut prefs = state.read()?;
    prefs.auto_check = enabled;
    state.write(&prefs)
}
#[derive(Serialize)]
pub struct Offer {
    current: String,
    version: String,
    notes: String,
}
#[tauri::command]
pub async fn check_app_update(
    manual: bool,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppUpdates>,
) -> Result<Option<Offer>, String> {
    let _busy = state.acquire()?;
    #[cfg(any(target_os = "macos", windows))]
    {
        use tauri_plugin_updater::UpdaterExt;
        let updater = app
            .updater_builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|_| "Не удалось настроить проверку обновлений.")?;
        let result = updater.check().await.map_err(|_| {
            "Не удалось проверить обновления в GitHub. Проверьте интернет и попробуйте позже."
        })?;
        let offer = if let Some(update) = &result {
            validate_offer(&update.version, update.download_url.as_str())?;
            Some(Offer {
                current: update.current_version.clone(),
                version: update.version.clone(),
                notes: update
                    .body
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .take(4000)
                    .collect(),
            })
        } else {
            None
        };
        if offer.as_ref().is_some_and(|v| {
            manual
                || state
                    .read()
                    .is_ok_and(|p| p.auto_check && p.skipped_version.as_deref() != Some(&v.version))
        }) {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }
        *state.offer.lock().unwrap() = result;
        Ok(offer)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (app, manual);
        Ok(None)
    }
}
#[cfg(any(target_os = "macos", windows))]
fn validate_offer(version: &str, url: &str) -> Result<(), String> {
    let parsed = semver::Version::parse(version).map_err(|_| "Некорректная версия обновления.")?;
    let expected = if cfg!(windows) {
        format!("https://github.com/kvashninsasha-gif/foxVPN/releases/download/v{version}/foxVPN_{version}_x64-setup.exe")
    } else {
        format!("https://github.com/kvashninsasha-gif/smart-vpn-router/releases/download/v{version}/foxVPN-{version}-macOS-arm64.app.tar.gz")
    };
    let architecture = cfg!(any(
        all(windows, target_arch = "x86_64"),
        all(target_os = "macos", target_arch = "aarch64")
    ));
    if !parsed.pre.is_empty() || !parsed.build.is_empty() || url != expected || !architecture {
        return Err("Нет подходящего официального обновления для этой платформы.".into());
    }
    Ok(())
}
#[tauri::command]
pub fn skip_app_update(version: String, state: tauri::State<AppUpdates>) -> Result<(), String> {
    let _busy = state.acquire()?;
    #[cfg(any(target_os = "macos", windows))]
    {
        if !state
            .offer
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|v| v.version == version)
        {
            return Err("Сначала проверьте доступную версию.".into());
        }
        let mut prefs = state.read()?;
        prefs.skipped_version = Some(version);
        state.write(&prefs)
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = version;
        Err("Обновление доступно только на macOS Apple Silicon.".into())
    }
}
#[derive(Clone, Serialize)]
struct Progress {
    stage: &'static str,
    downloaded: u64,
    total: Option<u64>,
}
#[tauri::command]
pub fn cancel_app_update(state: tauri::State<AppUpdates>) {
    #[cfg(any(target_os = "macos", windows))]
    if let Some(cancel) = state.cancel.lock().unwrap().as_ref() {
        cancel.notify_one();
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    let _ = state;
}
#[tauri::command]
pub async fn install_app_update(
    version: String,
    approved: bool,
    app: tauri::AppHandle,
    updates: tauri::State<'_, AppUpdates>,
    vpn: tauri::State<'_, crate::State>,
) -> Result<(), String> {
    if !approved {
        return Err("Обновление требует вашего согласия.".into());
    }
    if app
        .try_state::<crate::setup_plan::Plans>()
        .is_some_and(|p| p.is_busy())
    {
        return Err("Дождитесь завершения настройки помощником".into());
    }
    let _busy = updates.acquire()?;
    #[cfg(target_os = "macos")]
    {
        let mut update = updates
            .offer
            .lock()
            .unwrap()
            .clone()
            .ok_or("Сначала проверьте обновления.")?;
        if update.version != version {
            return Err("Доступная версия изменилась. Проверьте обновления заново.".into());
        }
        validate_offer(&version, update.download_url.as_str())?;
        let target = crate::update_install::app_path(
            &std::env::current_exe().map_err(|_| "Не найдено установленное приложение.")?,
        )?;
        let update_component = smart_vpn_engine::network_helper::installed();
        if update_component {
            smart_vpn_engine::network_helper::require_current()?;
        }
        update.timeout = Some(std::time::Duration::from_secs(600));
        let signal = std::sync::Arc::new(tokio::sync::Notify::new());
        *updates.cancel.lock().unwrap() = Some(signal.clone());
        let mut downloaded = 0u64;
        let mut emitted = 0u64;
        let oversized = AtomicBool::new(false);
        let _ = app.emit(
            "app-update-progress",
            Progress {
                stage: "downloading",
                downloaded: 0,
                total: None,
            },
        );
        let download = update.download(
            |chunk, total| {
                downloaded = downloaded.saturating_add(chunk as u64);
                if downloaded > 256 * 1024 * 1024 || total.is_some_and(|s| s > 256 * 1024 * 1024) {
                    oversized.store(true, Ordering::SeqCst);
                    signal.notify_one();
                }
                if downloaded - emitted >= 256 * 1024 {
                    emitted = downloaded;
                    let _ = app.emit(
                        "app-update-progress",
                        Progress {
                            stage: "downloading",
                            downloaded,
                            total,
                        },
                    );
                }
            },
            || {},
        );
        let bytes = tokio::select! { biased; _=signal.notified()=>return Err(if oversized.load(Ordering::SeqCst) {
            "Обновление превышает допустимый размер 256 МБ. Приложение и VPN не менялись."
        } else {
            "Скачивание отменено. Приложение и VPN не менялись."
        }.into()), result=download=>result.map_err(|_| "Не удалось скачать обновление или проверить его цифровую подпись. Приложение и VPN не менялись.")? };
        if bytes.len() > 256 * 1024 * 1024 {
            return Err("Обновление превышает допустимый размер.".into());
        }
        let _ = app.emit(
            "app-update-progress",
            Progress {
                stage: "verifying",
                downloaded: bytes.len() as u64,
                total: None,
            },
        );
        let v = version.clone();
        // This file is outside WebView control and inside the fixed per-owner
        // dropbox created by the root service. Root verifies the signature again.
        let archive_file = if update_component {
            use std::io::Write;
            let dropbox = std::path::Path::new(smart_vpn_engine::component_update::UPLOADS)
                .join(unsafe { libc::getuid() }.to_string());
            let mut file = tempfile::Builder::new()
                .prefix("foxvpn-update-")
                .suffix(".tar.gz")
                .tempfile_in(dropbox)
                .map_err(|_| "Не удалось подготовить совместное обновление компонента.")?;
            file.write_all(&bytes)
                .and_then(|_| file.as_file().sync_all())
                .map_err(|_| "Не удалось сохранить проверенный архив.")?;
            Some(file)
        } else {
            None
        };
        let component_request =
            archive_file
                .as_ref()
                .map(|file| smart_vpn_engine::component_update::InstallRequest {
                    archive: file.path().to_string_lossy().into_owned(),
                    signature: update.signature.clone(),
                    version: version.clone(),
                });
        let prepared = tauri::async_runtime::spawn_blocking(move || {
            crate::update_install::prepare(&bytes, &target, &v)
        })
        .await
        .map_err(|_| "Не удалось подготовить обновление.")??;
        let expected_hash = prepared.expected_hash()?;
        if signal.notified().now_or_never().is_some() {
            return Err("Установка отменена. Приложение и VPN не менялись.".into());
        }
        *updates.cancel.lock().unwrap() = None;
        // Persist recovery marker before replacement, while keeping the old preferences for rollback.
        let old = updates.read()?;
        let mut next = old.clone();
        next.pending_version = if update_component || vpn.profile.lock().unwrap().settings.tun {
            Some(version)
        } else {
            None
        };
        next.skipped_version = None;
        updates.write(&next)?;
        mark_installing(&vpn).await?;
        let _ = app.emit(
            "app-update-progress",
            Progress {
                stage: "installing",
                downloaded: 0,
                total: None,
            },
        );
        let state = vpn.inner().clone();
        let app_progress = app.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            let result = (|| {
                state.vault.save(&state.profile.lock().unwrap())?;
                crate::disconnect(&state)?;
                if let Some(request) = component_request {
                    let _ = app_progress.emit(
                        "app-update-progress",
                        Progress {
                            stage: "component",
                            downloaded: 0,
                            total: None,
                        },
                    );
                    smart_vpn_engine::network_helper::install_update(request, &expected_hash)?;
                    let _ = app_progress.emit(
                        "app-update-progress",
                        Progress {
                            stage: "installing",
                            downloaded: 0,
                            total: None,
                        },
                    );
                }
                prepared.commit().map(|_| ())
            })();
            if result.is_err() {
                state.installing.store(false, Ordering::SeqCst);
            }
            result
        })
        .await
        .map_err(|_| {
            vpn.installing.store(false, Ordering::SeqCst);
            let _ = updates.write(&old);
            "Не удалось установить обновление. Проверьте подключение VPN."
        })?;
        if let Err(error) = result {
            let _ = updates.write(&old);
            return Err(format!("{error} Если VPN отключён, подключите его заново."));
        }
        app.request_restart();
        Ok(())
    }
    #[cfg(windows)]
    {
        install_windows(version, app, &updates, &vpn).await
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        let _ = (version, app, vpn);
        Err("Обновление доступно только на macOS Apple Silicon.".into())
    }
}
#[cfg(any(target_os = "macos", windows))]
use futures_util::FutureExt;

#[cfg(windows)]
async fn install_windows(
    version: String,
    app: tauri::AppHandle,
    updates: &AppUpdates,
    vpn: &crate::State,
) -> Result<(), String> {
    let mut update = updates
        .offer
        .lock()
        .map_err(|_| "Не удалось прочитать обновление")?
        .clone()
        .ok_or("Сначала проверьте обновления.")?;
    if update.version != version {
        return Err("Доступная версия изменилась. Проверьте обновления заново.".into());
    }
    validate_offer(&version, update.download_url.as_str())?;
    update.timeout = Some(std::time::Duration::from_secs(600));
    let signal = std::sync::Arc::new(tokio::sync::Notify::new());
    *updates
        .cancel
        .lock()
        .map_err(|_| "Не удалось подготовить скачивание")? = Some(signal.clone());
    let mut downloaded = 0u64;
    let mut emitted = 0u64;
    let oversized = AtomicBool::new(false);
    let _ = app.emit(
        "app-update-progress",
        Progress {
            stage: "downloading",
            downloaded: 0,
            total: None,
        },
    );
    let download = update.download(
        |chunk, total| {
            downloaded = downloaded.saturating_add(chunk as u64);
            if downloaded > 256 * 1024 * 1024 || total.is_some_and(|v| v > 256 * 1024 * 1024) {
                oversized.store(true, Ordering::SeqCst);
                signal.notify_one();
            }
            if downloaded - emitted >= 256 * 1024 {
                emitted = downloaded;
                let _ = app.emit(
                    "app-update-progress",
                    Progress {
                        stage: "downloading",
                        downloaded,
                        total,
                    },
                );
            }
        },
        || {},
    );
    let bytes = tokio::select! { biased;
        _=signal.notified()=>return Err(if oversized.load(Ordering::SeqCst) {
            "Обновление превышает допустимый размер 256 МБ. VPN не менялся."
        } else { "Скачивание отменено. VPN не менялся." }.into()),
        result=download=>result.map_err(|_| "Не удалось скачать обновление или проверить цифровую подпись. VPN не менялся.")?
    };
    verify_windows_package(&bytes, &update.signature, &version)?;
    let _ = app.emit(
        "app-update-progress",
        Progress {
            stage: "verifying",
            downloaded: bytes.len() as u64,
            total: None,
        },
    );
    if signal.notified().now_or_never().is_some() {
        return Err("Подготовка отменена. VPN не менялся.".into());
    }
    *updates
        .cancel
        .lock()
        .map_err(|_| "Не удалось завершить подготовку")? = None;
    let old = updates.read()?;
    let mut next = old.clone();
    next.skipped_version = None;
    next.pending_version = None;
    updates.write(&next)?;
    mark_installing(&vpn).await?;
    let state = vpn.clone();
    let stopped = tauri::async_runtime::spawn_blocking(move || {
        let profile = state
            .profile
            .lock()
            .map_err(|_| "Не удалось сохранить профиль")?;
        state.vault.save(&profile)?;
        drop(profile);
        // Restore the Windows proxy and wait for core/guardian termination before
        // NSIS replaces their executable files. Direct exit bypasses Drop.
        crate::disconnect(&state)
    })
    .await
    .map_err(|_| "Не удалось подготовить завершение foxVPN".to_string())
    .and_then(|v| v);
    if let Err(error) = stopped {
        vpn.installing.store(false, Ordering::SeqCst);
        let _ = updates.write(&old);
        return Err(format!(
            "{error}. Установка не началась. Проверьте подключение VPN."
        ));
    }
    let _ = app.emit(
        "app-update-progress",
        Progress {
            stage: "installing",
            downloaded: 0,
            total: None,
        },
    );
    // The native updater starts the verified NSIS installer and exits only after
    // ShellExecute succeeds; NSIS handles its own progress, cancellation and restart.
    if update.install(bytes).is_err() {
        vpn.installing.store(false, Ordering::SeqCst);
        let _ = updates.write(&old);
        return Err(
            "Не удалось открыть установщик Windows. VPN отключён; его можно подключить заново."
                .into(),
        );
    }
    Ok(())
}

#[cfg(all(test, any(target_os = "macos", windows)))]
mod tests {
    use super::*;
    fn state(path: PathBuf) -> AppUpdates {
        AppUpdates {
            path,
            busy: AtomicBool::new(false),
            offer: Mutex::new(None),
            cancel: Mutex::new(None),
        }
    }
    #[test]
    fn defaults_and_atomic_preferences_do_not_use_profile() {
        let root = tempfile::tempdir().unwrap();
        let state = state(root.path().join("updates.json"));
        assert!(state.read().unwrap().auto_check);
        let p = Preferences {
            auto_check: false,
            skipped_version: Some("0.1.7".into()),
            pending_version: Some("0.1.8".into()),
        };
        state.write(&p).unwrap();
        let read = state.read().unwrap();
        assert!(!read.auto_check);
        assert_eq!(read.skipped_version, p.skipped_version);
        assert_eq!(read.pending_version, p.pending_version);
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
    #[test]
    fn corrupted_preferences_are_never_silently_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let state = state(root.path().join("updates.json"));
        fs::write(&state.path, "broken").unwrap();
        assert!(state.read().is_err());
        assert_eq!(fs::read_to_string(&state.path).unwrap(), "broken");
    }
    #[test]
    fn duplicate_operations_block_and_guard_releases_on_error() {
        let state = state(PathBuf::from("unused"));
        let first = state.acquire().unwrap();
        assert!(state.acquire().is_err());
        drop(first);
        assert!(state.acquire().is_ok());
    }
    #[test]
    fn critical_install_blocks_quit_but_allows_approved_restart() {
        assert!(!exit_allowed(true, None));
        assert!(!exit_allowed(true, Some(0)));
        assert!(exit_allowed(true, Some(tauri::RESTART_EXIT_CODE)));
        assert!(exit_allowed(false, None));
        assert!(exit_allowed(false, Some(0)));
    }
    #[test]
    fn oversized_preferences_remain_unchanged() {
        let root = tempfile::tempdir().unwrap();
        let state = state(root.path().join("updates.json"));
        fs::write(&state.path, vec![b' '; 16384]).unwrap();
        assert!(state.read().is_err());
        assert_eq!(fs::metadata(&state.path).unwrap().len(), 16384);
    }
    #[test]
    fn iphone_foreign_and_downgrade_channel_urls_rejected() {
        let valid = if cfg!(windows) {
            "https://github.com/kvashninsasha-gif/foxVPN/releases/download/v0.1.7/foxVPN_0.1.7_x64-setup.exe"
        } else {
            "https://github.com/kvashninsasha-gif/smart-vpn-router/releases/download/v0.1.7/foxVPN-0.1.7-macOS-arm64.app.tar.gz"
        };
        assert!(validate_offer("0.1.7", valid).is_ok());
        for (version, url) in [
            ("ios-v0.1.7", valid),
            ("0.1.7-beta.1", valid),
            ("0.1.7", "https://example.com/app.tar.gz"),
            ("0.1.8", valid),
            (
                "0.1.7",
                "http://github.com/kvashninsasha-gif/smart-vpn-router/app.tar.gz",
            ),
        ] {
            assert!(validate_offer(version, url).is_err());
        }
    }
    #[test]
    #[ignore = "requires the locally signed Windows release installer"]
    fn signed_windows_installer_accepts_only_original_bytes_and_version() {
        let artifact =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_ARTIFACT").expect("signed artifact path");
        let version =
            std::env::var("FOXVPN_TEST_WINDOWS_UPDATE_VERSION").expect("signed artifact version");
        let bytes = fs::read(&artifact).unwrap();
        let signature = fs::read_to_string(format!("{artifact}.sig")).unwrap();
        verify_windows_package(&bytes, &signature, &version).unwrap();
        assert!(verify_windows_package(&bytes, &signature, "999.0.0").is_err());
        let mut corrupted = bytes;
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        assert!(verify_windows_package(&corrupted, &signature, &version).is_err());
    }
}

#[cfg(any(windows, test))]
fn verify_windows_package(bytes: &[u8], signature: &str, version: &str) -> Result<(), String> {
    use base64::Engine;
    if bytes.len() > 256 * 1024 * 1024 || !bytes.starts_with(b"MZ") {
        return Err("Неверный формат установщика Windows. VPN не менялся.".into());
    }
    let config: serde_json::Value =
        serde_json::from_str(include_str!("../tauri.windows.conf.json"))
            .map_err(|_| "Не найден ключ проверки обновлений")?;
    let decode = |s: &str| -> Result<String, String> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(s.trim())
            .map_err(|_| "Некорректная подпись обновления")?;
        String::from_utf8(bytes).map_err(|_| "Некорректная подпись обновления".into())
    };
    let key = minisign_verify::PublicKey::decode(&decode(
        config["plugins"]["updater"]["pubkey"]
            .as_str()
            .ok_or("Не найден ключ проверки обновлений")?,
    )?)
    .map_err(|_| "Некорректный ключ обновлений")?;
    let signature = minisign_verify::Signature::decode(&decode(signature)?)
        .map_err(|_| "Некорректная подпись обновления")?;
    key.verify(bytes, &signature, false)
        .map_err(|_| "Подпись установщика не прошла проверку. VPN не менялся.")?;
    let signed = signature
        .trusted_comment()
        .split('\t')
        .find_map(|v| v.strip_prefix("version:"))
        .ok_or("Подпись не содержит версию установщика")?;
    if semver::Version::parse(signed).ok() != semver::Version::parse(version).ok()
        || semver::Version::parse(version).is_err()
    {
        return Err(
            "Версия в подписи не совпадает с предложенным обновлением. VPN не менялся.".into(),
        );
    }
    Ok(())
}
