//! No tools, network access, profiles or command execution in the model worker.
use llama_cpp_2::{
    context::params::LlamaContextParams,
    llama_backend::LlamaBackend,
    llama_batch::LlamaBatch,
    model::{params::LlamaModelParams, LlamaModel},
    sampling::LlamaSampler,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Read,
    num::NonZeroU32,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

pub const MODEL_BYTES: u64 = 639_446_688;
pub const MODEL_SHA: &str = "9465e63a22add5354d9bb4b99e90117043c7124007664907259bd16d043bb031";
pub const MODEL_NAME: &str = "Qwen3-0.6B-Q8_0.gguf";
pub const MODEL_URL: &str = "https://huggingface.co/Qwen/Qwen3-0.6B-GGUF/resolve/23749fefcc72300e3a2ad315e1317431b06b590a/Qwen3-0.6B-Q8_0.gguf";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    None,
    Reinstall,
    AddServer,
    Helper,
    WaitHelper,
    WindowsProxy,
    Connect,
}
impl Action {
    pub fn from_check(value: &str) -> Self {
        match value {
            "reinstall" => Self::Reinstall,
            "add_server" => Self::AddServer,
            "helper" => Self::Helper,
            "wait_helper" => Self::WaitHelper,
            "windows_proxy" => Self::WindowsProxy,
            "connect" => Self::Connect,
            _ => Self::None,
        }
    }
    pub fn advice(&self) -> &'static str {
        match self {
            Self::None => {
                "Исправление автоматически не выбрано. Используйте результаты проверки ниже."
            }
            Self::Reinstall => "Переустановите проверенную сборку foxVPN из нашего GitHub.",
            Self::AddServer => {
                "Добавьте VPN-сервер: приложение не создаёт серверы и ключи доступа."
            }
            Self::Helper => "Используйте кнопку установки сетевого компонента macOS ниже.",
            Self::WaitHelper => "Дождитесь запуска сетевого компонента и повторите проверку.",
            Self::WindowsProxy => {
                "Используйте кнопку «Настроить Windows автоматически» и подтвердите изменение."
            }
            Self::Connect => {
                "Используйте кнопку подключения ниже. Результат нужно проверить после подключения."
            }
        }
    }
}
/// Only enums, booleans and bounded counts cross the inference boundary.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Facts {
    pub platform: Platform,
    pub core_ok: bool,
    pub helper_ok: Option<bool>,
    pub connection_ok: Option<bool>,
    pub dns_ok: Option<bool>,
    pub proxy_ok: Option<bool>,
    pub servers_available: Option<bool>,
    pub tested: u8,
    pub has_servers: bool,
    pub has_recommendation: bool,
    pub action: Action,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    Macos,
    Windows,
    Other,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Job {
    pub model: PathBuf,
    pub facts: Facts,
}

pub fn verify_model(path: &Path) -> Result<(), String> {
    let m = std::fs::symlink_metadata(path).map_err(|_| "Сначала скачайте модель помощника")?;
    if !m.is_file() || m.len() != MODEL_BYTES {
        return Err("Модель повреждена. Скачайте её повторно".into());
    }
    let mut f = File::open(path).map_err(|_| "Не удалось открыть модель")?;
    let mut hash = Sha256::new();
    let mut buf = vec![0; 1024 * 1024];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|_| "Не удалось проверить модель")?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    if format!("{:x}", hash.finalize()) != MODEL_SHA {
        return Err("Модель не прошла проверку SHA256. Скачайте её повторно".into());
    }
    Ok(())
}
pub fn prompt(facts: &Facts) -> Result<String, String> {
    let result = |name: &str, value: Option<bool>| {
        format!(
            "{name}: {}.",
            match value {
                Some(true) => "проверка пройдена",
                Some(false) => "проверка не пройдена",
                None => "не проверялось",
            }
        )
    };
    let main = match facts.action {
        Action::Reinstall => "Ядро приложения отсутствует или не прошло проверку целостности.",
        Action::AddServer => "Для подключения не выбран VPN-сервер.",
        Action::Helper => "Отдельная служба foxVPN не установлена или требует обновления. Проверка не сообщает о несовместимости самой macOS.",
        Action::WaitHelper => "Сетевой компонент ещё запускается.",
        Action::WindowsProxy => "HTTPS через foxVPN работает, но параметры прокси Windows не соответствуют foxVPN.",
        Action::Connect => "Выбранный способ подключения прошёл контрольную проверку, можно перейти к подключению.",
        Action::None if facts.connection_ok == Some(true) => "Контрольный HTTPS-запрос прошёл. Остальные непроверенные свойства соединения неизвестны.",
        Action::None => "Автоматическое исправление не выбрано. Точная причина по этой проверке неизвестна.",
    };
    let details = [
        result("Ядро VPN", Some(facts.core_ok)),
        result("Компонент macOS", facts.helper_ok),
        result("Контрольный HTTPS-запрос", facts.connection_ok),
        result("Системный DNS", facts.dns_ok),
        result("Прокси Windows", facts.proxy_ok),
        result("Доступность серверов", facts.servers_available),
    ]
    .join("\n");
    Ok(format!("<|im_start|>system\nТы помощник foxVPN. Перескажи основной вывод и следующий шаг понятным русским языком, ровно в двух коротких предложениях. Используй только указанные факты. Не перечисляй все проверки, не добавляй причин и выполненных исправлений. Не предлагай терминал, команды и отключение защиты. Непроверенное не означает исправное.\n<|im_end|>\n<|im_start|>user\nОсновной вывод: {main}\nПодробности:\n{details}\nСледующий шаг: {}\nКратко объясни вывод и шаг. /no_think\n<|im_end|>\n<|im_start|>assistant\n<think>\n\n</think>\n\n", facts.action.advice()))
}

pub fn infer(job: Job) -> Result<String, String> {
    verify_model(&job.model)?;
    let backend = LlamaBackend::init().map_err(|_| "Не удалось запустить локальную модель")?;
    let model = LlamaModel::load_from_file(
        &backend,
        &job.model,
        &LlamaModelParams::default().with_n_gpu_layers(0),
    )
    .map_err(|_| "Не удалось загрузить локальную модель")?;
    let threads = std::thread::available_parallelism().map_or(2, |n| n.get().min(4)) as i32;
    let params = LlamaContextParams::default()
        .with_n_ctx(NonZeroU32::new(2048))
        .with_n_batch(1024)
        .with_n_ubatch(128)
        .with_n_threads(threads)
        .with_n_threads_batch(threads);
    let mut ctx = model
        .new_context(&backend, params)
        .map_err(|_| "Не удалось подготовить модель")?;
    let input = model
        .vocab()
        .tokenize(prompt(&job.facts)?.as_bytes(), true, true);
    if input.is_empty() || input.len() > 1024 {
        return Err("Результаты проверки слишком велики".into());
    }
    let mut batch = LlamaBatch::new(1024, 1);
    for (i, token) in input.iter().enumerate() {
        batch
            .add(*token, i as i32, &[0], i == input.len() - 1)
            .map_err(|_| "Ошибка подготовки ответа")?;
    }
    ctx.decode(&mut batch)
        .map_err(|_| "Модель не обработала проверку")?;
    let mut sampler = LlamaSampler::chain_simple([
        LlamaSampler::penalties(model.vocab().n_tokens(), 64, 1.1, 0.0, 0.0),
        LlamaSampler::greedy(),
    ]);
    let mut output = vec![];
    let started = Instant::now();
    for position in input.len()..input.len() + 240 {
        if started.elapsed() > Duration::from_secs(60) {
            return Err("Модель отвечала слишком долго. Повторите позже".into());
        }
        let token = sampler.sample(&ctx, batch.n_tokens() - 1);
        if model.vocab().is_eog(token) {
            break;
        }
        sampler.accept(token);
        output.push(token);
        batch.clear();
        batch
            .add(token, position as i32, &[0], true)
            .map_err(|_| "Ошибка ответа модели")?;
        ctx.decode(&mut batch).map_err(|_| "Ошибка ответа модели")?;
    }
    let text = String::from_utf8_lossy(&model.vocab().detokenize(&output, true, false))
        .trim()
        .to_owned();
    if text.is_empty() {
        return Err("Модель не дала ответа. Используйте проверенные рекомендации ниже".into());
    }
    Ok(text
        .chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(1800)
        .collect())
}

/// Called before Tauri, Keychain or Windows proxy recovery. No user profile is opened.
pub fn worker() -> Result<(), String> {
    watch_parent()?;
    let mut data = vec![];
    std::io::stdin()
        .take(8193)
        .read_to_end(&mut data)
        .map_err(|_| "Не удалось прочитать проверку")?;
    if data.len() > 8192 {
        return Err("Проверка слишком велика".into());
    }
    let job: Job = serde_json::from_slice(&data).map_err(|_| "Некорректная проверка")?;
    let text = infer(job)?;
    println!(
        "{}",
        serde_json::to_string(&text).map_err(|_| "Не удалось вернуть ответ")?
    );
    Ok(())
}

fn watch_parent() -> Result<(), String> {
    let parent: u32 = std::env::args()
        .nth(2)
        .ok_or("Не указан родительский процесс")?
        .parse()
        .map_err(|_| "Некорректный родительский процесс")?;
    if parent < 2 {
        return Err("Некорректный родительский процесс".into());
    }
    #[cfg(target_os = "macos")]
    {
        if unsafe { libc::getppid() } as u32 != parent {
            return Err("Родительский процесс изменился".into());
        }
        std::thread::spawn(move || loop {
            if unsafe { libc::getppid() } as u32 != parent {
                std::process::exit(1);
            }
            std::thread::sleep(Duration::from_millis(200));
        });
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::Threading::{OpenProcess, WaitForSingleObject},
        };
        let handle = unsafe { OpenProcess(0x00100000, 0, parent) };
        if handle.is_null() {
            return Err("Родительский процесс недоступен".into());
        }
        let handle = handle as usize;
        std::thread::spawn(move || {
            unsafe {
                WaitForSingleObject(handle as _, u32::MAX);
                CloseHandle(handle as _);
            }
            std::process::exit(1);
        });
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    pub fn fixture() -> Facts {
        Facts {
            platform: Platform::Macos,
            core_ok: true,
            helper_ok: Some(true),
            connection_ok: Some(false),
            dns_ok: None,
            proxy_ok: None,
            servers_available: Some(true),
            tested: 2,
            has_servers: true,
            has_recommendation: true,
            action: Action::Connect,
        }
    }
    #[test]
    fn model_cannot_receive_strings_or_invent_actions() {
        let mut facts = serde_json::to_value(fixture()).unwrap();
        facts["secret"] = "PRIVATE_TOKEN".into();
        assert!(serde_json::from_value::<Facts>(facts).is_err());
        assert!(serde_json::from_str::<Action>("\"run_shell\"").is_err());
        assert_eq!(Action::from_check("run_shell"), Action::None);
        let p = prompt(&fixture()).unwrap();
        assert!(!p.contains("PRIVATE_TOKEN"));
        assert!(p.contains("/no_think"));
    }
    #[test]
    fn damaged_model_is_rejected_before_native_parsing() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"GGUF corrupt").unwrap();
        assert!(verify_model(file.path()).is_err());
    }
    #[test]
    #[ignore = "requires the pinned public model; no user profile/network settings used"]
    fn actual_local_model_explains_public_fixture() {
        let model = PathBuf::from(std::env::var_os("FOXVPN_TEST_AI_MODEL").unwrap());
        let text = infer(Job {
            model,
            facts: fixture(),
        })
        .unwrap();
        assert!(text.chars().any(|c| ('а'..='я').contains(&c)));
        assert!(!text.contains("<think>"));
        println!("{text}");
    }
}
