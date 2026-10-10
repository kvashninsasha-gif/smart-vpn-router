use crate::{
    routing::{Mode, Rule},
    servers::Server,
};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub mode: Mode,
    pub tun: bool,
    pub kill_switch: bool,
    pub proxy_acknowledged: bool,
    pub windows_proxy_auto: Option<bool>,
    pub proxy_port: u16,
    pub dns_protection: bool,
    pub dns_provider: String,
    pub dns_transport: String,
    pub auto_connect: bool,
    pub start_minimized: bool,
    pub restore: bool,
    pub health_interval: u64,
    pub auto_metrics: bool,
    pub metric_interval: u64,
    pub failover: bool,
    pub favorites_only: bool,
    pub strategy: String,
    pub subscription_interval: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: Mode::Smart,
            tun: true,
            kill_switch: true,
            proxy_acknowledged: false,
            windows_proxy_auto: None,
            proxy_port: 2080,
            dns_protection: true,
            dns_provider: "cloudflare".into(),
            dns_transport: "https".into(),
            auto_connect: false,
            start_minimized: false,
            restore: true,
            health_interval: 30,
            auto_metrics: true,
            metric_interval: 600,
            failover: true,
            favorites_only: false,
            strategy: "balanced".into(),
            subscription_interval: 21600,
        }
    }
}
impl Settings {
    pub fn validate(&self) -> Result<(), String> {
        if !(60..=3600).contains(&self.metric_interval) {
            return Err(crate::text("metric_interval_invalid").into());
        }
        if self.proxy_port < 1024 {
            return Err(crate::text("proxy_port_invalid").into());
        }
        if !(10..=3600).contains(&self.health_interval) {
            return Err(crate::text("message_285").into());
        }
        if !["cloudflare", "google", "quad9"].contains(&self.dns_provider.as_str()) {
            return Err(crate::text("message_286").into());
        }
        if !["https", "tls", "local"].contains(&self.dns_transport.as_str()) {
            return Err(crate::text("message_287").into());
        }
        if self.dns_protection && self.dns_transport == "local" {
            return Err(crate::text("message_288").into());
        }
        if !["balanced", "latency", "speed", "stability", "random"]
            .contains(&self.strategy.as_str())
        {
            return Err(crate::text("message_289").into());
        }
        if ![0, 3600, 21600, 43200, 86400].contains(&self.subscription_interval) {
            return Err(crate::text("message_290").into());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    pub updated_at: Option<u64>,
    pub server_count: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Profile {
    pub version: u32,
    pub servers: Vec<Server>,
    pub selected: Option<String>,
    pub rules: Vec<Rule>,
    pub settings: Settings,
    pub subscriptions: Vec<Subscription>,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            version: 1,
            servers: vec![],
            selected: None,
            rules: vec![],
            settings: Settings::default(),
            subscriptions: vec![],
        }
    }
}
impl Profile {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != 1 {
            return Err(crate::text("message_291").into());
        }
        if self.servers.len() > 5000 || self.rules.len() > 5000 {
            return Err(crate::text("message_292").into());
        }
        self.settings.validate()?;
        crate::routing::validate(&self.rules)?;
        let mut ids = std::collections::HashSet::new();
        for s in &self.servers {
            let check = Server::parse(&s.uri()?)?;
            if check.uuid != s.uuid
                || check.address != s.address
                || check.port != s.port
                || check.transport != s.transport
                || check.security != s.security
            {
                return Err(crate::text("message_293").into());
            }
            if !ids.insert(&s.id) {
                return Err(crate::text("message_294").into());
            }
        }
        if let Some(id) = &self.selected {
            if !ids.contains(id) {
                return Err(crate::text("message_295").into());
            }
        }
        for sub in &self.subscriptions {
            crate::subscriptions::validate_url(&sub.url)?;
        }
        Ok(())
    }
}
/// All persisted user configuration participates in freshness checks. Only
/// observations updated in the background are excluded, and must be merged
/// from the latest profile when applying/restoring a configuration.
pub fn configuration_digest(profile: &Profile) -> Result<String, String> {
    let mut stable = profile.clone();
    for server in &mut stable.servers {
        server.latency_ms = None;
        server.download_mbps = None;
        server.status.clear();
        server.successes = 0;
        server.failures = 0;
        server.last_error = None;
    }
    for subscription in &mut stable.subscriptions {
        subscription.updated_at = None;
        subscription.server_count = 0;
    }
    let bytes = serde_json::to_vec(&stable).map_err(|_| crate::text("message_302"))?;
    use sha2::{Digest, Sha256};
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

// One successful OS credential read per Vault/session. Failed or denied reads
// remain retryable. The mutex also prevents concurrent first saves creating
// different master keys. Never serialize this cache or expose it over IPC.
#[derive(Default)]
struct SessionKey(std::sync::Mutex<Option<Zeroizing<[u8; 32]>>>);
impl SessionKey {
    fn get(
        &self,
        read: impl FnOnce() -> Result<Zeroizing<[u8; 32]>, String>,
    ) -> Result<Zeroizing<[u8; 32]>, String> {
        let mut cached = self.0.lock().map_err(|_| crate::text("message_296"))?;
        if cached.is_none() {
            *cached = Some(read()?);
        }
        Ok(Zeroizing::new(**cached.as_ref().unwrap()))
    }
}
pub struct Vault {
    service: String,
    path: std::path::PathBuf,
    key: SessionKey,
}
impl Vault {
    pub fn new(service: &str) -> Self {
        #[cfg(target_os = "macos")]
        let base = std::env::var_os("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_default()
            .join("Library/Application Support");
        #[cfg(windows)]
        let base = std::env::var_os("APPDATA")
            .map(std::path::PathBuf::from)
            .unwrap_or_default();
        #[cfg(not(any(target_os = "macos", windows)))]
        let base = std::env::var_os("XDG_DATA_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(std::path::PathBuf::from)
                    .unwrap_or_default()
                    .join(".local/share")
            });
        Self {
            service: service.into(),
            path: base.join(service).join("profile.enc"),
            key: SessionKey::default(),
        }
    }
    /// Test-only private storage with a caller-owned temporary path and public
    /// fixture key. Exercises production encryption/atomic writes, not Keychain.
    #[cfg(feature = "test-support")]
    pub fn test_fixture(path: std::path::PathBuf, key: [u8; 32]) -> Self {
        Self {
            service: "foxvpn-public-test-fixture".into(),
            path,
            key: SessionKey(std::sync::Mutex::new(Some(Zeroizing::new(key)))),
        }
    }
    fn key(&self, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        self.key.get(|| self.read_key(create))
    }
    fn read_key(&self, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
        let e = keyring::Entry::new(&self.service, "master-key")
            .map_err(|_| crate::text("message_296"))?;
        match e.get_password() {
            Ok(value) => {
                let value = Zeroizing::new(value);
                let bytes = Zeroizing::new(
                    STANDARD
                        .decode(value.as_bytes())
                        .map_err(|_| crate::text("message_297"))?,
                );
                let key: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| crate::text("message_297"))?;
                Ok(Zeroizing::new(key))
            }
            Err(keyring::Error::NoEntry) if create => {
                let mut key = Zeroizing::new([0u8; 32]);
                rand::rngs::OsRng.fill_bytes(key.as_mut());
                let encoded = Zeroizing::new(STANDARD.encode(key.as_ref()));
                e.set_password(&encoded)
                    .map_err(|_| crate::text("message_298"))?;
                Ok(key)
            }
            Err(_) => Err(crate::text("message_299").into()),
        }
    }
    pub fn load(&self) -> Result<Profile, String> {
        if !self.path.exists() {
            return Ok(Profile::default());
        }
        let data = std::fs::read(&self.path).map_err(|_| crate::text("message_300"))?;
        let plain = Zeroizing::new(decrypt_profile(&*self.key(false)?, &data)?);
        serde_json::from_slice(&plain).map_err(|_| crate::text("message_301").into())
    }
    pub fn save(&self, p: &Profile) -> Result<(), String> {
        p.validate()?;
        let plain = Zeroizing::new(serde_json::to_vec(p).map_err(|_| crate::text("message_302"))?);
        let data = encrypt_profile(&*self.key(true)?, &plain)?;
        let dir = self.path.parent().ok_or(crate::text("message_303"))?;
        std::fs::create_dir_all(dir).map_err(|_| crate::text("message_304"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| crate::text("message_305"))?;
        }
        let temp = dir.join(format!("profile-{}.tmp", uuid::Uuid::new_v4()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|_| crate::text("message_306"))?;
        use std::io::Write;
        file.write_all(&data)
            .and_then(|_| file.sync_all())
            .map_err(|_| crate::text("message_306"))?;
        drop(file);
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt;
            #[link(name = "kernel32")]
            extern "system" {
                fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
            }
            let source: Vec<u16> = temp.as_os_str().encode_wide().chain(Some(0)).collect();
            let target: Vec<u16> = self.path.as_os_str().encode_wide().chain(Some(0)).collect();
            // Replace atomically and flush through the Windows filesystem API.
            if unsafe { MoveFileExW(source.as_ptr(), target.as_ptr(), 1 | 8) } == 0 {
                return Err(crate::text("message_302").into());
            }
        }
        #[cfg(not(windows))]
        std::fs::rename(&temp, &self.path).map_err(|_| crate::text("message_302"))?;
        Ok(())
    }
}

#[cfg(test)]
mod session_key_tests {
    use super::SessionKey;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use zeroize::Zeroizing;

    #[test]
    fn concurrent_operations_read_os_credential_once() {
        let cache = Arc::new(SessionKey::default());
        let reads = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let cache = Arc::clone(&cache);
                let reads = Arc::clone(&reads);
                scope.spawn(move || {
                    for _ in 0..10 {
                        let key = cache
                            .get(|| {
                                reads.fetch_add(1, Ordering::SeqCst);
                                Ok(Zeroizing::new([42; 32]))
                            })
                            .unwrap();
                        assert_eq!(*key, [42; 32]);
                    }
                });
            }
        });
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn denial_is_retryable_and_never_replaces_an_existing_key() {
        let cache = SessionKey::default();
        assert!(cache.get(|| Err("denied".into())).is_err());
        assert_eq!(*cache.get(|| Ok(Zeroizing::new([7; 32]))).unwrap(), [7; 32]);
        assert_eq!(
            *cache.get(|| panic!("must not read the OS again")).unwrap(),
            [7; 32]
        );
    }
}
pub fn encrypt_profile(key: &[u8; 32], plain: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| crate::text("message_308"))?;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&nonce), plain)
        .map_err(|_| crate::text("message_309"))?;
    let mut data = b"SVP1".to_vec();
    data.extend_from_slice(&nonce);
    data.extend(encrypted);
    Ok(data)
}
pub fn decrypt_profile(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 32 || &data[..4] != b"SVP1" {
        return Err(crate::text("message_301").into());
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| crate::text("message_308"))?;
    cipher
        .decrypt(Nonce::from_slice(&data[4..16]), &data[16..])
        .map_err(|_| crate::text("message_310").into())
}

/// A legacy profile is never silently downgraded to an unprotected local proxy.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPlan {
    NeedsServer,
    NeedsProxyConsent,
    Ready,
}
pub fn connection_plan(profile: &Profile) -> ConnectionPlan {
    if !profile
        .servers
        .iter()
        .any(|server| Some(&server.id) == profile.selected.as_ref())
    {
        return ConnectionPlan::NeedsServer;
    }
    if profile.settings.tun
        || profile.settings.kill_switch
        || !profile.settings.proxy_acknowledged
        || (cfg!(windows) && profile.settings.windows_proxy_auto.is_none())
    {
        return ConnectionPlan::NeedsProxyConsent;
    }
    ConnectionPlan::Ready
}
/// The installed, authenticated helper supplies the protected TUN capability.
pub fn connection_plan_with_helper(profile: &Profile, helper_available: bool) -> ConnectionPlan {
    let plan = connection_plan(profile);
    if plan != ConnectionPlan::NeedsServer && profile.settings.tun && helper_available {
        ConnectionPlan::Ready
    } else {
        plan
    }
}
pub fn prepare_proxy(profile: &Profile, expected_selected: &str) -> Result<Profile, String> {
    if profile.selected.as_deref() != Some(expected_selected)
        || !profile
            .servers
            .iter()
            .any(|server| server.id == expected_selected)
    {
        return Err(crate::text("proxy_server_changed").into());
    }
    let mut next = profile.clone();
    next.settings.tun = false;
    next.settings.kill_switch = false;
    next.settings.proxy_acknowledged = true;
    if cfg!(windows) && next.settings.windows_proxy_auto.is_none() {
        next.settings.windows_proxy_auto = Some(false);
    }
    next.validate()?;
    Ok(next)
}
