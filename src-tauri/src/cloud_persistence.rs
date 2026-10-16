//! Encrypted single-instance cloud backup for stateless Web/Koyeb deployments.
//! Only enabled with all required CC_SWITCH_* environment variables.
//! This intentionally stores *configuration*, not sessions or managed OAuth accounts.

use std::{env, sync::{Arc, OnceLock}, time::Duration};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use reqwest::{Client, Url};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Notify};

use crate::{app_config::MultiAppConfig, store::AppState};

const MAX_CONFIG_SIZE: usize = 8 * 1024 * 1024;
const TABLE_PATH: &str = "rest/v1/cc_switch_cloud_config";
static DIRTY: OnceLock<Notify> = OnceLock::new();

#[derive(Clone)]
pub struct CloudPersistence {
    client: Client,
    endpoint: Url,
    secret: String,
    slot: String,
    encryption_key: [u8; 32],
    last_uploaded: Arc<Mutex<Option<String>>>,
}

#[derive(Deserialize)]
struct CloudRow {
    cipher_text: String,
}

impl CloudPersistence {
    /// Return None only when cloud persistence is intentionally disabled.
    /// Partial/malformed configuration MUST fail startup, never silently fall back.
    pub fn from_env() -> Result<Option<Self>> {
        let url = nonempty_env("CC_SWITCH_SUPABASE_URL");
        let secret = nonempty_env("CC_SWITCH_SUPABASE_SECRET_KEY");
        let encryption = nonempty_env("CC_SWITCH_SYNC_ENCRYPTION_KEY");
        let required = matches!(
            nonempty_env("CC_SWITCH_CLOUD_REQUIRED").as_deref(),
            Some("1" | "true" | "TRUE" | "yes")
        );
        if url.is_none() && secret.is_none() && encryption.is_none() {
            if required {
                bail!("Cloud persistence is required but CC_SWITCH_SUPABASE_URL, CC_SWITCH_SUPABASE_SECRET_KEY, or CC_SWITCH_SYNC_ENCRYPTION_KEY are missing");
            }
            return Ok(None);
        }

        let base = Url::parse(&url.context("Missing CC_SWITCH_SUPABASE_URL")?)
            .context("Invalid CC_SWITCH_SUPABASE_URL")?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || base.username() != ""
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/"
        {
            bail!("CC_SWITCH_SUPABASE_URL must be an HTTPS origin with no path, credentials, or query");
        }

        let slot = nonempty_env("CC_SWITCH_SYNC_SLOT").unwrap_or_else(|| "primary".into());
        if slot.len() > 64 || !slot.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            bail!("CC_SWITCH_SYNC_SLOT must contain 1-64 ASCII letters, digits, hyphens or underscores");
        }

        let encoded_key = encryption.context("Missing CC_SWITCH_SYNC_ENCRYPTION_KEY")?;
        let decoded = BASE64.decode(encoded_key.as_bytes())
            .context("CC_SWITCH_SYNC_ENCRYPTION_KEY must be base64")?;
        let encryption_key: [u8; 32] = decoded.try_into()
            .map_err(|_| anyhow!("CC_SWITCH_SYNC_ENCRYPTION_KEY must decode to exactly 32 bytes"))?;

        let client = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .context("Cannot create HTTPS client for cloud backup")?;

        Ok(Some(Self {
            endpoint: base.join(TABLE_PATH)?,
            client,
            secret: secret.context("Missing CC_SWITCH_SUPABASE_SECRET_KEY")?,
            slot,
            encryption_key,
            last_uploaded: Arc::new(Mutex::new(None)),
        }))
    }

    fn request(&self, method: reqwest::Method) -> reqwest::RequestBuilder {
        let req = self.client.request(method, self.endpoint.clone())
            .header("apikey", self.secret.as_str());
        // Legacy service_role JWTs also accept Authorization: Bearer <JWT>.
        // Modern sb_secret_* keys MUST be sent via apikey (they are not JWTs).
        if self.secret.starts_with("sb_secret_") {
            req
        } else {
            req.bearer_auth(&self.secret)
        }
    }

    /// Called before any client-facing traffic or proxy initialization.
    /// An inaccessible/corrupt remote snapshot is fatal: no empty overwrites.
    pub async fn restore(&self, state: &AppState) -> Result<bool> {
        let response = self.request(reqwest::Method::GET)
            .query(&[
                ("slot", format!("eq.{}", self.slot)),
                ("select", "cipher_text".to_string()),
                ("limit", "1".to_string()),
            ])
            .send().await.context("Cloud backup read failed")?;
        if !response.status().is_success() {
            bail!("Cloud backup read returned HTTP {}", response.status());
        }
        let rows: Vec<CloudRow> = response.json().await
            .context("Cannot parse cloud backup response")?;
        let Some(row) = rows.first() else {
            log::info!("Cloud backup slot is empty; starting with local configuration");
            return Ok(false);
        };
        let plaintext = decrypt_blob(&self.encryption_key, &row.cipher_text)
            .context("Unable to decrypt cloud backup (check CC_SWITCH_SYNC_ENCRYPTION_KEY)")?;
        if plaintext.len() > MAX_CONFIG_SIZE {
            bail!("Cloud configuration exceeds maximum size");
        }
        let config: MultiAppConfig = serde_json::from_slice(&plaintext)
            .context("Cloud backup configuration is invalid")?;
        let digest = digest_config(&config)?;
        state.replace_config(&config).context("Cannot restore cloud configuration to SQLite")?;
        *self.last_uploaded.lock().await = Some(digest);
        log::info!("Restored encrypted cloud configuration for slot {}", self.slot);
        Ok(true)
    }

    /// Skip identical snapshots; retry after transient errors. Only one server
    /// instance may write a slot: last writer wins in this single-instance design.
    pub async fn sync_pending(&self, state: &AppState) -> Result<bool> {
        let mut uploaded = self.last_uploaded.lock().await;
        let config = state.load_config().context("Cannot load local config for cloud backup")?;
        let bytes = canonical_config(&config)?;
        let digest = hex::encode(Sha256::digest(&bytes));
        if uploaded.as_deref() == Some(digest.as_str()) {
            return Ok(false);
        }
        if bytes.len() > MAX_CONFIG_SIZE {
            bail!("Cloud configuration exceeds maximum size");
        }
        let encrypted = encrypt_blob(&self.encryption_key, &bytes)?;
        let response = self.request(reqwest::Method::POST)
            .query(&[("on_conflict", "slot")])
            .header("Prefer", "resolution=merge-duplicates,return=minimal")
            .json(&serde_json::json!({
                "slot": self.slot,
                "cipher_text": encrypted
            }))
            .send().await.context("Cloud backup write failed")?;
        if !response.status().is_success() {
            bail!("Cloud backup write returned HTTP {}", response.status());
        }
        *uploaded = Some(digest);
        log::info!("Encrypted cloud configuration synchronized");
        Ok(true)
    }

    /// Immediate notification after provider changes, with a 2-second retry/poll
    /// fallback for other updates. Pending changes also flush on graceful exit.
    pub async fn run_worker(self, state: Arc<AppState>) {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let notifier = DIRTY.get_or_init(Notify::new);
        loop {
            tokio::select! {
                _ = interval.tick() => {},
                _ = notifier.notified() => {},
            }
            if let Err(err) = self.sync_pending(&state).await {
                log::warn!("Encrypted cloud configuration sync failed (will retry): {err:#}");
            }
        }
    }
}

pub fn notify_changed() {
    if let Some(notifier) = DIRTY.get() {
        notifier.notify_one();
    }
}

fn nonempty_env(name: &str) -> Option<String> {
    env::var(name).ok().map(|s| s.trim().to_owned()).filter(|s| !s.is_empty())
}

fn canonical_config(config: &MultiAppConfig) -> Result<Vec<u8>> {
    // serde_json::Value sorts map keys, avoiding uploads caused solely by
    // different HashMap iteration orders after a restart.
    let value = serde_json::to_value(config)?;
    Ok(serde_json::to_vec(&value)?)
}

fn digest_config(config: &MultiAppConfig) -> Result<String> {
    Ok(hex::encode(Sha256::digest(canonical_config(config)?)))
}

fn encrypt_blob(key: &[u8; 32], plaintext: &[u8]) -> Result<String> {
    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|_| anyhow!("Could not generate encryption nonce"))?;
    let cipher = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| anyhow!("Invalid encryption key"))?
    );
    let mut bytes = plaintext.to_vec();
    cipher.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce_bytes),
        Aad::from(b"cc-switch-cloud-config-v1".as_slice()),
        &mut bytes,
    ).map_err(|_| anyhow!("Cloud encryption failed"))?;
    Ok(format!("v1.{}.{}", BASE64.encode(nonce_bytes), BASE64.encode(bytes)))
}

fn decrypt_blob(key: &[u8; 32], encoded: &str) -> Result<Vec<u8>> {
    let mut parts = encoded.split('.');
    if parts.next() != Some("v1") {
        bail!("Unsupported encrypted backup version");
    }
    let nonce = BASE64.decode(parts.next().context("Missing backup nonce")?)?;
    let mut bytes = BASE64.decode(parts.next().context("Missing encrypted backup body")?)?;
    if parts.next().is_some() || nonce.len() != 12 || bytes.len() > MAX_CONFIG_SIZE + 16 {
        bail!("Invalid encrypted backup format or size");
    }
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| anyhow!("Invalid nonce length"))?;
    let cipher = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| anyhow!("Invalid encryption key"))?
    );
    let plaintext = cipher.open_in_place(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(b"cc-switch-cloud-config-v1".as_slice()),
        &mut bytes,
    ).map_err(|_| anyhow!("Backup authentication failed"))?;
    Ok(plaintext.to_vec())
}

#[cfg(test)]
mod tests {
    use super::{decrypt_blob, encrypt_blob};

    #[test]
    fn encrypted_backup_round_trip_and_random_nonces() {
        let key = [5u8; 32];
        let first = encrypt_blob(&key, b"secret api key").unwrap();
        let second = encrypt_blob(&key, b"secret api key").unwrap();
        assert_ne!(first, second);
        assert_eq!(decrypt_blob(&key, &first).unwrap(), b"secret api key");
    }

    #[test]
    fn tampered_backup_and_wrong_key_are_rejected() {
        let key = [7u8; 32];
        let ciphertext = encrypt_blob(&key, b"private").unwrap();
        assert!(decrypt_blob(&[8u8; 32], &ciphertext).is_err());
        assert!(decrypt_blob(&key, &format!("{ciphertext}AA")).is_err());
        assert!(decrypt_blob(&key, "v0.not-valid").is_err());
    }
}
