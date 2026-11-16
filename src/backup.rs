//! 配置备份与恢复。
//!
//! 备份文件格式：
//!   [4B magic "OLBK"] [1B version=1] [1B flags: bit0=encrypted]
//!   [若加密: 16B salt | 12B nonce] [payload]
//!
//! payload 未加密 = Config JSON 明文；加密 = AES-256-GCM 密文，
//! 密钥由用户密码经多轮 SHA256 派生（salt 存文件头）。

use crate::config::Config;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngExt;
use std::io;

const MAGIC: &[u8; 4] = b"OLBK";
/// 新建备份写 v2（argon2id KDF）；v1 是旧的 SHA256×2001 弱 KDF，仅保留读取兼容
const VERSION: u8 = 2;
const LEGACY_VERSION: u8 = 1;
const FLAG_ENCRYPTED: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// 旧版（v1）多轮 SHA256 迭代次数，仅用于读老备份
const LEGACY_KDF_ITERATIONS: u32 = 2000;

/// 创建备份文件字节。
///
/// `password` 为 `Some("")` 或 `None` 表示不加密；非空字符串表示用该密码加密。
pub fn create_backup(config: &Config, password: Option<&str>) -> io::Result<Vec<u8>> {
    let plain = serde_json::to_vec(config).map_err(io::Error::other)?;

    let mut out = Vec::with_capacity(plain.len() + 64);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);

    let pwd = password.map(str::trim).filter(|p| !p.is_empty());
    match pwd {
        Some(pw) => {
            let (salt, nonce, ciphertext) = encrypt_with_password(pw, &plain)
                .map_err(io::Error::other)?;
            out.push(FLAG_ENCRYPTED);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&nonce);
            out.extend_from_slice(&ciphertext);
        }
        None => {
            out.push(0);
            out.extend_from_slice(&plain);
        }
    }
    Ok(out)
}

/// 解析备份文件，返回 Config。
///
/// `password` 可选：加密备份必须提供，未加密备份传 `None` 即可（传非空会报错）。
pub fn parse_backup(blob: &[u8], password: Option<&str>) -> Result<Config, String> {
    if blob.len() < 6 {
        return Err("备份文件过短".into());
    }
    if &blob[0..4] != MAGIC {
        return Err("不是有效的备份文件（magic 不匹配）".into());
    }
    let version = blob[4];
    if version != VERSION && version != LEGACY_VERSION {
        return Err(format!("不支持的备份版本: {version}"));
    }
    let flags = blob[5];
    let encrypted = (flags & FLAG_ENCRYPTED) != 0;
    let payload = &blob[6..];

    if encrypted {
        if payload.len() < SALT_LEN + NONCE_LEN {
            return Err("加密备份文件过短".into());
        }
        let salt = &payload[..SALT_LEN];
        let nonce = &payload[SALT_LEN..SALT_LEN + NONCE_LEN];
        let ciphertext = &payload[SALT_LEN + NONCE_LEN..];

        let pw = password.map(str::trim).ok_or("该备份已加密，需要密码")?;
        if pw.is_empty() {
            return Err("密码不能为空".into());
        }
        let plain = decrypt_with_password(pw, salt, nonce, ciphertext, version)?;
        serde_json::from_slice::<Config>(&plain).map_err(|e| format!("备份数据解析失败: {e}"))
    } else {
        if password.is_some() {
            return Err("该备份未加密，不需要密码".into());
        }
        serde_json::from_slice::<Config>(payload).map_err(|e| format!("备份数据解析失败: {e}"))
    }
}

// ---------- 内部：加密 / 解密 ----------

type EncryptedParts = (Vec<u8>, Vec<u8>, Vec<u8>);

fn encrypt_with_password(
    password: &str,
    plain: &[u8],
) -> Result<EncryptedParts, String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill(&mut salt);
    rand::rng().fill(&mut nonce);

    let key = derive_key(password, &salt)?;
    let cipher = Aes256Gcm::new(&key.into());
    let nonce_ref: &Nonce<_> = (&nonce).into();
    let ct = cipher
        .encrypt(nonce_ref, plain)
        .map_err(|_| "加密失败".to_string())?;

    Ok((salt.to_vec(), nonce.to_vec(), ct))
}

fn decrypt_with_password(
    password: &str,
    salt: &[u8],
    nonce: &[u8],
    ct: &[u8],
    version: u8,
) -> Result<Vec<u8>, String> {
    let key = if version == LEGACY_VERSION {
        derive_key_legacy(password, salt)
    } else {
        derive_key(password, salt)?
    };
    let cipher = Aes256Gcm::new(&key.into());
    let nonce_ref: &Nonce<_> = nonce
        .try_into()
        .map_err(|_| format!("nonce 长度不是 {NONCE_LEN} 字节"))?;
    cipher
        .decrypt(nonce_ref, ct)
        .map_err(|_| "密码错误或数据损坏".to_string())
}

/// argon2id 密钥派生（v2）：password + salt → 32 字节 AES 密钥。
///
/// 与 src/password.rs 同一套参数（m=19MiB、t=2、p=1）。备份文件包含全部网盘
/// Cookie / refresh_token / 面板口令哈希，等价于整个服务的凭据库，必须用
/// 内存硬的 KDF 抵抗 GPU 离线爆破 —— 旧版 SHA256×2001 轮已废弃。
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    use argon2::Argon2;

    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("备份密钥派生失败: {e}"))?;
    Ok(key)
}

/// 旧版（v1）多轮 SHA256 密钥派生 —— 仅用于读取历史备份，不得用于新加密。
fn derive_key_legacy(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    use sha2::{Digest, Sha256};

    let mut input = Vec::with_capacity(password.len() + salt.len());
    input.extend_from_slice(password.as_bytes());
    input.extend_from_slice(salt);

    let mut result = Sha256::digest(&input);

    for _ in 0..LEGACY_KDF_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(password.as_bytes());
        hasher.update(salt);
        result = hasher.finalize();
    }

    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&result);
    key
}

// ---------- API handlers ----------

use axum::{
    body::Bytes,
    extract::{ConnectInfo, Multipart, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

use crate::state::AppState;

/// POST /api/web/backup/create
///
/// body: { "password": "可选密码" }
/// 返回二进制备份文件（application/octet-stream）
pub(crate) async fn create_backup_handler(
    State(st): State<AppState>,
    Json(req): Json<BackupCreateReq>,
) -> Response {
    let data = st.store.data.lock().unwrap_or_else(|e| e.into_inner());
    let config = data.clone();
    drop(data);

    let filename = backup_filename();
    match create_backup(&config, req.password.as_deref()) {
        Ok(blob) => {
            let headers = [
                (header::CONTENT_TYPE, "application/octet-stream"),
                (
                    header::CONTENT_DISPOSITION,
                    &format!("attachment; filename=\"{filename}\""),
                ),
            ];
            (StatusCode::OK, headers, blob).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("备份失败: {e}") })),
        )
            .into_response(),
    }
}

/// POST /api/web/backup/restore
///
/// multipart: file（必选）+ password（可选）
/// 解析验证后原子替换配置，清空全部会话。
pub(crate) async fn restore_backup_handler(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    mut multipart: Multipart,
) -> Response {
    let mut file_bytes: Option<Bytes> = None;
    let mut password: Option<String> = None;
    let mut old_password: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        match name {
            "file" => {
                file_bytes = field.bytes().await.ok();
            }
            "password" => {
                password = field.text().await.ok();
            }
            // 面板口令确认（与备份自身的加密口令是两回事）
            "old_password" => {
                old_password = field.text().await.ok();
            }
            _ => {}
        }
    }

    let blob = match file_bytes {
        Some(b) => b.to_vec(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "未上传备份文件" })),
            )
                .into_response();
        }
    };

    // 恢复会整份替换面板口令，必须比改密更严格地再确认一次
    let reauth = crate::auth::ReauthReq { old_password };
    if let Err(resp) = crate::auth::confirm_password(&st, peer.ip(), &reauth).await {
        return resp;
    }

    let pwd = password.as_deref().map(str::trim).filter(|p| !p.is_empty());
    let config = match parse_backup(&blob, pwd) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": e })),
            )
                .into_response()
        }
    };

    let account_count = config.accounts.len();
    // 先落盘再改内存：save 失败时内存/磁盘/鉴权态都保持原样
    let store = st.store.clone();
    let snapshot = config.clone();
    let saved: std::io::Result<()> = tokio::task::spawn_blocking(move || store.save(&snapshot))
        .await
        .unwrap_or_else(|e| Err(std::io::Error::other(e.to_string())));
    match saved {
        Ok(()) => {
            *st.store.data.lock().unwrap_or_else(|e| e.into_inner()) = config;
            // 配置已变更：重建内存鉴权态（含明文口令→argon2id 的哈希收口），再清空全部会话
            st.reload_auth();
            st.clear_sessions();
            (
                StatusCode::OK,
                Json(json!({ "ok": true, "accounts": account_count })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("保存失败: {e}") })),
        )
            .into_response(),
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct BackupCreateReq {
    password: Option<String>,
}

/// 生成备份文件名：openlist-backup-YYYYMMDD-HHMMSS.olbk
fn backup_filename() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let secs = now as i64;
    // 简单时间格式化：用 chrono 不便，手动算
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // 从 1970-01-01 起的天数 → 年月日（近似，够用）
    let mut y = 1970i64;
    let mut d = days;
    loop {
        let days_in_year = if is_leap(y) { 366 } else { 365 };
        if d < days_in_year {
            break;
        }
        d -= days_in_year;
        y += 1;
    }
    let month_days = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut m = 0usize;
    while m < 12 && d >= month_days[m] {
        d -= month_days[m];
        m += 1;
    }
    let month = (m + 1) as i64;
    let day = d + 1;

    format!("openlist-backup-{y:04}{month:02}{day:02}-{hours:02}{minutes:02}{seconds:02}.olbk")
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

// ---------- 单元测试 ----------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Credential};

    fn test_config() -> Config {
        Config {
            accounts: vec![crate::config::Account {
                id: "test-id".into(),
                name: "测试".into(),
                cred: Credential::Local {
                    root_path: "/tmp".into(),
                },
                root_fid: "0".into(),
                server_proxy: false,
                enabled: true,
            }],
            web_user: Some("admin".into()),
            web_pass: Some("$argon2id$v=19$m=19456,t=2,p=1$...".into()),
            api_token: Some("openlist-test".into()),
            sign_nonce: Some("test-nonce".into()),
        }
    }

    #[test]
    fn test_unencrypted_round_trip() {
        let cfg = test_config();
        let blob = create_backup(&cfg, None).unwrap();
        assert_eq!(&blob[0..4], MAGIC);
        assert_eq!(blob[4], VERSION);
        assert_eq!(blob[5], 0, "未加密备份 flags 应为 0");

        let restored = parse_backup(&blob, None).unwrap();
        assert_eq!(restored.accounts.len(), cfg.accounts.len());
        assert_eq!(restored.web_user, cfg.web_user);
        assert_eq!(restored.api_token, cfg.api_token);
    }

    #[test]
    fn test_encrypted_round_trip() {
        let cfg = test_config();
        let blob = create_backup(&cfg, Some("s3cret-pw")).unwrap();
        assert_eq!(&blob[0..4], MAGIC);
        assert_eq!(blob[5], FLAG_ENCRYPTED, "加密备份 flags 应为 0x01");

        let restored = parse_backup(&blob, Some("s3cret-pw")).unwrap();
        assert_eq!(restored.accounts.len(), cfg.accounts.len());
        assert_eq!(restored.web_user, cfg.web_user);
    }

    #[test]
    fn test_encrypted_wrong_password_fails() {
        let cfg = test_config();
        let blob = create_backup(&cfg, Some("correct-pw")).unwrap();
        assert!(parse_backup(&blob, Some("wrong-pw")).is_err());
    }

    #[test]
    fn test_unencrypted_backup_rejects_password() {
        let cfg = test_config();
        let blob = create_backup(&cfg, None).unwrap();
        assert!(parse_backup(&blob, Some("pw")).is_err());
    }

    #[test]
    fn test_encrypted_backup_requires_password() {
        let cfg = test_config();
        let blob = create_backup(&cfg, Some("pw")).unwrap();
        assert!(parse_backup(&blob, None).is_err());
    }

    #[test]
    fn test_empty_password_treated_as_unencrypted() {
        let cfg = test_config();
        let blob = create_backup(&cfg, Some("")).unwrap();
        assert_eq!(blob[5], 0, "空密码应视为不加密");
    }

    #[test]
    fn test_bad_magic_rejected() {
        let mut blob = create_backup(&test_config(), None).unwrap();
        blob[0] = b'X';
        assert!(parse_backup(&blob, None).is_err());
    }

    #[test]
    fn test_bad_version_rejected() {
        let mut blob = create_backup(&test_config(), None).unwrap();
        blob[4] = 99;
        assert!(parse_backup(&blob, None).is_err());
    }

    #[test]
    fn test_short_blob_rejected() {
        assert!(parse_backup(&[0u8; 5], None).is_err());
    }

    #[test]
    fn test_filename_format() {
        let name = backup_filename();
        assert!(name.starts_with("openlist-backup-"));
        assert!(name.ends_with(".olbk"));
        // YYYYMMDD-HHMMSS = 8 + 1 + 6 = 15 chars after prefix
        let body = &name["openlist-backup-".len()..name.len() - ".olbk".len()];
        assert_eq!(body.len(), 15, "filename body should be YYYYMMDD-HHMMSS: {body}");
        assert_eq!(body.as_bytes()[8], b'-');
    }

    #[test]
    fn test_derive_key_is_deterministic() {
        let k1 = derive_key("pw", b"salt1234567890").unwrap();
        let k2 = derive_key("pw", b"salt1234567890").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_differs_for_different_passwords() {
        let k1 = derive_key("pw1", b"salt1234567890").unwrap();
        let k2 = derive_key("pw2", b"salt1234567890").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_key_differs_for_different_salts() {
        let k1 = derive_key("pw", b"salt1234567890").unwrap();
        let k2 = derive_key("pw", b"different salt").unwrap();
        assert_ne!(k1, k2);
    }

    /// v1 旧备份（弱 KDF）必须仍能读：用 legacy KDF 手工构造 version=1 的 blob
    #[test]
    fn test_legacy_v1_backup_still_readable() {
        let cfg = test_config();
        let plain = serde_json::to_vec(&cfg).unwrap();
        let salt = [7u8; SALT_LEN];
        let nonce = [9u8; NONCE_LEN];
        let key = derive_key_legacy("old-pw", &salt);
        let cipher = Aes256Gcm::new(&key.into());
        let nonce_ref: &Nonce<_> = (&nonce).into();
        let ct = cipher.encrypt(nonce_ref, plain.as_slice()).unwrap();

        let mut blob = Vec::new();
        blob.extend_from_slice(MAGIC);
        blob.push(LEGACY_VERSION);
        blob.push(FLAG_ENCRYPTED);
        blob.extend_from_slice(&salt);
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ct);

        let restored = parse_backup(&blob, Some("old-pw")).unwrap();
        assert_eq!(restored.accounts.len(), cfg.accounts.len());
        assert_eq!(restored.web_user, cfg.web_user);
    }

    /// 新建备份必须是 v2（argon2id）
    #[test]
    fn test_new_backup_writes_v2() {
        let blob = create_backup(&test_config(), Some("pw")).unwrap();
        assert_eq!(blob[4], VERSION, "新建备份应写 v2");
        assert_eq!(VERSION, 2);
    }
}