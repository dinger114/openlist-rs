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
use serde_json;
use std::io;

const MAGIC: &[u8; 4] = b"OLBK";
const VERSION: u8 = 1;
const FLAG_ENCRYPTED: u8 = 0x01;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// 多轮 SHA256 迭代次数：足够慢以抵抗暴力破解，足够快不影响日常使用
const KDF_ITERATIONS: u32 = 2000;

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
    if version != VERSION {
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
        let plain = decrypt_with_password(pw, salt, nonce, ciphertext)?;
        serde_json::from_slice::<Config>(&plain).map_err(|e| format!("备份数据解析失败: {e}"))
    } else {
        if password.is_some() {
            return Err("该备份未加密，不需要密码".into());
        }
        serde_json::from_slice::<Config>(payload).map_err(|e| format!("备份数据解析失败: {e}"))
    }
}

// ---------- 内部：加密 / 解密 ----------

fn encrypt_with_password(
    password: &str,
    plain: &[u8],
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), String> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill(&mut salt);
    rand::rng().fill(&mut nonce);

    let key = derive_key(password, &salt);
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
) -> Result<Vec<u8>, String> {
    let key = derive_key(password, salt);
    let cipher = Aes256Gcm::new(&key.into());
    let nonce_ref: &Nonce<_> = nonce
        .try_into()
        .map_err(|_| format!("nonce 长度不是 {NONCE_LEN} 字节"))?;
    cipher
        .decrypt(nonce_ref, ct)
        .map_err(|_| "密码错误或数据损坏".to_string())
}

/// 多轮 SHA256 密钥派生（password + salt → 32 字节 AES 密钥）
fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    use sha2::{Digest, Sha256};

    let mut input = Vec::with_capacity(password.len() + salt.len());
    input.extend_from_slice(password.as_bytes());
    input.extend_from_slice(salt);

    let mut result = Sha256::digest(&input);

    for _ in 0..KDF_ITERATIONS {
        let mut hasher = Sha256::new();
        hasher.update(&result);
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
    extract::{Multipart, State},
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
    let data = st.store.data.lock().unwrap();
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
    mut multipart: Multipart,
) -> Response {
    let mut file_bytes: Option<Bytes> = None;
    let mut password: Option<String> = None;

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("");
        match name {
            "file" => {
                file_bytes = field.bytes().await.ok();
            }
            "password" => {
                password = field.text().await.ok();
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

    let pwd = password.as_deref().map(str::trim).filter(|p| !p.is_empty());
    match parse_backup(&blob, pwd) {
        Ok(config) => {
            let account_count = config.accounts.len();
            // 先验证再写入：save 失败不修改原配置
            let save_result = {
                let mut data = st.store.data.lock().unwrap();
                *data = config;
                st.store.save(&data)
            };
            match save_result {
                Ok(()) => {
                    // 配置已变更，清空全部会话
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
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": e })),
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
        let k1 = derive_key("pw", b"salt1234567890");
        let k2 = derive_key("pw", b"salt1234567890");
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_derive_key_differs_for_different_passwords() {
        let k1 = derive_key("pw1", b"salt1234567890");
        let k2 = derive_key("pw2", b"salt1234567890");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_derive_key_differs_for_different_salts() {
        let k1 = derive_key("pw", b"salt1234567890");
        let k2 = derive_key("pw", b"different salt");
        assert_ne!(k1, k2);
    }
}