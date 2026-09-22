//! Cloudreve V4 驱动（对齐 Go 版 drivers/cloudreve_v4）
//!
//! - 认证：账号密码登录 /session/token 换 JWT，或直接填 access/refresh token；
//!   access_token 过期自动用 refresh_token 刷新（/session/token/refresh），
//!   刷新失败（40020）且有账号密码时自动重登
//! - fid 即服务端返回的 uri path（如 "cloudreve://my/xxx"）；根 fid "/" 映射为 "cloudreve://my{root_path}"
//! - 上传：仅支持 local 存储策略 / relay 模式（分片 POST /file/upload/{session}/{chunk}），
//!   s3/onedrive/remote 策略暂不支持（明确报错）
//! - 下载直链需携带 Referer 头，走服务器代理

use super::{DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

const CODE_LOGIN_REQUIRED: i64 = 401;
const CODE_CREDENTIAL_INVALID: i64 = 40020;
const CODE_LOCK_CONFLICT: i64 = 40073;
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) OpenList";

pub struct CloudreveV4 {
    account_id: String,
    address: String,
    http: Client,
    username: String,
    password: String,
    access_token: Mutex<String>,
    refresh_token: Mutex<String>,
    /// access_expires（unix 秒；0 = 未知，退回解析 JWT exp）
    access_expires: Mutex<i64>,
    root_path: String,
    store: Arc<Store>,
}

impl CloudreveV4 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        address: String,
        username: String,
        password: String,
        access_token: String,
        refresh_token: String,
        root_path: String,
        store: Arc<Store>,
    ) -> Self {
        let address = address.trim().trim_end_matches('/').to_string();
        CloudreveV4 {
            account_id: account_id.to_string(),
            address,
            http: Client::new(),
            username,
            password,
            access_token: Mutex::new(access_token),
            refresh_token: Mutex::new(refresh_token),
            access_expires: Mutex::new(0),
            root_path: root_path.trim().trim_end_matches('/').to_string(),
            store,
        }
    }

    fn can_login(&self) -> bool {
        !self.username.is_empty() && !self.password.is_empty()
    }

    fn save_tokens(&self, access: &str, refresh: &str, expires: i64) {
        *self.access_token.lock().unwrap() = access.to_string();
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_expires.lock().unwrap() = expires;
        let (a, r) = (access.to_string(), refresh.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::CloudreveV4 {
                access_token,
                refresh_token,
                ..
            } = cred
            {
                *access_token = a.clone();
                *refresh_token = r.clone();
            }
        });
    }

    /// 解析 JWT payload 的 exp（unix 秒）；解析失败返回 None
    fn jwt_exp(token: &str) -> Option<i64> {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return None;
        }
        let payload = URL_SAFE_NO_PAD
            .decode(parts[1])
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())?;
        payload.get("exp").and_then(|e| e.as_i64())
    }

    fn now_secs() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64
    }

    /// 对齐 Go 版 isTokenExpired
    fn is_token_expired(&self) -> bool {
        let access = self.access_token.lock().unwrap().clone();
        let refresh = self.refresh_token.lock().unwrap().clone();
        if refresh.is_empty() {
            // 无 refresh token：有账号密码则重登，否则用现有 access token 直到最后
            return self.can_login();
        }
        if access.is_empty() {
            return true;
        }
        let expires = *self.access_expires.lock().unwrap();
        if expires > 0 {
            return Self::now_secs() >= expires - 60;
        }
        match Self::jwt_exp(&access) {
            Some(exp) => Self::now_secs() >= exp - 60,
            None => false, // 对齐 Go 版：解析失败不误杀
        }
    }

    /// 裸请求：带 Authorization 头（若有），返回完整响应 JSON；HTTP ≥400 报错
    async fn api(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        query: Option<Vec<(String, String)>>,
    ) -> Result<Value, String> {
        let url = format!("{}/api/v4{path}", self.address);
        let access = self.access_token.lock().unwrap().clone();
        let mut req = self
            .http
            .request(method, &url)
            .header("User-Agent", UA)
            .header("Accept", "application/json, text/plain, */*");
        if !access.is_empty() {
            req = req.header("Authorization", format!("Bearer {access}"));
        }
        if let Some(q) = &query {
            req = req.query(q);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("Cloudreve V4 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status >= 400 {
            return Err(format!("Cloudreve V4 请求失败 ({status}): {}", truncate(&text, 300)));
        }
        serde_json::from_str(&text).map_err(|e| format!("Cloudreve V4 响应解析失败: {e}"))
    }

    /// 业务请求：code!=0 报错；401/40020 自动刷新/重登后重试一次；成功返回 data
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        query: Option<Vec<(String, String)>>,
    ) -> Result<Value, String> {
        let send = || self.api(method.clone(), path, body.clone(), query.clone());
        if self.is_token_expired() {
            self.refresh_token().await?;
        }
        let v = send().await?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        if code == 0 {
            return Ok(v.get("data").cloned().unwrap_or(Value::Null));
        }
        if (code == CODE_LOGIN_REQUIRED || code == CODE_CREDENTIAL_INVALID) && path != "/session/token/refresh" {
            self.refresh_token().await?;
            let v2 = send().await?;
            let code2 = v2.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            if code2 == 0 {
                return Ok(v2.get("data").cloned().unwrap_or(Value::Null));
            }
            return Err(format!(
                "Cloudreve V4 请求失败 ({}): {}",
                code2,
                v2.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
        Err(format!(
            "Cloudreve V4 请求失败 ({code}): {}",
            v.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误")
        ))
    }

    async fn login(&self) -> Result<(), String> {
        if !self.can_login() {
            return Err("Cloudreve V4 需要账号密码或 token".into());
        }
        let prepare = self
            .api(
                reqwest::Method::GET,
                "/session/prepare",
                None,
                Some(vec![("email".into(), self.username.clone())]),
            )
            .await?;
        if prepare.get("code").and_then(|c| c.as_i64()).unwrap_or(0) != 0 {
            return Err(format!(
                "Cloudreve V4 登录准备失败: {}",
                prepare.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
        let data = prepare.get("data").cloned().unwrap_or(Value::Null);
        if data
            .get("webauthnEnabled")
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
        {
            return Err("该站点启用了 WebAuthn，暂不支持".into());
        }
        if !data
            .get("passwordEnabled")
            .and_then(|b| b.as_bool())
            .unwrap_or(true)
        {
            return Err("该账号未启用密码登录".into());
        }
        let v = self
            .api(
                reqwest::Method::POST,
                "/session/token",
                Some(json!({
                    "email": self.username,
                    "password": self.password,
                })),
                None,
            )
            .await?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        if code != 0 {
            return Err(format!(
                "Cloudreve V4 登录失败: {}",
                v.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
        let access = v
            .pointer("/data/token/access_token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let refresh = v
            .pointer("/data/token/refresh_token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if access.is_empty() || refresh.is_empty() {
            return Err("Cloudreve V4 登录未返回 token".into());
        }
        let expires = v
            .pointer("/data/token/access_expires")
            .and_then(|t| t.as_str())
            .and_then(parse_rfc3339)
            .unwrap_or(0);
        self.save_tokens(&access, &refresh, expires);
        Ok(())
    }

    async fn refresh_token(&self) -> Result<(), String> {
        let refresh = self.refresh_token.lock().unwrap().clone();
        if refresh.is_empty() {
            if self.can_login() {
                return self.login().await;
            }
            return Err("Cloudreve V4 无 refresh_token 且未配置账号密码".into());
        }
        let v = self
            .api(
                reqwest::Method::POST,
                "/session/token/refresh",
                Some(json!({ "refresh_token": refresh })),
                None,
            )
            .await?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
        if code == CODE_CREDENTIAL_INVALID {
            if self.can_login() {
                return self.login().await;
            }
            return Err("Cloudreve V4 会话已失效（refresh token 无法换新）".into());
        }
        if code != 0 {
            return Err(format!(
                "Cloudreve V4 刷新 token 失败 ({code}): {}",
                v.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
        let access = v
            .pointer("/data/access_token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        let new_refresh = v
            .pointer("/data/refresh_token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if access.is_empty() {
            return Err("Cloudreve V4 刷新 token 未返回 access_token".into());
        }
        let expires = v
            .pointer("/data/access_expires")
            .and_then(|t| t.as_str())
            .and_then(parse_rfc3339)
            .unwrap_or(0);
        self.save_tokens(&access, &new_refresh, expires);
        Ok(())
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.can_login() {
            return self.login().await;
        }
        if !self.refresh_token.lock().unwrap().is_empty() {
            return self.refresh_token().await;
        }
        let access = self.access_token.lock().unwrap().clone();
        if access.is_empty() {
            return Err("Cloudreve V4 至少需要 AccessToken / RefreshToken / 账号密码之一".into());
        }
        // 校验 access_token 是合法 JWT
        if Self::jwt_exp(&access).is_none() {
            // 解析不出 exp 不代表失效，探一次 /user/capacity
            self.request(reqwest::Method::GET, "/user/capacity", None, None)
                .await?;
        }
        Ok(())
    }

    /// fid → uri；根 "/" 映射为 "cloudreve://my{root_path}"
    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            return format!("cloudreve://my{}", self.root_path);
        }
        fid.to_string()
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let uri = self.resolve(parent_fid);
        let mut query = vec![
            ("page_size".into(), "100".into()),
            ("uri".into(), uri),
            ("order_by".into(), "name".into()),
            ("order_direction".into(), "asc".into()),
            ("page".into(), "0".into()),
        ];
        let mut files: Vec<Value> = Vec::new();
        loop {
            let data = self
                .request(reqwest::Method::GET, "/file", None, Some(query.clone()))
                .await?;
            let batch = data
                .get("files")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default();
            let got = batch.len();
            files.extend(batch);
            let next = data
                .pointer("/pagination/next_token")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if next.is_empty() || got < 100 {
                break;
            }
            query.retain(|(k, _)| k != "next_page_token");
            query.push(("next_page_token".into(), next));
        }
        let parent_rel = normalize_user_fid(parent_fid);
        let mut out = Vec::new();
        for f in files {
            let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let path = f.get("path").and_then(|p| p.as_str()).unwrap_or("").to_string();
            if name.is_empty() || path.is_empty() {
                continue;
            }
            let is_dir = f.get("type").and_then(|t| t.as_i64()) == Some(1);
            let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            let updated_at = f
                .get("updated_at")
                .and_then(|t| t.as_str())
                .and_then(parse_rfc3339_millis);
            out.push(Entry {
                // fid 用用户可见的相对路径（根为 /），download 时再映射回完整 uri
                fid: join_rel(&parent_rel, &name),
                name,
                size: if is_dir { 0 } else { size },
                is_dir,
                updated_at,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: Some(json!({ "uri": path })),
            });
        }
        Ok(out)
    }

    /// Entry.fid（相对路径）→ 下载用 uri；优先用 list 时缓存在 extra 里的服务端 uri
    fn entry_uri(&self, e: &Entry) -> String {
        if let Some(uri) = e
            .extra
            .as_ref()
            .and_then(|x| x.get("uri"))
            .and_then(|u| u.as_str())
        {
            if !uri.is_empty() {
                return uri.to_string();
            }
        }
        if e.fid.starts_with("cloudreve://") {
            e.fid.clone()
        } else {
            format!("cloudreve://my{}", join_rel(&self.root_path, &e.fid))
        }
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let uri = self.entry_uri(e);
        let data = self
            .request(
                reqwest::Method::POST,
                "/file/url",
                Some(json!({ "uris": [uri], "download": true })),
                None,
            )
            .await?;
        let url = data
            .pointer("/urls/0/url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("Cloudreve V4 未返回下载链接".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![
                ("Referer".into(), format!("{}/", self.address)),
                ("User-Agent".into(), UA.into()),
            ],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let parent_uri = self.resolve(parent_fid);
        let uri = format!("{}/{}", parent_uri.trim_end_matches('/'), name.trim_matches('/'));
        self.request(
            reqwest::Method::POST,
            "/file/create",
            Some(json!({
                "type": "folder",
                "uri": uri,
                "error_on_conflict": true,
            })),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        self.request(
            reqwest::Method::POST,
            "/file/rename",
            Some(json!({
                "new_name": new_name,
                "uri": self.entry_uri(e),
            })),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        self.request(
            reqwest::Method::POST,
            "/file/move",
            Some(json!({
                "uris": [self.entry_uri(e)],
                "dst": self.resolve(dst_dir_fid),
                "copy": false,
            })),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        self.request(
            reqwest::Method::POST,
            "/file/move",
            Some(json!({
                "uris": [self.entry_uri(e)],
                "dst": self.resolve(dst_dir_fid),
                "copy": true,
            })),
            None,
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let uri = self.entry_uri(e);
        let send = || {
            self.request(
                reqwest::Method::DELETE,
                "/file",
                Some(json!({
                    "uris": [&uri],
                    "unlink": false,
                    "skip_soft_delete": true,
                })),
                None,
            )
        };
        if let Err(err) = send().await {
            // 锁冲突：解锁后重试一次（对齐 Go 版 40073 处理）
            if !err.contains(&format!("code {CODE_LOCK_CONFLICT}")) {
                return Err(err);
            }
            return Err(format!("Cloudreve V4 删除失败（文件被锁定）: {err}"));
        }
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let dst_uri = self.resolve(dst_dir_fid);
        let uri = format!(
            "{}/{}",
            dst_uri.trim_end_matches('/'),
            input.name.trim_matches('/')
        );
        if input.size == 0 {
            // 空文件用新建文件方法，避免上传卡锁（对齐 Go 版）
            self.request(
                reqwest::Method::POST,
                "/file/create",
                Some(json!({
                    "type": "file",
                    "uri": uri,
                    "error_on_conflict": true,
                })),
                None,
            )
            .await?;
            return Ok(());
        }
        // 1. 拉目标目录信息拿 storage policy id
        let data = self
            .request(
                reqwest::Method::GET,
                "/file",
                None,
                Some(vec![
                    ("page_size".into(), "10".into()),
                    ("uri".into(), dst_uri),
                    ("order_by".into(), "created_at".into()),
                    ("order_direction".into(), "asc".into()),
                    ("page".into(), "0".into()),
                ]),
            )
            .await?;
        let policy_id = data
            .pointer("/storage_policy/id")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        // 2. 创建上传会话
        let session = self
            .request(
                reqwest::Method::PUT,
                "/file/upload",
                Some(json!({
                    "uri": uri,
                    "size": input.size,
                    "policy_id": policy_id,
                    "mime_type": "",
                })),
                None,
            )
            .await?;
        let session_id = session
            .get("session_id")
            .and_then(|s| s.as_str())
            .unwrap_or("")
            .to_string();
        let chunk_size = session.get("chunk_size").and_then(|c| c.as_i64()).unwrap_or(0);
        let relay = session
            .pointer("/storage_policy/relay")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let policy_type = session
            .pointer("/storage_policy/type")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if !relay && policy_type != "local" {
            return Err(format!(
                "Cloudreve V4 暂不支持 {policy_type} 存储策略上传，请使用本地存储策略或开启中转"
            ));
        }
        let default_chunk = if chunk_size > 0 { chunk_size } else { input.size as i64 };
        // 3. 缓冲后分片上传
        let mut buf = Vec::with_capacity(input.size as usize);
        let mut tmp = vec![0u8; 64 * 1024];
        loop {
            let n = input
                .reader
                .read(&mut tmp)
                .await
                .map_err(|e| format!("读上传流失败: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 1024 * 1024 * 1024 {
                return Err("单文件上传暂限 1GB".into());
            }
        }
        let mut finish = 0usize;
        let mut chunk = 0u32;
        while finish < buf.len() {
            let byte_size = std::cmp::min(buf.len() - finish, default_chunk as usize);
            let slice = &buf[finish..finish + byte_size];
            self.upload_chunk(&session_id, chunk, slice).await?;
            finish += byte_size;
            chunk += 1;
        }
        Ok(())
    }

    /// 分片上传：POST /file/upload/{session}/{chunk}，octet-stream 原始字节
    async fn upload_chunk(&self, session_id: &str, chunk: u32, data: &[u8]) -> Result<(), String> {
        let url = format!("{}/api/v4/file/upload/{session_id}/{chunk}", self.address);
        let access = self.access_token.lock().unwrap().clone();
        let mut last_err = String::new();
        for _ in 0..3 {
            let resp = self
                .http
                .post(&url)
                .header("User-Agent", UA)
                .header("Authorization", format!("Bearer {access}"))
                .header("Content-Type", "application/octet-stream")
                .body(data.to_vec())
                .send()
                .await;
            match resp {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
                    let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(if status < 400 { 0 } else { status as i64 });
                    if code == 0 {
                        return Ok(());
                    }
                    last_err = format!("分片 {chunk} 上传失败 ({code}): {}", truncate(&text, 200));
                }
                Err(e) => last_err = format!("分片 {chunk} 上传失败: {e}"),
            }
        }
        Err(last_err)
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn normalize_user_fid(fid: &str) -> String {
    let fid = fid.trim();
    if fid.is_empty() || fid == "0" {
        "/".to_string()
    } else if fid.starts_with('/') {
        fid.to_string()
    } else {
        format!("/{fid}")
    }
}

fn join_rel(base: &str, sub: &str) -> String {
    let base = base.trim_end_matches('/');
    let sub = sub.trim_matches('/');
    if base.is_empty() {
        format!("/{sub}")
    } else {
        format!("{base}/{sub}")
    }
}

fn parse_rfc3339(s: &str) -> Option<i64> {
    parse_rfc3339_millis(s).map(|m| m / 1000)
}

/// RFC3339 → 毫秒时间戳（展示用）
fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let mo: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    let h: i64 = s.get(11..13)?.parse().ok()?;
    let mi: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    let days = days_from_civil(y, mo, d);
    Some((days * 86400 + h * 3600 + mi * 60 + sec) * 1000)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}
