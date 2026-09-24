//! PikPak 驱动（对齐 Go 版 drivers/pikpak 核心能力）
//!
//! - 授权：refresh_token 优先；失效时用 username/password 登录（web client）
//! - 列表：drive/v1/files?parent_id=
//! - 下载：文件详情 web_content_link / medias
//! - 写：建目录、重命名、移动、删除、上传（GCID + OSS PUT）

use super::{DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::Client;
use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const USER_API: &str = "https://user.mypikpak.net";
const DRIVE_API: &str = "https://api-drive.mypikpak.net";
const WEB_CLIENT_ID: &str = "YUMx5nI8ZU8Ap8pm";
const WEB_CLIENT_SECRET: &str = "dbw2OtmVEeuUvIptb1Coyg";

pub struct PikPak {
    account_id: String,
    http: Client,
    username: String,
    password: String,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    device_id: Mutex<String>,
    store: Arc<Store>,
}

impl PikPak {
    pub fn new(
        account_id: &str,
        username: String,
        password: String,
        refresh_token: String,
        access_token: String,
        device_id: String,
        store: Arc<Store>,
    ) -> Self {
        let device_id = if device_id.trim().is_empty() {
            Uuid::new_v4().to_string().replace('-', "")
        } else {
            device_id
        };
        PikPak {
            account_id: account_id.to_string(),
            http: Client::new(),
            username,
            password,
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            device_id: Mutex::new(device_id),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let id = self.account_id.clone();
        let r = refresh.to_string();
        let a = access.to_string();
        let d = self.device_id.lock().unwrap().clone();
        self.store.update_credential(&id, |c| {
            if let Credential::PikPak {
                refresh_token,
                access_token,
                device_id,
                ..
            } = c
            {
                *refresh_token = r;
                *access_token = a;
                *device_id = d;
            }
        });
    }

    async fn login(&self) -> Result<(), String> {
        if self.username.trim().is_empty() || self.password.is_empty() {
            return Err("PikPak 需要 username/password 或有效 refresh_token".into());
        }
        let url = format!("{USER_API}/v1/auth/signin?client_id={WEB_CLIENT_ID}");
        let resp = self
            .http
            .post(&url)
            .json(&json!({
                "client_id": WEB_CLIENT_ID,
                "client_secret": WEB_CLIENT_SECRET,
                "username": self.username,
                "password": self.password,
            }))
            .send()
            .await
            .map_err(|e| format!("PikPak 登录失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        if let Some(code) = v.get("error_code").and_then(|c| c.as_i64()) {
            if code != 0 {
                return Err(format!(
                    "PikPak 登录失败: {}",
                    v.get("error_description")
                        .or_else(|| v.get("error"))
                        .and_then(|e| e.as_str())
                        .unwrap_or(&text)
                ));
            }
        }
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("登录无 access_token: {text}"))?;
        let refresh = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        self.save_tokens(refresh, access);
        Ok(())
    }

    async fn refresh(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if rt.is_empty() {
            return self.login().await;
        }
        let url = format!("{USER_API}/v1/auth/token?client_id={WEB_CLIENT_ID}");
        let resp = self
            .http
            .post(&url)
            .json(&json!({
                "client_id": WEB_CLIENT_ID,
                "client_secret": WEB_CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": rt,
            }))
            .send()
            .await
            .map_err(|e| format!("刷新 token 失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let err_code = v.get("error_code").and_then(|c| c.as_i64()).unwrap_or(0);
        if err_code != 0 {
            return self.login().await;
        }
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("刷新无 access_token: {text}"))?;
        let refresh = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or(&rt);
        self.save_tokens(refresh, access);
        Ok(())
    }

    async fn ensure_token(&self) -> Result<String, String> {
        let at = self.access_token.lock().unwrap().clone();
        if at.is_empty() {
            self.refresh().await?;
            return Ok(self.access_token.lock().unwrap().clone());
        }
        Ok(at)
    }

    async fn request(&self, method: &str, url: &str, body: Option<Value>) -> Result<Value, String> {
        let mut token = self.ensure_token().await?;
        let device = self.device_id.lock().unwrap().clone();
        for attempt in 0..2 {
            let mut req = match method {
                "GET" => self.http.get(url),
                "POST" => self.http.post(url),
                "PATCH" => self.http.patch(url),
                "DELETE" => self.http.delete(url),
                _ => self.http.request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                    url,
                ),
            };
            req = req
                .header("Authorization", format!("Bearer {token}"))
                .header("X-Device-Id", &device)
                .header("User-Agent", "Mozilla/5.0");
            if let Some(ref b) = body {
                req = req.json(b);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| format!("PikPak 请求失败: {e}"))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
            let err_code = v.get("error_code").and_then(|c| c.as_i64()).unwrap_or(0);
            if (status == 401 || err_code == 16) && attempt == 0 {
                self.refresh().await?;
                token = self.access_token.lock().unwrap().clone();
                continue;
            }
            if err_code != 0 {
                return Err(format!(
                    "PikPak 错误: {}",
                    v.get("error_description")
                        .or_else(|| v.get("error"))
                        .and_then(|e| e.as_str())
                        .unwrap_or(&text)
                ));
            }
            if !(200..300).contains(&status) && !text.is_empty() {
                return Err(format!("PikPak HTTP ({status}): {}", truncate(&text, 300)));
            }
            return Ok(v);
        }
        Err("PikPak 认证失败".into())
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.refresh().await?;
        let _ = self
            .request(
                "GET",
                &format!("{DRIVE_API}/drive/v1/files?parent_id=&limit=1"),
                None,
            )
            .await?;
        Ok(())
    }

    fn root_id(fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            String::new()
        } else {
            fid.trim_start_matches('/').to_string()
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = Self::root_id(parent_fid);
        let mut out = Vec::new();
        let mut page_token = String::new();
        loop {
            let mut url = format!(
                "{DRIVE_API}/drive/v1/files?parent_id={parent}&thumbnail_size=SIZE_LARGE&with_audit=true&limit=100&filters=%7B%22phase%22%3A%7B%22eq%22%3A%22PHASE_TYPE_COMPLETE%22%7D%2C%22trashed%22%3A%7B%22eq%22%3Afalse%7D%7D"
            );
            if !page_token.is_empty() {
                url.push_str(&format!("&page_token={page_token}"));
            }
            let v = self.request("GET", &url, None).await?;
            let files = v
                .get("files")
                .and_then(|f| f.as_array())
                .cloned()
                .unwrap_or_default();
            for f in files {
                let id = f
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = f
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let kind = f.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                let is_dir = kind == "drive#folder" || kind.contains("folder");
                let size: u64 = f
                    .get("size")
                    .and_then(|s| {
                        s.as_str()
                            .and_then(|x| x.parse().ok())
                            .or_else(|| s.as_u64())
                    })
                    .unwrap_or(0);
                if id.is_empty() || name.is_empty() {
                    continue;
                }
                out.push(Entry {
                    fid: id,
                    name,
                    size: if is_dir { 0 } else { size },
                    is_dir,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            page_token = v
                .get("next_page_token")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if page_token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let url = format!(
            "{DRIVE_API}/drive/v1/files/{}?_magic=2021&usage=FETCH&thumbnail_size=SIZE_LARGE",
            e.fid
        );
        let v = self.request("GET", &url, None).await?;
        let mut link = v
            .get("web_content_link")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if link.is_empty() {
            if let Some(medias) = v.get("medias").and_then(|m| m.as_array()) {
                if let Some(first) = medias.first() {
                    link = first
                        .pointer("/link/url")
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .to_string();
                }
            }
        }
        if link.is_empty() {
            return Err("PikPak 未返回下载链接".into());
        }
        Ok(DownloadInfo {
            url: link,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let parent = Self::root_id(parent_fid);
        self.request(
            "POST",
            &format!("{DRIVE_API}/drive/v1/files"),
            Some(json!({
                "kind": "drive#folder",
                "name": name,
                "parent_id": parent,
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        self.request(
            "PATCH",
            &format!("{DRIVE_API}/drive/v1/files/{}", e.fid),
            Some(json!({ "name": new_name })),
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
        let dst = Self::root_id(dst_dir_fid);
        self.request(
            "POST",
            &format!("{DRIVE_API}/drive/v1/files:batchMove"),
            Some(json!({
                "ids": [e.fid],
                "to": { "parent_id": dst },
            })),
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
        let dst = Self::root_id(dst_dir_fid);
        self.request(
            "POST",
            &format!("{DRIVE_API}/drive/v1/files:batchCopy"),
            Some(json!({
                "ids": [e.fid],
                "to": { "parent_id": dst },
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        self.request(
            "POST",
            &format!("{DRIVE_API}/drive/v1/files:batchTrash"),
            Some(json!({ "ids": [e.fid] })),
        )
        .await?;
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let tmp = std::env::temp_dir().join(format!("olrs-pikpak-{}", Uuid::new_v4()));
        let mut file = tokio::fs::File::create(&tmp)
            .await
            .map_err(|e| format!("创建临时文件: {e}"))?;
        let mut size = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = input
                .reader
                .read(&mut buf)
                .await
                .map_err(|e| format!("读流: {e}"))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .await
                .map_err(|e| format!("写临时: {e}"))?;
            size += n as u64;
        }
        file.flush().await.ok();
        drop(file);

        let data = tokio::fs::read(&tmp)
            .await
            .map_err(|e| format!("读临时: {e}"))?;
        let gcid = gcid_hex(&data);
        let parent = Self::root_id(dst_dir_fid);

        let v = self
            .request(
                "POST",
                &format!("{DRIVE_API}/drive/v1/files"),
                Some(json!({
                    "kind": "drive#file",
                    "name": input.name,
                    "size": size.to_string(),
                    "hash": gcid,
                    "upload_type": "UPLOAD_TYPE_RESUMABLE",
                    "objProvider": { "provider": "UPLOAD_TYPE_UNKNOWN" },
                    "parent_id": parent,
                    "folder_type": "NORMAL",
                })),
            )
            .await?;

        let resumable = v.get("resumable");
        if resumable.is_none() || resumable == Some(&json!(null)) {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Ok(());
        }
        let params = resumable
            .and_then(|r| r.get("params"))
            .ok_or("无 resumable.params")?;
        let access_key = params
            .get("access_key_id")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let secret = params
            .get("access_key_secret")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let bucket = params.get("bucket").and_then(|x| x.as_str()).unwrap_or("");
        let endpoint = params
            .get("endpoint")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        let key = params.get("key").and_then(|x| x.as_str()).unwrap_or("");
        let security_token = params
            .get("security_token")
            .and_then(|x| x.as_str())
            .unwrap_or("");
        if access_key.is_empty() || bucket.is_empty() || key.is_empty() {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(format!("OSS 参数不完整: {params}"));
        }

        let host = if endpoint.contains("://") {
            endpoint
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .to_string()
        } else {
            endpoint.to_string()
        };
        let url = if host.starts_with(&format!("{bucket}.")) {
            format!("https://{host}/{key}")
        } else {
            format!("https://{bucket}.{host}/{key}")
        };

        let date = httpdate_now();
        let resource = format!("/{bucket}/{key}");
        let mut string_to_sign = String::from("PUT");
        string_to_sign.push('\n');
        string_to_sign.push('\n');
        string_to_sign.push('\n');
        string_to_sign.push_str(&date);
        string_to_sign.push('\n');
        if !security_token.is_empty() {
            string_to_sign.push_str("x-oss-security-token:");
            string_to_sign.push_str(security_token);
            string_to_sign.push('\n');
        }
        string_to_sign.push_str(&resource);
        let mut mac =
            Hmac::<Sha1>::new_from_slice(secret.as_bytes()).map_err(|e| format!("hmac: {e}"))?;
        mac.update(string_to_sign.as_bytes());
        let sig = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        let auth = format!("OSS {access_key}:{sig}");

        let mut req = self
            .http
            .put(&url)
            .header("Date", &date)
            .header("Authorization", auth)
            .header("User-Agent", "aliyun-sdk-android/2.9.13");
        if !security_token.is_empty() {
            req = req.header("x-oss-security-token", security_token);
        }
        let resp = req
            .body(data)
            .send()
            .await
            .map_err(|e| format!("OSS PUT: {e}"))?;
        let st = resp.status().as_u16();
        let _ = tokio::fs::remove_file(&tmp).await;
        if !(200..300).contains(&st) {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("OSS PUT ({st}): {}", truncate(&text, 300)));
        }
        Ok(())
    }
}

/// 对齐 Go hash_extend.GCID（块大小随文件增大）
fn gcid_hex(data: &[u8]) -> String {
    let size = data.len() as i64;
    let mut psize: i64 = 0x40000;
    while (size as f64) / (psize as f64) > 512.0 && psize < 0x20_0000 {
        psize <<= 1;
    }
    let block = psize as usize;
    let mut outer = Sha1::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + block).min(data.len());
        let mut inner = Sha1::new();
        inner.update(&data[offset..end]);
        outer.update(inner.finalize());
        offset = end;
    }
    hex::encode(outer.finalize()).to_uppercase()
}

fn httpdate_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let day_idx = ((secs / 86400) + 4) % 7;
    let mut rem = secs;
    let mut days_since = rem / 86400;
    rem %= 86400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let mut year = 1970i32;
    loop {
        let diy = if is_leap(year) { 366 } else { 365 };
        if days_since < diy {
            break;
        }
        days_since -= diy;
        year += 1;
    }
    let md = [
        31,
        if is_leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0usize;
    while month < 12 && days_since >= md[month] {
        days_since -= md[month];
        month += 1;
    }
    let day = days_since + 1;
    format!(
        "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT",
        days[day_idx as usize], day, months[month], year, h, m, s
    )
}

fn is_leap(y: i32) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
