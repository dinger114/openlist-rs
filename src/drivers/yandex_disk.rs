//! Yandex.Disk 驱动（对齐 Go 版 drivers/yandex_disk）
//!
//! - 授权：refresh_token，默认走 olist 在线刷新 API（可关掉用自有 client_id/secret）
//! - API：https://cloud-api.yandex.net/v1/disk/resources
//! - 下载：GET /download 拿 href 直链（无需额外请求头）

use super::{DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const API: &str = "https://cloud-api.yandex.net/v1/disk/resources";
const ONLINE_REFRESH: &str = "https://api.oplist.org/yandexui/renewapi";

pub struct YandexDisk {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    use_online_api: bool,
    api_address: String,
    client_id: String,
    client_secret: String,
    root_path: String,
    store: Arc<Store>,
}

impl YandexDisk {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        use_online_api: bool,
        api_address: String,
        client_id: String,
        client_secret: String,
        root_path: String,
        store: Arc<Store>,
    ) -> Self {
        YandexDisk {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            use_online_api,
            api_address: if api_address.is_empty() {
                ONLINE_REFRESH.to_string()
            } else {
                api_address
            },
            client_id,
            client_secret,
            root_path: normalize_root(&root_path),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::YandexDisk {
                refresh_token,
                access_token,
                ..
            } = cred
            {
                *refresh_token = r.clone();
                *access_token = a.clone();
            }
        });
    }

    /// 刷新 token：默认 olist 在线 API；否则用 client_id/secret 走官方 OAuth
    async fn refresh_token(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if self.use_online_api {
            let url = format!(
                "{}?refresh_ui={}&server_use=true&driver_txt=yandexui_go",
                self.api_address,
                urlencode(&rt)
            );
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("刷新 Yandex token 失败: {e}"))?;
            let v: Value = resp
                .json()
                .await
                .map_err(|e| format!("刷新响应解析失败: {e}"))?;
            let access = v
                .get("access_token")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            let refresh = v
                .get("refresh_token")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if access.is_empty() || refresh.is_empty() {
                let msg = v
                    .get("text")
                    .or_else(|| v.get("message"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("空 token（refresh_token 可能不正确）");
                return Err(format!("刷新 Yandex token 失败: {msg}"));
            }
            self.save_tokens(&refresh, &access);
            return Ok(());
        }
        // 本地客户端刷新
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Err("未启用在线刷新且 client_id/client_secret 为空".into());
        }
        let resp = self
            .http
            .post("https://oauth.yandex.com/token")
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("刷新 Yandex token 失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("刷新响应解析失败: {e}"))?;
        if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
            let desc = v
                .get("error_description")
                .and_then(|x| x.as_str())
                .unwrap_or("");
            return Err(format!("刷新 Yandex token 失败: {err}: {desc}"));
        }
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let refresh = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or(&rt)
            .to_string();
        if access.is_empty() {
            return Err("刷新 Yandex token 失败: 空 access_token".into());
        }
        self.save_tokens(&refresh, &access);
        Ok(())
    }

    pub async fn validate(&self) -> Result<(), String> {
        // 无 access_token 或验证失败都直接刷新一次
        self.refresh_token().await?;
        Ok(())
    }

    /// fid(绝对路径) → 实际 API 路径（拼上 root_path 前缀）
    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        let sub = if fid.is_empty() || fid == "0" || fid == "/" {
            "/"
        } else {
            fid
        };
        join_path(&self.root_path, sub)
    }

    async fn request(
        &self,
        method: reqwest::Method,
        url: String,
        query: Option<Vec<(String, String)>>,
    ) -> Result<(u16, Value), String> {
        let token = self.access_token.lock().unwrap().clone();
        let mut req = self
            .http
            .request(method, &url)
            .header("Authorization", format!("OAuth {token}"));
        if let Some(q) = query {
            req = req.query(&q);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("Yandex 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        Ok((status, v))
    }

    /// 统一带 401 自动刷新重试的请求
    async fn request_auth(
        &self,
        method: reqwest::Method,
        path: &str,
        query: Option<Vec<(String, String)>>,
    ) -> Result<Value, String> {
        let url = format!("{API}{path}");
        let (status, v) = self
            .request(method.clone(), url.clone(), query.clone())
            .await?;
        if status == 401 {
            self.refresh_token().await?;
            let (status2, v2) = self.request(method, url, query).await?;
            if status2 >= 400 {
                return Err(format!(
                    "Yandex API 失败 ({status2}): {}",
                    api_err_msg(&v2, status2)
                ));
            }
            return Ok(v2);
        }
        if status >= 400 {
            return Err(format!(
                "Yandex API 失败 ({status}): {}",
                api_err_msg(&v, status)
            ));
        }
        Ok(v)
    }

    /// 分页拉取目录内容
    async fn get_files(&self, path: &str) -> Result<Vec<Value>, String> {
        let limit = 100i64;
        let mut offset = 0i64;
        let mut out = Vec::new();
        loop {
            let v = self
                .request_auth(
                    reqwest::Method::GET,
                    "",
                    Some(vec![
                        ("path".into(), path.into()),
                        ("limit".into(), limit.to_string()),
                        ("offset".into(), offset.to_string()),
                    ]),
                )
                .await?;
            let total = v
                .pointer("/_embedded/total")
                .and_then(|x| x.as_i64())
                .unwrap_or(0);
            let items = v
                .pointer("/_embedded/items")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            let got = items.len() as i64;
            out.extend(items);
            if got == 0 || offset + got >= total {
                break;
            }
            offset += got;
        }
        Ok(out)
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve(parent_fid);
        let files = self.get_files(&path).await?;
        let mut out = Vec::new();
        for f in files {
            let name = f
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }
            let is_dir = f.get("type").and_then(|t| t.as_str()) == Some("dir");
            let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            // 条目路径 = 父目录 fid（不带 root_path）+ 名称，保证 fid 是用户可见的相对路径
            let parent_rel = normalize_user_fid(parent_fid);
            let fid = join_path(&parent_rel, &name);
            let updated_at = f
                .get("modified")
                .and_then(|m| m.as_str())
                .and_then(parse_rfc3339_millis);
            out.push(Entry {
                fid,
                name,
                size: if is_dir { 0 } else { size },
                is_dir,
                updated_at,
                etag: None,
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let path = self.resolve(&e.fid);
        let v = self
            .request_auth(
                reqwest::Method::GET,
                "/download",
                Some(vec![("path".into(), path)]),
            )
            .await?;
        let url = v
            .get("href")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("Yandex 未返回下载 href".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let path = join_path(&self.resolve(parent_fid), name.trim_matches('/'));
        self.request_auth(reqwest::Method::PUT, "", Some(vec![("path".into(), path)]))
            .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let from = self.resolve(&e.fid);
        let parent = parent_of(&from);
        let to = join_path(&parent, new_name);
        self.request_auth(
            reqwest::Method::POST,
            "/move",
            Some(vec![
                ("from".into(), from),
                ("path".into(), to),
                ("overwrite".into(), "true".into()),
            ]),
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
        let from = self.resolve(&e.fid);
        let to = join_path(&self.resolve(dst_dir_fid), &e.name);
        self.request_auth(
            reqwest::Method::POST,
            "/move",
            Some(vec![
                ("from".into(), from),
                ("path".into(), to),
                ("overwrite".into(), "true".into()),
            ]),
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
        let from = self.resolve(&e.fid);
        let to = join_path(&self.resolve(dst_dir_fid), &e.name);
        self.request_auth(
            reqwest::Method::POST,
            "/copy",
            Some(vec![
                ("from".into(), from),
                ("path".into(), to),
                ("overwrite".into(), "true".into()),
            ]),
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.resolve(&e.fid);
        self.request_auth(
            reqwest::Method::DELETE,
            "",
            Some(vec![("path".into(), path)]),
        )
        .await?;
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        // Yandex 上传：先取上传 href，再 PUT 内容
        let path = join_path(&self.resolve(dst_dir_fid), &input.name);
        let v = self
            .request_auth(
                reqwest::Method::GET,
                "/upload",
                Some(vec![
                    ("path".into(), path),
                    ("overwrite".into(), "true".into()),
                ]),
            )
            .await?;
        let href = v
            .get("href")
            .and_then(|h| h.as_str())
            .unwrap_or("")
            .to_string();
        let method = v
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("PUT")
            .to_string();
        if href.is_empty() {
            return Err("Yandex 未返回上传 href".into());
        }
        let mut buf = Vec::new();
        let mut tmp = [0u8; 64 * 1024];
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
            if buf.len() > 500 * 1024 * 1024 {
                return Err("单文件上传暂限 500MB".into());
            }
        }
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::PUT);
        let resp = self
            .http
            .request(m, &href)
            .header("Content-Type", "application/octet-stream")
            .body(buf)
            .send()
            .await
            .map_err(|e| format!("Yandex 上传失败: {e}"))?;
        let status = resp.status().as_u16();
        if status >= 400 {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "Yandex 上传失败 ({status}): {}",
                truncate(&text, 200)
            ));
        }
        Ok(())
    }
}

// ---------- 小工具 ----------

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn api_err_msg(v: &Value, _status: u16) -> String {
    v.get("message")
        .or_else(|| v.get("description"))
        .or_else(|| v.get("error"))
        .and_then(|m| m.as_str())
        .unwrap_or("未知错误")
        .to_string()
}

fn normalize_root(root: &str) -> String {
    let root = root.trim();
    if root.is_empty() || root == "0" {
        "/".to_string()
    } else if root.starts_with('/') {
        root.trim_end_matches('/').to_string().to_string()
    } else {
        format!("/{}", root.trim_end_matches('/'))
    }
}

/// 用户可见 fid：把 root_path 前缀剥掉
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

fn join_path(base: &str, sub: &str) -> String {
    let base = base.trim_end_matches('/');
    let sub = sub.trim_matches('/');
    if sub.is_empty() {
        if base.is_empty() {
            "/".to_string()
        } else {
            base.to_string()
        }
    } else if base.is_empty() {
        format!("/{sub}")
    } else {
        format!("{base}/{sub}")
    }
}

fn parent_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) | None => "/".to_string(),
        Some(i) => path[..i].to_string(),
    }
}

/// RFC3339 → 毫秒时间戳（简化实现，只用于展示）
fn parse_rfc3339_millis(s: &str) -> Option<i64> {
    // 2024-01-02T15:04:05+08:00 / 2024-01-02T15:04:05.123Z
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let mo: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    let h: i64 = s.get(11..13)?.parse().ok()?;
    let mi: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    // 粗略按 UTC 天数累加（展示用，误差可接受）
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

fn urlencode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
