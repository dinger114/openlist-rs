//! 123 Open 驱动（对齐 Go 版 drivers/123_open）
//!
//! - 授权：ClientID+ClientSecret 或 RefreshToken 在线刷新（api.oplist.org）
//! - 列目录：GET https://open-api.123pan.com/api/v2/file/list
//! - 下载：GET https://open-api.123pan.com/api/v1/file/download_info

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const API: &str = "https://open-api.123pan.com";
const ONLINE_REFRESH: &str = "https://api.oplist.org/123cloud/renewapi";
const ACCESS_TOKEN_URL: &str = "https://open-api.123pan.com/api/v1/access_token";

pub struct Pan123Open {
    account_id: String,
    http: Client,
    client_id: String,
    client_secret: String,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    use_online_api: bool,
    api_address: String,
    expired_at: Mutex<Option<Instant>>,
    store: Arc<Store>,
}

impl Pan123Open {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        client_id: String,
        client_secret: String,
        refresh_token: String,
        access_token: String,
        use_online_api: bool,
        api_address: String,
        store: Arc<Store>,
    ) -> Self {
        Pan123Open {
            account_id: account_id.to_string(),
            http: Client::new(),
            client_id,
            client_secret,
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            use_online_api,
            api_address: if api_address.is_empty() {
                ONLINE_REFRESH.to_string()
            } else {
                api_address
            },
            expired_at: Mutex::new(None),
            store,
        }
    }

    fn save_tokens(&self, refresh: Option<&str>, access: &str) {
        *self.access_token.lock().unwrap() = access.to_string();
        if let Some(r) = refresh {
            *self.refresh_token.lock().unwrap() = r.to_string();
        }
        let (r, a) = (
            self.refresh_token.lock().unwrap().clone(),
            access.to_string(),
        );
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Pan123Open {
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

    async fn flush_access_token(&self) -> Result<(), String> {
        // 在线刷新
        if self.use_online_api && !self.refresh_token.lock().unwrap().is_empty() {
            let rt = self.refresh_token.lock().unwrap().clone();
            let url = format!(
                "{}?refresh_ui={}&server_use=true&driver_txt=123cloud_oa",
                self.api_address,
                urlencoding::encode(&rt)
            );
            let resp = self
                .http
                .get(&url)
                .send()
                .await
                .map_err(|e| format!("刷新 123 Open token 失败: {e}"))?;
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
            if access.is_empty() {
                let msg = v
                    .get("text")
                    .or_else(|| v.get("message"))
                    .or_else(|| v.get("error_description"))
                    .and_then(|x| x.as_str())
                    .unwrap_or("空 token");
                return Err(format!("刷新 123 Open token 失败: {msg}"));
            }
            self.save_tokens(if refresh.is_empty() { None } else { Some(&refresh) }, &access);
            *self.expired_at.lock().unwrap() =
                Some(Instant::now() + Duration::from_secs(90 * 24 * 3600));
            return Ok(());
        }
        // Client credentials
        if !self.client_id.is_empty() && !self.client_secret.is_empty() {
            let body = json!({
                "clientID": self.client_id,
                "clientSecret": self.client_secret,
            });
            let resp = self
                .http
                .post(ACCESS_TOKEN_URL)
                .header("platform", "open_platform")
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("获取 access_token 失败: {e}"))?;
            let v: Value = resp
                .json()
                .await
                .map_err(|e| format!("响应解析失败: {e}"))?;
            let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
            if code != 0 {
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                return Err(format!("获取 access_token 失败(code={code}): {msg}"));
            }
            let access = v
                .pointer("/data/accessToken")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if access.is_empty() {
                return Err("accessToken 为空".into());
            }
            self.save_tokens(None, &access);
            *self.expired_at.lock().unwrap() =
                Some(Instant::now() + Duration::from_secs(90 * 24 * 3600));
            return Ok(());
        }
        // 已有 access_token 且未过期
        if !self.access_token.lock().unwrap().is_empty() {
            return Ok(());
        }
        Err("无有效授权方式：请配置 ClientID+ClientSecret 或 RefreshToken".into())
    }

    async fn get_token(&self, force: bool) -> Result<String, String> {
        let need = force
            || self.access_token.lock().unwrap().is_empty()
            || self
                .expired_at
                .lock()
                .unwrap()
                .map(|t| t.elapsed() > Duration::ZERO)
                .unwrap_or(true);
        // expired_at 存的是「到期时刻」，elapsed>0 表示已过期
        let expired = self
            .expired_at
            .lock()
            .unwrap()
            .map(|t| Instant::now() >= t)
            .unwrap_or(true);
        if force || self.access_token.lock().unwrap().is_empty() || expired {
            let _ = need;
            self.flush_access_token().await?;
        }
        Ok(self.access_token.lock().unwrap().clone())
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: Option<&[(String, String)]>,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let token = self.get_token(false).await?;
        let url = format!("{API}{path}");
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header("authorization", format!("Bearer {token}"))
            .header("platform", "open_platform")
            .header("Content-Type", "application/json");
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(b) = body.clone() {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        if code == 401 && !retried {
            self.get_token(true).await?;
            return Box::pin(self.request(method, path, query, body, true)).await;
        }
        if code != 0 {
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("123 Open 接口错误(code={code}): {msg}"));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.get_token(false).await?;
        self.request(Method::GET, "/api/v1/user/info", None, None, false)
            .await?;
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent: i64 = parent_fid.parse().unwrap_or(0);
        let mut files = Vec::new();
        let mut last_file_id: i64 = 0;
        loop {
            let query = vec![
                ("parentFileId".into(), parent.to_string()),
                ("limit".into(), "100".into()),
                ("lastFileId".into(), last_file_id.to_string()),
            ];
            let resp = self
                .request(
                    Method::GET,
                    "/api/v2/file/list",
                    Some(&query),
                    None,
                    false,
                )
                .await?;
            let list = resp
                .pointer("/data/fileList")
                .or_else(|| resp.pointer("/data/FileList"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &list {
                let trashed = f
                    .get("trashed")
                    .or_else(|| f.get("Trashed"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                if trashed != 0 {
                    continue;
                }
                let ftype = f
                    .get("type")
                    .or_else(|| f.get("Type"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                let fid = f
                    .get("fileId")
                    .or_else(|| f.get("FileId"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                files.push(Entry {
                    fid: fid.to_string(),
                    name: f
                        .get("filename")
                        .or_else(|| f.get("FileName"))
                        .or_else(|| f.get("fileName"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f
                        .get("size")
                        .or_else(|| f.get("Size"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    is_dir: ftype == 1,
                    updated_at: None,
                    etag: f
                        .get("etag")
                        .or_else(|| f.get("Etag"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    s3_key_flag: f
                        .get("s3KeyFlag")
                        .or_else(|| f.get("S3KeyFlag"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    file_type: Some(ftype),
                    extra: None,
                });
            }
            last_file_id = resp
                .pointer("/data/lastFileId")
                .or_else(|| resp.pointer("/data/LastFileId"))
                .and_then(|v| v.as_i64())
                .unwrap_or(-1);
            if last_file_id == -1 || list.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let file_id: i64 = e.fid.parse().unwrap_or(0);
        let query = vec![("fileId".into(), file_id.to_string())];
        let resp = self
            .request(
                Method::GET,
                "/api/v1/file/download_info",
                Some(&query),
                None,
                false,
            )
            .await?;
        let url = resp
            .pointer("/data/downloadUrl")
            .or_else(|| resp.pointer("/data/DownloadUrl"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("123 Open 未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let parent: i64 = parent_fid.parse().unwrap_or(0);
        let body = json!({
            "name": name,
            "parentID": parent,
        });
        self.request(Method::POST, "/upload/v1/file/mkdir", None, Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn rename(&self, _p: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let body = json!({
            "fileId": e.fid.parse::<i64>().unwrap_or(0),
            "fileName": new_name,
        });
        self.request(Method::PUT, "/api/v1/file/name", None, Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn move_entry(&self, _p: &str, e: &Entry, dst: &str) -> Result<(), String> {
        let body = json!({
            "fileIDs": [e.fid.parse::<i64>().unwrap_or(0)],
            "toParentFileID": dst.parse::<i64>().unwrap_or(0),
        });
        self.request(Method::POST, "/api/v1/file/move", None, Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn copy(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("123 Open 不支持复制操作".into())
    }

    pub async fn remove(&self, _p: &str, e: &Entry) -> Result<(), String> {
        let body = json!({
            "fileIDs": [e.fid.parse::<i64>().unwrap_or(0)],
        });
        self.request(Method::POST, "/api/v1/file/trash", None, Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("123 Open 上传暂未实现，请使用网页版或 Go 版".into())
    }
}

// 简易 urlencoding
mod urlencoding {
    pub fn encode(s: &str) -> String {
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
}
