//! Dropbox 驱动（对齐 Go 版 drivers/dropbox）
//!
//! - 授权：refresh_token（优先 olist 在线刷新，或 client_id/secret）
//! - 列表：/2/files/list_folder
//! - 下载：/2/files/get_temporary_link
//! - 写：create_folder_v2 / move_v2 / delete_v2

use super::{DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const API: &str = "https://api.dropboxapi.com";
const ONLINE_REFRESH: &str = "https://api.oplist.org/dropboxs/renewapi";

pub struct Dropbox {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    root_path: String,
    use_online_api: bool,
    client_id: String,
    client_secret: String,
    root_namespace_id: Mutex<String>,
    store: Arc<Store>,
}

impl Dropbox {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        root_path: String,
        use_online_api: bool,
        client_id: String,
        client_secret: String,
        store: Arc<Store>,
    ) -> Self {
        let root_path = if root_path.trim().is_empty() || root_path.trim() == "/" {
            String::new()
        } else {
            root_path.trim().trim_end_matches('/').to_string()
        };
        Dropbox {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            root_path,
            use_online_api,
            client_id,
            client_secret,
            root_namespace_id: Mutex::new(String::new()),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let id = self.account_id.clone();
        let r = refresh.to_string();
        let a = access.to_string();
        self.store.update_credential(&id, |c| {
            if let Credential::Dropbox {
                refresh_token,
                access_token,
                ..
            } = c
            {
                *refresh_token = r;
                *access_token = a;
            }
        });
    }

    async fn refresh(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if rt.is_empty() {
            return Err("Dropbox 需要 refresh_token".into());
        }
        if self.use_online_api {
            let url = ONLINE_REFRESH;
            let resp = self
                .http
                .get(url)
                .query(&[
                    ("refresh_ui", rt.as_str()),
                    ("server_use", "true"),
                    ("driver_txt", "dropboxs_go"),
                ])
                .send()
                .await
                .map_err(|e| format!("刷新 token 失败: {e}"))?;
            let text = resp.text().await.unwrap_or_default();
            let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
            let access = v.get("access_token").and_then(|x| x.as_str()).unwrap_or("");
            let refresh = v
                .get("refresh_token")
                .and_then(|x| x.as_str())
                .unwrap_or(&rt);
            if access.is_empty() {
                return Err(format!(
                    "在线刷新失败: {}",
                    v.get("text").and_then(|t| t.as_str()).unwrap_or(&text)
                ));
            }
            self.save_tokens(refresh, access);
            return Ok(());
        }
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Err("未启用在线刷新时需要 client_id 与 client_secret".into());
        }
        let resp = self
            .http
            .post(format!("{API}/oauth2/token"))
            .form(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", rt.as_str()),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("刷新 token 失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status != 200 {
            return Err(format!("刷新 token 失败 ({status}): {text}"));
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("解析: {e}"))?;
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .ok_or("无 access_token")?;
        self.save_tokens(&rt, access);
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

    async fn api(&self, path: &str, body: Value) -> Result<Value, String> {
        let mut token = self.ensure_token().await?;
        for attempt in 0..2 {
            let mut req = self
                .http
                .post(format!("{API}{path}"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/json");
            let ns = self.root_namespace_id.lock().unwrap().clone();
            if !ns.is_empty() {
                req = req.header(
                    "Dropbox-API-Path-Root",
                    format!(r#"{{".tag":"root","root":"{ns}"}}"#),
                );
            }
            let resp = req
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Dropbox 请求失败: {e}"))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            if status == 401 && attempt == 0 {
                self.refresh().await?;
                token = self.access_token.lock().unwrap().clone();
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(format!("Dropbox API ({status}): {}", truncate(&text, 300)));
            }
            if text.is_empty() {
                return Ok(json!({}));
            }
            return serde_json::from_str(&text).map_err(|e| format!("解析: {e}"));
        }
        Err("Dropbox 认证失败".into())
    }

    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            return self.root_path.clone();
        }
        if fid.starts_with('/') {
            if self.root_path.is_empty() {
                fid.to_string()
            } else {
                format!("{}{}", self.root_path, fid)
            }
        } else {
            format!("{}/{}", self.root_path, fid)
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.refresh().await?;
        // get current account for root namespace
        let v = self
            .api("/2/users/get_current_account", json!(null))
            .await?;
        if let Some(ns) = v
            .pointer("/root_info/root_namespace_id")
            .and_then(|x| x.as_str())
        {
            *self.root_namespace_id.lock().unwrap() = ns.to_string();
        }
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve(parent_fid);
        let path_arg = if path.is_empty() { String::new() } else { path };
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        let mut has_more = true;
        while has_more {
            let v = if let Some(ref c) = cursor {
                self.api("/2/files/list_folder/continue", json!({ "cursor": c }))
                    .await?
            } else {
                self.api(
                    "/2/files/list_folder",
                    json!({
                        "path": path_arg,
                        "recursive": false,
                        "include_deleted": false,
                        "limit": 2000,
                    }),
                )
                .await?
            };
            let entries = v
                .get("entries")
                .and_then(|e| e.as_array())
                .cloned()
                .unwrap_or_default();
            for e in entries {
                let tag = e.get(".tag").and_then(|t| t.as_str()).unwrap_or("");
                let name = e
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                let is_dir = tag == "folder";
                let size = e.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                let path_display = e
                    .get("path_display")
                    .and_then(|p| p.as_str())
                    .unwrap_or("")
                    .to_string();
                let fid = if self.root_path.is_empty() {
                    path_display.clone()
                } else if let Some(rest) = path_display.strip_prefix(&self.root_path) {
                    rest.to_string()
                } else {
                    path_display.clone()
                };
                out.push(Entry {
                    fid: if fid.is_empty() { "/".into() } else { fid },
                    name,
                    size: if is_dir { 0 } else { size },
                    is_dir,
                    updated_at: None,
                    etag: e.get("id").and_then(|i| i.as_str()).map(|s| s.to_string()),
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            has_more = v.get("has_more").and_then(|h| h.as_bool()).unwrap_or(false);
            cursor = v
                .get("cursor")
                .and_then(|c| c.as_str())
                .map(|s| s.to_string());
            if !has_more {
                break;
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let path = self.resolve(&e.fid);
        let v = self
            .api("/2/files/get_temporary_link", json!({ "path": path }))
            .await?;
        let url = v
            .get("link")
            .and_then(|l| l.as_str())
            .ok_or("无临时链接")?
            .to_string();
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let path = format!(
            "{}/{}",
            self.resolve(parent_fid).trim_end_matches('/'),
            name.trim_matches('/')
        );
        self.api(
            "/2/files/create_folder_v2",
            json!({ "path": path, "autorename": false }),
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let from = self.resolve(&e.fid);
        let parent = match from.rfind('/') {
            Some(i) => &from[..i],
            None => "",
        };
        let to = if parent.is_empty() {
            format!("/{new_name}")
        } else {
            format!("{parent}/{new_name}")
        };
        self.api(
            "/2/files/move_v2",
            json!({
                "from_path": from,
                "to_path": to,
                "autorename": false,
            }),
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
        let to = format!(
            "{}/{}",
            self.resolve(dst_dir_fid).trim_end_matches('/'),
            e.name
        );
        self.api(
            "/2/files/move_v2",
            json!({
                "from_path": from,
                "to_path": to,
                "autorename": false,
            }),
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
        let to = format!(
            "{}/{}",
            self.resolve(dst_dir_fid).trim_end_matches('/'),
            e.name
        );
        self.api(
            "/2/files/copy_v2",
            json!({
                "from_path": from,
                "to_path": to,
                "autorename": false,
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.resolve(&e.fid);
        self.api("/2/files/delete_v2", json!({ "path": path }))
            .await?;
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        const PART: usize = 20 * 1024 * 1024; // 20MB，对齐 Go 版
        let token = self.ensure_token().await?;
        let content = "https://content.dropboxapi.com";
        let ns = self.root_namespace_id.lock().unwrap().clone();

        // start session
        let mut start_req = self
            .http
            .post(format!("{content}/2/files/upload_session/start"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/octet-stream")
            .header("Dropbox-API-Arg", r#"{"close":false}"#);
        if !ns.is_empty() {
            start_req = start_req.header(
                "Dropbox-API-Path-Root",
                format!(r#"{{".tag":"root","root":"{ns}"}}"#),
            );
        }
        let start_resp = start_req
            .send()
            .await
            .map_err(|e| format!("upload_session/start: {e}"))?;
        let start_text = start_resp.text().await.unwrap_or_default();
        let start_v: Value = serde_json::from_str(&start_text)
            .map_err(|e| format!("start 解析: {e} / {start_text}"))?;
        let session_id = start_v
            .get("session_id")
            .and_then(|s| s.as_str())
            .ok_or_else(|| format!("无 session_id: {start_text}"))?
            .to_string();

        let mut offset: u64 = 0;
        let mut buf = vec![0u8; PART];
        loop {
            let mut filled = 0usize;
            while filled < PART {
                let n = input
                    .reader
                    .read(&mut buf[filled..])
                    .await
                    .map_err(|e| format!("读上传流: {e}"))?;
                if n == 0 {
                    break;
                }
                filled += n;
            }
            if filled == 0 {
                break;
            }
            let chunk = &buf[..filled];
            let arg = json!({
                "cursor": { "session_id": session_id, "offset": offset },
                "close": false
            });
            let mut req = self
                .http
                .post(format!("{content}/2/files/upload_session/append_v2"))
                .header("Authorization", format!("Bearer {token}"))
                .header("Content-Type", "application/octet-stream")
                .header("Dropbox-API-Arg", arg.to_string());
            if !ns.is_empty() {
                req = req.header(
                    "Dropbox-API-Path-Root",
                    format!(r#"{{".tag":"root","root":"{ns}"}}"#),
                );
            }
            let resp = req
                .body(chunk.to_vec())
                .send()
                .await
                .map_err(|e| format!("append_v2: {e}"))?;
            let st = resp.status().as_u16();
            if !(200..300).contains(&st) {
                let text = resp.text().await.unwrap_or_default();
                return Err(format!("append_v2 ({st}): {text}"));
            }
            offset += filled as u64;
        }

        let path = format!(
            "{}/{}",
            self.resolve(dst_dir_fid).trim_end_matches('/'),
            input.name
        );
        let path = if path.starts_with('/') {
            path
        } else {
            format!("/{path}")
        };
        let finish_arg = json!({
            "cursor": { "session_id": session_id, "offset": offset },
            "commit": {
                "path": path,
                "mode": "add",
                "autorename": true,
                "mute": false,
                "strict_conflict": false
            }
        });
        let mut fin = self
            .http
            .post(format!("{content}/2/files/upload_session/finish"))
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/octet-stream")
            .header("Dropbox-API-Arg", finish_arg.to_string());
        if !ns.is_empty() {
            fin = fin.header(
                "Dropbox-API-Path-Root",
                format!(r#"{{".tag":"root","root":"{ns}"}}"#),
            );
        }
        let resp = fin.send().await.map_err(|e| format!("finish: {e}"))?;
        let st = resp.status().as_u16();
        if !(200..300).contains(&st) {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("upload finish ({st}): {text}"));
        }
        Ok(())
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
