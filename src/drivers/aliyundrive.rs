//! 阿里云盘（旧版，对齐 Go drivers/aliyundrive）
//!
//! **已废弃**：原版标记 Deprecated，建议改用 `aliyundrive_open`。
//! 本实现仅做 refresh_token + 基础 list/download（不实现设备 ECDSA 会话签名）。
//! 若接口要求签名导致失败，请改用开放平台驱动。

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const AUTH_URL: &str = "https://auth.alipan.com/v2/account/token";
const API: &str = "https://api.alipan.com";

pub struct Aliyundrive {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    drive_id: Mutex<String>,
    store: Arc<Store>,
}

impl Aliyundrive {
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        store: Arc<Store>,
    ) -> Self {
        Aliyundrive {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            drive_id: Mutex::new(String::new()),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Aliyundrive {
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

    async fn refresh(&self) -> Result<(), String> {
        let body = json!({
            "refresh_token": self.refresh_token.lock().unwrap().clone(),
            "grant_type": "refresh_token",
        });
        let resp = self
            .http
            .post(AUTH_URL)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("刷新 token 失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("刷新响应解析失败: {e}"))?;
        if let Some(code) = v.get("code").and_then(|c| c.as_str()) {
            if !code.is_empty() {
                let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
                return Err(format!("刷新 token 失败({code}): {msg}"));
            }
        }
        let refresh = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if refresh.is_empty() || access.is_empty() {
            return Err("刷新 token 返回空（旧版驱动已废弃，建议改用 aliyundrive_open）".into());
        }
        self.save_tokens(&refresh, &access);
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let url = format!("{API}{path}");
        let access = self.access_token.lock().unwrap().clone();
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header("Authorization", format!("Bearer {access}"))
            .header("content-type", "application/json");
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("");
        if !code.is_empty() {
            if !retried && (code == "AccessTokenInvalid" || code == "AccessTokenExpired") {
                self.refresh().await?;
                return Box::pin(self.request(method, path, body, true)).await;
            }
            let msg = v.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
            return Err(format!(
                "阿里云盘(旧)接口错误({code}): {msg}；若持续失败请改用 aliyundrive_open"
            ));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.refresh_token.lock().unwrap().is_empty() {
            return Err("refresh_token 不能为空".into());
        }
        if self.access_token.lock().unwrap().is_empty() {
            self.refresh().await?;
        }
        let res = match self
            .request(Method::POST, "/v2/user/get", None, false)
            .await
        {
            Ok(v) => v,
            Err(_) => {
                self.request(
                    Method::POST,
                    "/adrive/v1.0/user/getDriveInfo",
                    None,
                    false,
                )
                .await?
            }
        };
        let drive_id = res
            .get("default_drive_id")
            .or_else(|| res.get("resource_drive_id"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        *self.drive_id.lock().unwrap() = drive_id;
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = match parent_fid {
            "" | "0" => "root",
            other => other,
        };
        let drive_id = self.drive_id.lock().unwrap().clone();
        let mut files = Vec::new();
        let mut marker = String::new();
        loop {
            let body = json!({
                "drive_id": drive_id,
                "parent_file_id": parent,
                "limit": 200,
                "all": false,
                "url_expire_sec": 14400,
                "fields": "*",
                "order_by": "updated_at",
                "order_direction": "DESC",
                "marker": marker,
            });
            let resp = self
                .request(Method::POST, "/adrive/v3/file/list", Some(body), false)
                .await?;
            let items = resp
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &items {
                let updated_at = f
                    .get("updated_at")
                    .and_then(|v| v.as_str())
                    .and_then(super::aliyundrive_open::iso_to_ms);
                files.push(Entry {
                    fid: f
                        .get("file_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: f.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir: f.get("type").and_then(|v| v.as_str()) == Some("folder"),
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            marker = resp
                .get("next_marker")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if marker.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "expire_sec": 14400,
        });
        let resp = self
            .request(Method::POST, "/v2/file/get_download_url", Some(body), false)
            .await?;
        let url = resp
            .get("url")
            .or_else(|| resp.get("download_url"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("阿里云盘(旧)未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![("Referer".into(), "https://www.aliyundrive.com/".into())],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let parent = if parent_fid.is_empty() || parent_fid == "0" {
            "root"
        } else {
            parent_fid
        };
        let body = json!({
            "drive_id": drive_id,
            "parent_file_id": parent,
            "name": name,
            "type": "folder",
            "check_name_mode": "refuse",
        });
        self.request(Method::POST, "/adrive/v2/file/createWithFolders", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn rename(&self, _p: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "name": new_name,
            "check_name_mode": "refuse",
        });
        self.request(Method::POST, "/v3/file/update", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn move_entry(&self, _p: &str, e: &Entry, dst: &str) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "to_parent_file_id": if dst.is_empty() || dst == "0" { "root" } else { dst },
            "check_name_mode": "refuse",
        });
        self.request(Method::POST, "/v3/file/move", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn copy(&self, _p: &str, e: &Entry, dst: &str) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "to_parent_file_id": if dst.is_empty() || dst == "0" { "root" } else { dst },
            "auto_rename": true,
        });
        self.request(Method::POST, "/v2/file/copy", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn remove(&self, _p: &str, e: &Entry) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
        });
        self.request(Method::POST, "/v2/recyclebin/trash", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("阿里云盘(旧)上传未实现，请使用 aliyundrive_open".into())
    }
}
