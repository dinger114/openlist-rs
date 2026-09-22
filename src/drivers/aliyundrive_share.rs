//! 阿里云盘分享驱动（对齐 Go 版 drivers/aliyundrive_share，只读）
//!
//! - 授权：refresh_token（账号级，用于刷新 access_token）+ share_id + 可选 share_pwd
//! - 列目录：POST https://api.alipan.com/adrive/v3/file/list（带 x-share-token）
//! - 下载：POST https://api.alipan.com/v2/file/get_share_link_download_url

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const AUTH_URL: &str = "https://auth.alipan.com/v2/account/token";
const SHARE_TOKEN_URL: &str = "https://api.alipan.com/v2/share_link/get_share_token";
const LIST_URL: &str = "https://api.alipan.com/adrive/v3/file/list";
const DOWNLOAD_URL: &str = "https://api.alipan.com/v2/file/get_share_link_download_url";
const CANARY: &str = "client=web,app=share,version=v2.3.1";

pub struct AliyundriveShare {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    share_token: Mutex<String>,
    share_id: String,
    share_pwd: String,
    drive_id: Mutex<String>,
    store: Arc<Store>,
}

impl AliyundriveShare {
    pub fn new(
        account_id: &str,
        refresh_token: String,
        share_id: String,
        share_pwd: String,
        store: Arc<Store>,
    ) -> Self {
        AliyundriveShare {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(String::new()),
            share_token: Mutex::new(String::new()),
            share_id,
            share_pwd,
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
            if let Credential::AliyundriveShare {
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

    async fn refresh_access_token(&self) -> Result<(), String> {
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
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
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
            return Err("刷新 token 返回空".into());
        }
        self.save_tokens(&refresh, &access);
        Ok(())
    }

    async fn get_share_token(&self) -> Result<(), String> {
        let mut data = json!({ "share_id": self.share_id });
        if !self.share_pwd.is_empty() {
            data["share_pwd"] = json!(self.share_pwd);
        }
        let resp = self
            .http
            .post(SHARE_TOKEN_URL)
            .json(&data)
            .send()
            .await
            .map_err(|e| format!("获取 share_token 失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("share_token 响应解析失败: {e}"))?;
        if let Some(code) = v.get("code").and_then(|c| c.as_str()) {
            if !code.is_empty() {
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown");
                return Err(format!("获取 share_token 失败({code}): {msg}"));
            }
        }
        let st = v
            .get("share_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if st.is_empty() {
            return Err("share_token 为空".into());
        }
        *self.share_token.lock().unwrap() = st;
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let access = self.access_token.lock().unwrap().clone();
        let share_tok = self.share_token.lock().unwrap().clone();
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("content-type", "application/json")
            .header("Authorization", format!("Bearer\t{access}"))
            .header("X-Canary", CANARY)
            .header("x-share-token", &share_tok);
        if let Some(b) = &body {
            req = req.json(b);
        } else {
            req = req.json(&json!({}));
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("");
        if !code.is_empty() {
            if !retried && (code == "AccessTokenInvalid" || code == "ShareLinkTokenInvalid") {
                if code == "AccessTokenInvalid" {
                    self.refresh_access_token().await?;
                } else {
                    self.get_share_token().await?;
                }
                return Box::pin(self.request(method, url, body, true)).await;
            }
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("阿里分享接口错误({code}): {msg}"));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.share_id.is_empty() {
            return Err("share_id 不能为空".into());
        }
        if self.refresh_token.lock().unwrap().is_empty() {
            return Err("refresh_token 不能为空".into());
        }
        self.refresh_access_token().await?;
        self.get_share_token().await?;
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = match parent_fid {
            "" | "0" => "root",
            other => other,
        };
        let mut files = Vec::new();
        let mut marker = String::new();
        loop {
            let body = json!({
                "share_id": self.share_id,
                "parent_file_id": parent,
                "limit": 200,
                "image_thumbnail_process": "image/resize,w_160/format,jpeg",
                "image_url_process": "image/resize,w_1920/format,jpeg",
                "video_thumbnail_process": "video/snapshot,t_1000,f_jpg,ar_auto,w_300",
                "order_by": "name",
                "order_direction": "ASC",
                "marker": marker,
            });
            let resp = self
                .request(Method::POST, LIST_URL, Some(body), false)
                .await?;
            let items = resp
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &items {
                if self.drive_id.lock().unwrap().is_empty() {
                    if let Some(did) = f.get("drive_id").and_then(|x| x.as_str()) {
                        *self.drive_id.lock().unwrap() = did.to_string();
                    }
                }
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
                    name: f
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
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
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let body = json!({
            "share_id": self.share_id,
            "file_id": e.fid,
            "expire_sec": 14400,
        });
        let resp = self
            .request(Method::POST, DOWNLOAD_URL, Some(body), false)
            .await?;
        let url = resp
            .get("download_url")
            .or_else(|| resp.get("url"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("阿里分享未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _p: &str, _n: &str) -> Result<(), String> {
        Err("阿里云盘分享为只读驱动，不支持此操作".into())
    }
    pub async fn rename(&self, _p: &str, _e: &Entry, _n: &str) -> Result<(), String> {
        Err("阿里云盘分享为只读驱动，不支持此操作".into())
    }
    pub async fn move_entry(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("阿里云盘分享为只读驱动，不支持此操作".into())
    }
    pub async fn copy(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("阿里云盘分享为只读驱动，不支持此操作".into())
    }
    pub async fn remove(&self, _p: &str, _e: &Entry) -> Result<(), String> {
        Err("阿里云盘分享为只读驱动，不支持此操作".into())
    }
    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("阿里云盘分享为只读驱动，不支持此操作".into())
    }
}
