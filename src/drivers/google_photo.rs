//! Google Photos 驱动（对齐 Go 版 drivers/google_photo）
//!
//! - 根目录虚拟节点：all / albums / share_albums
//! - 相册下列媒体；下载用 baseUrl=d
//! - 默认只读浏览；上传未在本期实现

use super::{DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const TOKEN_URL: &str = "https://www.googleapis.com/oauth2/v4/token";
const API: &str = "https://photoslibrary.googleapis.com/v1";
const DEFAULT_CLIENT_ID: &str = "202264815644.apps.googleusercontent.com";
const DEFAULT_CLIENT_SECRET: &str = "X4Z3ca8xfWDb1Voo-F9a7ZxJ";

pub struct GooglePhoto {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    client_id: String,
    client_secret: String,
    store: Arc<Store>,
}

impl GooglePhoto {
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        client_id: String,
        client_secret: String,
        store: Arc<Store>,
    ) -> Self {
        let client_id = if client_id.trim().is_empty() {
            DEFAULT_CLIENT_ID.into()
        } else {
            client_id
        };
        let client_secret = if client_secret.trim().is_empty() {
            DEFAULT_CLIENT_SECRET.into()
        } else {
            client_secret
        };
        GooglePhoto {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            client_id,
            client_secret,
            store,
        }
    }

    fn save_access(&self, access: &str) {
        *self.access_token.lock().unwrap() = access.to_string();
        let id = self.account_id.clone();
        let a = access.to_string();
        self.store.update_credential(&id, |c| {
            if let Credential::GooglePhoto { access_token, .. } = c {
                *access_token = a;
            }
        });
    }

    async fn refresh(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if rt.is_empty() {
            return Err("Google Photos 需要 refresh_token".into());
        }
        let resp = self
            .http
            .post(TOKEN_URL)
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", rt.as_str()),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await
            .map_err(|e| format!("刷新 token 失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                format!(
                    "刷新失败: {}",
                    v.get("error").and_then(|e| e.as_str()).unwrap_or(&text)
                )
            })?;
        self.save_access(access);
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

    async fn api_get(&self, url: &str, query: &[(&str, &str)]) -> Result<Value, String> {
        let mut token = self.ensure_token().await?;
        for attempt in 0..2 {
            let resp = self
                .http
                .get(url)
                .bearer_auth(&token)
                .query(query)
                .send()
                .await
                .map_err(|e| format!("Google Photos 请求失败: {e}"))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            if status == 401 && attempt == 0 {
                self.refresh().await?;
                token = self.access_token.lock().unwrap().clone();
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(format!("Google Photos API ({status}): {}", truncate(&text, 300)));
            }
            return serde_json::from_str(&text).map_err(|e| format!("解析: {e}"));
        }
        Err("Google Photos 认证失败".into())
    }

    async fn api_post(&self, url: &str, body: Value) -> Result<Value, String> {
        let mut token = self.ensure_token().await?;
        for attempt in 0..2 {
            let resp = self
                .http
                .post(url)
                .bearer_auth(&token)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("Google Photos 请求失败: {e}"))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            if status == 401 && attempt == 0 {
                self.refresh().await?;
                token = self.access_token.lock().unwrap().clone();
                continue;
            }
            if !(200..300).contains(&status) {
                return Err(format!("Google Photos API ({status}): {}", truncate(&text, 300)));
            }
            return serde_json::from_str(&text).map_err(|e| format!("解析: {e}"));
        }
        Err("Google Photos 认证失败".into())
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.refresh().await?;
        // 试拉相册列表
        let _ = self
            .api_get(
                &format!("{API}/albums"),
                &[("pageSize", "1"), ("fields", "albums(id)")],
            )
            .await?;
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let fid = parent_fid.trim();
        let fid = if fid.is_empty() || fid == "0" || fid == "/" {
            "root"
        } else {
            fid.trim_start_matches('/')
        };

        match fid {
            "root" => Ok(vec![
                virtual_dir("all", "all"),
                virtual_dir("albums", "albums"),
                virtual_dir("share_albums", "share_albums"),
            ]),
            "albums" => self.list_albums(false).await,
            "share_albums" => self.list_albums(true).await,
            "all" => self.list_all_media().await,
            album_id => self.list_album_media(album_id).await,
        }
    }

    async fn list_albums(&self, shared: bool) -> Result<Vec<Entry>, String> {
        let path = if shared {
            format!("{API}/sharedAlbums")
        } else {
            format!("{API}/albums")
        };
        let key = if shared { "sharedAlbums" } else { "albums" };
        let mut out = Vec::new();
        let mut page_token = String::new();
        loop {
            let mut q = vec![("pageSize", "50"), ("fields", "albums(id,title),sharedAlbums(id,title),nextPageToken")];
            if !page_token.is_empty() {
                q.push(("pageToken", page_token.as_str()));
            }
            // fields 对 shared 不同，简化
            let v = self.api_get(&path, &q).await?;
            let albums = v
                .get(key)
                .or_else(|| v.get("albums"))
                .or_else(|| v.get("sharedAlbums"))
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            for a in albums {
                let id = a.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                let title = a
                    .get("title")
                    .and_then(|t| t.as_str())
                    .unwrap_or("album")
                    .to_string();
                if id.is_empty() {
                    continue;
                }
                out.push(Entry {
                    fid: id,
                    name: title,
                    size: 0,
                    is_dir: true,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            page_token = v
                .get("nextPageToken")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if page_token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    async fn list_all_media(&self) -> Result<Vec<Entry>, String> {
        let mut out = Vec::new();
        let mut page_token = String::new();
        loop {
            let body = if page_token.is_empty() {
                json!({ "pageSize": 100 })
            } else {
                json!({ "pageSize": 100, "pageToken": page_token })
            };
            let v = self
                .api_post(&format!("{API}/mediaItems:search"), body)
                .await?;
            self.push_media(&v, &mut out);
            page_token = v
                .get("nextPageToken")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if page_token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    async fn list_album_media(&self, album_id: &str) -> Result<Vec<Entry>, String> {
        let mut out = Vec::new();
        let mut page_token = String::new();
        loop {
            let body = if page_token.is_empty() {
                json!({ "albumId": album_id, "pageSize": 100 })
            } else {
                json!({ "albumId": album_id, "pageSize": 100, "pageToken": page_token })
            };
            let v = self
                .api_post(&format!("{API}/mediaItems:search"), body)
                .await?;
            self.push_media(&v, &mut out);
            page_token = v
                .get("nextPageToken")
                .and_then(|t| t.as_str())
                .unwrap_or("")
                .to_string();
            if page_token.is_empty() {
                break;
            }
        }
        Ok(out)
    }

    fn push_media(&self, v: &Value, out: &mut Vec<Entry>) {
        let items = v
            .get("mediaItems")
            .and_then(|m| m.as_array())
            .cloned()
            .unwrap_or_default();
        for m in items {
            let id = m.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
            let filename = m
                .get("filename")
                .and_then(|n| n.as_str())
                .unwrap_or("photo")
                .to_string();
            let base = m
                .get("baseUrl")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            if id.is_empty() {
                continue;
            }
            out.push(Entry {
                fid: id,
                name: filename,
                size: 0,
                is_dir: false,
                updated_at: None,
                etag: if base.is_empty() {
                    None
                } else {
                    Some(format!("{base}=d"))
                },
                s3_key_flag: None,
                file_type: None,
                extra: None,
            });
        }
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let mut url = e.etag.clone().unwrap_or_default();
        if url.is_empty() {
            // 回源取 baseUrl
            let v = self
                .api_get(
                    &format!("{API}/mediaItems/{}", e.fid),
                    &[("fields", "baseUrl,filename")],
                )
                .await?;
            let base = v
                .get("baseUrl")
                .and_then(|u| u.as_str())
                .ok_or("无 baseUrl")?;
            url = format!("{base}=d");
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: true, // Google Photos baseUrl 常需代理
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _: &str, _: &str) -> Result<(), String> {
        Err("Google Photos 暂不支持建目录".into())
    }
    pub async fn rename(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("Google Photos 不支持重命名".into())
    }
    pub async fn move_entry(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("Google Photos 不支持移动".into())
    }
    pub async fn copy(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("Google Photos 不支持复制".into())
    }
    pub async fn remove(&self, _: &str, _: &Entry) -> Result<(), String> {
        Err("Google Photos 不支持删除".into())
    }
    pub async fn put(&self, _: &str, _: PutInput) -> Result<(), String> {
        Err("Google Photos 上传请后续版本".into())
    }
}

fn virtual_dir(id: &str, name: &str) -> Entry {
    Entry {
        fid: id.into(),
        name: name.into(),
        size: 0,
        is_dir: true,
        updated_at: None,
        etag: None,
        s3_key_flag: None,
        file_type: None,
        extra: None,
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
