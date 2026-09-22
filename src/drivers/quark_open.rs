//! 夸克开放平台驱动（对齐 Go 版 drivers/quark_open）
//!
//! - 授权：refresh_token + app_id + sign_key，access_token 在线刷新
//! - 签名：x-pan-token = sha256(method & pathname & timestamp & signKey)
//! - 列目录：POST /open/v1/file/list
//! - 下载：GET /open/v1/file/download

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use md5::Md5;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

const API: &str = "https://open-api-drive.quark.cn";
const ONLINE_REFRESH: &str = "https://api.oplist.org/quarkyun/renewapi";
const UA: &str = "go-resty/3.0.0-beta.1 (https://resty.dev)";

pub struct QuarkOpen {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    app_id: String,
    sign_key: String,
    use_online_api: bool,
    api_address: String,
    store: Arc<Store>,
}

impl QuarkOpen {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        app_id: String,
        sign_key: String,
        use_online_api: bool,
        api_address: String,
        store: Arc<Store>,
    ) -> Self {
        QuarkOpen {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            app_id,
            sign_key,
            use_online_api,
            api_address: if api_address.is_empty() {
                ONLINE_REFRESH.to_string()
            } else {
                api_address
            },
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::QuarkOpen {
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

    /// method & pathname & timestamp & signKey -> sha256 hex
    fn generate_req_sign(&self, method: &str, pathname: &str) -> (String, String, String) {
        let tm = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let token_data = format!("{method}&{pathname}&{tm}&{}", self.sign_key);
        let hash = Sha256::digest(token_data.as_bytes());
        let token = hex::encode(hash);
        let req_id = Uuid::new_v4().to_string();
        (tm, token, req_id)
    }

    async fn refresh_token(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if !self.use_online_api {
            return Err("未启用在线刷新且无本地 client 凭证".into());
        }
        let url = format!(
            "{}?refresh_ui={}&server_use=true&driver_txt=quarkyun",
            self.api_address,
            url_encode(&rt)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("刷新夸克 Open token 失败: {e}"))?;
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
                .and_then(|x| x.as_str())
                .unwrap_or("空 token");
            return Err(format!("刷新夸克 Open token 失败: {msg}"));
        }
        self.save_tokens(
            if refresh.is_empty() { &rt } else { &refresh },
            &access,
        );
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        pathname: &str,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let (tm, token, req_id) = self.generate_req_sign(method.as_str(), pathname);
        let access = self.access_token.lock().unwrap().clone();
        let url = format!("{API}{pathname}");
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header("Accept", "application/json, text/plain, */*")
            .header("User-Agent", UA)
            .header("x-pan-tm", &tm)
            .header("x-pan-token", &token)
            .header("x-pan-client-id", &self.app_id)
            .query(&[("req_id", req_id.as_str()), ("access_token", access.as_str())]);
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        let status = v.get("status").and_then(|s| s.as_i64()).unwrap_or(0);
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(0);
        let err_info = v
            .get("error_info")
            .or_else(|| v.get("errorInfo"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        // token 过期
        if status == -1
            && (errno == 11001
                || (errno == 14001 && err_info.contains("access_token")))
            && !retried
        {
            self.refresh_token().await?;
            return Box::pin(self.request(method, pathname, body, true)).await;
        }
        if status >= 400 || errno != 0 {
            return Err(if err_info.is_empty() {
                format!("夸克 Open 接口错误(status={status}, errno={errno})")
            } else {
                err_info
            });
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.refresh_token.lock().unwrap().is_empty() {
            return Err("refresh_token 不能为空".into());
        }
        if self.app_id.is_empty() || self.sign_key.is_empty() {
            return Err("app_id 与 sign_key 不能为空".into());
        }
        if self.access_token.lock().unwrap().is_empty() {
            self.refresh_token().await?;
        }
        // 探测 list 根
        let _ = self
            .request(
                Method::POST,
                "/open/v1/file/list",
                Some(json!({
                    "parent_fid": "0",
                    "size": 1,
                    "sort": "file_name:asc",
                })),
                false,
            )
            .await?;
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = if parent_fid.is_empty() {
            "0"
        } else {
            parent_fid
        };
        let mut files = Vec::new();
        let mut cursor: Option<Value> = None;
        loop {
            let mut body = json!({
                "parent_fid": parent,
                "size": 100,
                "sort": "file_name:asc",
            });
            if let Some(c) = &cursor {
                body["query_cursor"] = c.clone();
            }
            let resp = self
                .request(Method::POST, "/open/v1/file/list", Some(body), false)
                .await?;
            let list = resp
                .pointer("/data/file_list")
                .or_else(|| resp.pointer("/data/list"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &list {
                let is_dir = f
                    .get("dir")
                    .or_else(|| f.get("file"))
                    .map(|v| {
                        if let Some(b) = v.as_bool() {
                            // dir=true 或 file=false
                            if f.get("dir").is_some() {
                                b
                            } else {
                                !b
                            }
                        } else {
                            f.get("file_type")
                                .and_then(|t| t.as_i64())
                                .map(|t| t == 0)
                                .unwrap_or(false)
                        }
                    })
                    .unwrap_or(false);
                files.push(Entry {
                    fid: f
                        .get("fid")
                        .or_else(|| f.get("file_id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: f
                        .get("file_name")
                        .or_else(|| f.get("name"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir,
                    updated_at: f
                        .get("updated_at")
                        .and_then(|v| v.as_i64())
                        .or_else(|| {
                            f.get("l_updated_at").and_then(|v| v.as_i64())
                        }),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            cursor = resp
                .pointer("/data/query_cursor")
                .cloned()
                .filter(|c| !c.is_null());
            let has_more = resp
                .pointer("/data/has_more")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if !has_more || list.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let (tm, token, req_id) = self.generate_req_sign("GET", "/open/v1/file/download");
        let access = self.access_token.lock().unwrap().clone();
        let url = format!("{API}/open/v1/file/download");
        let resp = self
            .http
            .get(&url)
            .header("Accept", "application/json, text/plain, */*")
            .header("User-Agent", UA)
            .header("x-pan-tm", &tm)
            .header("x-pan-token", &token)
            .header("x-pan-client-id", &self.app_id)
            .query(&[
                ("req_id", req_id.as_str()),
                ("access_token", access.as_str()),
                ("fid", e.fid.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        let status = v.get("status").and_then(|s| s.as_i64()).unwrap_or(0);
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(0);
        if status >= 400 || errno != 0 {
            let msg = v
                .get("error_info")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            return Err(format!("夸克 Open 下载失败: {msg}"));
        }
        let dl = v
            .pointer("/data/download_url")
            .or_else(|| v.pointer("/data/url"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if dl.is_empty() {
            // 有些版本 data 是数组
            let dl = v
                .pointer("/data/0/download_url")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if dl.is_empty() {
                return Err("夸克 Open 未返回下载直链".into());
            }
            return Ok(DownloadInfo {
                url: dl,
                headers: vec![],
                proxy: true,
                local_path: None,
            });
        }
        Ok(DownloadInfo {
            url: dl,
            headers: vec![],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let body = json!({
            "parent_fid": parent_fid,
            "file_name": name,
            "dir": true,
        });
        self.request(Method::POST, "/open/v1/file/create", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn rename(&self, _p: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let body = json!({
            "fid": e.fid,
            "file_name": new_name,
        });
        self.request(Method::POST, "/open/v1/file/rename", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn move_entry(&self, _p: &str, e: &Entry, dst: &str) -> Result<(), String> {
        let body = json!({
            "filelist": [e.fid],
            "to_pdir_fid": dst,
        });
        self.request(Method::POST, "/open/v1/file/move", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn copy(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("夸克 Open 不支持复制".into())
    }

    pub async fn remove(&self, _p: &str, e: &Entry) -> Result<(), String> {
        let body = json!({ "filelist": [e.fid] });
        self.request(Method::POST, "/open/v1/file/delete", Some(body), false)
            .await?;
        Ok(())
    }

    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("夸克 Open 上传暂未实现".into())
    }
}

fn url_encode(s: &str) -> String {
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

// silence unused import warnings for md5 used potentially later
#[allow(dead_code)]
fn _md5_hex(s: &str) -> String {
    hex::encode(Md5::digest(s.as_bytes()))
}
