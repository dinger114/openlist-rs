//! 夸克 TV / UC TV 驱动（对齐 Go 版 drivers/quark_uc_tv，只读）
//!
//! - 授权：refresh_token + device_id（TV OAuth）
//! - 签名同 quark_open：x-pan-token = sha256(method & path & ts & signKey)
//! - 列目录 / 下载走 open-api-drive.quark.cn 或 open-api-drive.uc.cn

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use md5::Md5;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy)]
pub struct TvConf {
    pub api: &'static str,
    pub client_id: &'static str,
    pub sign_key: &'static str,
    pub app_ver: &'static str,
    #[allow(dead_code)]
    pub channel: &'static str,
}

pub const QUARK_TV: TvConf = TvConf {
    api: "https://open-api-drive.quark.cn",
    client_id: "d3194e61504e493eb6222857bccfed94",
    sign_key: "kw2dvtd7p4t3pjl2d9ed9yc8yej8kw2d",
    app_ver: "1.8.2.2",
    channel: "GENERAL",
};

pub const UC_TV: TvConf = TvConf {
    api: "https://open-api-drive.uc.cn",
    client_id: "5acf882d27b74502b7040b0c65519aa7",
    sign_key: "l3srvtd7p42l0d0x1u8d7yc8ye9kki4d",
    app_ver: "1.7.2.2",
    channel: "UCTVOFFICIALWEB",
};

pub struct QuarkUcTv {
    account_id: String,
    http: Client,
    conf: TvConf,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    device_id: Mutex<String>,
    /// download | streaming
    link_method: String,
    store: Arc<Store>,
}

impl QuarkUcTv {
    pub fn new_quark_tv(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        device_id: String,
        link_method: String,
        store: Arc<Store>,
    ) -> Self {
        Self::with_conf(
            account_id,
            refresh_token,
            access_token,
            device_id,
            link_method,
            store,
            QUARK_TV,
        )
    }

    pub fn new_uc_tv(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        device_id: String,
        link_method: String,
        store: Arc<Store>,
    ) -> Self {
        Self::with_conf(
            account_id,
            refresh_token,
            access_token,
            device_id,
            link_method,
            store,
            UC_TV,
        )
    }

    fn with_conf(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        device_id: String,
        link_method: String,
        store: Arc<Store>,
        conf: TvConf,
    ) -> Self {
        QuarkUcTv {
            account_id: account_id.to_string(),
            http: Client::new(),
            conf,
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            device_id: Mutex::new(device_id),
            link_method: if link_method.is_empty() {
                "download".into()
            } else {
                link_method
            },
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str, device_id: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        *self.device_id.lock().unwrap() = device_id.to_string();
        let (r, a, d) = (
            refresh.to_string(),
            access.to_string(),
            device_id.to_string(),
        );
        let id = self.account_id.clone();
        let is_uc = self.conf.api == UC_TV.api;
        self.store.update_credential(&id, |cred| match cred {
            Credential::QuarkTv {
                refresh_token,
                access_token,
                device_id,
                ..
            } if !is_uc => {
                *refresh_token = r.clone();
                *access_token = a.clone();
                *device_id = d.clone();
            }
            Credential::UcTv {
                refresh_token,
                access_token,
                device_id,
                ..
            } if is_uc => {
                *refresh_token = r.clone();
                *access_token = a.clone();
                *device_id = d.clone();
            }
            _ => {}
        });
    }

    fn generate_req_sign(&self, method: &str, pathname: &str) -> (String, String, String) {
        let tm = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            .to_string();
        let mut device_id = self.device_id.lock().unwrap().clone();
        if device_id.is_empty() {
            device_id = hex::encode(Md5::digest(tm.as_bytes()));
            *self.device_id.lock().unwrap() = device_id.clone();
        }
        let req_id = hex::encode(Md5::digest(format!("{device_id}{tm}").as_bytes()));
        let token_data = format!("{method}&{pathname}&{tm}&{}", self.conf.sign_key);
        let token = hex::encode(Sha256::digest(token_data.as_bytes()));
        (tm, token, req_id)
    }

    async fn refresh_by_token(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if rt.is_empty() {
            return Err("refresh_token 为空，请先在 TV 端完成扫码授权后填入".into());
        }
        let pathname = "/token";
        let (tm, token, req_id) = self.generate_req_sign("POST", pathname);
        let url = format!("{}{pathname}", self.conf.api);
        let body = json!({
            "client_id": self.conf.client_id,
            "grant_type": "refresh_token",
            "refresh_token": rt,
        });
        let resp = self
            .http
            .post(&url)
            .header("x-pan-tm", &tm)
            .header("x-pan-token", &token)
            .header("x-pan-client-id", self.conf.client_id)
            .query(&[("req_id", req_id.as_str())])
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("刷新 TV token 失败: {e}"))?;
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
            .unwrap_or(&rt)
            .to_string();
        if access.is_empty() {
            let msg = v
                .get("error_info")
                .or_else(|| v.get("error"))
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            return Err(format!("刷新 TV token 失败: {msg}"));
        }
        let did = self.device_id.lock().unwrap().clone();
        self.save_tokens(&refresh, &access, &did);
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        pathname: &str,
        query: Option<&[(&str, String)]>,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let (tm, token, req_id) = self.generate_req_sign(method.as_str(), pathname);
        let access = self.access_token.lock().unwrap().clone();
        let url = format!("{}{pathname}", self.conf.api);
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header("x-pan-tm", &tm)
            .header("x-pan-token", &token)
            .header("x-pan-client-id", self.conf.client_id)
            .header("User-Agent", format!("QuarkUCTV/{}", self.conf.app_ver))
            .query(&[
                ("req_id", req_id.as_str()),
                ("access_token", access.as_str()),
            ]);
        if let Some(q) = query {
            for (k, v) in q {
                req = req.query(&[(k, v)]);
            }
        }
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        let status = v.get("status").and_then(|s| s.as_i64()).unwrap_or(0);
        let errno = v.get("errno").and_then(|e| e.as_i64()).unwrap_or(0);
        let err_info = v
            .get("error_info")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_lowercase();
        let token_bad = (status == -1 && (errno == 10001 || errno == 11001))
            || err_info.contains("access token")
            || err_info.contains("access_token")
            || err_info.contains("token无效")
            || err_info.contains("token 无效");
        if token_bad && !retried {
            self.refresh_by_token().await?;
            return Box::pin(self.request(method, pathname, query, body, true)).await;
        }
        if status >= 400 || errno != 0 {
            let msg = v
                .get("error_info")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            return Err(format!("TV 接口错误: {msg}"));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.access_token.lock().unwrap().is_empty() {
            self.refresh_by_token().await?;
        }
        // 探测列表
        let _ = self
            .request(
                Method::GET,
                "/file",
                Some(&[
                    ("method", "list".into()),
                    ("parent_fid", "0".into()),
                    ("size", "1".into()),
                ]),
                None,
                false,
            )
            .await;
        // 不强制失败（接口路径可能因版本变化），token 刷新成功即可
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let parent = if parent_fid.is_empty() {
            "0"
        } else {
            parent_fid
        };
        let mut files = Vec::new();
        let mut page = 1u32;
        loop {
            let resp = self
                .request(
                    Method::GET,
                    "/file",
                    Some(&[
                        ("method", "list".into()),
                        ("parent_fid", parent.to_string()),
                        ("size", "100".into()),
                        ("page", page.to_string()),
                        ("order_by", "updated_at".into()),
                        ("order_direction", "desc".into()),
                    ]),
                    None,
                    false,
                )
                .await?;
            let list = resp
                .pointer("/data/list")
                .or_else(|| resp.pointer("/data/file_list"))
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &list {
                let is_dir = f
                    .get("dir")
                    .and_then(|v| v.as_bool())
                    .unwrap_or_else(|| !f.get("file").and_then(|v| v.as_bool()).unwrap_or(true));
                files.push(Entry {
                    fid: f
                        .get("fid")
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
                    updated_at: f.get("updated_at").and_then(|v| v.as_i64()),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            if list.len() < 100 {
                break;
            }
            page += 1;
        }
        Ok(files)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let method = if self.link_method == "streaming" {
            "streaming"
        } else {
            "download"
        };
        let resp = self
            .request(
                Method::GET,
                "/file",
                Some(&[
                    ("method", method.into()),
                    ("fid", e.fid.clone()),
                    ("group_by", "source".into()),
                ]),
                None,
                false,
            )
            .await?;
        let url = resp
            .pointer("/data/download_url")
            .or_else(|| resp.pointer("/data/video_info/0/url"))
            .or_else(|| resp.pointer("/data/url"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("TV 未返回下载/播放地址".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _p: &str, _n: &str) -> Result<(), String> {
        Err("夸克/UC TV 为只读驱动，不支持此操作".into())
    }
    pub async fn rename(&self, _p: &str, _e: &Entry, _n: &str) -> Result<(), String> {
        Err("夸克/UC TV 为只读驱动，不支持此操作".into())
    }
    pub async fn move_entry(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("夸克/UC TV 为只读驱动，不支持此操作".into())
    }
    pub async fn copy(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("夸克/UC TV 为只读驱动，不支持此操作".into())
    }
    pub async fn remove(&self, _p: &str, _e: &Entry) -> Result<(), String> {
        Err("夸克/UC TV 为只读驱动，不支持此操作".into())
    }
    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("夸克/UC TV 为只读驱动，不支持此操作".into())
    }
}
