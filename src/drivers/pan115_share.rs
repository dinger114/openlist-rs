//! 115 分享驱动（对齐 Go 版 drivers/115_share，只读）
//!
//! - 授权：cookie（UID/CID/SEID）或仅用 share_code + receive_code（部分接口可不登录）
//! - 列目录：GET https://webapi.115.com/share/snap
//! - 下载：GET https://proapi.115.com/app/share/downurl

use super::DownloadInfo;
use crate::config::Entry;
use reqwest::{Client, Method};
use serde_json::Value;
use std::sync::Mutex;

const API_SHARE_SNAP: &str = "https://webapi.115.com/share/snap";
const API_SHARE_DOWN: &str = "https://proapi.115.com/app/share/downurl";
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";

pub struct Pan115Share {
    http: Client,
    cookie: Mutex<String>,
    share_code: String,
    receive_code: String,
    page_size: i64,
}

impl Pan115Share {
    pub fn new(cookie: String, share_code: String, receive_code: String) -> Self {
        Pan115Share {
            http: Client::new(),
            cookie: Mutex::new(cookie),
            share_code,
            receive_code,
            page_size: 1000,
        }
    }

    fn cookie(&self) -> String {
        self.cookie.lock().unwrap().clone()
    }

    async fn request(
        &self,
        method: Method,
        url: &str,
        query: &[(&str, String)],
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method, url)
            .header("User-Agent", UA)
            .header("Referer", "https://115.com/");
        let c = self.cookie();
        if !c.is_empty() {
            req = req.header("Cookie", c);
        }
        for (k, v) in query {
            req = req.query(&[(k, v)]);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        if v.get("state") == Some(&Value::Bool(false)) {
            let msg = v
                .get("error")
                .or_else(|| v.get("message"))
                .or_else(|| v.get("msg"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("115 分享接口错误: {msg}"));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.share_code.is_empty() {
            return Err("share_code 不能为空".into());
        }
        // 探测根目录
        let _ = self
            .request(
                Method::GET,
                API_SHARE_SNAP,
                &[
                    ("share_code", self.share_code.clone()),
                    ("receive_code", self.receive_code.clone()),
                    ("cid", "0".into()),
                    ("limit", "1".into()),
                    ("offset", "0".into()),
                ],
            )
            .await?;
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let cid = if parent_fid.is_empty() {
            "0"
        } else {
            parent_fid
        };
        let mut files = Vec::new();
        let mut offset: i64 = 0;
        let limit = self.page_size;
        loop {
            let resp = self
                .request(
                    Method::GET,
                    API_SHARE_SNAP,
                    &[
                        ("share_code", self.share_code.clone()),
                        ("receive_code", self.receive_code.clone()),
                        ("cid", cid.to_string()),
                        ("limit", limit.to_string()),
                        ("offset", offset.to_string()),
                    ],
                )
                .await?;
            let list = resp
                .pointer("/data/list")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let count = resp
                .pointer("/data/count")
                .and_then(|v| v.as_i64())
                .unwrap_or(list.len() as i64);
            for f in &list {
                // is_file: 0=dir, 1=file（对齐 ShareFile）
                let is_file = f
                    .get("is_file")
                    .or_else(|| f.get("fc"))
                    .and_then(|v| v.as_i64())
                    .unwrap_or(1);
                let is_dir = is_file == 0;
                let fid = if is_dir {
                    coerce_str(f.get("cid").or_else(|| f.get("category_id")))
                } else {
                    coerce_str(f.get("fid").or_else(|| f.get("file_id")))
                };
                let name = coerce_str(f.get("n").or_else(|| f.get("file_name")));
                let size = f
                    .get("s")
                    .or_else(|| f.get("file_size"))
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        f.get("s")
                            .or_else(|| f.get("file_size"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| s.parse().ok())
                    })
                    .unwrap_or(0);
                let updated_at = coerce_str(f.get("t").or_else(|| f.get("update_time")))
                    .parse::<i64>()
                    .ok()
                    .map(|s| if s > 1_000_000_000_000 { s } else { s * 1000 });
                let pick_code = coerce_str(f.get("pc").or_else(|| f.get("pick_code")));
                files.push(Entry {
                    fid,
                    name,
                    size,
                    is_dir,
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: if !pick_code.is_empty() {
                        Some(serde_json::json!({ "pick_code": pick_code }))
                    } else {
                        None
                    },
                });
            }
            offset += list.len() as i64;
            if list.is_empty() || offset >= count {
                break;
            }
        }
        Ok(files)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        // 优先用 file_id
        let resp = self
            .request(
                Method::GET,
                API_SHARE_DOWN,
                &[
                    ("share_code", self.share_code.clone()),
                    ("receive_code", self.receive_code.clone()),
                    ("file_id", e.fid.clone()),
                ],
            )
            .await?;
        // 响应可能是 data.url 或 data.{fid}.url
        let url = resp
            .pointer("/data/url")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                resp.get("data").and_then(|d| {
                    if let Some(obj) = d.as_object() {
                        for (_k, v) in obj {
                            if let Some(u) = v.get("url").and_then(|x| x.as_str()) {
                                return Some(u.to_string());
                            }
                            if let Some(u) = v.pointer("/url/url").and_then(|x| x.as_str()) {
                                return Some(u.to_string());
                            }
                        }
                    }
                    None
                })
            })
            .unwrap_or_default();
        if url.is_empty() {
            return Err("115 分享未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![
                ("User-Agent".into(), UA.into()),
                ("Referer".into(), "https://115.com/".into()),
            ],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _p: &str, _n: &str) -> Result<(), String> {
        Err("115 分享为只读驱动，不支持此操作".into())
    }
    pub async fn rename(&self, _p: &str, _e: &Entry, _n: &str) -> Result<(), String> {
        Err("115 分享为只读驱动，不支持此操作".into())
    }
    pub async fn move_entry(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("115 分享为只读驱动，不支持此操作".into())
    }
    pub async fn copy(&self, _p: &str, _e: &Entry, _d: &str) -> Result<(), String> {
        Err("115 分享为只读驱动，不支持此操作".into())
    }
    pub async fn remove(&self, _p: &str, _e: &Entry) -> Result<(), String> {
        Err("115 分享为只读驱动，不支持此操作".into())
    }
    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("115 分享为只读驱动，不支持此操作".into())
    }
}

fn coerce_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}
