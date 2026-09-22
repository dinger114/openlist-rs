//! OpenList 分享挂载（对齐 Go 版 drivers/openlist_share，只读）
//!
//! 列表走对方的 /api/fs/list（路径拼 /@s/{share_id} 前缀），
//! 下载直接拼对方的 /sd{path}?pwd= 分享直链。

use super::DownloadInfo;
use crate::config::Entry;
use reqwest::Client;
use serde_json::{json, Value};

pub struct OpenlistShare {
    address: String,
    share_id: String,
    share_pwd: String,
    http: Client,
}

impl OpenlistShare {
    pub fn new(address: String, share_id: String, share_pwd: String) -> Self {
        let address = address.trim().trim_end_matches('/').to_string();
        OpenlistShare {
            address,
            share_id,
            share_pwd,
            http: Client::new(),
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        let url = format!("{}/api/public/settings", self.address);
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OpenList 分享连接失败: {e}"))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(format!("OpenList 分享站点连接失败 ({status})"));
        }
        Ok(())
    }

    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            return "/".into();
        }
        if fid.starts_with('/') {
            fid.to_string()
        } else {
            format!("/{fid}")
        }
    }

    async fn fs_list(&self, path: &str) -> Result<Value, String> {
        let url = format!("{}/api/fs/list", self.address);
        let body = json!({
            "path": format!("/@s/{}{}", self.share_id, path),
            "password": self.share_pwd,
            "page": 1,
            "per_page": 0,
            "refresh": false,
        });
        let resp = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("OpenList 分享请求失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text)
            .map_err(|e| format!("OpenList 分享响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(200);
        if code != 200 {
            return Err(format!(
                "OpenList 分享列表失败: {}",
                v.get("message").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
        Ok(v)
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve(parent_fid);
        let v = self.fs_list(&path).await?;
        let content = v
            .pointer("/data/content")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for f in content {
            let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            if name.is_empty() {
                continue;
            }
            let is_dir = f.get("is_dir").and_then(|b| b.as_bool()).unwrap_or(false);
            let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
            let fid = if path == "/" {
                format!("/{name}")
            } else {
                format!("{path}/{name}")
            };
            out.push(Entry {
                fid,
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
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        // 对齐 Go 版：url = {address}/sd{share_id + path}?pwd={share_pwd}
        let path = self.resolve(&e.fid);
        let url = format!(
            "{}/sd/{}{}?pwd={}",
            self.address,
            self.share_id,
            path,
            urlencoding_query(&self.share_pwd)
        );
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _parent_fid: &str, _name: &str) -> Result<(), String> {
        Err("OpenList 分享为只读存储".into())
    }

    pub async fn rename(&self, _parent_fid: &str, _e: &Entry, _new_name: &str) -> Result<(), String> {
        Err("OpenList 分享为只读存储".into())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("OpenList 分享为只读存储".into())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("OpenList 分享为只读存储".into())
    }

    pub async fn remove(&self, _parent_fid: &str, _e: &Entry) -> Result<(), String> {
        Err("OpenList 分享为只读存储".into())
    }

    pub async fn put(&self, _dst_dir_fid: &str, _input: super::PutInput) -> Result<(), String> {
        Err("OpenList 分享为只读存储".into())
    }
}

/// query 值编码（保留字母数字与 -_.~）
fn urlencoding_query(s: &str) -> String {
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
