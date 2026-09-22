//! 115 Open 驱动（对齐 Go 版 drivers/115_open 的接口语义）
//!
//! Go 版依赖 OpenListTeam/115-sdk-go；本实现直接走 115 开放平台 HTTP：
//! - 刷新：POST https://passportapi.115.com/open/refreshToken
//! - 列目录：GET https://proapi.115.com/open/ufile/files
//! - 下载：GET https://proapi.115.com/open/ufile/downurl
//!
//! 需要在 115 开放平台申请应用后拿到 access_token / refresh_token。

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

const REFRESH_URL: &str = "https://passportapi.115.com/open/refreshToken";
const FILE_LIST: &str = "https://proapi.115.com/open/ufile/files";
const DOWN_URL: &str = "https://proapi.115.com/open/ufile/downurl";
const USER_INFO: &str = "https://proapi.115.com/open/user/info";

pub struct Pan115Open {
    account_id: String,
    http: Client,
    access_token: Mutex<String>,
    refresh_token: Mutex<String>,
    page_size: i64,
    store: Arc<Store>,
}

impl Pan115Open {
    pub fn new(
        account_id: &str,
        access_token: String,
        refresh_token: String,
        store: Arc<Store>,
    ) -> Self {
        Pan115Open {
            account_id: account_id.to_string(),
            http: Client::new(),
            access_token: Mutex::new(access_token),
            refresh_token: Mutex::new(refresh_token),
            page_size: 200,
            store,
        }
    }

    fn save_tokens(&self, access: &str, refresh: &str) {
        *self.access_token.lock().unwrap() = access.to_string();
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        let (a, r) = (access.to_string(), refresh.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Pan115Open {
                access_token,
                refresh_token,
                ..
            } = cred
            {
                *access_token = a.clone();
                *refresh_token = r.clone();
            }
        });
    }

    async fn refresh(&self) -> Result<(), String> {
        let rt = self.refresh_token.lock().unwrap().clone();
        if rt.is_empty() {
            return Err("refresh_token 为空".into());
        }
        let resp = self
            .http
            .post(REFRESH_URL)
            .form(&[("refresh_token", rt.as_str())])
            .send()
            .await
            .map_err(|e| format!("刷新 115 Open token 失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("刷新响应解析失败: {e}"))?;
        // 兼容 {data:{access_token,refresh_token}} 与顶层字段
        let data = v.get("data").cloned().unwrap_or(v.clone());
        let access = data
            .get("access_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let refresh = data
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or(&rt)
            .to_string();
        if access.is_empty() {
            let msg = v
                .get("message")
                .or_else(|| v.get("error"))
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            return Err(format!("刷新 115 Open token 失败: {msg}"));
        }
        self.save_tokens(&access, &refresh);
        Ok(())
    }

    async fn request(
        &self,
        method: Method,
        url: &str,
        query: Option<&[(String, String)]>,
        form: Option<&[(&str, String)]>,
        retried: bool,
    ) -> Result<Value, String> {
        let token = self.access_token.lock().unwrap().clone();
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {token}"));
        if let Some(q) = query {
            req = req.query(q);
        }
        if let Some(f) = form {
            req = req.form(f);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        // state=false 或 code 非 0
        let bad = v.get("state") == Some(&Value::Bool(false))
            || v.get("code").and_then(|c| c.as_i64()).unwrap_or(0) != 0
                && v.get("code").is_some();
        if bad || status.as_u16() == 401 {
            let msg = v
                .get("message")
                .or_else(|| v.get("error"))
                .or_else(|| v.get("msg"))
                .and_then(|m| m.as_str())
                .unwrap_or("")
                .to_lowercase();
            if !retried
                && (status.as_u16() == 401
                    || msg.contains("token")
                    || msg.contains("login")
                    || msg.contains("auth"))
            {
                self.refresh().await?;
                return Box::pin(self.request(method, url, query, form, true)).await;
            }
            let msg = v
                .get("message")
                .or_else(|| v.get("error"))
                .or_else(|| v.get("msg"))
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("115 Open 接口错误: {msg}"));
        }
        Ok(v)
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.access_token.lock().unwrap().is_empty()
            && self.refresh_token.lock().unwrap().is_empty()
        {
            return Err("access_token 与 refresh_token 不能同时为空".into());
        }
        if self.access_token.lock().unwrap().is_empty() {
            self.refresh().await?;
        }
        // 尝试用户信息；失败则尝试 list
        match self
            .request(Method::GET, USER_INFO, None, None, false)
            .await
        {
            Ok(_) => Ok(()),
            Err(_) => {
                let q = vec![
                    ("cid".into(), "0".into()),
                    ("limit".into(), "1".into()),
                    ("offset".into(), "0".into()),
                    ("show_dir".into(), "1".into()),
                ];
                self.request(Method::GET, FILE_LIST, Some(&q), None, false)
                    .await?;
                Ok(())
            }
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let cid = if parent_fid.is_empty() {
            "0"
        } else {
            parent_fid
        };
        let mut files = Vec::new();
        let mut offset: i64 = 0;
        let limit = self.page_size.min(1150);
        loop {
            let q = vec![
                ("cid".into(), cid.to_string()),
                ("limit".into(), limit.to_string()),
                ("offset".into(), offset.to_string()),
                ("show_dir".into(), "1".into()),
                ("o".into(), "user_utime".into()),
                ("asc".into(), "0".into()),
            ];
            let resp = self
                .request(Method::GET, FILE_LIST, Some(&q), None, false)
                .await?;
            let list = resp
                .get("data")
                .and_then(|v| v.as_array())
                .cloned()
                .or_else(|| {
                    resp.pointer("/data/list")
                        .and_then(|v| v.as_array())
                        .cloned()
                })
                .unwrap_or_default();
            let count = resp
                .get("count")
                .or_else(|| resp.pointer("/data/count"))
                .and_then(|v| v.as_i64())
                .unwrap_or(list.len() as i64);
            for f in &list {
                let file_id = coerce_str(f.get("fid").or_else(|| f.get("file_id")));
                let (entry_fid, is_dir) = if file_id.is_empty() {
                    (coerce_str(f.get("cid").or_else(|| f.get("file_id"))), true)
                } else {
                    // fc: "0"=dir "1"=file
                    let fc = coerce_str(f.get("fc"));
                    (file_id, fc == "0" || f.get("file_category").and_then(|v| v.as_str()) == Some("0"))
                };
                let name = coerce_str(f.get("fn").or_else(|| f.get("file_name")).or_else(|| f.get("n")));
                let size = f
                    .get("fs")
                    .or_else(|| f.get("file_size"))
                    .or_else(|| f.get("s"))
                    .and_then(|v| v.as_u64())
                    .or_else(|| {
                        coerce_str(f.get("fs").or_else(|| f.get("file_size")))
                            .parse()
                            .ok()
                    })
                    .unwrap_or(0);
                let pick = coerce_str(f.get("pc").or_else(|| f.get("pick_code")));
                let updated_at = coerce_str(f.get("upt").or_else(|| f.get("user_utime")))
                    .parse::<i64>()
                    .ok()
                    .map(|s| if s > 1_000_000_000_000 { s } else { s * 1000 });
                files.push(Entry {
                    fid: entry_fid,
                    name,
                    size,
                    is_dir,
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: if !pick.is_empty() {
                        Some(json!({ "pick_code": pick }))
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
        let pick = e
            .extra
            .as_ref()
            .and_then(|v| v.get("pick_code"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let mut q = vec![("file_id".into(), e.fid.clone())];
        if !pick.is_empty() {
            q.push(("pick_code".into(), pick));
        }
        let resp = self
            .request(Method::GET, DOWN_URL, Some(&q), None, false)
            .await?;
        // data 可能是 map[file_id]{url} 或 data.url
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
            return Err("115 Open 未返回下载直链".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![("User-Agent".into(), "Mozilla/5.0".into())],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let form = [
            ("pid", parent_fid.to_string()),
            ("name", name.to_string()),
        ];
        self.request(
            Method::POST,
            "https://proapi.115.com/open/folder/add",
            None,
            Some(&form),
            false,
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, _p: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let form = [
            ("file_id", e.fid.clone()),
            ("file_name", new_name.to_string()),
        ];
        self.request(
            Method::POST,
            "https://proapi.115.com/open/ufile/update",
            None,
            Some(&form),
            false,
        )
        .await?;
        Ok(())
    }

    pub async fn move_entry(&self, _p: &str, e: &Entry, dst: &str) -> Result<(), String> {
        let form = [
            ("file_ids", e.fid.clone()),
            ("to_cid", dst.to_string()),
        ];
        self.request(
            Method::POST,
            "https://proapi.115.com/open/ufile/move",
            None,
            Some(&form),
            false,
        )
        .await?;
        Ok(())
    }

    pub async fn copy(&self, _p: &str, e: &Entry, dst: &str) -> Result<(), String> {
        let form = [
            ("file_id", e.fid.clone()),
            ("pid", dst.to_string()),
        ];
        self.request(
            Method::POST,
            "https://proapi.115.com/open/ufile/copy",
            None,
            Some(&form),
            false,
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let form = [
            ("file_ids", e.fid.clone()),
            ("parent_id", parent_fid.to_string()),
        ];
        self.request(
            Method::POST,
            "https://proapi.115.com/open/ufile/delete",
            None,
            Some(&form),
            false,
        )
        .await?;
        Ok(())
    }

    pub async fn put(&self, _d: &str, _input: super::PutInput) -> Result<(), String> {
        Err("115 Open 上传暂未实现（Go 版依赖官方 SDK + OSS）".into())
    }
}

fn coerce_str(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Number(n)) => n.to_string(),
        _ => String::new(),
    }
}
