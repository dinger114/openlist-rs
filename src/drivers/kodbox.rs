//! 可道云 KodBox 驱动（对齐 Go 版 drivers/kodbox）
//!
//! - 地址 + 账号密码登录 /?user/index/loginSubmit 换 accessToken
//! - 响应 code 为 bool（true 成功）或字符串 "10001"（token 过期，重登重试）
//! - 文件操作全部走 form 表单 POST；fid 即 KodBox 内部 path

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Mutex;

pub struct Kodbox {
    address: String,
    http: Client,
    username: String,
    password: String,
    root_path: String,
    authorization: Mutex<String>,
}

impl Kodbox {
    pub fn new(address: String, username: String, password: String, root_path: String) -> Self {
        let address = address.trim().trim_end_matches('/').to_string();
        let root_path = root_path.trim().trim_start_matches('/').to_string();
        Kodbox {
            address,
            http: Client::new(),
            username,
            password,
            root_path,
            authorization: Mutex::new(String::new()),
        }
    }

    fn save_token(&self, token: &str) {
        // 对齐 Go 版：accessToken 仅保存在驱动实例内存中，不落盘
        *self.authorization.lock().unwrap() = token.to_string();
    }

    async fn get_token(&self) -> Result<String, String> {
        let cur = self.authorization.lock().unwrap().clone();
        if !cur.is_empty() {
            return Ok(cur);
        }
        self.login().await
    }

    async fn login(&self) -> Result<String, String> {
        if self.username.is_empty() {
            return Err("KodBox 需要 accessToken 或账号密码".into());
        }
        let url = format!("{}/?user/index/loginSubmit", self.address);
        let resp = self
            .http
            .post(&url)
            .query(&[
                ("name", self.username.as_str()),
                ("password", self.password.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("KodBox 登录请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status >= 400 {
            return Err(format!(
                "KodBox 获取 token 失败 ({status}): {}",
                truncate(&text, 200)
            ));
        }
        let v: Value =
            serde_json::from_str(&text).map_err(|e| format!("KodBox 响应解析失败: {e}"))?;
        if v.get("code").and_then(|c| c.as_bool()) == Some(false) {
            return Err(format!(
                "KodBox 登录失败: {}",
                v.get("data").and_then(|d| d.as_str()).unwrap_or("未知错误")
            ));
        }
        let token = v
            .get("info")
            .and_then(|i| i.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err("KodBox 登录未返回 accessToken".into());
        }
        self.save_token(&token);
        Ok(token)
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.login().await?;
        Ok(())
    }

    /// 统一请求：accessToken 与业务参数同走 form 表单；code="10001" 时重登重试一次
    async fn request(&self, pathname: &str, form: Vec<(String, String)>) -> Result<Value, String> {
        let send = |token: String| {
            let mut fields: Vec<(String, String)> = vec![("accessToken".into(), token)];
            fields.extend(form.clone());
            self.http
                .post(format!("{}{pathname}", self.address))
                .form(&fields)
        };
        let token = self.get_token().await?;
        let resp = send(token)
            .send()
            .await
            .map_err(|e| format!("KodBox 请求失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        // code 为字符串且为 10001 → token 过期，重登再试
        if v.get("code").and_then(|c| c.as_str()) == Some("10001") {
            self.authorization.lock().unwrap().clear();
            let token = self.login().await?;
            let resp = send(token)
                .send()
                .await
                .map_err(|e| format!("KodBox 请求失败: {e}"))?;
            let text = resp.text().await.unwrap_or_default();
            return serde_json::from_str(&text).map_err(|e| format!("解析失败: {e}"));
        }
        Ok(v)
    }

    /// 校验业务 code（bool true = 成功）
    fn check(v: &Value) -> Result<(), String> {
        match v.get("code") {
            Some(Value::Bool(true)) => Ok(()),
            _ => Err(format!(
                "KodBox 操作失败: {}",
                v.get("data")
                    .map(|d| match d {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    })
                    .unwrap_or_else(|| "未知错误".into())
            )),
        }
    }

    /// fid → KodBox path（根 = root_path）
    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            return format!("/{}", self.root_path.trim_matches('/'));
        }
        fid.to_string()
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve(parent_fid);
        let v = self
            .request("/?explorer/list/path", vec![("path".into(), path)])
            .await?;
        Self::check(&v)?;
        let mut out = Vec::new();
        for key in ["folderList", "fileList"] {
            if let Some(items) = v
                .get("data")
                .and_then(|d| d.get(key))
                .and_then(|x| x.as_array())
            {
                for f in items {
                    let name = f
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    let fpath = f
                        .get("path")
                        .and_then(|p| p.as_str())
                        .unwrap_or("")
                        .to_string();
                    if name.is_empty() || fpath.is_empty() {
                        continue;
                    }
                    let is_dir = key == "folderList"
                        || f.get("type").and_then(|t| t.as_str()) == Some("folder");
                    let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                    let mtime = f
                        .get("modifyTime")
                        .and_then(|t| t.as_i64())
                        .map(|s| s * 1000);
                    out.push(Entry {
                        fid: fpath,
                        name,
                        size: if is_dir { 0 } else { size },
                        is_dir,
                        updated_at: mtime,
                        etag: None,
                        s3_key_flag: None,
                        file_type: None,
                        extra: None,
                    });
                }
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let token = self.get_token().await?;
        let url = format!(
            "{}/?explorer/index/fileOut&path={}&download=1&accessToken={}",
            self.address,
            urlencode(&self.resolve(&e.fid)),
            urlencode(&token)
        );
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let new_dir = format!(
            "{}/{}",
            self.resolve(parent_fid).trim_end_matches('/'),
            name.trim_matches('/')
        );
        let v = self
            .request("/?explorer/index/mkdir", vec![("path".into(), new_dir)])
            .await?;
        Self::check(&v)
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let v = self
            .request(
                "/?explorer/index/pathRename",
                vec![
                    ("path".into(), self.resolve(&e.fid)),
                    ("newName".into(), new_name.into()),
                ],
            )
            .await?;
        Self::check(&v)
    }

    fn data_arr(path: &str, name: &str) -> String {
        format!("[{{\"path\": \"{path}\", \"name\": \"{name}\"}}]")
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let v = self
            .request(
                "/?explorer/index/pathCuteTo",
                vec![
                    (
                        "dataArr".into(),
                        Self::data_arr(&self.resolve(&e.fid), &e.name),
                    ),
                    ("path".into(), self.resolve(dst_dir_fid)),
                ],
            )
            .await?;
        Self::check(&v)
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let v = self
            .request(
                "/?explorer/index/pathCopyTo",
                vec![
                    (
                        "dataArr".into(),
                        Self::data_arr(&self.resolve(&e.fid), &e.name),
                    ),
                    ("path".into(), self.resolve(dst_dir_fid)),
                ],
            )
            .await?;
        Self::check(&v)
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let v = self
            .request(
                "/?explorer/index/pathDelete",
                vec![
                    (
                        "dataArr".into(),
                        Self::data_arr(&self.resolve(&e.fid), &e.name),
                    ),
                    ("shiftDelete".into(), "1".into()),
                ],
            )
            .await?;
        Self::check(&v)
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut tmp = [0u8; 64 * 1024];
        loop {
            let n = input
                .reader
                .read(&mut tmp)
                .await
                .map_err(|e| format!("读上传流失败: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.len() > 500 * 1024 * 1024 {
                return Err("单文件上传暂限 500MB".into());
            }
        }
        let token = self.get_token().await?;
        let part = reqwest::multipart::Part::bytes(buf).file_name(input.name.clone());
        let form = reqwest::multipart::Form::new()
            .text("path", self.resolve(dst_dir_fid))
            .part("file", part);
        let resp = self
            .http
            .post(format!("{}/?explorer/upload/fileUpload", self.address))
            .header("accessToken", token)
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("KodBox 上传失败: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        Self::check(&v)
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}

fn urlencode(s: &str) -> String {
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
