//! AList V3 / OpenList 远程挂载（对齐 Go 版 drivers/alist_v3）
//!
//! 通过对方的 /api/* 接口代理列表与下载；支持用户名密码登录或直接 Token。

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::Mutex;

/// 浏览器化 UA，与 Go 版 `drivers/base/client.go` 的 `base.UserAgent` 同源。
///
/// **不能留空**：reqwest 默认不发 `User-Agent`，部分站点/前置 CDN 会对无 UA 请求
/// 直接回挑战页（HTTP 403 + HTML），被业务层吃成「AList 需要 token 或 username/password:
/// `<!DOCTYPE html>…`」这类误导性报错。
const USER_AGENT: &str = "Mozilla/5.0 (Macintosh; Apple macOS 26_1_0) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Safari/537.36 Chrome/142.0.0.0 OpenList/425.6.30";

pub struct AlistV3 {
    address: String,
    meta_password: String,
    username: String,
    password: String,
    token: Mutex<String>,
    http: Client,
}

impl AlistV3 {
    pub fn new(
        address: String,
        meta_password: String,
        username: String,
        password: String,
        token: String,
    ) -> Self {
        let address = address.trim().trim_end_matches('/').to_string();
        AlistV3 {
            address,
            meta_password,
            username,
            password,
            token: Mutex::new(token),
            http: Client::builder()
                .user_agent(USER_AGENT)
                .build()
                .unwrap_or_else(|_| Client::new()),
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        // 有用户名则登录；否则直接探 /api/me
        if !self.username.trim().is_empty() {
            self.login().await?;
        }
        let (code, body) = self.api("GET", "/me", None).await?;
        if code == 401 || code == 403 {
            if !self.username.trim().is_empty() {
                self.login().await?;
                let (code2, body2) = self.api("GET", "/me", None).await?;
                if code2 != 200 {
                    return Err(format!("AList 登录后仍失败: {}", truncate(&body2, 200)));
                }
            } else {
                return Err(format!(
                    "AList 需要 token 或 username/password: {}",
                    truncate(&body, 200)
                ));
            }
        } else if code != 200 {
            return Err(format!("AList 连接失败 ({code}): {}", truncate(&body, 200)));
        }
        Ok(())
    }

    async fn login(&self) -> Result<(), String> {
        if self.username.trim().is_empty() {
            return Ok(());
        }
        let url = format!("{}/api/auth/login", self.address);
        let resp = self
            .http
            .post(&url)
            .json(&json!({
                "username": self.username,
                "password": self.password,
            }))
            .send()
            .await
            .map_err(|e| format!("AList 登录请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let code = v
            .get("code")
            .and_then(|c| c.as_i64())
            .unwrap_or(status as i64);
        if code != 200 {
            return Err(format!(
                "AList 登录失败: {}",
                v.get("message").and_then(|m| m.as_str()).unwrap_or(&text)
            ));
        }
        let token = v
            .pointer("/data/token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err("AList 登录未返回 token".into());
        }
        *self.token.lock().await = token;
        Ok(())
    }

    async fn api(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<(u16, String), String> {
        let url = format!("{}/api{path}", self.address);
        let token = self.token.lock().await.clone();
        let mut req = match method {
            "GET" => self.http.get(&url),
            "POST" => self.http.post(&url),
            "PUT" => self.http.put(&url),
            _ => self.http.request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
                &url,
            ),
        };
        if !token.is_empty() {
            req = req.header("Authorization", token);
        }
        if let Some(b) = body {
            req = req.json(&b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("AList 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        // 统一解析业务 code
        if let Ok(v) = serde_json::from_str::<Value>(&text) {
            let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(200);
            if code == 401 || code == 403 {
                return Ok((401, text));
            }
            if code != 200 && status < 400 {
                return Ok((code as u16, text));
            }
        }
        Ok((status, text))
    }

    async fn api_ok(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, String> {
        let (code, text) = self.api(method, path, body.clone()).await?;
        if code == 401 || code == 403 {
            self.login().await?;
            let (code2, text2) = self.api(method, path, body).await?;
            if code2 != 200 {
                return Err(format!(
                    "AList API 失败 ({code2}): {}",
                    truncate(&text2, 300)
                ));
            }
            return serde_json::from_str(&text2).map_err(|e| format!("解析失败: {e}"));
        }
        if code != 200 {
            return Err(format!("AList API 失败 ({code}): {}", truncate(&text, 300)));
        }
        serde_json::from_str(&text).map_err(|e| format!("解析失败: {e}"))
    }

    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" {
            return "/".into();
        }
        if fid.starts_with('/') {
            fid.to_string()
        } else {
            format!("/{fid}")
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.resolve(parent_fid);
        let v = self
            .api_ok(
                "POST",
                "/fs/list",
                Some(json!({
                    "path": path,
                    "password": self.meta_password,
                    "page": 1,
                    "per_page": 0,
                    "refresh": false,
                })),
            )
            .await?;
        let content = v
            .pointer("/data/content")
            .and_then(|c| c.as_array())
            .cloned()
            .unwrap_or_default();
        let mut out = Vec::new();
        for f in content {
            let name = f
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
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
        let path = self.resolve(&e.fid);
        let v = self
            .api_ok(
                "POST",
                "/fs/get",
                Some(json!({
                    "path": path,
                    "password": self.meta_password,
                })),
            )
            .await?;
        let url = v
            .pointer("/data/raw_url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("AList 未返回 raw_url".into());
        }
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
        self.api_ok("POST", "/fs/mkdir", Some(json!({ "path": path })))
            .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        self.api_ok(
            "POST",
            "/fs/rename",
            Some(json!({
                "path": self.resolve(&e.fid),
                "name": new_name,
            })),
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
        let src = self.resolve(&e.fid);
        let src_dir = match src.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => src[..i].to_string(),
        };
        self.api_ok(
            "POST",
            "/fs/move",
            Some(json!({
                "src_dir": src_dir,
                "dst_dir": self.resolve(dst_dir_fid),
                "names": [e.name],
            })),
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
        let src = self.resolve(&e.fid);
        let src_dir = match src.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => src[..i].to_string(),
        };
        self.api_ok(
            "POST",
            "/fs/copy",
            Some(json!({
                "src_dir": src_dir,
                "dst_dir": self.resolve(dst_dir_fid),
                "names": [e.name],
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.resolve(&e.fid);
        let dir = match path.rfind('/') {
            Some(0) | None => "/".to_string(),
            Some(i) => path[..i].to_string(),
        };
        self.api_ok(
            "POST",
            "/fs/remove",
            Some(json!({
                "dir": dir,
                "names": [e.name],
            })),
        )
        .await?;
        Ok(())
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
        let file_path = format!(
            "{}/{}",
            self.resolve(dst_dir_fid).trim_end_matches('/'),
            input.name
        );
        let url = format!("{}/api/fs/put", self.address);
        let token = self.token.lock().await.clone();
        let resp = self
            .http
            .put(&url)
            .header("Authorization", token)
            .header("File-Path", urlencoding_path(&file_path))
            .header("Password", &self.meta_password)
            .header("Content-Length", buf.len().to_string())
            .body(buf)
            .send()
            .await
            .map_err(|e| format!("AList 上传失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let code = v
            .get("code")
            .and_then(|c| c.as_i64())
            .unwrap_or(status as i64);
        if code != 200 {
            return Err(format!(
                "AList 上传失败: {}",
                v.get("message").and_then(|m| m.as_str()).unwrap_or(&text)
            ));
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

fn urlencoding_path(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
