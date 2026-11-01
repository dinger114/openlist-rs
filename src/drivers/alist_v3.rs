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
    /// 可选：随每个请求发送的 Cookie 串（过 Cloudflare `cf_clearance` 这类挑战）
    cookie: String,
    /// 实际生效的 User-Agent。取直链时服务器侧要复用它 —— `cf_clearance` 与 UA 绑定，
    /// 中转请求换了 UA 同样会被判挑战。
    ua: String,
    http: Client,
}

/// 洗掉用户可能连前缀一起粘进来的 `Cookie:`，只留 `k=v; k2=v2`。
fn normalize_cookie(raw: &str) -> String {
    let mut s = raw.trim();
    for p in ["Cookie:", "cookie:", "COOKIE:"] {
        if let Some(rest) = s.strip_prefix(p) {
            s = rest.trim();
            break;
        }
    }
    s.to_string()
}

impl AlistV3 {
    pub fn new(
        address: String,
        meta_password: String,
        username: String,
        password: String,
        token: String,
    ) -> Self {
        Self::with_ua_cookie(
            address,
            meta_password,
            username,
            password,
            token,
            String::new(),
            String::new(),
        )
    }

    /// 带自定义 UA / Cookie 的构造（`alist_v3` 用它；`openlist` 仍走 `new`）。
    ///
    /// **UA 与 Cookie 必须成对给**：前置 Cloudflare 的 `cf_clearance` 与签发时的 UA 绑定，
    /// 只给 cookie 而 UA 用驱动默认值 → 直接判挑战页（实测同一枚 clearance 配默认 UA 回 403）。
    #[allow(clippy::too_many_arguments)]
    pub fn with_ua_cookie(
        address: String,
        meta_password: String,
        username: String,
        password: String,
        token: String,
        ua: String,
        cookie: String,
    ) -> Self {
        let address = address.trim().trim_end_matches('/').to_string();
        let ua = match ua.trim() {
            "" => USER_AGENT.to_string(),
            other => other.to_string(),
        };
        let cookie = normalize_cookie(&cookie);
        let mut builder = Client::builder().user_agent(ua.as_str());
        if !cookie.is_empty() {
            // 浏览器等价：Cookie 之外还得补 `Referer`。前置 Cloudflare 的 WAF 规则对
            // `/api/*` 要求带 Referer，缺了直接回「Sorry, you have been blocked」（实测同一枚
            // cookie + UA，只去掉 Referer 就被拦；补上即 200，与本机 TLS 指纹无关）。
            let mut h = reqwest::header::HeaderMap::new();
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&cookie) {
                h.insert(reqwest::header::COOKIE, v);
            }
            if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("{address}/")) {
                h.insert(reqwest::header::REFERER, v);
            }
            builder = builder.default_headers(h);
        }
        AlistV3 {
            address,
            meta_password,
            username,
            password,
            token: Mutex::new(token),
            cookie,
            ua,
            http: builder.build().unwrap_or_else(|_| Client::new()),
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
                // 上游 Go 版把 `modified` 映射进 Obj.Modified（drivers/alist_v3/driver.go:99）；
                // 漏了这步挂载盘的所有条目都没时间：面板/客户端显示 1970，
                // 且 AList 客户端按时间排序时会因 null 抛错（整页空白）。
                updated_at: modified_ms(&f),
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
        // 服务器侧中转（面板预览的 `proxy=true`、账号级「服务器代理」开关）会带上
        // `info.headers` 去拉上游；有 Cookie 的站点必须把 UA 一起带上 ——
        // `cf_clearance` 与签发时的 UA 绑定，缺了 UA 一样判挑战页。
        let mut headers = Vec::new();
        if !self.cookie.is_empty() {
            headers.push(("Cookie".to_string(), self.cookie.clone()));
            headers.push(("User-Agent".to_string(), self.ua.clone()));
            headers.push(("Referer".to_string(), format!("{}/", self.address)));
        }
        Ok(DownloadInfo {
            url,
            headers,
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

/// 上游条目 JSON 的 `modified`（RFC3339，如 `2025-12-20T21:42:03+08:00`）→ unix 毫秒。
/// 缺失/为 null/格式不认识时返回 None（由兼容层兜成 1970 占位，绝不发 null）。
fn modified_ms(f: &Value) -> Option<i64> {
    f.get("modified")
        .and_then(|m| m.as_str())
        .and_then(super::aliyundrive_open::iso_to_ms)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modified_ms_parses_upstream_rfc3339() {
        // 上游 /api/fs/list 的真实形状（东八区偏移）
        let f = json!({ "name": "a.mp3", "modified": "2025-12-20T21:42:03+08:00" });
        assert_eq!(modified_ms(&f), Some(1_766_238_123_000));
        // 带毫秒的 UTC
        let f = json!({ "modified": "2024-01-02T03:04:05.000Z" });
        assert_eq!(modified_ms(&f), Some(1_704_164_645_000));
        // 缺失 / null / 空串都不 panic，返回 None（兼容层再兜 1970 占位）
        assert_eq!(modified_ms(&json!({ "name": "a" })), None);
        assert_eq!(modified_ms(&json!({ "modified": null })), None);
        assert_eq!(modified_ms(&json!({ "modified": "" })), None);
    }

    #[test]
    fn ua_and_cookie_are_pairwise_optional() {
        // 都不填 → 保持原行为：驱动默认浏览器化 UA、不发 Cookie
        let d = AlistV3::new(
            "https://x.example/".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        );
        assert_eq!(d.address, "https://x.example");
        assert_eq!(d.ua, super::USER_AGENT);
        assert!(d.cookie.is_empty());

        // 只填 UA → cookie 仍空；填的 UA 原样生效（尾斜杠也被吃掉）
        let d = AlistV3::with_ua_cookie(
            "https://x.example".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "UA-vendor".into(),
            String::new(),
        );
        assert_eq!(d.ua, "UA-vendor");
        assert!(d.cookie.is_empty());

        // 用户把 `Cookie: ` 前缀一起粘进来要能洗掉；空白 UA 回落到默认值
        let d = AlistV3::with_ua_cookie(
            "https://x.example".into(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            "   ".into(),
            "Cookie: cf_clearance=abc; _ga=1".into(),
        );
        assert_eq!(d.ua, super::USER_AGENT);
        assert_eq!(d.cookie, "cf_clearance=abc; _ga=1");
    }
}
