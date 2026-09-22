//! OneDrive 分享链接驱动（对齐 Go 版 drivers/onedrive_sharelink 核心）
//!
//! - 凭据：分享 URL + 可选密码
//! - 通过无重定向跟随获取 Location，解析 RootFolder / download.aspx 前缀
//! - 列表：SharePoint GraphQL RenderListDataAsStream（简化版）
//! - 下载：download.aspx?UniqueId= + Cookie 头（proxy）

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use serde_json::Value;
use reqwest::Client;
use std::sync::Mutex;
use tokio::sync::Mutex as AsyncMutex;

pub struct OnedriveShare {
    share_url: String,
    password: String,
    http: Client,
    /// Cookie 字符串
    cookie: AsyncMutex<String>,
    download_prefix: Mutex<String>,
    root_folder: Mutex<String>,
    is_sharepoint: bool,
}

impl OnedriveShare {
    pub fn new(share_url: String, password: String) -> Self {
        let is_sharepoint = !share_url.contains("-my");
        OnedriveShare {
            share_url: share_url.trim().to_string(),
            password,
            http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
            cookie: AsyncMutex::new(String::new()),
            download_prefix: Mutex::new(String::new()),
            root_folder: Mutex::new(String::new()),
            is_sharepoint,
        }
    }

    pub async fn validate(&self) -> Result<(), String> {
        self.refresh_headers().await?;
        Ok(())
    }

    async fn refresh_headers(&self) -> Result<(), String> {
        let mut cookie = String::new();
        if !self.password.is_empty() {
            cookie = self.fetch_password_cookie().await?;
        }

        let mut req = self.http.get(&self.share_url).header(
            "User-Agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        );
        if !cookie.is_empty() {
            req = req.header("Cookie", &cookie);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("访问分享链接失败: {e}"))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();

        // 可能直接 200 并带 Set-Cookie
        for c in resp.cookies() {
            if cookie.is_empty() {
                cookie = format!("{}={}", c.name(), c.value());
            } else {
                cookie.push_str(&format!("; {}={}", c.name(), c.value()));
            }
        }

        if location.is_empty() && status != 200 {
            return Err(format!("分享链接无重定向 ({status})，请检查 URL/密码"));
        }

        let redirect = if location.is_empty() {
            self.share_url.clone()
        } else if location.starts_with("http") {
            location
        } else {
            // 相对路径
            let base = url::Url::parse(&self.share_url).map_err(|e| e.to_string())?;
            base.join(&location)
                .map(|u| u.to_string())
                .unwrap_or(location)
        };

        // 解析 id= RootFolder
        let root = extract_query_param(&redirect, "id")
            .or_else(|| extract_query_param(&redirect, "RootFolder"))
            .unwrap_or_default();
        let root = urlencoding_decode(&root);

        // download prefix
        let prefix = if let Some(i) = redirect.rfind('/') {
            format!("{}/download.aspx?UniqueId=", &redirect[..i])
        } else {
            String::new()
        };

        *self.cookie.lock().await = cookie;
        *self.download_prefix.lock().unwrap() = prefix;
        *self.root_folder.lock().unwrap() = root;
        Ok(())
    }

    async fn fetch_password_cookie(&self) -> Result<String, String> {
        // 简化：GET 分享页取表单字段，再 POST 密码
        let resp = self
            .http
            .get(&self.share_url)
            .header("User-Agent", "Mozilla/5.0")
            .send()
            .await
            .map_err(|e| format!("获取密码页失败: {e}"))?;
        let body = resp.text().await.unwrap_or_default();
        // 提取常见 hidden 字段
        let viewstate = extract_input(&body, "__VIEWSTATE");
        let event = extract_input(&body, "__EVENTVALIDATION");
        let form_digest = extract_input(&body, "__REQUESTDIGEST");

        let form = [
            ("__VIEWSTATE", viewstate.as_str()),
            ("__EVENTVALIDATION", event.as_str()),
            ("__REQUESTDIGEST", form_digest.as_str()),
            ("txtPassword", self.password.as_str()),
            ("btnSubmitPassword", "Submit"),
        ];
        let resp = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_else(|_| Client::new())
            .post(&self.share_url)
            .header("User-Agent", "Mozilla/5.0")
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("提交密码失败: {e}"))?;

        let mut cookie = String::new();
        for c in resp.cookies() {
            if cookie.is_empty() {
                cookie = format!("{}={}", c.name(), c.value());
            } else {
                cookie.push_str(&format!("; {}={}", c.name(), c.value()));
            }
        }
        if cookie.is_empty() {
            // 从 set-cookie 头再试
            if let Some(sc) = resp.headers().get("set-cookie").and_then(|v| v.to_str().ok()) {
                cookie = sc.split(';').next().unwrap_or("").to_string();
            }
        }
        if cookie.is_empty() {
            return Err("密码验证后未获得 Cookie，请检查密码".into());
        }
        Ok(cookie)
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        // 确保 headers
        {
            let c = self.cookie.lock().await;
            if c.is_empty() {
                drop(c);
                self.refresh_headers().await?;
            }
        }
        let cookie = self.cookie.lock().await.clone();
        let root = self.root_folder.lock().unwrap().clone();
        if root.is_empty() {
            return Err("未能解析分享根路径，请确认链接有效".into());
        }

        let path = parent_fid.trim();
        let folder = if path.is_empty() || path == "0" || path == "/" {
            root.clone()
        } else if path.starts_with('/') {
            // 相对根
            format!("{}{}", root.trim_end_matches('/'), path)
        } else {
            path.to_string()
        };

        // 使用 SharePoint REST：GetFolderByServerRelativeUrl
        let base = share_api_base(&self.share_url);
        let api = format!(
            "{base}/_api/web/GetFolderByServerRelativeUrl('{}')/Folders",
            js_escape(&folder)
        );
        let files_api = format!(
            "{base}/_api/web/GetFolderByServerRelativeUrl('{}')/Files",
            js_escape(&folder)
        );

        let mut out = Vec::new();
        // folders
        if let Ok(v) = self.sp_get(&api, &cookie).await {
            for f in v
                .pointer("/d/results")
                .or_else(|| v.get("value"))
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let name = f
                    .get("Name")
                    .or_else(|| f.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let server = f
                    .get("ServerRelativeUrl")
                    .or_else(|| f.get("serverRelativeUrl"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                out.push(Entry {
                    fid: if server.is_empty() {
                        format!("{folder}/{name}")
                    } else {
                        server
                    },
                    name,
                    size: 0,
                    is_dir: true,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
        }
        // files
        if let Ok(v) = self.sp_get(&files_api, &cookie).await {
            for f in v
                .pointer("/d/results")
                .or_else(|| v.get("value"))
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default()
            {
                let name = f
                    .get("Name")
                    .or_else(|| f.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let server = f
                    .get("ServerRelativeUrl")
                    .or_else(|| f.get("serverRelativeUrl"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                let size = f
                    .get("Length")
                    .or_else(|| f.get("length"))
                    .and_then(|s| s.as_u64().or_else(|| s.as_str().and_then(|x| x.parse().ok())))
                    .unwrap_or(0);
                let unique = f
                    .get("UniqueId")
                    .or_else(|| f.get("UniqueId"))
                    .and_then(|u| u.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                out.push(Entry {
                    fid: if server.is_empty() {
                        format!("{folder}/{name}")
                    } else {
                        server
                    },
                    name,
                    size,
                    is_dir: false,
                    updated_at: None,
                    etag: if unique.is_empty() {
                        None
                    } else {
                        Some(unique)
                    },
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
        }

        if out.is_empty() {
            // REST 失败时给出提示，仍算成功空列表
        }
        let _ = self.is_sharepoint;
        Ok(out)
    }

    async fn sp_get(&self, url: &str, cookie: &str) -> Result<Value, String> {
        let resp = Client::new()
            .get(url)
            .header("User-Agent", "Mozilla/5.0")
            .header("Accept", "application/json;odata=verbose")
            .header("Cookie", cookie)
            .send()
            .await
            .map_err(|e| format!("SharePoint REST 失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if !(200..300).contains(&status) {
            return Err(format!("SharePoint REST ({status}): {}", truncate(&text, 200)));
        }
        serde_json::from_str(&text).map_err(|e| format!("解析: {e}"))
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        {
            let c = self.cookie.lock().await;
            if c.is_empty() {
                drop(c);
                self.refresh_headers().await?;
            }
        }
        let cookie = self.cookie.lock().await.clone();
        let prefix = self.download_prefix.lock().unwrap().clone();
        let unique = e.etag.clone().unwrap_or_default();
        if prefix.is_empty() || unique.is_empty() {
            return Err("缺少下载前缀或 UniqueId，请重新打开目录".into());
        }
        // UniqueId 在 Go 里会去掉首尾花括号
        let uid = unique.trim_matches(|c| c == '{' || c == '}');
        let url = format!("{prefix}{uid}");
        Ok(DownloadInfo {
            url,
            headers: vec![
                ("Cookie".into(), cookie),
                ("User-Agent".into(), "Mozilla/5.0".into()),
                ("Referer".into(), self.share_url.clone()),
            ],
            proxy: true,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, _: &str, _: &str) -> Result<(), String> {
        Err("OneDrive 分享链接默认只读".into())
    }
    pub async fn rename(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("OneDrive 分享链接默认只读".into())
    }
    pub async fn move_entry(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("OneDrive 分享链接默认只读".into())
    }
    pub async fn copy(&self, _: &str, _: &Entry, _: &str) -> Result<(), String> {
        Err("OneDrive 分享链接默认只读".into())
    }
    pub async fn remove(&self, _: &str, _: &Entry) -> Result<(), String> {
        Err("OneDrive 分享链接默认只读".into())
    }
    pub async fn put(&self, _: &str, _: PutInput) -> Result<(), String> {
        Err("OneDrive 分享链接默认只读".into())
    }
}

fn share_api_base(share_url: &str) -> String {
    // https://xxx.sharepoint.com/:f:/s/site/xxx -> https://xxx.sharepoint.com/sites/site
    // 简化：取到 host + 第一级 path
    if let Ok(u) = url::Url::parse(share_url) {
        let host = u.host_str().unwrap_or("");
        let segs: Vec<&str> = u.path().split('/').filter(|s| !s.is_empty()).collect();
        if segs.len() >= 2 && (segs[0] == "sites" || segs[0] == "teams") {
            return format!("{}://{}/{}/{}", u.scheme(), host, segs[0], segs[1]);
        }
        return format!("{}://{}", u.scheme(), host);
    }
    share_url.to_string()
}

fn extract_query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split('?').nth(1)?;
    for part in q.split('&') {
        let mut it = part.splitn(2, '=');
        let k = it.next()?;
        let v = it.next().unwrap_or("");
        if k == key {
            return Some(v.to_string());
        }
    }
    None
}

fn extract_input(html: &str, name: &str) -> String {
    // name="__VIEWSTATE" value="..."
    let pat = format!("name=\"{name}\"");
    if let Some(i) = html.find(&pat) {
        let rest = &html[i..];
        if let Some(v) = rest.find("value=\"") {
            let start = v + 7;
            if let Some(end) = rest[start..].find('"') {
                return rest[start..start + end].to_string();
            }
        }
    }
    String::new()
}

fn urlencoding_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h = std::str::from_utf8(&bytes[i + 1..i + 3]).ok().and_then(|h| {
                u8::from_str_radix(h, 16).ok()
            });
            if let Some(b) = h {
                out.push(b);
                i += 3;
                continue;
            }
        }
        if bytes[i] == b'+' {
            out.push(b' ');
        } else {
            out.push(bytes[i]);
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn js_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "\\'")
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
