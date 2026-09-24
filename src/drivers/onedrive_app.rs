//! OneDrive APP 驱动（对齐 Go 版 drivers/onedrive_app）
//!
//! - 授权：Azure AD 应用 client_credentials（client_id + client_secret + tenant_id）
//! - 以组织用户邮箱挂载个人/工作盘：/v1.0/users/{email}/drive/...
//! - 列表/下载走 Microsoft Graph

use super::{DownloadInfo, PutInput};
use crate::config::Entry;
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Mutex;

struct Host {
    oauth: &'static str,
    api: &'static str,
}

fn host(region: &str) -> Host {
    match region {
        "cn" => Host {
            oauth: "https://login.chinacloudapi.cn",
            api: "https://microsoftgraph.chinacloudapi.cn",
        },
        "us" => Host {
            oauth: "https://login.microsoftonline.us",
            api: "https://graph.microsoft.us",
        },
        "de" => Host {
            oauth: "https://login.microsoftonline.de",
            api: "https://graph.microsoft.de",
        },
        _ => Host {
            oauth: "https://login.microsoftonline.com",
            api: "https://graph.microsoft.com",
        },
    }
}

fn encode_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return String::new();
    }
    let path = path.trim_start_matches('/');
    path.split('/')
        .map(|seg| {
            let mut out = String::new();
            for b in seg.bytes() {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                        out.push(b as char)
                    }
                    _ => out.push_str(&format!("%{b:02X}")),
                }
            }
            out
        })
        .collect::<Vec<_>>()
        .join("/")
}

pub struct OnedriveApp {
    region: String,
    client_id: String,
    client_secret: String,
    tenant_id: String,
    email: String,
    custom_host: String,
    root_path: String,
    http: Client,
    access_token: Mutex<String>,
}

impl OnedriveApp {
    pub fn new(
        region: String,
        client_id: String,
        client_secret: String,
        tenant_id: String,
        email: String,
        custom_host: String,
        root_path: String,
    ) -> Self {
        let region = if region.is_empty() {
            "global".into()
        } else {
            region
        };
        let root_path = if root_path.is_empty() {
            "/".into()
        } else {
            root_path
        };
        OnedriveApp {
            region,
            client_id,
            client_secret,
            tenant_id,
            email,
            custom_host,
            root_path,
            http: Client::new(),
            access_token: Mutex::new(String::new()),
        }
    }

    fn meta_url(&self, path: &str) -> String {
        let h = host(&self.region);
        let email = urlencoding_encode(&self.email);
        if path.is_empty() || path == "/" {
            format!("{}/v1.0/users/{}/drive/root", h.api, email)
        } else {
            let ep = encode_path(path);
            format!("{}/v1.0/users/{}/drive/root:/{}:", h.api, email, ep)
        }
    }

    async fn access_token(&self) -> Result<(), String> {
        let h = host(&self.region);
        let tenant = if self.tenant_id.is_empty() {
            "common"
        } else {
            &self.tenant_id
        };
        let url = format!("{}/{}/oauth2/token", h.oauth, tenant);
        let resource = format!("{}/", h.api);
        let scope = format!("{}/.default", h.api);
        let resp = self
            .http
            .post(&url)
            .form(&[
                ("grant_type", "client_credentials"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("resource", resource.as_str()),
                ("scope", scope.as_str()),
            ])
            .send()
            .await
            .map_err(|e| format!("OnedriveAPP token: {e}"))?;
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        if let Some(err) = v.get("error").and_then(|e| e.as_str()) {
            if !err.is_empty() {
                return Err(format!(
                    "OnedriveAPP token 失败: {} {}",
                    err,
                    v.get("error_description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("")
                ));
            }
        }
        let at = v
            .get("access_token")
            .and_then(|t| t.as_str())
            .ok_or_else(|| format!("OnedriveAPP 无 access_token: {text}"))?;
        *self.access_token.lock().unwrap() = at.to_string();
        Ok(())
    }

    async fn ensure_token(&self) -> Result<String, String> {
        let t = self.access_token.lock().unwrap().clone();
        if t.is_empty() {
            self.access_token().await?;
            return Ok(self.access_token.lock().unwrap().clone());
        }
        Ok(t)
    }

    async fn request(&self, method: &str, url: &str, body: Option<Value>) -> Result<Value, String> {
        let mut token = self.ensure_token().await?;
        for attempt in 0..2 {
            let mut req = match method {
                "POST" => self.http.post(url),
                "PUT" => self.http.put(url),
                "PATCH" => self.http.patch(url),
                "DELETE" => self.http.delete(url),
                _ => self.http.get(url),
            };
            req = req.header("Authorization", format!("Bearer {token}"));
            if let Some(ref b) = body {
                req = req.json(b);
            }
            let resp = req
                .send()
                .await
                .map_err(|e| format!("OnedriveAPP 请求失败: {e}"))?;
            let status = resp.status().as_u16();
            let text = resp.text().await.unwrap_or_default();
            let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
            if status == 401 && attempt == 0 {
                self.access_token().await?;
                token = self.access_token.lock().unwrap().clone();
                continue;
            }
            if let Some(code) = v.pointer("/error/code").and_then(|c| c.as_str()) {
                if code == "InvalidAuthenticationToken" && attempt == 0 {
                    self.access_token().await?;
                    token = self.access_token.lock().unwrap().clone();
                    continue;
                }
                let msg = v
                    .pointer("/error/message")
                    .and_then(|m| m.as_str())
                    .unwrap_or(code);
                return Err(format!("OnedriveAPP: {msg}"));
            }
            if !(200..300).contains(&status) && !text.is_empty() {
                return Err(format!(
                    "OnedriveAPP HTTP {status}: {}",
                    truncate(&text, 300)
                ));
            }
            return Ok(v);
        }
        Err("OnedriveAPP 认证失败".into())
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.client_id.is_empty() || self.client_secret.is_empty() {
            return Err("OnedriveAPP 需要 client_id / client_secret".into());
        }
        if self.email.is_empty() {
            return Err("OnedriveAPP 需要用户邮箱 email".into());
        }
        self.access_token().await?;
        let url = format!("{}/children?$top=1", self.meta_url(&self.root_path));
        let _ = self.request("GET", &url, None).await?;
        Ok(())
    }

    fn abs_path(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" || fid == "root" {
            self.root_path.clone()
        } else if fid.starts_with('/') {
            fid.to_string()
        } else {
            let root = self.root_path.trim_end_matches('/');
            if root.is_empty() || root == "/" {
                format!("/{fid}")
            } else {
                format!("{root}/{fid}")
            }
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let path = self.abs_path(parent_fid);
        let mut out = Vec::new();
        let mut next = format!(
            "{}/children?$top=1000&$select=id,name,size,lastModifiedDateTime,file,@microsoft.graph.downloadUrl,folder,parentReference",
            self.meta_url(&path)
        );
        while !next.is_empty() {
            let v = self.request("GET", &next, None).await?;
            let values = v
                .get("value")
                .and_then(|x| x.as_array())
                .cloned()
                .unwrap_or_default();
            for f in values {
                let name = f
                    .get("name")
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
                    .to_string();
                if name.is_empty() {
                    continue;
                }
                let is_dir = f.get("folder").is_some();
                let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                let child_path = if path == "/" || path.is_empty() {
                    format!("/{name}")
                } else {
                    format!("{}/{}", path.trim_end_matches('/'), name)
                };
                let id = f
                    .get("id")
                    .and_then(|i| i.as_str())
                    .unwrap_or("")
                    .to_string();
                out.push(Entry {
                    fid: child_path.clone(),
                    name,
                    size: if is_dir { 0 } else { size },
                    is_dir,
                    updated_at: None,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: Some(json!({ "id": id, "path": child_path })),
                });
            }
            next = v
                .get("@odata.nextLink")
                .and_then(|l| l.as_str())
                .unwrap_or("")
                .to_string();
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let path = self.abs_path(&e.fid);
        let url = self.meta_url(&path);
        let v = self.request("GET", &url, None).await?;
        let mut link = v
            .get("@microsoft.graph.downloadUrl")
            .or_else(|| v.get("@content.downloadUrl"))
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if link.is_empty() {
            return Err("OnedriveAPP 未返回下载链接".into());
        }
        if !self.custom_host.is_empty() {
            if let Ok(u) = url::Url::parse(&link) {
                if let Some(h) = u.host_str() {
                    link = link.replacen(h, &self.custom_host, 1);
                }
            }
        }
        Ok(DownloadInfo {
            url: link,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let path = self.abs_path(parent_fid);
        let url = format!("{}/children", self.meta_url(&path));
        self.request(
            "POST",
            &url,
            Some(json!({
                "name": name,
                "folder": {},
                "@microsoft.graph.conflictBehavior": "rename"
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let path = self.abs_path(&e.fid);
        let url = self.meta_url(&path);
        self.request("PATCH", &url, Some(json!({ "name": new_name })))
            .await?;
        Ok(())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let path = self.abs_path(&e.fid);
        let dst = self.abs_path(dst_dir_fid);
        let url = self.meta_url(&path);
        let parent_ref = if dst == "/" || dst.is_empty() {
            json!({ "path": "/drive/root" })
        } else {
            json!({ "path": format!("/drive/root:{}:", dst) })
        };
        self.request(
            "PATCH",
            &url,
            Some(json!({ "parentReference": parent_ref })),
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
        let path = self.abs_path(&e.fid);
        let dst = self.abs_path(dst_dir_fid);
        let url = format!("{}/copy", self.meta_url(&path));
        let parent_ref = if dst == "/" || dst.is_empty() {
            json!({ "path": "/drive/root" })
        } else {
            json!({ "path": format!("/drive/root:{}:", dst) })
        };
        self.request(
            "POST",
            &url,
            Some(json!({ "parentReference": parent_ref, "name": e.name })),
        )
        .await?;
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let path = self.abs_path(&e.fid);
        let url = self.meta_url(&path);
        self.request("DELETE", &url, None).await?;
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let path = self.abs_path(dst_dir_fid);
        let file_path = if path == "/" || path.is_empty() {
            format!("/{}", input.name)
        } else {
            format!("{}/{}", path.trim_end_matches('/'), input.name)
        };
        let mut buf = Vec::new();
        let mut tmp = vec![0u8; 64 * 1024];
        loop {
            let n = input
                .reader
                .read(&mut tmp)
                .await
                .map_err(|e| format!("读流: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        let url = format!("{}/content", self.meta_url(&file_path));
        let token = self.ensure_token().await?;
        let resp = self
            .http
            .put(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/octet-stream")
            .body(buf)
            .send()
            .await
            .map_err(|e| format!("OnedriveAPP 上传: {e}"))?;
        let st = resp.status().as_u16();
        if !(200..300).contains(&st) {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "OnedriveAPP 上传失败 ({st}): {}",
                truncate(&text, 300)
            ));
        }
        Ok(())
    }
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'@' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n])
    }
}
