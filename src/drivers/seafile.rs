//! Seafile 驱动（对齐 Go 版 drivers/seafile）
//!
//! - 地址 + Token（优先）或账号密码登录 /api2/auth-token/
//! - repoId 配置了则根目录 = 该资料库内 root_path；否则根目录 = 资料库列表
//! - Entry.fid 编码为 "{repoId}:{path}"（repoId 为 uuid 不含冒号），根目录 fid = "/"

use super::{DownloadInfo, PutInput};
use crate::config::{Credential, Entry, Store};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

pub struct Seafile {
    account_id: String,
    address: String,
    http: Client,
    username: String,
    password: String,
    token: Mutex<String>,
    repo_id: String,
    repo_pwd: String,
    root_path: String,
    store: Arc<Store>,
}

impl Seafile {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: &str,
        address: String,
        username: String,
        password: String,
        token: String,
        repo_id: String,
        repo_pwd: String,
        root_path: String,
        store: Arc<Store>,
    ) -> Self {
        let address = address.trim().trim_end_matches('/').to_string();
        Seafile {
            account_id: account_id.to_string(),
            address,
            http: Client::new(),
            username,
            password,
            token: Mutex::new(token),
            repo_id,
            repo_pwd,
            root_path: if root_path.trim().is_empty() {
                "/".to_string()
            } else {
                root_path.trim().to_string()
            },
            store,
        }
    }

    fn save_token(&self, token: &str) {
        *self.token.lock().unwrap() = token.to_string();
        let t = token.to_string();
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Seafile { token, .. } = cred {
                *token = t.clone();
            }
        });
    }

    /// Token 优先；否则账号密码换 Token
    async fn get_token(&self) -> Result<String, String> {
        let cur = self.token.lock().unwrap().clone();
        if !cur.is_empty() {
            return Ok(cur);
        }
        if self.username.is_empty() {
            return Err("Seafile 需要 token 或账号密码".into());
        }
        let url = format!("{}/api2/auth-token/", self.address);
        let resp = self
            .http
            .post(&url)
            .form(&[("username", self.username.as_str()), ("password", self.password.as_str())])
            .send()
            .await
            .map_err(|e| format!("Seafile 登录请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status >= 400 {
            return Err(format!("Seafile 获取 token 失败 ({status}): {}", truncate(&text, 200)));
        }
        let v: Value = serde_json::from_str(&text).map_err(|e| format!("Seafile 响应解析失败: {e}"))?;
        let token = v
            .get("token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err("Seafile 登录未返回 token".into());
        }
        self.save_token(&token);
        Ok(token)
    }

    pub async fn validate(&self) -> Result<(), String> {
        let auth = self.get_token().await?;
        // 探活：repoId 配置了则校验资料库；否则拉资料库列表
        if !self.repo_id.is_empty() {
            let url = format!("{}/api2/repos/{}/", self.address, self.repo_id);
            let resp = self
                .http
                .get(&url)
                .header("Authorization", format!("Token {auth}"))
                .send()
                .await
                .map_err(|e| format!("Seafile 请求失败: {e}"))?;
            if resp.status().as_u16() >= 400 {
                return Err(format!("Seafile 资料库 {} 不存在或无权限", self.repo_id));
            }
        } else {
            let url = format!("{}/api2/repos/", self.address);
            let resp = self
                .http
                .get(&url)
                .header("Authorization", format!("Token {auth}"))
                .send()
                .await
                .map_err(|e| format!("Seafile 请求失败: {e}"))?;
            if resp.status().as_u16() >= 400 {
                return Err(format!("Seafile 连接失败 ({})", resp.status().as_u16()));
            }
        }
        Ok(())
    }

    /// 带授权请求；401 时重新获取 token 重试一次
    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        query: Option<Vec<(String, String)>>,
        form: Option<Vec<(String, String)>>,
    ) -> Result<(u16, String), String> {
        let auth = self.get_token().await?;
        let url = if path.starts_with("http") {
            path.to_string()
        } else {
            format!("{}{path}", self.address)
        };
        let send = |token: String| {
            let mut req = self
                .http
                .request(method.clone(), &url)
                .header("Authorization", format!("Token {token}"));
            if let Some(q) = &query {
                req = req.query(q);
            }
            if let Some(f) = &form {
                req = req.form(f);
            }
            req
        };
        let resp = send(auth)
            .send()
            .await
            .map_err(|e| format!("Seafile 请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        if status == 401 {
            // token 失效：清空后重取并重试一次
            self.save_token("");
            let auth = self.get_token().await?;
            let resp = send(auth)
                .send()
                .await
                .map_err(|e| format!("Seafile 请求失败: {e}"))?;
            let status2 = resp.status().as_u16();
            let text2 = resp.text().await.unwrap_or_default();
            return Ok((status2, text2));
        }
        Ok((status, text))
    }

    /// 解析 fid → (repo_id, path)；根目录时按配置推导
    fn parse_fid(&self, fid: &str) -> (String, String) {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            // 根：repoId 配置了则直接落在该库 root_path；否则表示"资料库列表层"
            if !self.repo_id.is_empty() {
                return (self.repo_id.clone(), self.root_path.clone());
            }
            return (String::new(), "/".to_string());
        }
        match fid.split_once(':') {
            Some((repo, path)) => (repo.to_string(), path.to_string()),
            None => (fid.to_string(), "/".to_string()),
        }
    }

    fn make_fid(repo: &str, path: &str) -> String {
        format!("{repo}:{path}")
    }

    /// 加密资料库解密（对齐 Go 版 decryptLibrary）
    async fn decrypt_library(&self, repo_id: &str) -> Result<(), String> {
        // 拉库信息判断是否加密
        let (status, text) = self
            .request(
                reqwest::Method::GET,
                &format!("/api2/repos/{repo_id}/"),
                None,
                None,
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 资料库 {repo_id} 信息获取失败 ({status})"));
        }
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let encrypted = v.get("encrypted").and_then(|b| b.as_bool()).unwrap_or(false);
        if !encrypted {
            return Ok(());
        }
        if self.repo_pwd.is_empty() {
            return Err("资料库已加密，请在配置中填写 repo_pwd".into());
        }
        let (status, text) = self
            .request(
                reqwest::Method::POST,
                &format!("/api2/repos/{repo_id}/"),
                None,
                Some(vec![("password".into(), self.repo_pwd.clone())]),
            )
            .await?;
        if status >= 400 || !text.contains("success") {
            return Err("资料库密码不正确".into());
        }
        Ok(())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let (repo, path) = self.parse_fid(parent_fid);
        // 根目录且未配置 repoId：列出资料库
        if repo.is_empty() {
            let (status, text) = self
                .request(reqwest::Method::GET, "/api2/repos/", None, None)
                .await?;
            if status >= 400 {
                return Err(format!("Seafile 资料库列表失败 ({status})"));
            }
            let arr: Value = serde_json::from_str(&text).map_err(|e| format!("解析失败: {e}"))?;
            let mut out = Vec::new();
            if let Some(items) = arr.as_array() {
                for f in items {
                    let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                    let id = f.get("id").and_then(|i| i.as_str()).unwrap_or("").to_string();
                    if name.is_empty() || id.is_empty() {
                        continue;
                    }
                    out.push(Entry {
                        fid: Self::make_fid(&id, "/"),
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
            return Ok(out);
        }

        // 进入具体资料库：加密库先解密
        self.decrypt_library(&repo).await?;

        // dir 查询路径：配置了 repoId 且在根层时用 root_path；否则用 fid 里的 path
        let query_path = if path == "/" && !self.repo_id.is_empty() && repo == self.repo_id {
            self.root_path.clone()
        } else {
            path.clone()
        };
        let (status, text) = self
            .request(
                reqwest::Method::GET,
                &format!("/api2/repos/{repo}/dir/"),
                Some(vec![("p".into(), query_path)]),
                None,
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 列表失败 ({status}): {}", truncate(&text, 200)));
        }
        let arr: Value = serde_json::from_str(&text).map_err(|e| format!("解析失败: {e}"))?;
        let base = if path == "/" { "" } else { path.trim_end_matches('/') };
        let mut out = Vec::new();
        if let Some(items) = arr.as_array() {
            for f in items {
                let name = f.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                if name.is_empty() {
                    continue;
                }
                let typ = f.get("type").and_then(|t| t.as_str()).unwrap_or("file");
                let is_dir = typ == "dir";
                let size = f.get("size").and_then(|s| s.as_u64()).unwrap_or(0);
                let mtime = f.get("mtime").and_then(|m| m.as_i64()).map(|s| s * 1000);
                let item_path = if base.is_empty() {
                    format!("/{name}")
                } else {
                    format!("{base}/{name}")
                };
                out.push(Entry {
                    fid: Self::make_fid(&repo, &item_path),
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
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let (repo, path) = self.parse_fid(&e.fid);
        let (status, text) = self
            .request(
                reqwest::Method::GET,
                &format!("/api2/repos/{repo}/file/"),
                Some(vec![
                    ("p".into(), path),
                    ("reuse".into(), "1".into()),
                ]),
                None,
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 获取下载链接失败 ({status})"));
        }
        let url = text.trim().trim_matches('"').to_string();
        if url.is_empty() {
            return Err("Seafile 未返回下载链接".into());
        }
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let (repo, path) = self.parse_fid(parent_fid);
        if repo.is_empty() {
            return Err("请在资料库内创建文件夹".into());
        }
        let dir_path = join_path(&path, name.trim_matches('/'));
        let (status, text) = self
            .request(
                reqwest::Method::POST,
                &format!("/api2/repos/{repo}/dir/"),
                Some(vec![("p".into(), dir_path)]),
                Some(vec![("operation".into(), "mkdir".into())]),
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 创建文件夹失败 ({status}): {}", truncate(&text, 200)));
        }
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let (repo, path) = self.parse_fid(&e.fid);
        let (status, text) = self
            .request(
                reqwest::Method::POST,
                &format!("/api2/repos/{repo}/file/"),
                Some(vec![("p".into(), path)]),
                Some(vec![
                    ("operation".into(), "rename".into()),
                    ("newname".into(), new_name.into()),
                ]),
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 重命名失败 ({status}): {}", truncate(&text, 200)));
        }
        Ok(())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let (repo, path) = self.parse_fid(&e.fid);
        let (dst_repo, dst_path) = self.parse_fid(dst_dir_fid);
        let (status, text) = self
            .request(
                reqwest::Method::POST,
                &format!("/api2/repos/{repo}/file/"),
                Some(vec![("p".into(), path)]),
                Some(vec![
                    ("operation".into(), "move".into()),
                    ("dst_repo".into(), dst_repo),
                    ("dst_dir".into(), dst_path),
                ]),
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 移动失败 ({status}): {}", truncate(&text, 200)));
        }
        Ok(())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let (repo, path) = self.parse_fid(&e.fid);
        let (dst_repo, dst_path) = self.parse_fid(dst_dir_fid);
        let (status, text) = self
            .request(
                reqwest::Method::POST,
                &format!("/api2/repos/{repo}/file/"),
                Some(vec![("p".into(), path)]),
                Some(vec![
                    ("operation".into(), "copy".into()),
                    ("dst_repo".into(), dst_repo),
                    ("dst_dir".into(), dst_path),
                ]),
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 复制失败 ({status}): {}", truncate(&text, 200)));
        }
        Ok(())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let (repo, path) = self.parse_fid(&e.fid);
        let (status, text) = self
            .request(
                reqwest::Method::DELETE,
                &format!("/api2/repos/{repo}/file/"),
                Some(vec![("p".into(), path)]),
                None,
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 删除失败 ({status}): {}", truncate(&text, 200)));
        }
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let (repo, path) = self.parse_fid(dst_dir_fid);
        if repo.is_empty() {
            return Err("请上传到具体资料库内".into());
        }
        // 1. 取 upload-link
        let (status, text) = self
            .request(
                reqwest::Method::GET,
                &format!("/api2/repos/{repo}/upload-link/"),
                Some(vec![("p".into(), path.clone())]),
                None,
            )
            .await?;
        if status >= 400 {
            return Err(format!("Seafile 获取上传链接失败 ({status})"));
        }
        let upload_link = text.trim().trim_matches('"').to_string();

        // 2. 缓冲后 multipart 上传（对齐 Go 版 SetFileReader）
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
        let part = reqwest::multipart::Part::bytes(buf).file_name(input.name.clone());
        let form = reqwest::multipart::Form::new()
            .text("parent_dir", path)
            .text("replace", "1")
            .part("file", part);
        let resp = self
            .http
            .post(&upload_link)
            .header(
                "Authorization",
                format!("Token {}", self.get_token().await?),
            )
            .multipart(form)
            .send()
            .await
            .map_err(|e| format!("Seafile 上传失败: {e}"))?;
        let status = resp.status().as_u16();
        if status >= 400 {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!("Seafile 上传失败 ({status}): {}", truncate(&text, 200)));
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

fn join_path(base: &str, sub: &str) -> String {
    let base = base.trim_end_matches('/');
    let sub = sub.trim_matches('/');
    if sub.is_empty() {
        if base.is_empty() {
            "/".to_string()
        } else {
            base.to_string()
        }
    } else if base.is_empty() {
        format!("/{sub}")
    } else {
        format!("{base}/{sub}")
    }
}
