//! OneDrive / SharePoint 驱动（对齐 Go 版 drivers/onedrive，浏览/下载/写操作）
//!
//! - 授权：refresh_token 刷新 access_token（默认走 olist 在线刷新 API，
//!   对齐本仓库 aliyundrive_open / baidu_netdisk 的做法，不存 client_id/secret）
//! - 寻址：fid 即网盘内路径（对齐 Go 版按 path 寻址），根目录 = root_path（默认 /）
//! - 列目录：GET /v1.0/{me|sites/{siteId}}/drive/root:/path:/children
//!   （$top=1000，@odata.nextLink 翻页）
//! - 下载：GET 文件元数据取 @microsoft.graph.downloadUrl（预鉴权直链，无需附加头）
//! - 写操作：/children 建目录、PATCH 移动/重命名、/copy 复制、DELETE 删除；
//!   上传：≤4MB PUT /content 直传，更大走 createUploadSession + Content-Range 分片 PUT
//! - region：global / cn / us / de（对齐 Go 版 onedriveHostMap）

use super::DownloadInfo;
use super::aliyundrive_open::iso_to_ms;
use crate::config::{Credential, Entry, Store};
use reqwest::{Client, Method};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

/// 对齐 Go 版默认在线刷新 API
const ONLINE_REFRESH_API: &str = "https://api.oplist.org/onedrive/renewapi";
/// children 列表查询参数（对齐 Go 版 getFiles）
const CHILDREN_QUERY: &str =
    "?$top=1000&$expand=thumbnails($select=medium)&$select=id,name,size,fileSystemInfo,content.downloadUrl,file,parentReference";
/// access_token 失效错误码（对齐 Go 版 Request 的 InvalidAuthenticationToken 重试）
const TOKEN_EXPIRED_CODE: &str = "InvalidAuthenticationToken";
/// 简单上传（PUT /content）大小上限（对齐 Go 版 upSmall 阈值 4MB）
const SMALL_UPLOAD_LIMIT: u64 = 4 * 1024 * 1024;
/// 分片上传块大小（对齐 Go 版默认 ChunkSize 5MB）
const UPLOAD_CHUNK_SIZE: u64 = 5 * 1024 * 1024;

pub struct Onedrive {
    account_id: String,
    http: Client,
    region: String,
    is_sharepoint: bool,
    site_id: String,
    root_path: String,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    store: Arc<Store>,
}

/// region -> (oauth host, graph api host)，对齐 Go 版 onedriveHostMap
fn host_of(region: &str) -> (&'static str, &'static str) {
    match region {
        "cn" => (
            "https://login.chinacloudapi.cn",
            "https://microsoftgraph.chinacloudapi.cn",
        ),
        "us" => (
            "https://login.microsoftonline.us",
            "https://graph.microsoft.us",
        ),
        "de" => (
            "https://login.microsoftonline.de",
            "https://graph.microsoft.de",
        ),
        // 默认 global
        _ => (
            "https://login.microsoftonline.com",
            "https://graph.microsoft.com",
        ),
    }
}

/// 构造参数（避免 8 参构造函数触发 clippy::too_many_arguments）
pub struct OnedriveConfig {
    pub region: String,
    pub is_sharepoint: bool,
    pub site_id: String,
    pub root_path: String,
    pub refresh_token: String,
    pub access_token: String,
}

impl Onedrive {
    pub fn new(account_id: &str, cfg: OnedriveConfig, store: Arc<Store>) -> Self {
        Onedrive {
            account_id: account_id.to_string(),
            http: Client::new(),
            region: cfg.region,
            is_sharepoint: cfg.is_sharepoint,
            site_id: cfg.site_id,
            root_path: cfg.root_path,
            refresh_token: Mutex::new(cfg.refresh_token),
            access_token: Mutex::new(cfg.access_token),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Onedrive {
                refresh_token,
                access_token,
                ..
            } = cred
            {
                *refresh_token = r.clone();
                *access_token = a.clone();
            }
        });
    }

    fn access_token(&self) -> String {
        self.access_token.lock().unwrap().clone()
    }

    /// 对齐 Go 版 refreshToken()：olist 在线 API 刷新
    async fn refresh_token(&self) -> Result<(), String> {
        let cur = self.refresh_token.lock().unwrap().clone();
        let url = format!(
            "{}?refresh_ui={}&server_use=true&driver_txt=onedrive_pr",
            ONLINE_REFRESH_API,
            urlencode(&cur)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("刷新 OneDrive token 失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("刷新响应解析失败: {e}"))?;
        let refresh = v
            .get("refresh_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        let access = v
            .get("access_token")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if refresh.is_empty() || access.is_empty() {
            let msg = v
                .get("text")
                .and_then(|x| x.as_str())
                .unwrap_or("在线 API 返回空 token，refresh_token 可能已失效");
            return Err(format!("刷新 OneDrive token 失败: {msg}"));
        }
        self.save_tokens(&refresh, &access);
        Ok(())
    }

    /// 对齐 Go 版 GetMetaUrl(false, path)：按 region + 是否 SharePoint 生成元数据 URL，
    /// path 为 "/" 时返回 drive root 本身，否则返回 root:/path: 形式
    fn meta_url(&self, path: &str) -> String {
        let (_, api) = host_of(&self.region);
        let p = encode_path(path);
        let base = if self.is_sharepoint {
            format!("{api}/v1.0/sites/{}/drive/root", self.site_id)
        } else {
            format!("{api}/v1.0/me/drive/root")
        };
        if p.is_empty() || p == "/" {
            base
        } else {
            format!("{base}:{p}:")
        }
    }

    /// 对齐 Go 版 Request()：InvalidAuthenticationToken 自动刷新重试一次
    async fn request(&self, method: Method, url: &str, retried: bool) -> Result<Value, String> {
        let resp = self
            .http
            .request(method, url)
            .header("Authorization", format!("Bearer {}", self.access_token()))
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        let code = v
            .pointer("/error/code")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        if !code.is_empty() {
            if code == TOKEN_EXPIRED_CODE && !retried {
                self.refresh_token().await?;
                return Box::pin(self.request(Method::GET, url, true)).await;
            }
            let msg = v
                .pointer("/error/message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("OneDrive 接口错误({code}): {msg}"));
        }
        if status.as_u16() >= 400 {
            return Err(format!("OneDrive 接口 HTTP {status}"));
        }
        Ok(v)
    }

    /// 对齐 Go 版 Init()：刷新 token 并验证（取 drive 信息）
    pub async fn validate(&self) -> Result<(), String> {
        if self.is_sharepoint && self.site_id.is_empty() {
            return Err("SharePoint 模式需要填写 site_id".into());
        }
        if self.access_token().is_empty() {
            self.refresh_token().await?;
        }
        let (_, api) = host_of(&self.region);
        let url = if self.is_sharepoint {
            format!("{api}/v1.0/sites/{}/drive", self.site_id)
        } else {
            format!("{api}/v1.0/me/drive")
        };
        self.request(Method::GET, &url, false).await?;
        Ok(())
    }

    /// 对齐 Go 版 getFiles()：children 接口 + @odata.nextLink 翻页，
    /// Entry.fid = 网盘内完整路径（父路径 + 名称）
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        // 根目录 = root_path（对齐 Go 版 DefaultRoot "/" + RootFolderPath）；
        // 旧配置里可能存了兜底值 "0"
        let dir: String = match parent_fid {
            "" | "0" => self.root_path.clone(),
            other => other.to_string(),
        };
        let mut files = Vec::new();
        // 首个 URL 由路径构造，后续直接使用服务端返回的 nextLink（绝对地址）
        let mut next_link = format!("{}{CHILDREN_QUERY}", self.meta_url(&dir));
        loop {
            let resp = self.request(Method::GET, &next_link, false).await?;
            let items = resp
                .get("value")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &items {
                let name = f
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let updated_at = f
                    .pointer("/fileSystemInfo/lastModifiedDateTime")
                    .and_then(|v| v.as_str())
                    .and_then(iso_to_ms);
                files.push(Entry {
                    fid: join_path(&dir, &name),
                    name,
                    size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    // 对齐 Go 版 fileToObj：File 字段存在为文件，否则为文件夹
                    is_dir: f.get("file").is_none(),
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            next_link = resp
                .get("@odata.nextLink")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if next_link.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    /// 对齐 Go 版 Link()：取文件元数据中的 @microsoft.graph.downloadUrl
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let f = self
            .request(Method::GET, &self.meta_url(&e.fid), false)
            .await?;
        if f.get("file").is_none() {
            return Err("目标不是文件，无法下载".into());
        }
        let url = f
            .get("@microsoft.graph.downloadUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("OneDrive 未返回下载直链".into());
        }
        // downloadUrl 为预鉴权直链，浏览器可直接访问
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Move/Rename/Copy/Remove/Put） ----------

    /// 目录 fid 归一化：""/"0" -> root_path（对齐 list()）
    fn normalize_dir(&self, fid: &str) -> String {
        match fid {
            "" | "0" => self.root_path.clone(),
            other => other.to_string(),
        }
    }

    /// 通用写请求：带 Authorization 与 JSON 体，InvalidAuthenticationToken/401
    /// 自动刷新重试一次（对齐 Go 版 Request()），返回解析后的响应体（空响应为 Null）
    async fn request_write(
        &self,
        method: Method,
        url: &str,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {}", self.access_token()));
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("读取响应失败: {e}"))?;
        let v: Value = if text.trim().is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text)
                .map_err(|e| format!("响应解析失败: {e}: {}", trunc200(&text)))?
        };
        let code = v
            .pointer("/error/code")
            .and_then(|c| c.as_str())
            .unwrap_or("")
            .to_string();
        if !code.is_empty() {
            if code == TOKEN_EXPIRED_CODE && !retried {
                self.refresh_token().await?;
                return Box::pin(self.request_write(method, url, body, true)).await;
            }
            let msg = v
                .pointer("/error/message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("OneDrive 接口错误({code}): {msg}"));
        }
        if status == 401 && !retried {
            self.refresh_token().await?;
            return Box::pin(self.request_write(method, url, body, true)).await;
        }
        if status >= 400 {
            return Err(format!("OneDrive 接口 HTTP {status}"));
        }
        Ok(v)
    }

    /// 对齐 MakeDir：POST {parent}/children，同名自动重命名
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("目录名为空".into());
        }
        let dir = self.normalize_dir(parent_fid);
        let url = format!("{}/children", self.meta_url(&dir));
        let data = json!({
            "name": name,
            "folder": {},
            "@microsoft.graph.conflictBehavior": "rename",
        });
        self.request_write(Method::POST, &url, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Move：PATCH src，parentReference 指向目标目录。
    /// Go 版用内存中的目录 id；本实现按路径寻址，先 GET 目标目录元数据取 id
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let dst_dir = self.normalize_dir(dst_dir_fid);
        let dst = self
            .request(Method::GET, &self.meta_url(&dst_dir), false)
            .await?;
        let dst_id = dst
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if dst_id.is_empty() {
            return Err("OneDrive 未获取到目标目录 id".into());
        }
        let data = json!({
            "parentReference": { "id": dst_id, "path": "" },
            "name": e.name,
        });
        let url = self.meta_url(&e.fid);
        self.request_write(Method::PATCH, &url, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Rename：PATCH src，body 为 {parentReference:{id}, name}。
    /// Go 版取条目 ParentID；本实现按路径寻址，先 GET 父目录元数据取 id
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("新名称为空".into());
        }
        let parent = self.normalize_dir(parent_fid);
        let meta = self
            .request(Method::GET, &self.meta_url(&parent), false)
            .await?;
        let mut pid = meta
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if pid.is_empty() {
            // 对齐 Go 版：parentID 为空时回退 "root"
            pid = "root".to_string();
        }
        let data = json!({
            "parentReference": { "id": pid },
            "name": new_name,
        });
        let url = self.meta_url(&e.fid);
        self.request_write(Method::PATCH, &url, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Copy：POST src/copy，parentReference 带 driveId + 目标目录 id（异步操作）
    pub async fn copy(&self, _parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let dst_dir = self.normalize_dir(dst_dir_fid);
        let dst = self
            .request(Method::GET, &self.meta_url(&dst_dir), false)
            .await?;
        let dst_id = dst
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if dst_id.is_empty() {
            return Err("OneDrive 未获取到目标目录 id".into());
        }
        let drive_id = dst
            .pointer("/parentReference/driveId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let data = json!({
            "parentReference": { "driveId": drive_id, "id": dst_id },
            "name": e.name,
        });
        let url = format!("{}/copy", self.meta_url(&e.fid));
        self.request_write(Method::POST, &url, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Remove：DELETE src
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let url = self.meta_url(&e.fid);
        self.request_write(Method::DELETE, &url, None, false).await?;
        Ok(())
    }

    /// 对齐 Put：≤4MB PUT /content 直传；更大走 createUploadSession + 分片 PUT。
    /// reader 只能读一次：小文件读入内存（可重试），大文件/未知大小先落临时文件
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let dir = self.normalize_dir(dst_dir_fid);
        let filepath = join_path(&dir, &input.name);
        if input.size > 0 && input.size <= SMALL_UPLOAD_LIMIT {
            // 小文件：整读入内存后直传（对齐 Go upSmall）
            let data = read_exact_n(input.reader, input.size).await?;
            self.put_small(&filepath, data).await
        } else {
            // 大文件或未知大小：先落临时文件（finally 删除），再分片上传（对齐 Go upBig）
            let tmp_path = temp_file_path();
            let _guard = TempFileGuard(tmp_path.clone());
            let size = spool_to_temp(input.reader, &tmp_path).await?;
            self.put_big(&filepath, &tmp_path, size).await
        }
    }

    /// 对齐 upSmall：PUT {item}/content，body 为文件内容
    async fn put_small(&self, filepath: &str, data: Vec<u8>) -> Result<(), String> {
        let url = format!("{}/content", self.meta_url(filepath));
        let mut last_err = String::new();
        for attempt in 0..2 {
            if attempt > 0 {
                // 对齐 Go Request()：token 失效刷新后重试一次
                self.refresh_token().await?;
            }
            let resp = self
                .http
                .put(&url)
                .header("Authorization", format!("Bearer {}", self.access_token()))
                .body(data.clone())
                .send()
                .await
                .map_err(|e| format!("OneDrive 上传失败: {e}"))?;
            let status = resp.status().as_u16();
            if (200..300).contains(&status) {
                return Ok(());
            }
            let text = resp.text().await.unwrap_or_default();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                let code = v
                    .pointer("/error/code")
                    .and_then(|c| c.as_str())
                    .unwrap_or("")
                    .to_string();
                if code == TOKEN_EXPIRED_CODE && attempt == 0 {
                    last_err = format!("OneDrive 上传返回 {code}");
                    continue;
                }
                if !code.is_empty() {
                    let msg = v
                        .pointer("/error/message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown");
                    return Err(format!("OneDrive 上传失败({code}): {msg}"));
                }
            }
            last_err = format!(
                "OneDrive 上传返回 HTTP {status}: {}",
                trunc200(&text)
            );
            // 非 token 错误不再重试
            break;
        }
        Err(last_err)
    }

    /// 对齐 upBig：createUploadSession 取 uploadUrl，按 5MB 分片带 Content-Range PUT。
    /// 上传 URL 为预鉴权直链，无需 Authorization；200/201/202 成功，500-504 重试
    async fn put_big(&self, filepath: &str, tmp_path: &Path, size: u64) -> Result<(), String> {
        // 空文件：退化为直传空内容（createUploadSession 空传不会真正建文件）
        if size == 0 {
            return self.put_small(filepath, Vec::new()).await;
        }
        // 创建上传会话
        // 注：Go 版会附带 fileSystemInfo 时间戳（取自上传流的元数据），本实现的
        // PutInput 无时间信息，省略该字段避免覆盖云端 mtime
        let url = format!("{}/createUploadSession", self.meta_url(filepath));
        let v = self
            .request_write(Method::POST, &url, Some(json!({ "item": {} })), false)
            .await?;
        let upload_url = v
            .get("uploadUrl")
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .to_string();
        if upload_url.is_empty() {
            return Err("OneDrive 未返回 uploadUrl".into());
        }
        // 分片上传（对齐 Go：Content-Range bytes {start}-{end}/{total}，重试 3 次）
        let mut finish: u64 = 0;
        while finish < size {
            let byte_size = std::cmp::min(size - finish, UPLOAD_CHUNK_SIZE);
            let range = format!(
                "bytes {}-{}/{}",
                finish,
                finish + byte_size - 1,
                size
            );
            let mut last_err = String::new();
            let mut ok = false;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                let data = match read_temp_part(tmp_path, finish, byte_size).await {
                    Ok(d) => d,
                    Err(e) => {
                        last_err = e;
                        continue;
                    }
                };
                match self
                    .http
                    .put(&upload_url)
                    .header("Content-Range", &range)
                    .body(data)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if (200..300).contains(&status) {
                            ok = true;
                            break;
                        }
                        let text = resp.text().await.unwrap_or_default();
                        if (500..=504).contains(&status) {
                            // 对齐 Go：服务端错误重试
                            last_err = format!("OneDrive 分片上传服务端错误: {status}");
                            continue;
                        }
                        last_err = format!(
                            "OneDrive 分片上传返回 HTTP {status}: {}",
                            trunc200(&text)
                        );
                    }
                    Err(e) => last_err = format!("OneDrive 分片上传失败: {e}"),
                }
            }
            if !ok {
                return Err(last_err);
            }
            finish += byte_size;
        }
        Ok(())
    }
}

/// 拼接子路径（fid = 网盘内路径）
fn join_path(dir: &str, name: &str) -> String {
    if dir.is_empty() || dir == "/" {
        format!("/{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// 对齐 Go 版 utils.EncodePath：按路径段做百分号编码（保留 "/"）
fn encode_path(p: &str) -> String {
    p.split('/')
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

/// 错误信息里附带的原始响应片段（按字符截断，避免 UTF-8 边界 panic）
fn trunc200(s: &str) -> String {
    s.chars().take(200).collect()
}

// ---------- 上传辅助：临时文件落盘 / 分片读取 ----------

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-onedrive-{}", Uuid::new_v4()))
}

/// 把上传流落到临时文件并返回实际大小
async fn spool_to_temp(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    path: &Path,
) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("OneDrive 创建临时文件失败: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("OneDrive 读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("OneDrive 写入临时文件失败: {e}"))?;
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("OneDrive 临时文件落盘失败: {e}"))?;
    Ok(total)
}

/// 从临时文件读取 [offset, offset+len) 分片
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("OneDrive 打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("OneDrive 定位临时文件失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    if len > 0 {
        f.read_exact(&mut buf)
            .await
            .map_err(|e| format!("OneDrive 读取临时文件分片失败: {e}"))?;
    }
    Ok(buf)
}

/// 从上传流精确读取 n 字节（小文件内存直传用）
async fn read_exact_n(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    n: u64,
) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n as usize];
    reader
        .read_exact(&mut buf)
        .await
        .map_err(|e| format!("OneDrive 读取上传流失败: {e}"))?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::{encode_path, join_path};

    #[test]
    fn test_encode_path() {
        assert_eq!(encode_path("/"), "/");
        assert_eq!(encode_path("/a/b/c.txt"), "/a/b/c.txt");
        // 空格、#、% 需要编码，"/" 保留
        assert_eq!(encode_path("/my docs/a#b%.mp4"), "/my%20docs/a%23b%25.mp4");
        assert_eq!(encode_path("/中文/名.txt"), "/%E4%B8%AD%E6%96%87/%E5%90%8D.txt");
    }

    #[test]
    fn test_join_path() {
        assert_eq!(join_path("/", "a.txt"), "/a.txt");
        assert_eq!(join_path("/docs", "a.txt"), "/docs/a.txt");
    }
}
