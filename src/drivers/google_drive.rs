//! Google Drive 驱动（对齐 Go 版 drivers/google_drive，浏览/下载/写操作）
//!
//! - 授权：refresh_token 刷新 access_token（走 olist 在线刷新 API，
//!   对齐本仓库 aliyundrive_open / baidu_netdisk 的做法；Go 版的服务账号
//!   JSON 文件模式不适用本场景，未实现）
//! - 列目录：GET /drive/v3/files?q='parentID' in parents and trashed = false
//!   （pageSize=1000，pageToken 翻页，orderBy 对齐 Go 版默认值；
//!   文件快捷方式回源取目标文件大小等信息）
//! - 下载：GET /drive/v3/files/{id}?alt=media（需 Bearer 头，
//!   Go 版 OnlyProxy，仅支持服务器代理中转）
//! - 写操作：POST /drive/v3/files 建目录、PATCH 改名/移动、DELETE 删除
//!   （Go 版 Copy 返回 NotSupport）；上传走 resumable session：
//!   POST /upload/drive/v3/files?uploadType=resumable 取 Location，
//!   <5MB 单请求 PUT，否则按 5MB 分片带 Content-Range PUT

use super::aliyundrive_open::iso_to_ms;
use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use reqwest::{Client, Method};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const API: &str = "https://www.googleapis.com";
/// 对齐 Go 版默认在线刷新 API
const ONLINE_REFRESH_API: &str = "https://api.oplist.org/googleui/renewapi";
/// 对齐 Go 版 FilesListFields
const FILES_LIST_FIELDS: &str = "files(id,name,mimeType,size,modifiedTime,createdTime,thumbnailLink,shortcutDetails,md5Checksum,sha1Checksum,sha256Checksum),nextPageToken";
/// 对齐 Go 版 FileInfoFields（快捷方式回源用）
const FILE_INFO_FIELDS: &str = "id,name,mimeType,size,md5Checksum,sha1Checksum,sha256Checksum";
const FOLDER_MIME: &str = "application/vnd.google-apps.folder";
const SHORTCUT_MIME: &str = "application/vnd.google-apps.shortcut";
/// 分片上传块大小（对齐 Go 版默认 ChunkSize 5MB）
const UPLOAD_CHUNK_SIZE: u64 = 5 * 1024 * 1024;

pub struct GoogleDrive {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    /// 根目录文件夹 id（对齐 Go 版 RootID），空为 "root"
    root_folder_id: String,
    store: Arc<Store>,
}

impl GoogleDrive {
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        root_folder_id: String,
        store: Arc<Store>,
    ) -> Self {
        GoogleDrive {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            root_folder_id,
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::GoogleDrive {
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

    /// 根目录 fid：配置了 root_folder_id 用之，否则 "root"（对齐 Go 版 DefaultRoot）
    fn root_fid(&self) -> String {
        if self.root_folder_id.is_empty() {
            "root".to_string()
        } else {
            self.root_folder_id.clone()
        }
    }

    /// 对齐 Go 版 refreshToken()：olist 在线 API 刷新
    async fn refresh_token(&self) -> Result<(), String> {
        let cur = self.refresh_token.lock().unwrap().clone();
        let url = format!(
            "{}?refresh_ui={}&server_use=true&driver_txt=googleui_go",
            ONLINE_REFRESH_API,
            urlencode(&cur)
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("刷新 Google Drive token 失败: {e}"))?;
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
            return Err(format!("刷新 Google Drive token 失败: {msg}"));
        }
        self.save_tokens(&refresh, &access);
        Ok(())
    }

    /// 对齐 Go 版 request()：401 自动刷新重试一次
    async fn request(
        &self,
        method: Method,
        url: &str,
        params: &[(String, String)],
        retried: bool,
    ) -> Result<Value, String> {
        let resp = self
            .http
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {}", self.access_token()))
            // 对齐 Go 版 request() 里恒定的两个查询参数
            .query(&[
                ("includeItemsFromAllDrives", "true"),
                ("supportsAllDrives", "true"),
            ])
            .query(params)
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
            .and_then(|c| c.as_i64())
            .unwrap_or(0);
        if code != 0 {
            if code == 401 && !retried {
                self.refresh_token().await?;
                return Box::pin(self.request(method, url, params, true)).await;
            }
            let msg = v
                .pointer("/error/message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("Google Drive 接口错误({code}): {msg}"));
        }
        if status.as_u16() >= 400 {
            return Err(format!("Google Drive 接口 HTTP {status}"));
        }
        Ok(v)
    }

    /// 对齐 Go 版 Init()：刷新 token 并验证（取 about 配额信息）
    pub async fn validate(&self) -> Result<(), String> {
        if self.access_token().is_empty() {
            self.refresh_token().await?;
        }
        let url = format!("{API}/drive/v3/about");
        self.request(
            Method::GET,
            &url,
            &[("fields".into(), "storageQuota".into())],
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 getFiles()：pageToken 翻页 + 文件快捷方式回源
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        // 根目录为 "root"（Go 版 DefaultRoot）；旧配置里可能存了兜底值 "0"
        let parent = match parent_fid {
            "" | "0" => self.root_fid(),
            other => other.to_string(),
        };
        let mut files = Vec::new();
        let mut page_token = String::new();
        loop {
            let mut params: Vec<(String, String)> = vec![
                (
                    "orderBy".into(),
                    // 对齐 Go 版默认排序
                    "folder,name,modifiedTime desc".into(),
                ),
                ("fields".into(), FILES_LIST_FIELDS.into()),
                ("pageSize".into(), "1000".into()),
                (
                    "q".into(),
                    format!("'{parent}' in parents and trashed = false"),
                ),
            ];
            if !page_token.is_empty() {
                params.push(("pageToken".into(), page_token.clone()));
            }
            let resp = self
                .request(
                    Method::GET,
                    &format!("{API}/drive/v3/files"),
                    &params,
                    false,
                )
                .await?;
            let mut items = resp
                .get("files")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            page_token = resp
                .get("nextPageToken")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            // 文件快捷方式回源（对齐 Go 版 batchGetTargetFilesInfo，顺序请求），
            // 回填目标文件 size 后再统一转换
            for item in &mut items {
                let mime = item
                    .get("mimeType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target_id = item
                    .pointer("/shortcutDetails/targetId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let target_mime = item
                    .pointer("/shortcutDetails/targetMimeType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if mime == SHORTCUT_MIME && !target_id.is_empty() && target_mime != FOLDER_MIME {
                    if let Ok(target) = self.get_target_file_info(&target_id).await {
                        if let Some(size) = target.get("size").and_then(|v| v.as_str()) {
                            if let Some(obj) = item.as_object_mut() {
                                // API 对文件返回的 size 本就是字符串，直接覆盖
                                obj.insert("size".into(), Value::String(size.to_string()));
                            }
                        }
                    }
                }
            }

            for f in &items {
                files.push(Self::file_to_entry(f));
            }
            if page_token.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    /// 对齐 Go 版 getTargetFileInfo：快捷方式目标文件信息
    async fn get_target_file_info(&self, target_id: &str) -> Result<Value, String> {
        let url = format!("{API}/drive/v3/files/{target_id}");
        self.request(
            Method::GET,
            &url,
            &[("fields".into(), FILE_INFO_FIELDS.into())],
            false,
        )
        .await
    }

    /// 对齐 Go 版 fileToObj：快捷方式条目的 fid 直接替换为目标 id
    fn file_to_entry(f: &Value) -> Entry {
        let mime = f
            .get("mimeType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let id = f
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target_id = f
            .pointer("/shortcutDetails/targetId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let target_mime = f
            .pointer("/shortcutDetails/targetMimeType")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let (fid, is_dir) = if mime == SHORTCUT_MIME && !target_id.is_empty() {
            (target_id, target_mime == FOLDER_MIME)
        } else {
            (id, mime == FOLDER_MIME)
        };
        // Go 版 size 为字符串形式的整数
        let size = f
            .get("size")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .or_else(|| f.get("size").and_then(|v| v.as_u64()))
            .unwrap_or(0);
        let updated_at = f
            .get("modifiedTime")
            .and_then(|v| v.as_str())
            .and_then(iso_to_ms);
        Entry {
            fid,
            name: f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            size,
            is_dir,
            updated_at,
            etag: f
                .get("md5Checksum")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            s3_key_flag: None,
            file_type: None,
            extra: None,
        }
    }

    /// 对齐 Go 版 Link()：先请求一次元数据验证 token（401 会自动刷新），
    /// 再拼 alt=media 直链（需 Bearer 头，仅代理中转）
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let meta_url = format!("{API}/drive/v3/files/{}", urlencode(&e.fid));
        self.request(Method::GET, &meta_url, &[], false).await?;
        let url = format!("{meta_url}&alt=media&acknowledgeAbuse=true");
        Ok(DownloadInfo {
            url,
            headers: vec![(
                "Authorization".into(),
                format!("Bearer {}", self.access_token()),
            )],
            // 浏览器无法附带 Bearer 头，必须经后端 /api/stream 中转（对齐 Go 版 OnlyProxy）
            proxy: true,
            local_path: None,
        })
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Rename/Move/Copy/Remove/Put） ----------

    /// 目录 fid 归一化：""/"0" -> 根目录（对齐 list()）
    fn normalize_dir(&self, fid: &str) -> String {
        match fid {
            "" | "0" => self.root_fid(),
            other => other.to_string(),
        }
    }

    /// 通用写请求：带 Authorization、恒定的两个查询参数与 JSON 体，
    /// 401 自动刷新重试一次（对齐 Go 版 request()），
    /// 返回解析后的响应体（DELETE 等空响应为 Null）
    async fn request_write(
        &self,
        method: Method,
        url: &str,
        params: &[(String, String)],
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let mut req = self
            .http
            .request(method.clone(), url)
            .header("Authorization", format!("Bearer {}", self.access_token()))
            // 对齐 Go 版 request() 里恒定的两个查询参数
            .query(&[
                ("includeItemsFromAllDrives", "true"),
                ("supportsAllDrives", "true"),
            ])
            .query(params);
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
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
            .and_then(|c| c.as_i64())
            .unwrap_or(0);
        if code != 0 {
            if code == 401 && !retried {
                self.refresh_token().await?;
                return Box::pin(self.request_write(method, url, params, body, true)).await;
            }
            let msg = v
                .pointer("/error/message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("Google Drive 接口错误({code}): {msg}"));
        }
        if status == 401 && !retried {
            self.refresh_token().await?;
            return Box::pin(self.request_write(method, url, params, body, true)).await;
        }
        if status >= 400 {
            return Err(format!("Google Drive 接口 HTTP {status}"));
        }
        Ok(v)
    }

    /// 对齐 MakeDir：POST /drive/v3/files，body 带 parents + folder mimeType
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("目录名为空".into());
        }
        let parent = self.normalize_dir(parent_fid);
        let data = json!({
            "name": name,
            "parents": [parent],
            "mimeType": FOLDER_MIME,
        });
        self.request_write(
            Method::POST,
            &format!("{API}/drive/v3/files"),
            &[],
            Some(data),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Rename：PATCH /drive/v3/files/{id}，body {"name": newName}
    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if new_name.is_empty() {
            return Err("新名称为空".into());
        }
        let url = format!("{API}/drive/v3/files/{}", urlencode(&e.fid));
        let data = json!({ "name": new_name });
        self.request_write(Method::PATCH, &url, &[], Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Move：PATCH /drive/v3/files/{id}?addParents=dst&removeParents=root
    /// （与 Go 版一致，removeParents 固定为 "root"）
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let dst = self.normalize_dir(dst_dir_fid);
        let url = format!("{API}/drive/v3/files/{}", urlencode(&e.fid));
        let params = vec![
            ("addParents".to_string(), dst),
            ("removeParents".to_string(), "root".to_string()),
        ];
        self.request_write(Method::PATCH, &url, &params, None, false)
            .await?;
        Ok(())
    }

    /// 对齐 Copy（Go 版返回 errs.NotSupport）
    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        Err("Google Drive 不支持复制操作".into())
    }

    /// 对齐 Remove：DELETE /drive/v3/files/{id}（204 空响应）
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let url = format!("{API}/drive/v3/files/{}", urlencode(&e.fid));
        self.request_write(Method::DELETE, &url, &[], None, false)
            .await?;
        Ok(())
    }

    /// 对齐 Put：resumable session 上传。
    /// <5MB：整读后单请求 PUT；更大或未知大小：先落临时文件再按 5MB 分片 Content-Range PUT。
    /// reader 只能读一次，未知大小时先落临时文件确定实际大小
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let dst = self.normalize_dir(dst_dir_fid);
        let mime = mime_by_ext(&input.name);
        if input.size > 0 && input.size < UPLOAD_CHUNK_SIZE {
            // 小文件（对齐 Go：GetSize() < ChunkSize -> 单请求 PUT）
            let data = read_exact_n(input.reader, input.size).await?;
            let put_url = self
                .create_resumable_session(&dst, &input.name, mime, input.size)
                .await?;
            self.put_single(&put_url, data).await
        } else {
            // 大文件或未知大小：先落临时文件（finally 删除）
            let tmp_path = temp_file_path();
            let _guard = TempFileGuard(tmp_path.clone());
            let size = spool_to_temp(input.reader, &tmp_path).await?;
            let put_url = self
                .create_resumable_session(&dst, &input.name, mime, size)
                .await?;
            if size < UPLOAD_CHUNK_SIZE {
                let data = read_temp_part(&tmp_path, 0, size).await?;
                self.put_single(&put_url, data).await
            } else {
                self.put_chunks(&put_url, &tmp_path, size).await
            }
        }
    }

    /// 创建 resumable 上传会话（对齐 Go Put 前半段）：
    /// POST /upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true，
    /// headers 带 X-Upload-Content-Type/Length，成功从 Location 头取上传 URL
    async fn create_resumable_session(
        &self,
        dst: &str,
        name: &str,
        mime: &str,
        size: u64,
    ) -> Result<String, String> {
        let url =
            format!("{API}/upload/drive/v3/files?uploadType=resumable&supportsAllDrives=true");
        let data = json!({ "name": name, "parents": [dst] });
        let mut last_err = String::new();
        for attempt in 0..2 {
            if attempt > 0 {
                // 对齐 Go Put：401 刷新 token 后整体重试一次
                self.refresh_token().await?;
            }
            let resp = self
                .http
                .post(&url)
                .header("Authorization", format!("Bearer {}", self.access_token()))
                .header("X-Upload-Content-Type", mime)
                .header("X-Upload-Content-Length", size.to_string())
                .json(&data)
                .send()
                .await
                .map_err(|e| format!("Google Drive 创建上传会话失败: {e}"))?;
            let status = resp.status().as_u16();
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            let text = resp.text().await.unwrap_or_default();
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                let code = v
                    .pointer("/error/code")
                    .and_then(|c| c.as_i64())
                    .unwrap_or(0);
                if code == 401 && attempt == 0 {
                    last_err = "Google Drive 创建上传会话返回 401".into();
                    continue;
                }
                if code != 0 {
                    let msg = v
                        .pointer("/error/message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("unknown");
                    return Err(format!("Google Drive 接口错误({code}): {msg}"));
                }
            }
            if !(200..300).contains(&status) {
                return Err(format!(
                    "Google Drive 创建上传会话返回 HTTP {status}: {}",
                    trunc200(&text)
                ));
            }
            if location.is_empty() {
                return Err("Google Drive 未返回上传 Location".into());
            }
            return Ok(location);
        }
        Err(last_err)
    }

    /// 单请求整文件上传（对齐 Go：GetSize() < ChunkSize 分支，PUT 整个内容，
    /// 附 includeItemsFromAllDrives/supportsAllDrives 查询参数）
    async fn put_single(&self, put_url: &str, data: Vec<u8>) -> Result<(), String> {
        let url = format!("{put_url}?includeItemsFromAllDrives=true&supportsAllDrives=true");
        let mut last_err = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            match self
                .http
                .put(&url)
                .header("Authorization", format!("Bearer {}", self.access_token()))
                .body(data.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    let code = v
                        .pointer("/error/code")
                        .and_then(|c| c.as_i64())
                        .unwrap_or(0);
                    if code == 401 && attempt < 2 {
                        // 对齐 Go request()：401 刷新后重试
                        self.refresh_token().await?;
                        last_err = "Google Drive 上传返回 401".into();
                        continue;
                    }
                    if code != 0 {
                        let msg = v
                            .pointer("/error/message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("unknown");
                        return Err(format!("Google Drive 接口错误({code}): {msg}"));
                    }
                    if (200..300).contains(&status) || status == 308 {
                        return Ok(());
                    }
                    last_err = format!("Google Drive 上传返回 HTTP {status}: {}", trunc200(&text));
                }
                Err(e) => last_err = format!("Google Drive 上传失败: {e}"),
            }
        }
        Err(last_err)
    }

    /// 分片上传（对齐 Go chunkUpload）：Content-Range bytes {start}-{end}/{total}，
    /// 308 表示分片未完继续，200/201 表示全部完成；每片重试 3 次
    async fn put_chunks(&self, put_url: &str, tmp_path: &Path, size: u64) -> Result<(), String> {
        let url = format!("{put_url}?includeItemsFromAllDrives=true&supportsAllDrives=true");
        let mut offset: u64 = 0;
        while offset < size {
            let chunk_size = std::cmp::min(size - offset, UPLOAD_CHUNK_SIZE);
            let range = format!("bytes {}-{}/{}", offset, offset + chunk_size - 1, size);
            let mut last_err = String::new();
            let mut done = false;
            for attempt in 0..3 {
                if attempt > 0 {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
                let data = match read_temp_part(tmp_path, offset, chunk_size).await {
                    Ok(d) => d,
                    Err(e) => {
                        last_err = e;
                        continue;
                    }
                };
                match self
                    .http
                    .put(&url)
                    .header("Authorization", format!("Bearer {}", self.access_token()))
                    .header("Content-Range", &range)
                    .body(data)
                    .send()
                    .await
                {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        let text = resp.text().await.unwrap_or_default();
                        let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                        let code = v
                            .pointer("/error/code")
                            .and_then(|c| c.as_i64())
                            .unwrap_or(0);
                        if code == 401 && attempt < 2 {
                            // 对齐 Go chunkUpload：401 刷新 token 后由重试机制重传本片
                            self.refresh_token().await?;
                            last_err = "Google Drive 分片上传返回 401".into();
                            continue;
                        }
                        if code != 0 {
                            let msg = v
                                .pointer("/error/message")
                                .and_then(|m| m.as_str())
                                .unwrap_or("unknown");
                            return Err(format!("Google Drive 接口错误({code}): {msg}"));
                        }
                        if (200..300).contains(&status) || status == 308 {
                            done = true;
                            break;
                        }
                        last_err = format!(
                            "Google Drive 分片上传返回 HTTP {status}: {}",
                            trunc200(&text)
                        );
                    }
                    Err(e) => last_err = format!("Google Drive 分片上传失败: {e}"),
                }
            }
            if !done {
                return Err(last_err);
            }
            offset += chunk_size;
        }
        Ok(())
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

/// 错误信息里附带的原始响应片段（按字符截断，避免 UTF-8 边界 panic）
fn trunc200(s: &str) -> String {
    s.chars().take(200).collect()
}

/// 扩展名 -> MIME（对齐 Go utils.GetMimeType 的常用集）
fn mime_by_ext(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" | "md" | "log" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" => "application/gzip",
        "tar" => "application/x-tar",
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "avi" => "video/x-msvideo",
        "mov" => "video/quicktime",
        "ts" => "video/mp2t",
        "mp3" => "audio/mpeg",
        "flac" => "audio/flac",
        "ogg" | "opus" => "audio/ogg",
        "m4a" => "audio/mp4",
        "wav" => "audio/wav",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        _ => "application/octet-stream",
    }
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
    std::env::temp_dir().join(format!("openlist-rs-gdrive-{}", Uuid::new_v4()))
}

/// 把上传流落到临时文件并返回实际大小
async fn spool_to_temp(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    path: &Path,
) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("Google Drive 创建临时文件失败: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("Google Drive 读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("Google Drive 写入临时文件失败: {e}"))?;
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("Google Drive 临时文件落盘失败: {e}"))?;
    Ok(total)
}

/// 从临时文件读取 [offset, offset+len) 分片
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("Google Drive 打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("Google Drive 定位临时文件失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    if len > 0 {
        f.read_exact(&mut buf)
            .await
            .map_err(|e| format!("Google Drive 读取临时文件分片失败: {e}"))?;
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
        .map_err(|e| format!("Google Drive 读取上传流失败: {e}"))?;
    Ok(buf)
}
