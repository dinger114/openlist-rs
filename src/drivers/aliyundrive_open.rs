//! 阿里云盘开放平台驱动（对齐 Go 版 drivers/aliyundrive_open）
//!
//! - 授权：refresh_token 换 access_token（默认走 olist 在线刷新 API，
//!   无需 client_id/client_secret）
//! - 列目录：POST /adrive/v1.0/openFile/list（marker 分页，limit 200）
//! - 下载：POST /adrive/v1.0/openFile/getDownloadUrl（返回无需附加头的直链）
//! - 写操作：/adrive/v1.0/openFile/{create,update,move,copy,recyclebin/trash,complete}
//! - 上传：create（可带 pre_hash/proof v1 秒传探测）-> 分片 PUT -> complete

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use base64::Engine;
use md5::Digest;
use reqwest::{Client, Method};
use serde_json::{json, Value};
use sha1::Sha1;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const API_URL: &str = "https://openapi.alipan.com";
/// 对齐 Go 版默认在线刷新 API
const ONLINE_REFRESH_API: &str = "https://api.oplist.org/alicloud/renewapi";
/// access_token 失效错误码
const TOKEN_EXPIRED_CODES: [&str; 3] = ["AccessTokenInvalid", "AccessTokenExpired", "I400JD"];

pub struct AliyundriveOpen {
    account_id: String,
    http: Client,
    refresh_token: Mutex<String>,
    access_token: Mutex<String>,
    alipan_type: String,
    drive_id: Mutex<String>,
    store: Arc<Store>,
}

/// ISO8601 时间（如 2024-01-02T15:04:05.000Z / +08:00）-> unix 毫秒
pub(crate) fn iso_to_ms(s: &str) -> Option<i64> {
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    if s.len() < 19 {
        return None;
    }
    let y = num(0..4)?;
    let mo = num(5..7)?;
    let d = num(8..10)?;
    let h = num(11..13)?;
    let mi = num(14..16)?;
    let se = num(17..19)?;
    let ms = num(20..23).unwrap_or(0);
    let mut secs = days_from_civil(y, mo, d) * 86400 + h * 3600 + mi * 60 + se;
    // 时区后缀：Z / +hh:mm / -hh:mm（可能跟在毫秒段之后，需先定位符号位）
    let tz = &s[19..];
    if let Some(pos) = tz.find(['+', '-']) {
        let sign: i64 = if tz.as_bytes()[pos] == b'+' { -1 } else { 1 };
        let nums: Vec<i64> = tz[pos + 1..]
            .split(':')
            .filter_map(|p| p.parse().ok())
            .collect();
        if nums.len() == 2 {
            secs += sign * (nums[0] * 3600 + nums[1] * 60);
        }
    }
    Some(secs * 1000 + ms)
}

// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::{civil_from_days, days_from_civil};

impl AliyundriveOpen {
    pub fn new(
        account_id: &str,
        refresh_token: String,
        access_token: String,
        alipan_type: String,
        store: Arc<Store>,
    ) -> Self {
        AliyundriveOpen {
            account_id: account_id.to_string(),
            http: Client::new(),
            refresh_token: Mutex::new(refresh_token),
            access_token: Mutex::new(access_token),
            alipan_type,
            drive_id: Mutex::new(String::new()),
            store,
        }
    }

    fn save_tokens(&self, refresh: &str, access: &str) {
        *self.refresh_token.lock().unwrap() = refresh.to_string();
        *self.access_token.lock().unwrap() = access.to_string();
        let (r, a) = (refresh.to_string(), access.to_string());
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::AliyundriveOpen {
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

    /// 对齐 Go 版 refreshToken()：走在线刷新 API
    async fn refresh_token(&self) -> Result<(), String> {
        let cur = self.refresh_token.lock().unwrap().clone();
        let url = format!(
            "{}?refresh_ui={}&server_use=true&driver_txt={}",
            ONLINE_REFRESH_API,
            urlencoding(&cur),
            if self.alipan_type == "alipanTV" {
                "alicloud_tv"
            } else {
                "alicloud_qr"
            }
        );
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("刷新阿里云盘 token 失败: {e}"))?;
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
            return Err(format!("刷新阿里云盘 token 失败: {msg}"));
        }
        // 校验 jwt sub 一致（对齐 Go 版 getSub 比对）
        if !cur.is_empty() && sub_of(&cur) != sub_of(&refresh) {
            return Err("刷新阿里云盘 token 失败: sub 不匹配".into());
        }
        self.save_tokens(&refresh, &access);
        Ok(())
    }

    /// 对齐 Go 版 requestReturnErrResp：token 失效自动刷新重试一次
    async fn request(
        &self,
        method: Method,
        uri: &str,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let url = format!("{API_URL}{uri}");
        let mut req = self
            .http
            .request(method, &url)
            .header("Authorization", format!("Bearer {}", self.access_token()));
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let status = resp.status();
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_str()).unwrap_or("");
        if !code.is_empty() {
            if !retried && (TOKEN_EXPIRED_CODES.contains(&code) || self.access_token().is_empty()) {
                self.refresh_token().await?;
                return Box::pin(self.request(Method::POST, uri, body, true)).await;
            }
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("阿里云盘接口错误({code}): {msg}"));
        }
        if status.as_u16() >= 400 {
            return Err(format!("阿里云盘接口 HTTP {status}"));
        }
        Ok(v)
    }

    /// 对齐 Go 版 Init()：取 drive_id 并验证 token
    pub async fn validate(&self) -> Result<(), String> {
        let res = self
            .request(Method::POST, "/adrive/v1.0/user/getDriveInfo", None, false)
            .await?;
        // AlipanType=alipanTV 用资源盘，其余按 default -> resource -> backup 兜底
        let keys: &[&str] = if self.alipan_type == "alipanTV" {
            &["resource_drive_id", "default_drive_id"]
        } else {
            &["default_drive_id", "resource_drive_id", "backup_drive_id"]
        };
        let drive_id = keys
            .iter()
            .find_map(|k| res.get(k).and_then(|v| v.as_str()))
            .unwrap_or("")
            .to_string();
        *self.drive_id.lock().unwrap() = drive_id;
        Ok(())
    }

    /// 对齐 Go 版 getFiles()：marker 分页
    pub async fn list(&self, parent_file_id: &str) -> Result<Vec<Entry>, String> {
        // 根目录固定为 "root"（Go 版 DefaultRoot）；旧配置里可能存了兜底值 "0"
        let parent_file_id = match parent_file_id {
            "" | "0" => "root",
            other => other,
        };
        let drive_id = self.drive_id.lock().unwrap().clone();
        let mut files = Vec::new();
        let mut marker = String::new();
        loop {
            let body = json!({
                "drive_id": drive_id,
                "limit": 200,
                "marker": marker,
                "order_by": "updated_at",
                "order_direction": "DESC",
                "parent_file_id": parent_file_id,
            });
            let resp = self
                .request(
                    Method::POST,
                    "/adrive/v1.0/openFile/list",
                    Some(body),
                    false,
                )
                .await?;
            let items = resp
                .get("items")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            for f in &items {
                let updated_at = f
                    .get("updated_at")
                    .and_then(|v| v.as_str())
                    .and_then(iso_to_ms);
                files.push(Entry {
                    fid: f
                        .get("file_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: f
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir: f.get("type").and_then(|v| v.as_str()) == Some("folder"),
                    updated_at,
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            marker = resp
                .get("next_marker")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if marker.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    /// 对齐 Go 版 Link()：POST /adrive/v1.0/openFile/getDownloadUrl
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "expire_sec": 14400,
        });
        let resp = self
            .request(
                Method::POST,
                "/adrive/v1.0/openFile/getDownloadUrl",
                Some(body),
                false,
            )
            .await?;
        let url = resp
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if url.is_empty() {
            return Err("阿里云盘未返回下载直链".into());
        }
        // 直链为 CDN 地址，无附加头即可访问
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    // ---------- 写操作（对齐 Go 版 MakeDir/Rename/Move/Copy/Remove） ----------

    /// 对齐 Go 版 MakeDir()：POST /adrive/v1.0/openFile/create
    /// （type=folder，check_name_mode=refuse）
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "parent_file_id": norm_fid(parent_fid),
            "name": name,
            "type": "folder",
            "check_name_mode": "refuse",
        });
        self.request(
            Method::POST,
            "/adrive/v1.0/openFile/create",
            Some(body),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 Rename()：POST /adrive/v1.0/openFile/update
    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "name": new_name,
        });
        self.request(
            Method::POST,
            "/adrive/v1.0/openFile/update",
            Some(body),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 Move()：POST /adrive/v1.0/openFile/move（check_name_mode=ignore）
    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "to_parent_file_id": norm_fid(dst_dir_fid),
            "check_name_mode": "ignore",
        });
        self.request(
            Method::POST,
            "/adrive/v1.0/openFile/move",
            Some(body),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 Copy()：POST /adrive/v1.0/openFile/copy（auto_rename=false）
    pub async fn copy(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
            "to_parent_file_id": norm_fid(dst_dir_fid),
            "auto_rename": false,
        });
        self.request(
            Method::POST,
            "/adrive/v1.0/openFile/copy",
            Some(body),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 Remove()：POST /adrive/v1.0/openFile/recyclebin/trash
    /// （Rust 版未暴露 remove_way 配置，固定进回收站，对齐 Go 版默认值）
    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let drive_id = self.drive_id.lock().unwrap().clone();
        let body = json!({
            "drive_id": drive_id,
            "file_id": e.fid,
        });
        self.request(
            Method::POST,
            "/adrive/v1.0/openFile/recyclebin/trash",
            Some(body),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 Put() -> upload()：
    /// 1. create（秒传探测时带 pre_hash，命中 PreHashMatched 后补 proof v1 重试）
    /// 2. 非 rapid_upload：按 part_info_list 逐片 PUT（每片重试 3 次，超 50 分钟刷新上传地址）
    /// 3. complete
    ///
    /// proof_code 需要按文件随机偏移读 8 字节、分片重试需要重读内容 →
    /// 先把 reader 落临时文件，边写边算整文件 SHA1 与前 1024 字节 pre_hash。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let dst = norm_fid(dst_dir_fid);
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let (size, pre_hash, full_sha1) = spool_and_sha1(input.reader, &tmp_path).await?;

        let drive_id = self.drive_id.lock().unwrap().clone();
        let part_size = cal_part_size(size);
        let count: u64 = size.div_ceil(part_size);
        // Go 用文件 mtime/ctime；上传流没有时间信息，用当前 UTC 时间
        let now = iso_now();
        let mut create_data = json!({
            "drive_id": drive_id,
            "parent_file_id": dst,
            "name": input.name,
            "type": "file",
            "check_name_mode": "ignore",
            "local_modified_at": now.clone(),
            "local_created_at": now,
            "part_info_list": make_part_infos(count),
        });
        // 对齐 Go：rapidUpload && size > 100KB 时带 pre_hash 秒传探测
        // （Rust 版未暴露 rapid_upload 开关，按开启处理）
        let rapid_upload = size > 100 * 1024;
        if rapid_upload {
            create_data["size"] = json!(size);
            create_data["pre_hash"] = json!(pre_hash);
        }
        let uri = "/adrive/v1.0/openFile/create";
        let resp = match self
            .request(Method::POST, uri, Some(create_data.clone()), false)
            .await
        {
            Ok(v) => v,
            Err(err) => {
                // 对齐 Go：PreHashMatched -> 计算 proof v1 后重试 create
                if !rapid_upload || !err.contains("PreHashMatched") {
                    return Err(err);
                }
                let proof_code = self.cal_proof_code(&tmp_path, size).await?;
                if let Some(obj) = create_data.as_object_mut() {
                    obj.remove("pre_hash");
                }
                create_data["proof_version"] = json!("v1");
                create_data["content_hash_name"] = json!("sha1");
                create_data["content_hash"] = json!(full_sha1);
                create_data["proof_code"] = json!(proof_code);
                self.request(Method::POST, uri, Some(create_data), false)
                    .await?
            }
        };

        let rapid_hit = resp
            .get("rapid_upload")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if !rapid_hit {
            // 2. 普通分片上传
            let file_id = resp
                .get("file_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let upload_id = resp
                .get("upload_id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let mut part_info_list = resp
                .get("part_info_list")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let mut offset: u64 = 0;
            let mut pre_time = Instant::now();
            for i in 0..part_info_list.len() {
                // 超过 50 分钟刷新上传地址（对齐 Go）
                if pre_time.elapsed() > Duration::from_secs(50 * 60) {
                    part_info_list = self
                        .get_upload_url(&drive_id, count, &file_id, &upload_id)
                        .await?;
                    pre_time = Instant::now();
                }
                if i >= part_info_list.len() {
                    break; // 刷新后分片数异常，避免越界
                }
                let upload_url = part_info_list[i]
                    .get("upload_url")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if upload_url.is_empty() {
                    return Err(format!("阿里云盘未返回第 {} 片的上传地址", i + 1));
                }
                let remain = size.saturating_sub(offset);
                if remain == 0 {
                    break;
                }
                let this_len = std::cmp::min(part_size, remain);
                // 对齐 Go：每片重试 3 次（退避 1s/2s）
                let mut last_err = String::new();
                for attempt in 0..3u32 {
                    if attempt > 0 {
                        tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
                    }
                    match read_temp_part(&tmp_path, offset, this_len).await {
                        Ok(data) => match self.upload_part(&upload_url, data).await {
                            Ok(()) => {
                                last_err.clear();
                                break;
                            }
                            Err(e) => last_err = e,
                        },
                        Err(e) => last_err = e,
                    }
                }
                if !last_err.is_empty() {
                    return Err(last_err);
                }
                offset += part_size;
            }
        }
        // 3. complete
        let file_id = resp
            .get("file_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let upload_id = resp
            .get("upload_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let body = json!({
            "drive_id": drive_id,
            "file_id": file_id,
            "upload_id": upload_id,
        });
        self.request(
            Method::POST,
            "/adrive/v1.0/openFile/complete",
            Some(body),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go getUploadUrl()：分片上传地址过期时重新获取
    async fn get_upload_url(
        &self,
        drive_id: &str,
        count: u64,
        file_id: &str,
        upload_id: &str,
    ) -> Result<Vec<Value>, String> {
        let body = json!({
            "drive_id": drive_id,
            "file_id": file_id,
            "part_info_list": make_part_infos(count),
            "upload_id": upload_id,
        });
        let resp = self
            .request(
                Method::POST,
                "/adrive/v1.0/openFile/getUploadUrl",
                Some(body),
                false,
            )
            .await?;
        Ok(resp
            .get("part_info_list")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default())
    }

    /// 对齐 Go uploadPart()：PUT 分片到 OSS 上传地址，200/409 均算成功
    async fn upload_part(&self, upload_url: &str, data: Vec<u8>) -> Result<(), String> {
        let resp = self
            .http
            .put(upload_url)
            .body(data)
            .send()
            .await
            .map_err(|e| format!("阿里云盘分片上传失败: {e}"))?;
        let status = resp.status().as_u16();
        if status != 200 && status != 409 {
            let text = resp.text().await.unwrap_or_default();
            return Err(format!(
                "阿里云盘分片上传返回异常状态 {status}: {}",
                trunc(&text, 200)
            ));
        }
        Ok(())
    }

    /// 对齐 Go calProofCode()：按 proof 区间从临时文件读 8 字节做 base64
    async fn cal_proof_code(&self, tmp_path: &Path, size: u64) -> Result<String, String> {
        let (start, end) = proof_range(&self.access_token(), size)?;
        let data = read_temp_part(tmp_path, start, end - start).await?;
        Ok(base64::engine::general_purpose::STANDARD.encode(&data))
    }
}

/// 从 JWT payload 里取 sub
fn sub_of(token: &str) -> String {
    let segs: Vec<&str> = token.split('.').collect();
    if segs.len() != 3 {
        return String::new();
    }
    base64::engine::general_purpose::STANDARD
        .decode(segs[1])
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| v.get("sub").and_then(|s| s.as_str()).map(|s| s.to_string()))
        .unwrap_or_default()
}

fn urlencoding(s: &str) -> String {
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

// ---------- 写操作辅助 ----------

/// 根目录 fid 归一（对齐 list()："" / "0" -> "root"）
fn norm_fid(fid: &str) -> &str {
    match fid {
        "" | "0" => "root",
        other => other,
    }
}

/// 对齐 Go makePartInfos()：part_number 从 1 开始
fn make_part_infos(count: u64) -> Vec<Value> {
    (0..count)
        .map(|i| json!({ "part_number": (i + 1) as i64 }))
        .collect()
}

/// 对齐 Go calPartSize()：默认 20MB，按文件大小逐档加大（最大 5GB）
fn cal_part_size(size: u64) -> u64 {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    const TB: u64 = 1024 * 1024 * 1024 * 1024;
    let mut part_size: u64 = 20 * MB;
    if size > part_size {
        if size > TB {
            part_size = 5 * GB;
        } else if size > 768 * GB {
            part_size = 109_951_163;
        } else if size > 512 * GB {
            part_size = 82_463_373;
        } else if size > 384 * GB {
            part_size = 54_975_582;
        } else if size > 256 * GB {
            part_size = 41_231_687;
        } else if size > 128 * GB {
            part_size = 27_487_791;
        }
    }
    part_size
}

/// 对齐 Go getProofRange()：md5(accessToken) 前 16 个 hex 字符定位 proof 区间 [index, index+8)
fn proof_range(input: &str, size: u64) -> Result<(u64, u64), String> {
    if size == 0 {
        return Ok((0, 0));
    }
    let md5hex = hex::encode(md5::Md5::digest(input.as_bytes()));
    let tmp_int =
        u64::from_str_radix(&md5hex[0..16], 16).map_err(|e| format!("计算 proof 区间失败: {e}"))?;
    let index = tmp_int % size;
    let start = index;
    let end = std::cmp::min(index + 8, size);
    Ok((start, end))
}

/// 当前 UTC 时间，格式对齐 Go "2006-01-02T15:04:05.000Z"
fn iso_now() -> String {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    let ms = now_ms.rem_euclid(1000);
    let secs = now_ms.div_euclid(1000);
    let (days, sec_of_day) = (secs.div_euclid(86400), secs.rem_euclid(86400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        sec_of_day / 3600,
        sec_of_day % 3600 / 60,
        sec_of_day % 60
    )
}

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-ali-{}", Uuid::new_v4()))
}

/// 从临时文件按偏移读一段（分片上传 / proof_code 用）
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("阿里云盘打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("阿里云盘临时文件 seek 失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| format!("阿里云盘读取临时文件分片失败: {e}"))?;
    Ok(buf)
}

/// 把上传流落到临时文件，单趟同时计算：
/// - 整文件 SHA1（秒传 content_hash）
/// - 前 1024 字节 SHA1（秒传 pre_hash）
async fn spool_and_sha1(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
) -> Result<(u64, String, String), String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("阿里云盘创建临时文件失败: {e}"))?;
    let mut full = Sha1::new();
    let mut pre = Sha1::new();
    let mut fed_pre: u64 = 0;
    let mut total: u64 = 0;
    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("阿里云盘读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("阿里云盘写入临时文件失败: {e}"))?;
        full.update(&buf[..n]);
        if fed_pre < 1024 {
            let take = std::cmp::min(n as u64, 1024 - fed_pre) as usize;
            pre.update(&buf[..take]);
            fed_pre += take as u64;
        }
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("阿里云盘临时文件落盘失败: {e}"))?;
    Ok((
        total,
        hex::encode(pre.finalize()),
        hex::encode(full.finalize()),
    ))
}

/// 按字符截断，避免多字节字符串按字节切片 panic
fn trunc(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

#[cfg(test)]
mod tests {
    use super::iso_to_ms;

    #[test]
    fn test_iso_to_ms() {
        // 2024-01-02T15:04:05.000Z = 1704207845000
        assert_eq!(iso_to_ms("2024-01-02T15:04:05.000Z"), Some(1704207845000));
        // 1970-01-01T00:00:00Z
        assert_eq!(iso_to_ms("1970-01-01T00:00:00Z"), Some(0));
        // +08:00 时区（23:04:05+08:00 = 15:04:05Z）
        assert_eq!(
            iso_to_ms("2024-01-02T23:04:05.000+08:00"),
            Some(1704207845000)
        );
    }
}
