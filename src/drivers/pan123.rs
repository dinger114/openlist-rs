use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use base64::Engine;
use md5::{Digest, Md5};
use reqwest::{Client, Method, redirect};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

const MAIN_API: &str = "https://yun.123pan.com/b/api";
const SIGN_IN: &str = "https://login.123pan.com/api/user/sign_in";
const FILE_LIST: &str = "/file/list/new";
const DOWNLOAD_INFO: &str = "/file/download_info";
const USER_INFO: &str = "/user/info";
/// 对齐 Go 版 drivers/123/util.go 的写操作 endpoint 常量
const MKDIR: &str = "/file/upload_request";
const MOVE: &str = "/file/mod_pid";
const RENAME: &str = "/file/rename";
const TRASH: &str = "/file/trash";
const UPLOAD_REQUEST: &str = "/file/upload_request";
const S3_PRESIGNED_URLS: &str = "/file/s3_repare_upload_parts_batch";
const S3_AUTH: &str = "/file/s3_upload_object/auth";
const UPLOAD_COMPLETE_V2: &str = "/file/upload_complete/v2";
/// 对齐 Go 版 APIRateLimit: 700ms/请求（仅列表接口）
const LIST_RATE_LIMIT_MS: u64 = 700;

// ---------- signPath 移植（对齐 Go 版 drivers/123/util.go） ----------

const SIGN_TABLE: &[u8] = b"adefghlmyijnopkqrstubcvwsz";

/// IEEE CRC32
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = !0;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// unix 秒 -> 北京时间 (UTC+8) "yyyyMMddHHmm" 字符串
fn beijing_yyyymmddhhmm(unix_secs: u64) -> String {
    let secs = unix_secs + 8 * 3600;
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let hour = rem / 3600;
    let min = (rem % 3600) / 60;
    // Howard Hinnant civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}{m:02}{d:02}{hour:02}{min:02}")
}

/// 对齐 Go 版 signPath(): 返回 (k=timeSign, v="timestamp-random-dataSign")
fn sign_path(path: &str, os: &str, version: &str) -> (String, String) {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Go: %.f of math.Round(1e7*rand.Float64()) -> 0..10000000 的整数十进制串
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos() as u64;
    let random = (nanos.wrapping_mul(2_654_435_761) % 10_000_001).to_string();
    let timestamp = now_unix.to_string();

    // 时间数字串经 table 映射后取 CRC32
    let now_str = beijing_yyyymmddhhmm(now_unix);
    let mapped: Vec<u8> = now_str
        .bytes()
        .map(|b| SIGN_TABLE[(b - b'0') as usize])
        .collect();
    let time_sign = crc32(&mapped).to_string();

    let data = format!("{timestamp}|{random}|{path}|{os}|{version}|{time_sign}");
    let data_sign = crc32(data.as_bytes()).to_string();
    (time_sign, format!("{timestamp}-{random}-{data_sign}"))
}

// ---------- 驱动 ----------

pub struct Pan123 {
    account_id: String,
    http: Client,
    http_no_redirect: Client,
    username: String,
    password: String,
    access_token: Mutex<String>,
    platform: String,
    store: Arc<Store>,
}

impl Pan123 {
    pub fn new(
        account_id: &str,
        username: String,
        password: String,
        access_token: String,
        platform: String,
        store: Arc<Store>,
    ) -> Self {
        Pan123 {
            account_id: account_id.to_string(),
            http: Client::new(),
            http_no_redirect: Client::builder()
                .redirect(redirect::Policy::none())
                .build()
                .unwrap(),
            username,
            password,
            access_token: Mutex::new(access_token),
            platform,
            store,
        }
    }

    fn save_token(&self, token: &str) {
        *self.access_token.lock().unwrap() = token.to_string();
        let token = token.to_string();
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Pan123 { access_token, .. } = cred {
                *access_token = token.clone();
            }
        });
    }

    /// 对齐 Go 版 login(): 账号密码换 token
    pub async fn login(&self) -> Result<(), String> {
        let is_email = self.username.contains('@') && self.username.contains('.');
        let body = if is_email {
            json!({ "mail": self.username, "password": self.password, "type": 2 })
        } else {
            json!({ "passport": self.username, "password": self.password, "remember": true })
        };
        let resp = self
            .http
            .post(SIGN_IN)
            .header("origin", "https://yun.123pan.com")
            .header("referer", "https://yun.123pan.com/")
            .header("user-agent", "Dart/2.19(dart:io)-openlist")
            .header("platform", "web")
            .header("app-version", "3")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("123 登录请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("登录响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        if code != 200 {
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("123 登录失败(code={code}): {msg}"));
        }
        let token = v
            .pointer("/data/token")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err("123 登录成功但未返回 token".into());
        }
        self.save_token(&token);
        Ok(())
    }

    /// 对齐 Go 版 GetApi(): 在 query 上追加签名参数
    fn signed_url(&self, path: &str, query: &[(String, String)]) -> String {
        let (k, v) = sign_path(path, "web", "3");
        let mut qs: Vec<String> = query
            .iter()
            .map(|(key, val)| format!("{}={}", urlencoded(key), urlencoded(val)))
            .collect();
        qs.push(format!("{}={}", urlencoded(&k), urlencoded(&v)));
        format!("{}{}?{}", MAIN_API, path, qs.join("&"))
    }

    /// 对齐 Go 版 Request(): 401 自动重登一次
    async fn request(
        &self,
        method: Method,
        path: &str,
        query: Option<&[(String, String)]>,
        body: Option<Value>,
        retried: bool,
    ) -> Result<Value, String> {
        let url = self.signed_url(path, query.unwrap_or(&[]));
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header("origin", "https://yun.123pan.com")
            .header("referer", "https://yun.123pan.com/")
            .header("authorization", format!("Bearer {}", self.access_token.lock().unwrap()))
            .header("user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) openlist-client")
            .header("platform", &self.platform)
            .header("app-version", "3");
        if let Some(b) = body.clone() {
            req = req.json(&b);
        }
        let resp = req.send().await.map_err(|e| format!("请求失败: {e}"))?;
        let v: Value = resp.json().await.map_err(|e| format!("响应解析失败: {e}"))?;
        let code = v.get("code").and_then(|c| c.as_i64()).unwrap_or(-1);
        if code != 0 {
            if code == 401 && !retried {
                self.login().await?;
                return Box::pin(self.request(method, path, query, body, true)).await;
            }
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown");
            return Err(format!("123 接口错误(code={code}): {msg}"));
        }
        Ok(v)
    }

    /// 对齐 Go 版 Init(): GET /user/info 验证 token
    pub async fn validate(&self) -> Result<(), String> {
        if self.access_token.lock().unwrap().is_empty() {
            self.login().await?;
        }
        self.request(Method::GET, USER_INFO, None, None, false).await?;
        Ok(())
    }

    /// 对齐 Go 版 getFiles(): GET /file/list/new 分页拉取，700ms 限速
    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let mut files = Vec::new();
        let mut page: u32 = 1;
        loop {
            if page > 1 {
                tokio::time::sleep(std::time::Duration::from_millis(LIST_RATE_LIMIT_MS)).await;
            }
            let query: Vec<(String, String)> = vec![
                ("driveId".into(), "0".into()),
                ("limit".into(), "100".into()),
                ("next".into(), "0".into()),
                ("orderBy".into(), "file_id".into()),
                ("orderDirection".into(), "desc".into()),
                ("parentFileId".into(), parent_fid.to_string()),
                ("trashed".into(), "false".into()),
                ("SearchData".into(), String::new()),
                ("Page".into(), page.to_string()),
                ("OnlyLookAbnormalFile".into(), "0".into()),
                ("event".into(), "homeListFile".into()),
                ("operateType".into(), "4".into()),
                ("inDirectSpace".into(), "false".into()),
            ];
            let resp = self
                .request(Method::GET, FILE_LIST, Some(&query), None, false)
                .await?;
            let info_list = resp
                .pointer("/data/InfoList")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            let next = resp
                .pointer("/data/Next")
                .and_then(|v| v.as_str())
                .unwrap_or("-1")
                .to_string();
            for f in &info_list {
                let ftype = f.get("Type").and_then(|v| v.as_i64()).unwrap_or(0);
                files.push(Entry {
                    fid: f
                        .get("FileId")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        .to_string(),
                    name: f
                        .get("FileName")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: f.get("Size").and_then(|v| v.as_u64()).unwrap_or(0),
                    is_dir: ftype == 1,
                    updated_at: None,
                    etag: f.get("Etag").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    s3_key_flag: f
                        .get("S3KeyFlag")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    file_type: Some(ftype),
                    extra: None,
                });
            }
            if info_list.is_empty() || next == "-1" {
                break;
            }
            page += 1;
        }
        Ok(files)
    }

    /// 对齐 Go 版 Link(): POST /file/download_info -> 跟 302 拿最终直链
    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let body = json!({
            "driveId": 0,
            "etag": e.etag.clone().unwrap_or_default(),
            "fileId": e.fid.parse::<i64>().unwrap_or(0),
            "fileName": e.name,
            "s3keyFlag": e.s3_key_flag.clone().unwrap_or_default(),
            "size": e.size,
            "type": e.file_type.unwrap_or(0),
        });
        let resp = self
            .request(Method::POST, DOWNLOAD_INFO, None, Some(body), false)
            .await?;
        let mut download_url = resp
            .pointer("/data/DownloadUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if download_url.is_empty() {
            return Err("123 未返回下载直链".into());
        }
        // Go 版：DownloadUrl 的 query 里若带 params=<base64 url>，解码后才是真实地址
        if let Ok(mut parsed) = url::Url::parse(&download_url) {
            if let Some(params) = parsed.query_pairs().find(|(k, _)| k == "params").map(|(_, v)| v.to_string()) {
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&params) {
                    if let Ok(real) = String::from_utf8(decoded) {
                        if url::Url::parse(&real).is_ok() {
                            download_url = real;
                            parsed = url::Url::parse(&download_url).unwrap();
                        }
                    }
                }
            }
            let scheme_host = format!("{}://{}/", parsed.scheme(), parsed.host_str().unwrap_or(""));
            // 跟随一次 302 / JSON redirect_url 拿最终直链
            let r = self
                .http_no_redirect
                .get(&download_url)
                .header("Referer", "https://yun.123pan.com/")
                .send()
                .await
                .map_err(|e| format!("获取直链失败: {e}"))?;
            let final_url = match r.status().as_u16() {
                301 | 302 | 303 | 307 | 308 => r
                    .headers()
                    .get("location")
                    .and_then(|l| l.to_str().ok())
                    .unwrap_or(&download_url)
                    .to_string(),
                s if (200..300).contains(&s) => {
                    let v: Value = r.json().await.unwrap_or(Value::Null);
                    v.pointer("/data/redirect_url")
                        .and_then(|x| x.as_str())
                        .unwrap_or(&download_url)
                        .to_string()
                }
                _ => download_url.clone(),
            };
            Ok(DownloadInfo {
                url: final_url,
                headers: vec![("Referer".into(), scheme_host)],
                proxy: false,
            local_path: None,
            })
        } else {
            Err(format!("123 直链格式异常: {download_url}"))
        }
    }

    /// 对齐 Go 版 MakeDir()：POST /file/upload_request（type=1 目录）
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let data = json!({
            "driveId": 0,
            "etag": "",
            "fileName": name,
            "parentFileId": parent_fid,
            "size": 0,
            "type": 1,
        });
        self.request(Method::POST, MKDIR, None, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Move()：POST /file/mod_pid
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let data = json!({
            "fileIdList": [ { "FileId": e.fid } ],
            "parentFileId": dst_dir_fid,
        });
        self.request(Method::POST, MOVE, None, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Rename()：POST /file/rename
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let _ = parent_fid;
        let data = json!({
            "driveId": 0,
            "fileId": e.fid,
            "fileName": new_name,
        });
        self.request(Method::POST, RENAME, None, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Copy()：errs.NotSupport
    pub async fn copy(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let _ = e;
        let _ = dst_dir_fid;
        Err("123 云盘不支持复制操作".into())
    }

    /// 对齐 Go 版 Remove()：POST /file/trash（fileTrashInfoList 携带完整 File 结构）
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let _ = parent_fid;
        let file_type = e.file_type.unwrap_or(if e.is_dir { 1 } else { 0 });
        // 对齐 Go File.UpdateAt 序列化：无时间时为零值 "0001-01-01T00:00:00Z"
        let update_at = e
            .updated_at
            .map(rfc3339_utc)
            .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_string());
        let file = json!({
            "FileName": e.name,
            "Size": e.size as i64,
            "UpdateAt": update_at,
            "FileId": e.fid.parse::<i64>().unwrap_or(0),
            "Type": file_type,
            "Etag": e.etag.clone().unwrap_or_default(),
            "S3KeyFlag": e.s3_key_flag.clone().unwrap_or_default(),
            "DownloadUrl": "",
        });
        let data = json!({
            "driveId": 0,
            "operation": true,
            "fileTrashInfoList": [file],
        });
        self.request(Method::POST, TRASH, None, Some(data), false)
            .await?;
        Ok(())
    }

    /// 对齐 Go 版 Put()：算 md5 -> /file/upload_request（duplicate=2 覆盖）
    /// -> Reuse 或 Key 为空即秒传 -> 否则走 newUpload() 预签名分片上传 -> upload_complete/v2。
    /// md5 需要全量内容且分片重试需重读 -> 先落临时文件边写边算。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let (size, etag) = spool_md5(input.reader, &tmp_path).await?;
        let data = json!({
            "driveId": 0,
            "duplicate": 2, // 2->覆盖 1->重命名 0->默认
            "etag": etag.to_lowercase(),
            "fileName": input.name,
            "parentFileId": dst_dir_fid,
            "size": size as i64,
            "type": 0,
        });
        let resp = self
            .request(Method::POST, UPLOAD_REQUEST, None, Some(data), false)
            .await?;
        let d = resp.get("data").cloned().unwrap_or(Value::Null);
        let reuse = d.get("Reuse").and_then(|v| v.as_bool()).unwrap_or(false);
        let key = d.get("Key").and_then(|v| v.as_str()).unwrap_or("");
        // 对齐 Go 版：Reuse 或 Key 为空 -> 秒传/无需上传
        if reuse || key.is_empty() {
            return Ok(());
        }
        let upload_id = d.get("UploadId").and_then(|v| v.as_str()).unwrap_or("").to_string();
        if upload_id.is_empty() {
            // Go 版此分支用 AWS SDK（AccessKeyId/SecretAccessKey/SessionToken + SigV4）直传，
            // 依赖列表无 sha2/hmac，无法实现 SigV4 签名，明确报错而不是猜测 API
            let has_creds = ["AccessKeyId", "SecretAccessKey", "SessionToken"]
                .iter()
                .all(|k| {
                    d.get(k)
                        .and_then(|v| v.as_str())
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                });
            if has_creds {
                return Err("123 返回 S3 凭据直传模式，暂不支持该上传方式".into());
            }
            return Err("123 上传响应缺少 uploadId，无法分片上传".into());
        }
        self.new_upload(&d, size, &tmp_path).await
    }

    /// 对齐 Go 版 newUpload()：预签名 URL 分片上传（16MB/片，单批 1 或 10 片），完成后 completeS3
    async fn new_upload(&self, d: &Value, size: u64, tmp: &Path) -> Result<(), String> {
        let bucket = d.get("Bucket").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let key = d.get("Key").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let upload_id = d.get("UploadId").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let storage_node = d.get("StorageNode").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let file_id = d.get("FileId").and_then(|v| v.as_i64()).unwrap_or(0);

        let chunk_size: u64 = 16 * 1024 * 1024;
        let chunk_count: u64 = size.div_ceil(chunk_size).max(1);
        // 对齐 Go 版：只允许 1 批请求；单分片用 /s3_upload_object/auth，多分片用批量预签名接口
        let batch_size: u64 = if chunk_count > 1 { 10 } else { 1 };
        let use_batch = chunk_count > 1;

        let mut start = 1u64;
        while start <= chunk_count {
            let end = std::cmp::min(start + batch_size, chunk_count + 1);
            let mut urls = self
                .get_s3_urls(S3UrlArgs {
                    bucket: &bucket,
                    key: &key,
                    upload_id: &upload_id,
                    storage_node: &storage_node,
                    start,
                    end,
                    use_batch,
                })
                .await?;
            // 上传当前批的每个分片（对齐 Go 版 3 次重试 + 403 刷新预签名地址）
            for cur in start..end {
                let offset = (cur - 1) * chunk_size;
                let cur_size = std::cmp::min(chunk_size, size - offset);
                let mut ok = false;
                let mut last_err = String::new();
                for attempt in 0..3u64 {
                    if attempt > 0 {
                        tokio::time::sleep(std::time::Duration::from_secs(1 << (attempt - 1))).await;
                    }
                    let upload_url = match urls.get(&cur.to_string()) {
                        Some(u) if !u.is_empty() => u.clone(),
                        _ => {
                            // 分片地址缺失：对齐 Go 版重新拉取当前批的预签名地址
                            urls = self
                                .get_s3_urls(S3UrlArgs {
                                    bucket: &bucket,
                                    key: &key,
                                    upload_id: &upload_id,
                                    storage_node: &storage_node,
                                    start: cur,
                                    end,
                                    use_batch,
                                })
                                .await?;
                            last_err = format!("123 分片 {cur} 上传地址为空");
                            continue;
                        }
                    };
                    let data = read_temp_part(tmp, offset, cur_size).await?;
                    match self.http.put(&upload_url).body(data).send().await {
                        Ok(r) => {
                            let status = r.status().as_u16();
                            if status == 403 {
                                // 对齐 Go 版：403 说明预签名过期，刷新后重试
                                urls = self
                                    .get_s3_urls(S3UrlArgs {
                                        bucket: &bucket,
                                        key: &key,
                                        upload_id: &upload_id,
                                        storage_node: &storage_node,
                                        start: cur,
                                        end,
                                        use_batch,
                                    })
                                    .await?;
                                last_err = format!("123 分片 {cur} 上传被拒绝(403)，已刷新地址");
                                continue;
                            }
                            if status != 200 {
                                let t = r.text().await.unwrap_or_default();
                                last_err = format!(
                                    "123 分片 {cur} 上传失败: status={status}, body={}",
                                    &t[..t.len().min(200)]
                                );
                                continue;
                            }
                            ok = true;
                            break;
                        }
                        Err(e) => last_err = format!("123 分片 {cur} 上传失败: {e}"),
                    }
                }
                if !ok {
                    return Err(last_err);
                }
            }
            start = end;
        }
        // 对齐 Go 版 completeS3()：POST /file/upload_complete/v2
        self.request(
            Method::POST,
            UPLOAD_COMPLETE_V2,
            None,
            Some(json!({
                "StorageNode": storage_node,
                "bucket": bucket,
                "fileId": file_id,
                "fileSize": size as i64,
                "isMultipart": chunk_count > 1,
                "key": key,
                "uploadId": upload_id,
            })),
            false,
        )
        .await?;
        Ok(())
    }

    /// 对齐 Go 版 getS3PreSignedUrls()（批量）/ getS3Auth()（单个）：返回 分片号 -> 预签名地址
    async fn get_s3_urls(
        &self,
        args: S3UrlArgs<'_>,
    ) -> Result<std::collections::HashMap<String, String>, String> {
        let S3UrlArgs {
            bucket,
            key,
            upload_id,
            storage_node,
            start,
            end,
            use_batch,
        } = args;
        let path = if use_batch { S3_PRESIGNED_URLS } else { S3_AUTH };
        let data = json!({
            "StorageNode": storage_node,
            "bucket": bucket,
            "key": key,
            "partNumberEnd": end,
            "partNumberStart": start,
            "uploadId": upload_id,
        });
        let resp = self.request(Method::POST, path, None, Some(data), false).await?;
        let map = resp
            .pointer("/data/presignedUrls")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(k, v)| v.as_str().map(|s| (k, s.to_string())))
            .collect();
        Ok(map)
    }
}

fn urlencoded(s: &str) -> String {
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

// ---------- 上传辅助 ----------

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

/// get_s3_urls() 参数结构体（参数对齐 Go 版 getS3PreSignedUrls/getS3Auth 入参）
struct S3UrlArgs<'a> {
    bucket: &'a str,
    key: &'a str,
    upload_id: &'a str,
    storage_node: &'a str,
    start: u64,
    end: u64,
    use_batch: bool,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-123-{}", Uuid::new_v4()))
}

/// 把上传流落到临时文件，同时计算整文件 md5（对齐 Go 版 Put 里 CacheFullAndHash）
async fn spool_md5(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
) -> Result<(u64, String), String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("123 创建临时文件失败: {e}"))?;
    let mut hasher = Md5::new();
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("123 读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("123 写入临时文件失败: {e}"))?;
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("123 临时文件落盘失败: {e}"))?;
    Ok((total, hex::encode(hasher.finalize())))
}

/// 从临时文件读取指定区间（分片重试时每次重读）
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("123 打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("123 临时文件 seek 失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| format!("123 读取临时分片失败: {e}"))?;
    Ok(buf)
}

/// epoch 毫秒 -> RFC3339 UTC（对齐 Go time.Time JSON 序列化，用于 trash 的 UpdateAt 字段）
fn rfc3339_utc(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Howard Hinnant civil_from_days
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
