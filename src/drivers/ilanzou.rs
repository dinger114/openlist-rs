//! 蓝奏云优创（iLanZou）/ 飞鸡盘（FeijiPan）驱动（对齐 Go 版 drivers/ilanzou）
//!
//! - 同一套接口，站点常量不同（base/secret/bucket/unproved/proved/site）
//! - 所有请求 query 带设备信息 + timestamp（AES-128-ECB 加密，hex）
//! - 登录 /login 换 appToken；code -1/-2 或 token 为空时重登重试一次
//! - 下载直链：unproved /file/redirect，downloadId/auth 也是 AES 加密参数
//! - 上传：七牛（getUpToken → 直传或分片 → /7n/results 轮询）
//! - Entry.fid = fileId / folderId；根目录 fid = "0"

use super::{DownloadInfo, PutInput};
use crate::config::{Entry, Store};
use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use aes::Aes128;
use base64::engine::general_purpose::URL_SAFE;
use base64::Engine;
use md5::{Digest, Md5};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

struct SiteConf {
    base: &'static str,
    secret: [u8; 16],
    bucket: &'static str,
    unproved: &'static str,
    proved: &'static str,
    dev_version: &'static str,
    site: &'static str,
}

const ILANZOU: SiteConf = SiteConf {
    base: "https://apis.ilanzou.com",
    secret: *b"lanZouY-disk-app",
    bucket: "wpanstore-lanzou",
    unproved: "unproved",
    proved: "proved",
    dev_version: "125",
    site: "https://www.ilanzou.com",
};

const FEIJIPAN: SiteConf = SiteConf {
    base: "https://api.feijipan.com",
    secret: *b"dingHao-disk-app",
    bucket: "wpanstore",
    unproved: "ws",
    proved: "app",
    dev_version: "125",
    site: "https://www.feijipan.com",
};

const PART_SIZE: u64 = 1024 * 1024 * 8;

pub struct Ilanzou {
    conf: &'static SiteConf,
    http: Client,
    /// 不跟随重定向（下载直链靠 302 location 解析）
    link_http: Client,
    username: String,
    password: String,
    uuid: Mutex<String>,
    token: Mutex<String>,
    user_id: Mutex<String>,
    account: Mutex<String>,
    root_folder_id: String,
    #[allow(dead_code)]
    store: Arc<Store>,
}

impl Ilanzou {
    pub fn new(
        _account_id: &str,
        site: String,
        username: String,
        password: String,
        root_folder_id: String,
        store: Arc<Store>,
    ) -> Self {
        let conf = if site == "feijipan" {
            &FEIJIPAN
        } else {
            &ILANZOU
        };
        Ilanzou {
            conf,
            http: Client::new(),
            link_http: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_else(|_| Client::new()),
            username,
            password,
            uuid: Mutex::new(String::new()),
            token: Mutex::new(String::new()),
            user_id: Mutex::new(String::new()),
            account: Mutex::new(String::new()),
            root_folder_id: if root_folder_id.trim().is_empty() {
                "0".to_string()
            } else {
                root_folder_id.trim().to_string()
            },
            store,
        }
    }

    fn save_token(&self, token: &str) {
        // 对齐 Go 版：appToken 仅保存在运行期，不落盘
        *self.token.lock().unwrap() = token.to_string();
    }

    async fn login(&self) -> Result<(), String> {
        let v = self
            .unproved(
                "/login",
                reqwest::Method::POST,
                None,
                Some(json!({"loginName": self.username, "loginPwd": self.password})),
            )
            .await?;
        let token = v
            .pointer("/data/appToken")
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();
        if token.is_empty() {
            return Err(format!(
                "蓝奏云登录失败: {}",
                v.get("msg")
                    .and_then(|m| m.as_str())
                    .unwrap_or("token 为空")
            ));
        }
        self.save_token(&token);
        Ok(())
    }

    pub async fn validate(&self) -> Result<(), String> {
        if self.uuid.lock().unwrap().is_empty() {
            let v = self
                .unproved("/getUuid", reqwest::Method::GET, None, None)
                .await?;
            let uuid = v
                .get("uuid")
                .and_then(|u| u.as_str())
                .unwrap_or("")
                .to_string();
            if uuid.is_empty() {
                return Err("蓝奏云未返回设备 uuid".into());
            }
            *self.uuid.lock().unwrap() = uuid;
        }
        let v = self
            .proved("/user/account/map", reqwest::Method::GET, None, None)
            .await?;
        let user_id = v
            .pointer("/map/userId")
            .map(value_to_string)
            .unwrap_or_default();
        let account = v
            .pointer("/map/account")
            .map(value_to_string)
            .unwrap_or_default();
        if user_id.is_empty() {
            return Err("蓝奏云登录态校验失败（账号密码错误或未登录）".into());
        }
        *self.user_id.lock().unwrap() = user_id;
        *self.account.lock().unwrap() = account;
        Ok(())
    }

    /// AES-128-ECB + PKCS7 加密，返回 hex（对齐 Go 版 mopan.AesEncrypt + hex）
    fn aes_encrypt_hex(plain: &[u8], key: &[u8; 16]) -> String {
        let cipher = Aes128::new(GenericArray::from_slice(key));
        let pad = 16 - (plain.len() % 16);
        let mut buf = plain.to_vec();
        buf.extend(std::iter::repeat_n(pad as u8, pad));
        for chunk in buf.chunks_mut(16) {
            cipher.encrypt_block(GenericArray::from_mut_slice(chunk));
        }
        hex::encode(buf)
    }

    /// 当前毫秒时间戳 + 加密后的 timestamp 参数
    fn get_timestamp(&self) -> (i64, String) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let enc = Self::aes_encrypt_hex(ts.to_string().as_bytes(), &self.conf.secret);
        (ts, enc)
    }

    /// 统一请求（对齐 Go 版 request：公共 query + 额外 query + JSON body + code -1/-2 重登重试）
    async fn request_inner(
        &self,
        pathname: &str,
        proved: bool,
        method: reqwest::Method,
        query_extra: Option<String>,
        body: Option<Value>,
        is_retry: bool,
    ) -> Result<Value, String> {
        let uuid = self.uuid.lock().unwrap().clone();
        let (_, ts) = self.get_timestamp();
        let mut params = vec![
            format!("uuid={}", urlencode(&uuid)),
            "devType=6".to_string(),
            format!("devCode={}", urlencode(&uuid)),
            "devModel=chrome".to_string(),
            format!("devVersion={}", urlencode(self.conf.dev_version)),
            "appVersion=".to_string(),
            format!("timestamp={ts}"),
        ];
        if proved {
            let token = self.token.lock().unwrap().clone();
            params.push(format!("appToken={}", app_token_query_value(&token)));
        }
        params.push("extra=2".to_string());
        let url = if let Some(q) = &query_extra {
            format!("{}{}?{}&{}", self.conf.base, pathname, params.join("&"), q)
        } else {
            format!("{}{}?{}", self.conf.base, pathname, params.join("&"))
        };
        let mut req = self
            .http
            .request(method.clone(), &url)
            .header("Origin", self.conf.site)
            .header("Referer", format!("{}/", self.conf.site))
            .header("Accept-Encoding", "gzip")
            .header("Accept-Language", "zh-CN,zh;q=0.9,en-US,en;q=0.8");
        if let Some(b) = &body {
            req = req.json(b);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| format!("蓝奏云请求失败: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({}));
        let code = v
            .get("code")
            .and_then(|c| c.as_i64())
            .unwrap_or(if status == 200 { 200 } else { status as i64 });
        if code != 200 {
            // 登录态失效：重登重试一次
            if !is_retry
                && proved
                && (code == -1 || code == -2 || self.token.lock().unwrap().is_empty())
            {
                self.login().await?;
                // Box::pin 打断异步递归（重登后重试一次）
                return Box::pin(self.request_inner(
                    pathname,
                    proved,
                    method,
                    query_extra,
                    body,
                    true,
                ))
                .await;
            }
            return Err(format!(
                "蓝奏云请求失败 ({code}): {}",
                v.get("msg").and_then(|m| m.as_str()).unwrap_or("未知错误")
            ));
        }
        Ok(v)
    }

    async fn unproved(
        &self,
        pathname: &str,
        method: reqwest::Method,
        query_extra: Option<String>,
        body: Option<Value>,
    ) -> Result<Value, String> {
        // request_inner → login → unproved/proved → request_inner 存在异步递归，
        // 在此引入 Box::pin 打断无限大小 future（E0733）
        Box::pin(self.request_inner(
            &format!("/{}{pathname}", self.conf.unproved),
            false,
            method,
            query_extra,
            body,
            false,
        ))
        .await
    }

    async fn proved(
        &self,
        pathname: &str,
        method: reqwest::Method,
        query_extra: Option<String>,
        body: Option<Value>,
    ) -> Result<Value, String> {
        // 同 unproved：Box::pin 打断异步递归（E0733）
        Box::pin(self.request_inner(
            &format!("/{}{pathname}", self.conf.proved),
            true,
            method,
            query_extra,
            body,
            false,
        ))
        .await
    }

    /// fid 解析：根 = root_folder_id
    fn resolve(&self, fid: &str) -> String {
        let fid = fid.trim();
        if fid.is_empty() || fid == "0" || fid == "/" {
            self.root_folder_id.clone()
        } else {
            fid.to_string()
        }
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let folder_id = self.resolve(parent_fid);
        let mut offset: i64 = 1;
        let mut out: Vec<Entry> = Vec::new();
        loop {
            let v = self
                .proved(
                    "/record/file/list",
                    reqwest::Method::GET,
                    Some(format!(
                        "offset={offset}&limit=60&folderId={folder_id}&type=0"
                    )),
                    None,
                )
                .await?;
            let total_page = v.get("totalPage").and_then(|t| t.as_i64()).unwrap_or(0);
            let cur_offset = v.get("offset").and_then(|t| t.as_i64()).unwrap_or(0);
            if let Some(list) = v.get("list").and_then(|l| l.as_array()) {
                for f in list {
                    let file_type = f.get("fileType").and_then(|t| t.as_i64()).unwrap_or(0);
                    let upd_time = f
                        .get("updTime")
                        .and_then(|t| t.as_str())
                        .and_then(parse_local_datetime_millis);
                    if file_type == 2 {
                        // 文件夹
                        let name = f
                            .get("folderName")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let id = f.get("folderId").and_then(|i| i.as_i64()).unwrap_or(0);
                        if name.is_empty() || id == 0 {
                            continue;
                        }
                        out.push(Entry {
                            fid: id.to_string(),
                            name,
                            size: 0,
                            is_dir: true,
                            updated_at: upd_time,
                            etag: None,
                            s3_key_flag: None,
                            file_type: None,
                            extra: None,
                        });
                    } else {
                        let name = f
                            .get("fileName")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let id = f.get("fileId").and_then(|i| i.as_i64()).unwrap_or(0);
                        if name.is_empty() || id == 0 {
                            continue;
                        }
                        // 对齐 Go 版：FileSize 单位 KiB
                        let size = f.get("fileSize").and_then(|s| s.as_i64()).unwrap_or(0) * 1024;
                        out.push(Entry {
                            fid: id.to_string(),
                            name,
                            size: size.max(0) as u64,
                            is_dir: false,
                            updated_at: upd_time,
                            etag: None,
                            s3_key_flag: None,
                            file_type: None,
                            extra: None,
                        });
                    }
                }
            }
            if cur_offset < total_page {
                offset += 1;
            } else {
                break;
            }
        }
        Ok(out)
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        if e.is_dir {
            return Err("目录无法下载".into());
        }
        let uuid = self.uuid.lock().unwrap().clone();
        let user_id = self.user_id.lock().unwrap().clone();
        if user_id.is_empty() {
            return Err("蓝奏云尚未初始化完成".into());
        }
        let (ts, ts_enc) = self.get_timestamp();
        let download_id = Self::aes_encrypt_hex(
            format!("{}|{}", e.fid, user_id).as_bytes(),
            &self.conf.secret,
        );
        let auth = Self::aes_encrypt_hex(format!("{}|{}", e.fid, ts).as_bytes(), &self.conf.secret);
        let url = format!(
            "{}/{}/file/redirect?uuid={}&devType=6&devCode={}&devModel=chrome&devVersion={}&appVersion=&timestamp={}&appToken={}&enable=1&downloadId={}&auth={}",
            self.conf.base,
            self.conf.unproved,
            urlencode(&uuid),
            urlencode(&uuid),
            urlencode(self.conf.dev_version),
            urlencode(&ts_enc),
            urlencode(&self.token.lock().unwrap()),
            urlencode(&download_id),
            urlencode(&auth),
        );
        // 请求一次拿 302 location（部分文件类型返回 200 + JSON url）
        let resp = self
            .link_http
            .get(&url)
            .header("Origin", self.conf.site)
            .header("Referer", format!("{}/", self.conf.site))
            .header("Accept-Encoding", "gzip")
            .send()
            .await
            .map_err(|e| format!("蓝奏云解析直链失败: {e}"))?;
        let status = resp.status().as_u16();
        let location = resp
            .headers()
            .get("location")
            .and_then(|l| l.to_str().ok())
            .unwrap_or("")
            .to_string();
        let real_url = if ((300..400).contains(&status) || status == 200) && !location.is_empty() {
            location
        } else if status == 200 {
            let v: Value = resp.json().await.unwrap_or(json!({}));
            let u = v
                .get("url")
                .or_else(|| v.pointer("/data/url"))
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if u.is_empty() {
                return Err(format!(
                    "蓝奏云下载解析失败: {}",
                    v.get("msg").and_then(|m| m.as_str()).unwrap_or("无 url")
                ));
            }
            u
        } else {
            return Err(format!("蓝奏云下载解析失败 (status {status})"));
        };
        Ok(DownloadInfo {
            url: real_url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let folder_id = self.resolve(parent_fid);
        let v = self
            .proved(
                "/file/folder/save",
                reqwest::Method::POST,
                None,
                Some(json!({
                    "folderDesc": "",
                    "folderId": folder_id,
                    "folderName": name,
                })),
            )
            .await?;
        if v.pointer("/list/0/id").is_none() {
            return Err("蓝奏云创建文件夹失败（未返回 id）".into());
        }
        Ok(())
    }

    pub async fn rename(&self, _parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        if e.is_dir {
            self.proved(
                "/file/folder/edit",
                reqwest::Method::POST,
                None,
                Some(json!({
                    "folderDesc": "",
                    "folderId": e.fid,
                    "folderName": new_name,
                })),
            )
            .await?;
        } else {
            self.proved(
                "/file/edit",
                reqwest::Method::POST,
                None,
                Some(json!({
                    "fileDesc": "",
                    "fileId": e.fid,
                    "fileName": new_name,
                })),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn move_entry(
        &self,
        _parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let (file_ids, folder_ids) = if e.is_dir {
            (String::new(), e.fid.clone())
        } else {
            (e.fid.clone(), String::new())
        };
        self.proved(
            "/file/folder/move",
            reqwest::Method::POST,
            None,
            Some(json!({
                "folderIds": folder_ids,
                "fileIds": file_ids,
                "targetId": self.resolve(dst_dir_fid),
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn copy(
        &self,
        _parent_fid: &str,
        _e: &Entry,
        _dst_dir_fid: &str,
    ) -> Result<(), String> {
        // 对齐 Go 版：无服务端复制原语，返回不支持
        Err("蓝奏云不支持复制操作（服务端无对应接口）".into())
    }

    pub async fn remove(&self, _parent_fid: &str, e: &Entry) -> Result<(), String> {
        let (file_ids, folder_ids) = if e.is_dir {
            (String::new(), e.fid.clone())
        } else {
            (e.fid.clone(), String::new())
        };
        self.proved(
            "/file/delete",
            reqwest::Method::POST,
            None,
            Some(json!({
                "folderIds": folder_ids,
                "fileIds": file_ids,
                "status": 0,
            })),
        )
        .await?;
        Ok(())
    }

    pub async fn put(&self, dst_dir_fid: &str, mut input: PutInput) -> Result<(), String> {
        use tokio::io::AsyncReadExt;
        let folder_id = self.resolve(dst_dir_fid);
        let mut buf = Vec::with_capacity(input.size as usize);
        let mut tmp = vec![0u8; 64 * 1024];
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
            if buf.len() as u64 > 1024 * 1024 * 1024 {
                return Err("单文件上传暂限 1GB".into());
            }
        }
        // md5 etag
        let mut h = Md5::new();
        h.update(&buf);
        let etag = hex::encode(h.finalize());
        let file_size_kib = ((buf.len() as i64) + 1023) / 1024;
        let account = self.account.lock().unwrap().clone();
        // 1. getUpToken
        let v = self
            .proved(
                "/7n/getUpToken",
                reqwest::Method::POST,
                None,
                Some(json!({
                    "fileId": "",
                    "fileName": input.name.clone(),
                    "fileSize": file_size_kib.max(1),
                    "folderId": folder_id,
                    "md5": etag,
                    "type": 1,
                })),
            )
            .await?;
        let up_token = v.get("upToken").map(value_to_string).unwrap_or_default();
        if up_token == "-1" {
            // 秒传成功
            return Ok(());
        }
        if up_token.is_empty() {
            return Err("蓝奏云上传失败（未返回 upToken）".into());
        }
        // 2. 七牛 key（对齐 Go 版生成的对象 key 格式）
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64;
        let now_secs = now_ms / 1000;
        // 用 civil 日历算年月日
        let days = now_secs.div_euclid(86400);
        let (y, m, d) = civil_from_days(days);
        let key = format!("disk/{:04}/{:02}/{:02}/{account}/{now_ms}.rar", y, m, d);
        let token = if (buf.len() as u64) <= PART_SIZE {
            let part = reqwest::multipart::Part::bytes(buf).file_name(input.name.clone());
            let form = reqwest::multipart::Form::new()
                .text("token", up_token.clone())
                .text("key", key.clone())
                .text("fname", input.name.clone())
                .part("file", part);
            let resp = self
                .http
                .post("https://upload.qiniup.com/")
                .multipart(form)
                .send()
                .await
                .map_err(|e| format!("蓝奏云上传失败: {e}"))?;
            let v: Value = resp.json().await.unwrap_or(json!({}));
            v.get("token").map(value_to_string).unwrap_or_default()
        } else {
            // 七牛分片上传
            let key_b64 = URL_SAFE.encode(key.as_bytes());
            let init_url = format!(
                "https://upload.qiniup.com/buckets/{}/objects/{}/uploads",
                self.conf.bucket, key_b64
            );
            let resp = self
                .http
                .post(&init_url)
                .header("Authorization", format!("UpToken {up_token}"))
                .send()
                .await
                .map_err(|e| format!("蓝奏云分片上传初始化失败: {e}"))?;
            let v: Value = resp.json().await.unwrap_or(json!({}));
            let upload_id = v.get("uploadId").map(value_to_string).unwrap_or_default();
            if upload_id.is_empty() {
                return Err("蓝奏云分片上传初始化失败（无 uploadId）".into());
            }
            let total = buf.len() as u64;
            let part_num = total.div_ceil(PART_SIZE) as u32;
            let mut parts: Vec<Value> = Vec::with_capacity(part_num as usize);
            for i in 1..=part_num {
                let start = (i as u64 - 1) * PART_SIZE;
                let end = std::cmp::min(start + PART_SIZE, total) as usize;
                let part_url = format!(
                    "https://upload.qiniup.com/buckets/{}/objects/{}/uploads/{}/{}",
                    self.conf.bucket, key_b64, upload_id, i
                );
                let resp = self
                    .http
                    .put(&part_url)
                    .header("Authorization", format!("UpToken {up_token}"))
                    .body(buf[start as usize..end].to_vec())
                    .send()
                    .await
                    .map_err(|e| format!("蓝奏云分片上传失败: {e}"))?;
                let v: Value = resp.json().await.unwrap_or(json!({}));
                let etag_i = v.get("etag").map(value_to_string).unwrap_or_default();
                parts.push(json!({"partNumber": i, "etag": etag_i}));
            }
            let complete_url = format!(
                "https://upload.qiniup.com/buckets/{}/objects/{}/uploads/{}",
                self.conf.bucket, key_b64, upload_id
            );
            let resp = self
                .http
                .post(&complete_url)
                .header("Authorization", format!("UpToken {up_token}"))
                .json(&json!({"fname": input.name, "parts": parts}))
                .send()
                .await
                .map_err(|e| format!("蓝奏云分片合并失败: {e}"))?;
            let v: Value = resp.json().await.unwrap_or(json!({}));
            v.get("token").map(value_to_string).unwrap_or_default()
        };
        if token.is_empty() {
            return Err("蓝奏云上传失败（未返回结果 token）".into());
        }
        // 3. 轮询上传结果（对齐 Go 版 maxUploadCommitRetries=10）
        let query = format!("tokenList={token}&tokenTime={}", http_date_time_now());
        for _ in 0..10 {
            let v = self
                .unproved(
                    "/7n/results",
                    reqwest::Method::POST,
                    Some(query.clone()),
                    None,
                )
                .await?;
            let status = v
                .pointer("/list/0/status")
                .and_then(|s| s.as_i64())
                .unwrap_or(0);
            if status == 1 {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
        Err("蓝奏云上传结果确认超时".into())
    }
}

fn value_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn app_token_query_value(token: &str) -> String {
    // 对齐 Go 版：appToken 里字面 ':' 保留，其余保留字符转义
    urlencode(token).replace("%3A", ":")
}

/// Go 版 tokenTime 格式：Mon Jan 02 2006 15:04:05 GMT-0700 (MST)
fn http_date_time_now() -> String {
    // 简化实现：使用 RFC1123 风格；服务端对该字段宽容（仅记录用）
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let days = now.div_euclid(86400);
    let secs = now.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let weekday = (days + 4) % 7; // 1970-01-01 是周四
    const W: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MO: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    format!(
        "{} {:02} {} {:04} {:02}:{:02}:{:02} GMT+0000",
        W[weekday as usize],
        d,
        MO[(m - 1) as usize],
        y,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 本地 datetime "2006-01-02 15:04:05" → 毫秒时间戳
fn parse_local_datetime_millis(s: &str) -> Option<i64> {
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let mo: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    let h: i64 = s.get(11..13)?.parse().ok()?;
    let mi: i64 = s.get(14..16)?.parse().ok()?;
    let sec: i64 = s.get(17..19)?.parse().ok()?;
    let z = days_from_civil(y, mo, d);
    Some((z * 86400 + h * 3600 + mi * 60 + sec) * 1000)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
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
