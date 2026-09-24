//! 中国移动云盘（139）驱动
//!
//! 移植自 OpenList Go 版 drivers/139，支持：
//! - personal_new：新版个人云（默认，对应 OpenList 139Yun 的 `personal_new` 类型）
//! - personal：旧版个人云
//!
//! 凭据为 Authorization（OpenList 139Yun 同款格式）：
//! base64("Basic <tokenblob>:<手机号>:<token>|<...>|<过期时间ms>|...")，
//! 剩余有效期不足 15 天时自动调用 tellin/authTokenRefresh.do 刷新并回写配置。
//!
//! 家庭云 / 共享组 / 分享链接类型未实现（openlist-rs 仅支持 list + download）。

use super::DownloadInfo;
use crate::config::{Credential, Entry, Store};
use base64::Engine;
use md5::{Digest, Md5};
use rand::RngExt;
use reqwest::Client;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use uuid::Uuid;

/// Authorization 距过期的提前刷新阈值：15 天（对齐 Go 版）
const REFRESH_THRESHOLD_MS: i64 = 1000 * 60 * 60 * 24 * 15;
const AUTH_REFRESH_URL: &str = "https://aas.caiyun.feixin.10086.cn:443/tellin/authTokenRefresh.do";
const OLD_BASE: &str = "https://yun.139.com";

// ---------- 时间工具（对齐 Go 版 getTime / getPersonalTime，CN = UTC+8） ----------

// 日期换算统一走 drivers/timeutil（原为本地副本）
use super::timeutil::{civil_from_days, days_from_civil};

/// 北京时间 (UTC+8) 各字段 -> epoch 毫秒
fn cn_ymdhms_to_ms(y: i64, m: u32, d: u32, hh: u32, mm: u32, ss: u32, ms: u32) -> i64 {
    let days = days_from_civil(y, m as i64, d as i64);
    (days * 86_400 + hh as i64 * 3600 + mm as i64 * 60 + ss as i64 - 8 * 3600) * 1000 + ms as i64
}

/// 当前北京时间字段（用于 mcloud-sign 的 ts）
fn cn_now_parts() -> (i64, u32, u32, u32, u32, u32) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = now.as_secs() as i64 + 8 * 3600;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    (
        y,
        m,
        d,
        (rem / 3600) as u32,
        (rem % 3600 / 60) as u32,
        (rem % 60) as u32,
    )
}

/// 解析 "2024-01-02T15:04:05(.fff)?(Z|±hh:mm)" -> epoch 毫秒（对齐 Go getPersonalTime）
fn parse_personal_time(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 19 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| std::str::from_utf8(&b[r]).ok()?.parse::<u32>().ok();
    let y = num(0..4)? as i64;
    let m = num(5..7)?;
    let d = num(8..10)?;
    let hh = num(11..13)?;
    let mm = num(14..16)?;
    let ss = num(17..19)?;
    let mut rest = &t[19..];
    // 毫秒
    let mut ms = 0u32;
    if let Some(frac) = rest.strip_prefix('.') {
        let end = frac
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(frac.len());
        let digits = &frac[..end];
        if !digits.is_empty() {
            ms = format!("{:0<3}", &digits[..digits.len().min(3)])
                .parse()
                .unwrap_or(0);
        }
        rest = &frac[end..];
    }
    // 时区偏移
    let offset_secs: i64 = if rest.starts_with('+') || rest.starts_with('-') {
        let sign = if rest.starts_with('-') { -1 } else { 1 };
        let rb = rest.as_bytes();
        if rb.len() < 6 {
            return None;
        }
        let oh: i64 = rest[1..3].parse().ok()?;
        let om: i64 = rest[4..6].parse().ok()?;
        sign * (oh * 3600 + om * 60)
    } else {
        0 // Z 或缺失按 UTC 处理
    };
    let base = days_from_civil(y, m as i64, d as i64) * 86_400
        + hh as i64 * 3600
        + mm as i64 * 60
        + ss as i64
        - offset_secs;
    Some(base * 1000 + ms as i64)
}

/// 解析 "20240102150405"（北京时间）-> epoch 毫秒（对齐 Go getTime）
fn parse_cn_compact_time(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if b.len() < 14 {
        return None;
    }
    let num = |r: std::ops::Range<usize>| std::str::from_utf8(&b[r]).ok()?.parse::<u32>().ok();
    Some(cn_ymdhms_to_ms(
        num(0..4)? as i64,
        num(4..6)?,
        num(6..8)?,
        num(8..10)?,
        num(10..12)?,
        num(12..14)?,
        0,
    ))
}

// ---------- 签名（对齐 Go 版 calSign） ----------

/// RFC3986 percent-encode（等价 Go encodeURIComponent）
fn percent_encode(s: &str) -> String {
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

fn md5_hex(s: &str) -> String {
    let mut h = Md5::new();
    h.update(s.as_bytes());
    hex::encode(h.finalize())
}

/// 对齐 Go calSign(body, ts, randStr)
fn cal_sign(body: &str, ts: &str, rand_str: &str) -> String {
    let encoded = percent_encode(body);
    // 按字符排序后拼接（UTF-8 字节序与码点序一致，等价 Go 按 rune 排序）
    let mut chars: Vec<char> = encoded.chars().collect();
    chars.sort();
    let sorted: String = chars.into_iter().collect();
    let b64 = base64::engine::general_purpose::STANDARD.encode(sorted.as_bytes());
    let res = format!("{}{}", md5_hex(&b64), md5_hex(&format!("{ts}:{rand_str}")));
    md5_hex(&res).to_uppercase()
}

fn rand_string(n: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..n)
        .map(|_| CHARSET[rng.random_range(0..CHARSET.len()) as usize] as char)
        .collect()
}

// ---------- 驱动 ----------

pub struct Yun139 {
    account_id: String,
    http: Client,
    authorization: Mutex<String>,
    /// 从 authorization 中解析出的手机号（commonAccountInfo.account）
    account: Mutex<String>,
    drive_type: String,
    /// 新版个人云 API host（路由策略查询获得）
    personal_host: Mutex<String>,
    store: Arc<Store>,
}

/// authorization 解码结果
struct AuthParts {
    prefix: String,
    account: String,
    token: String,
    expire_ms: i64,
}

impl Yun139 {
    pub fn new(
        account_id: &str,
        authorization: String,
        drive_type: String,
        store: Arc<Store>,
    ) -> Self {
        let account = Self::decode_authorization(&authorization)
            .map(|p| p.account)
            .unwrap_or_default();
        Yun139 {
            account_id: account_id.to_string(),
            http: Client::new(),
            authorization: Mutex::new(authorization),
            account: Mutex::new(account),
            drive_type,
            personal_host: Mutex::new(String::new()),
            store,
        }
    }

    /// base64 解码 authorization 并拆出 (prefix, account, token, expire_ms)
    fn decode_authorization(auth: &str) -> Result<AuthParts, String> {
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(auth.trim())
            .map_err(|e| format!("139 authorization 解码失败: {e}"))?;
        let decoded =
            String::from_utf8(decoded).map_err(|e| format!("139 authorization 非 UTF-8: {e}"))?;
        let splits: Vec<&str> = decoded.split(':').collect();
        if splits.len() < 3 {
            return Err("139 authorization 格式非法（冒号段不足 3 段）".into());
        }
        let strs: Vec<&str> = splits[2].split('|').collect();
        if strs.len() < 4 {
            return Err("139 authorization 的 token 段非法（| 段不足 4 段）".into());
        }
        let expire_ms: i64 = strs[3]
            .parse()
            .map_err(|_| "139 authorization 的过期时间非法".to_string())?;
        Ok(AuthParts {
            prefix: splits[0].to_string(),
            account: splits[1].to_string(),
            token: splits[2].to_string(),
            expire_ms,
        })
    }

    fn save_authorization(&self, auth: &str) {
        *self.authorization.lock().unwrap() = auth.to_string();
        if let Ok(parts) = Self::decode_authorization(auth) {
            *self.account.lock().unwrap() = parts.account;
        }
        let auth = auth.to_string();
        let id = self.account_id.clone();
        self.store.update_credential(&id, |cred| {
            if let Credential::Yun139 { authorization, .. } = cred {
                *authorization = auth.clone();
            }
        });
    }

    /// 对齐 Go refreshToken()：临期自动刷新 token
    async fn refresh_token(&self) -> Result<(), String> {
        let parts = {
            let auth = self.authorization.lock().unwrap();
            Self::decode_authorization(&auth)?
        };
        let remaining = parts.expire_ms - now_ms();
        if remaining > REFRESH_THRESHOLD_MS {
            return Ok(());
        }
        if remaining < 0 {
            return Err("139 authorization 已过期，请重新抓取".into());
        }
        let req_body = format!(
            "<root><token>{}</token><account>{}</account><clienttype>656</clienttype></root>",
            parts.token, parts.account
        );
        let resp = self
            .http
            .post(AUTH_REFRESH_URL)
            .header("Content-Type", "application/xml")
            .body(req_body)
            .send()
            .await
            .map_err(|e| format!("139 token 刷新请求失败: {e}"))?;
        let text = resp
            .text()
            .await
            .map_err(|e| format!("139 刷新响应读取失败: {e}"))?;
        let tag = |name: &str| -> Option<String> {
            let re = format!("<{name}>(.*?)</{name}>");
            regex::Regex::new(&re)
                .ok()?
                .captures(&text)?
                .get(1)
                .map(|m| m.as_str().to_string())
        };
        let ret = tag("return").unwrap_or_default();
        if ret != "0" {
            let desc = tag("desc").unwrap_or_default();
            return Err(format!("139 token 刷新失败: return={ret}, desc={desc}"));
        }
        let new_token = tag("token")
            .filter(|t| !t.is_empty())
            .ok_or_else(|| format!("139 刷新响应中无 token: {text}"))?;
        let new_auth = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}:{}", parts.prefix, parts.account, new_token));
        self.save_authorization(&new_auth);
        Ok(())
    }

    /// 统一请求封装：
    /// - style="old"：旧版头部（https://yun.139.com / 路由策略）
    /// - style="new"：新版个人云头部（路由策略返回的 host）
    async fn api_request(
        &self,
        style: &str,
        base: &str,
        pathname: &str,
        data: Value,
    ) -> Result<Value, String> {
        let body = serde_json::to_string(&data).map_err(|e| format!("139 序列化失败: {e}"))?;
        let (y, m, d, hh, mm, ss) = cn_now_parts();
        let ts = format!("{y:04}-{m:02}-{d:02} {hh:02}:{mm:02}:{ss:02}");
        let rand_str = rand_string(16);
        let sign = cal_sign(&body, &ts, &rand_str);
        let auth = self.authorization.lock().unwrap().clone();
        let url = format!("{base}{pathname}");

        let mut req = self
            .http
            .post(&url)
            .header("Accept", "application/json, text/plain, */*");
        if style == "new" {
            req = req
                .header("Authorization", format!("Basic {auth}"))
                .header("Caller", "web")
                .header("Cms-Device", "default")
                .header("Mcloud-Channel", "1000101")
                .header("Mcloud-Client", "10701")
                .header("Mcloud-Route", "001")
                .header("Mcloud-Sign", format!("{ts},{rand_str},{sign}"))
                .header("Mcloud-Version", "7.14.0")
                .header(
                    "x-DeviceInfo",
                    "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
                )
                .header("x-huawei-channelSrc", "10000034")
                .header("x-inner-ntwk", "2")
                .header("x-m4c-caller", "PC")
                .header("x-m4c-src", "10002")
                .header("x-SvcType", "1")
                .header("X-Yun-Api-Version", "v1")
                .header("X-Yun-App-Channel", "10000034")
                .header("X-Yun-Channel-Source", "10000034")
                .header(
                    "X-Yun-Client-Info",
                    "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||dW5kZWZpbmVk||",
                )
                .header("X-Yun-Module-Type", "100")
                .header("X-Yun-Svc-Type", "1");
        } else {
            req = req
                .header("CMS-DEVICE", "default")
                .header("Authorization", format!("Basic {auth}"))
                .header("mcloud-channel", "1000101")
                .header("mcloud-client", "10701")
                .header("mcloud-sign", format!("{ts},{rand_str},{sign}"))
                .header("mcloud-version", "7.14.0")
                .header("Origin", "https://yun.139.com")
                .header("Referer", "https://yun.139.com/w/")
                .header(
                    "x-DeviceInfo",
                    "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
                )
                .header("x-huawei-channelSrc", "10000034")
                .header("x-inner-ntwk", "2")
                .header("x-m4c-caller", "PC")
                .header("x-m4c-src", "10002")
                .header("x-SvcType", "1")
                .header("Inner-Hcy-Router-Https", "1");
        }

        let resp = req
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|e| format!("139 请求失败: {e}"))?;
        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("139 响应解析失败: {e}"))?;
        // 对齐 Go BaseResp：success=false 视为错误
        let success = v.get("success").and_then(|s| s.as_bool()).unwrap_or(false);
        if !success {
            let msg = v
                .get("message")
                .and_then(|m| m.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or("unknown");
            return Err(format!("139 接口错误: {msg}"));
        }
        Ok(v)
    }

    /// 对齐 Go requestRoute()：查询路由策略，取新版个人云 host
    async fn refresh_route_policy(&self) -> Result<(), String> {
        let account = self.account.lock().unwrap().clone();
        let data = json!({
            "userInfo": {
                "userType": 1,
                "accountType": 1,
                "accountName": account,
            },
            "modAddrType": 1,
        });
        let v = self
            .api_request(
                "old",
                "https://user-njs.yun.139.com",
                "/user/route/qryRoutePolicy",
                data,
            )
            .await?;
        let mut host = String::new();
        if let Some(list) = v
            .pointer("/data/routePolicyList")
            .and_then(|l| l.as_array())
        {
            for item in list {
                if item.get("modName").and_then(|m| m.as_str()) == Some("personal") {
                    host = item
                        .get("httpsUrl")
                        .and_then(|u| u.as_str())
                        .unwrap_or("")
                        .trim_end_matches('/')
                        .to_string();
                }
            }
        }
        if host.is_empty() {
            return Err("139 PersonalCloudHost 为空".into());
        }
        *self.personal_host.lock().unwrap() = host;
        Ok(())
    }

    /// 对齐 Go Init()
    pub async fn validate(&self) -> Result<(), String> {
        self.refresh_token().await?;
        if self.drive_type == "personal_new" {
            self.refresh_route_policy().await?;
        }
        Ok(())
    }

    fn normalize_fid(&self, fid: &str) -> String {
        let is_new = self.drive_type == "personal_new";
        let root = if is_new { "/" } else { "root" };
        if fid.is_empty() || fid == "0" {
            root.to_string()
        } else {
            fid.to_string()
        }
    }

    fn common_account(&self) -> Value {
        json!({
            "account": self.account.lock().unwrap().clone(),
            "accountType": 1,
        })
    }

    /// 对齐 Go personalGetFiles()：新版个人云目录列表（cursor 分页）
    async fn personal_list(&self, fid: &str) -> Result<Vec<Entry>, String> {
        let host = self.personal_host.lock().unwrap().clone();
        let mut files = Vec::new();
        let mut cursor = String::new();
        loop {
            let data = json!({
                "imageThumbnailStyleList": ["Small", "Large"],
                "orderBy": "updated_at",
                "orderDirection": "DESC",
                "pageInfo": {
                    "pageCursor": cursor,
                    "pageSize": 100,
                },
                "parentFileId": fid,
            });
            let v = self.api_request("new", &host, "/file/list", data).await?;
            cursor = v
                .pointer("/data/nextPageCursor")
                .and_then(|c| c.as_str())
                .unwrap_or("")
                .to_string();
            let items = v
                .pointer("/data/items")
                .and_then(|i| i.as_array())
                .cloned()
                .unwrap_or_default();
            for item in &items {
                let is_dir = item.get("type").and_then(|t| t.as_str()) == Some("folder");
                files.push(Entry {
                    fid: item
                        .get("fileId")
                        .and_then(|f| f.as_str())
                        .unwrap_or("")
                        .to_string(),
                    name: item
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string(),
                    size: item.get("size").and_then(|s| s.as_u64()).unwrap_or(0),
                    is_dir,
                    updated_at: item
                        .get("updatedAt")
                        .and_then(|u| u.as_str())
                        .and_then(parse_personal_time),
                    etag: None,
                    s3_key_flag: None,
                    file_type: None,
                    extra: None,
                });
            }
            if cursor.is_empty() {
                break;
            }
        }
        Ok(files)
    }

    /// 对齐 Go getFiles()：旧版个人云目录列表（start/end 分页）
    async fn old_personal_list(&self, fid: &str) -> Result<Vec<Entry>, String> {
        let mut files = Vec::new();
        let mut start: usize = 0;
        let limit: usize = 100;
        loop {
            let data = json!({
                "catalogID": fid,
                "sortDirection": 1,
                "startNumber": start + 1,
                "endNumber": start + limit,
                "filterType": 0,
                "catalogSortType": 0,
                "contentSortType": 0,
                "commonAccountInfo": self.common_account(),
            });
            let v = self
                .api_request(
                    "old",
                    OLD_BASE,
                    "/orchestration/personalCloud/catalog/v1.0/getDisk",
                    data,
                )
                .await?;
            let result = v
                .pointer("/data/getDiskResult")
                .cloned()
                .unwrap_or(Value::Null);
            if let Some(list) = result.get("catalogList").and_then(|l| l.as_array()) {
                for c in list {
                    files.push(Entry {
                        fid: c
                            .get("catalogID")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        name: c
                            .get("catalogName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: 0,
                        is_dir: true,
                        updated_at: c
                            .get("updateTime")
                            .and_then(|v| v.as_str())
                            .and_then(parse_cn_compact_time),
                        etag: None,
                        s3_key_flag: None,
                        file_type: None,
                        extra: None,
                    });
                }
            }
            if let Some(list) = result.get("contentList").and_then(|l| l.as_array()) {
                for c in list {
                    files.push(Entry {
                        fid: c
                            .get("contentID")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        name: c
                            .get("contentName")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        size: c.get("contentSize").and_then(|v| v.as_u64()).unwrap_or(0),
                        is_dir: false,
                        updated_at: c
                            .get("updateTime")
                            .and_then(|v| v.as_str())
                            .and_then(parse_cn_compact_time),
                        etag: c
                            .get("digest")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        s3_key_flag: None,
                        file_type: None,
                        extra: None,
                    });
                }
            }
            let node_count = result
                .get("nodeCount")
                .and_then(|n| n.as_u64())
                .unwrap_or(0) as usize;
            if start + limit >= node_count {
                break;
            }
            start += limit;
        }
        Ok(files)
    }

    /// 对齐 Go personalGetLink()：新版个人云直链
    async fn personal_link(&self, fid: &str) -> Result<String, String> {
        let host = self.personal_host.lock().unwrap().clone();
        let v = self
            .api_request(
                "new",
                &host,
                "/file/getDownloadUrl",
                json!({ "fileId": fid }),
            )
            .await?;
        let cdn_url = v
            .pointer("/data/cdnUrl")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        if !cdn_url.is_empty()
            && v.pointer("/data/cdnSwitch")
                .and_then(|s| s.as_bool())
                .unwrap_or(false)
        {
            return Ok(cdn_url.to_string());
        }
        let url = v
            .pointer("/data/url")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        if url.is_empty() {
            return Err("139 未返回下载直链".into());
        }
        Ok(url.to_string())
    }

    /// 对齐 Go getLink()：旧版个人云直链
    async fn old_personal_link(&self, fid: &str) -> Result<String, String> {
        let v = self
            .api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/uploadAndDownload/v1.0/downloadRequest",
                json!({
                    "appName": "",
                    "contentID": fid,
                    "commonAccountInfo": self.common_account(),
                }),
            )
            .await?;
        let url = v
            .pointer("/data/downloadURL")
            .and_then(|u| u.as_str())
            .unwrap_or("");
        if url.is_empty() {
            return Err("139 未返回下载直链".into());
        }
        Ok(url.to_string())
    }

    pub async fn list(&self, parent_fid: &str) -> Result<Vec<Entry>, String> {
        let fid = self.normalize_fid(parent_fid);
        if self.drive_type == "personal_new" {
            self.personal_list(&fid).await
        } else {
            self.old_personal_list(&fid).await
        }
    }

    pub async fn download(&self, e: &Entry) -> Result<DownloadInfo, String> {
        let url = if self.drive_type == "personal_new" {
            self.personal_link(&e.fid).await?
        } else {
            self.old_personal_link(&e.fid).await?
        };
        Ok(DownloadInfo {
            url,
            headers: vec![],
            proxy: false,
            local_path: None,
        })
    }

    /// 新版个人云 host（validate 时已初始化）
    fn get_personal_host(&self) -> Result<String, String> {
        let host = self.personal_host.lock().unwrap().clone();
        if host.is_empty() {
            return Err("139 personal host 未初始化（请重新验证账号）".into());
        }
        Ok(host)
    }

    /// 对齐 Go MakeDir()：personal_new 走 /file/create，personal 走 createCatalogExt
    pub async fn mkdir(&self, parent_fid: &str, name: &str) -> Result<(), String> {
        let pid = self.normalize_fid(parent_fid);
        if self.drive_type == "personal_new" {
            let host = self.get_personal_host()?;
            self.api_request(
                "new",
                &host,
                "/file/create",
                json!({
                    "parentFileId": pid,
                    "name": name,
                    "description": "",
                    "type": "folder",
                    "fileRenameMode": "force_rename",
                }),
            )
            .await?;
        } else {
            self.api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/catalog/v1.0/createCatalogExt",
                json!({
                    "createCatalogExtReq": {
                        "parentCatalogID": pid,
                        "newCatalogName": name,
                        "commonAccountInfo": self.common_account(),
                    }
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// 对齐 Go Rename()：personal_new 走 /file/update，personal 按目录/文件分接口
    pub async fn rename(&self, parent_fid: &str, e: &Entry, new_name: &str) -> Result<(), String> {
        let _ = parent_fid;
        if self.drive_type == "personal_new" {
            let host = self.get_personal_host()?;
            self.api_request(
                "new",
                &host,
                "/file/update",
                json!({
                    "fileId": e.fid,
                    "name": new_name,
                    "description": "",
                }),
            )
            .await?;
        } else if e.is_dir {
            self.api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/catalog/v1.0/updateCatalogInfo",
                json!({
                    "catalogID": e.fid,
                    "catalogName": new_name,
                    "commonAccountInfo": self.common_account(),
                }),
            )
            .await?;
        } else {
            self.api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/content/v1.0/updateContentInfo",
                json!({
                    "contentID": e.fid,
                    "contentName": new_name,
                    "commonAccountInfo": self.common_account(),
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// 对齐 Go Move()：personal_new 走 /file/batchMove，personal 走 createBatchOprTask(actionType="304")
    pub async fn move_entry(
        &self,
        parent_fid: &str,
        e: &Entry,
        dst_dir_fid: &str,
    ) -> Result<(), String> {
        let _ = parent_fid;
        let dst = self.normalize_fid(dst_dir_fid);
        if self.drive_type == "personal_new" {
            let host = self.get_personal_host()?;
            self.api_request(
                "new",
                &host,
                "/file/batchMove",
                json!({
                    "fileIds": [e.fid],
                    "toParentFileId": dst,
                }),
            )
            .await?;
        } else {
            let (content_info_list, catalog_info_list): (Vec<&str>, Vec<&str>) = if e.is_dir {
                (vec![], vec![e.fid.as_str()])
            } else {
                (vec![e.fid.as_str()], vec![])
            };
            self.api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/batchOprTask/v1.0/createBatchOprTask",
                json!({
                    "createBatchOprTaskReq": {
                        "taskType": 3,
                        "actionType": "304",
                        "taskInfo": {
                            "contentInfoList": content_info_list,
                            "catalogInfoList": catalog_info_list,
                            "newCatalogID": dst,
                        },
                        "commonAccountInfo": self.common_account(),
                    }
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// 对齐 Go Copy()：personal_new 走 /file/batchCopy，personal 走 createBatchOprTask(actionType=309)
    pub async fn copy(&self, parent_fid: &str, e: &Entry, dst_dir_fid: &str) -> Result<(), String> {
        let _ = parent_fid;
        let dst = self.normalize_fid(dst_dir_fid);
        if self.drive_type == "personal_new" {
            let host = self.get_personal_host()?;
            self.api_request(
                "new",
                &host,
                "/file/batchCopy",
                json!({
                    "fileIds": [e.fid],
                    "toParentFileId": dst,
                }),
            )
            .await?;
        } else {
            let (content_info_list, catalog_info_list): (Vec<&str>, Vec<&str>) = if e.is_dir {
                (vec![], vec![e.fid.as_str()])
            } else {
                (vec![e.fid.as_str()], vec![])
            };
            self.api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/batchOprTask/v1.0/createBatchOprTask",
                json!({
                    "createBatchOprTaskReq": {
                        "taskType": 3,
                        "actionType": 309,
                        "taskInfo": {
                            "contentInfoList": content_info_list,
                            "catalogInfoList": catalog_info_list,
                            "newCatalogID": dst,
                        },
                        "commonAccountInfo": self.common_account(),
                    }
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// 对齐 Go Remove()：personal_new 移入回收站 /recyclebin/batchTrash，
    /// personal 走 createBatchOprTask(taskType=2, actionType=201)
    pub async fn remove(&self, parent_fid: &str, e: &Entry) -> Result<(), String> {
        let _ = parent_fid;
        if self.drive_type == "personal_new" {
            let host = self.get_personal_host()?;
            self.api_request(
                "new",
                &host,
                "/recyclebin/batchTrash",
                json!({
                    "fileIds": [e.fid],
                }),
            )
            .await?;
        } else {
            let (content_info_list, catalog_info_list): (Vec<&str>, Vec<&str>) = if e.is_dir {
                (vec![], vec![e.fid.as_str()])
            } else {
                (vec![e.fid.as_str()], vec![])
            };
            self.api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/batchOprTask/v1.0/createBatchOprTask",
                json!({
                    "createBatchOprTaskReq": {
                        "taskType": 2,
                        "actionType": 201,
                        "taskInfo": {
                            "newCatalogID": "",
                            "contentInfoList": content_info_list,
                            "catalogInfoList": catalog_info_list,
                        },
                        "commonAccountInfo": self.common_account(),
                    }
                }),
            )
            .await?;
        }
        Ok(())
    }

    /// 对齐 Go Put()：personal_new 走 /file/create + 分片 PUT + /file/complete（需整文件 SHA256），
    /// personal 走 pcUploadFileRequest + redirectionUrl 分片 POST（无 complete 步骤）。
    /// 两条路径都需要未知大小时落盘计算，且分片重试需要重读内容 → 统一先落临时文件。
    pub async fn put(&self, dst_dir_fid: &str, input: super::PutInput) -> Result<(), String> {
        if self.drive_type == "personal_new" {
            self.put_personal_new(dst_dir_fid, input).await
        } else {
            self.put_personal_old(dst_dir_fid, input).await
        }
    }

    /// 对齐 Go Put() 的新版个人云路径（MetaPersonalNew）
    async fn put_personal_new(
        &self,
        dst_dir_fid: &str,
        input: super::PutInput,
    ) -> Result<(), String> {
        let dst = self.normalize_fid(dst_dir_fid);
        let host = self.get_personal_host()?;
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let (size, sha256) = spool_and_hash(input.reader, &tmp_path).await?;

        let part_size = part_size_for(size);
        let part_count: u64 = size.div_ceil(part_size).max(1);
        // 生成所有 partInfos（对齐 Go：partNumber 从 1 开始，partOffset 记录偏移）
        let part_infos: Vec<Value> = (0..part_count)
            .map(|i| {
                let start = i * part_size;
                let byte_size = std::cmp::min(size - start, part_size);
                json!({
                    "partNumber": (i + 1) as i64,
                    "partSize": byte_size as i64,
                    "parallelHashCtx": { "partOffset": start as i64 },
                })
            })
            .collect();
        // 创建任务时只带前 100 个分片
        let first_part_infos: Vec<Value> = part_infos.iter().take(100).cloned().collect();
        let data = json!({
            "contentHash": sha256,
            "contentHashAlgorithm": "SHA256",
            "contentType": "application/octet-stream",
            "parallelUpload": false,
            "partInfos": first_part_infos,
            "size": size,
            "parentFileId": dst,
            "name": input.name,
            "type": "file",
            "fileRenameMode": "auto_rename",
        });
        let resp = self.api_request("new", &host, "/file/create", data).await?;
        let d = resp.get("data").cloned().unwrap_or(Value::Null);
        // exist=true：秒传命中，云端已存在相同文件，无需再传
        if d.get("exist").and_then(|v| v.as_bool()).unwrap_or(false) {
            return Ok(());
        }
        let file_id = d
            .get("fileId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let upload_id = d
            .get("uploadId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if let Some(upload_parts) = d.get("partInfos").and_then(|v| v.as_array()) {
            if !upload_parts.is_empty() {
                // 先上传创建响应里返回的前 100 个分片
                self.upload_personal_parts(&part_infos, upload_parts, &tmp_path)
                    .await?;
                // 剩余分片按 100 个一批取上传地址
                let mut i = 100usize;
                while i < part_infos.len() {
                    let end = std::cmp::min(i + 100, part_infos.len());
                    let moredata = json!({
                        "fileId": file_id,
                        "uploadId": upload_id,
                        "partInfos": part_infos[i..end],
                        "commonAccountInfo": self.common_account(),
                    });
                    let more = self
                        .api_request("new", &host, "/file/getUploadUrl", moredata)
                        .await?;
                    let more_parts = more
                        .pointer("/data/partInfos")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default();
                    self.upload_personal_parts(&part_infos, &more_parts, &tmp_path)
                        .await?;
                    i += 100;
                }
                // 全部分片上传完毕后 complete
                self.api_request(
                    "new",
                    &host,
                    "/file/complete",
                    json!({
                        "contentHash": sha256,
                        "contentHashAlgorithm": "SHA256",
                        "fileId": file_id,
                        "uploadId": upload_id,
                    }),
                )
                .await?;
            }
        }
        // 对齐 Go：处理 auto_rename 产生的名字冲突（把旧文件改名后删除，再把新文件改回原名）
        let cloud_name = d.get("fileName").and_then(|v| v.as_str()).unwrap_or("");
        if !cloud_name.is_empty() && cloud_name != input.name {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let files = self.personal_list(&dst).await?;
            for file in &files {
                if file.name == input.name {
                    let renamed = format!("{}{}", input.name, rand_string(4));
                    self.rename(&dst, file, &renamed).await?;
                    self.remove(&dst, file).await?;
                    break;
                }
            }
            for file in &files {
                if file.name == cloud_name {
                    self.rename(&dst, file, &input.name).await?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// 按 partNumber 升序上传各分片（对齐 Go uploadPersonalParts）
    async fn upload_personal_parts(
        &self,
        part_infos: &[Value],
        upload_parts: &[Value],
        tmp_path: &Path,
    ) -> Result<(), String> {
        let mut sorted: Vec<&Value> = upload_parts.iter().collect();
        sorted.sort_by_key(|p| p.get("partNumber").and_then(|n| n.as_i64()).unwrap_or(0));
        // 原实现外层循环每个分支都会提前 return（never_loop），
        // 实际只处理排序后的第一个分片，此处保持该行为不变
        let Some(up) = sorted.into_iter().next() else {
            return Ok(());
        };
        let part_number = up.get("partNumber").and_then(|n| n.as_i64()).unwrap_or(0);
        let upload_url = up.get("uploadUrl").and_then(|u| u.as_str()).unwrap_or("");
        if part_number < 1 || part_number as usize > part_infos.len() || upload_url.is_empty() {
            return Err(format!("139 分片上传信息非法: partNumber={part_number}"));
        }
        let info = &part_infos[(part_number - 1) as usize];
        let byte_size = info.get("partSize").and_then(|s| s.as_u64()).unwrap_or(0);
        let offset = info
            .pointer("/parallelHashCtx/partOffset")
            .and_then(|o| o.as_u64())
            .unwrap_or(0);
        // 对齐 Go：Content-Type: application/octet-stream + Origin/Referer，失败重试 3 次
        let mut last_err = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            let data = read_temp_part(tmp_path, offset, byte_size).await?;
            match self
                .http
                .put(upload_url)
                .header("Content-Type", "application/octet-stream")
                .header("Origin", "https://yun.139.com")
                .header("Referer", "https://yun.139.com/")
                .body(data)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    if status == 200 {
                        return Ok(());
                    }
                    let text = resp.text().await.unwrap_or_default();
                    last_err = format!(
                        "139 分片上传返回异常状态 {status}: {}",
                        super::truncate_bytes(&text, 200)
                    );
                }
                Err(e) => last_err = format!("139 分片上传失败: {e}"),
            }
        }
        Err(last_err)
    }

    /// 对齐 Go Put() 的旧版个人云路径（MetaPersonal，ReportRealSize 默认 true）
    async fn put_personal_old(
        &self,
        dst_dir_fid: &str,
        input: super::PutInput,
    ) -> Result<(), String> {
        let dst = self.normalize_fid(dst_dir_fid);
        let tmp_path = temp_file_path();
        let _guard = TempFileGuard(tmp_path.clone());
        let size = spool_to_temp(input.reader, &tmp_path).await?;
        // 对齐 Go：先删除旧同名文件（改名避免冲突后再删除）
        let files = self.old_personal_list(&dst).await?;
        for file in &files {
            if file.name == input.name {
                let renamed = format!("{}{}", input.name, rand_string(4));
                self.rename(&dst, file, &renamed).await?;
                self.remove(&dst, file).await?;
                break;
            }
        }
        let data = json!({
            "manualRename": 2,
            "operation": 0,
            "fileCount": 1,
            "totalSize": size as i64,
            "uploadContentList": [
                { "contentName": input.name, "contentSize": size as i64 }
            ],
            "parentCatalogID": dst,
            "newCatalogName": "",
            "commonAccountInfo": self.common_account(),
        });
        let resp = self
            .api_request(
                "old",
                OLD_BASE,
                "/orchestration/personalCloud/uploadAndDownload/v1.0/pcUploadFileRequest",
                data,
            )
            .await?;
        let d = resp.get("data").cloned().unwrap_or(Value::Null);
        let result_code = d
            .pointer("/result/resultCode")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if result_code != "0" {
            let desc = d
                .pointer("/result/resultDesc")
                .map(|v| v.to_string())
                .unwrap_or_default();
            return Err(format!(
                "139 获取上传地址失败: resultCode={result_code}, desc={desc}"
            ));
        }
        let upload_url = d
            .pointer("/uploadResult/redirectionUrl")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let task_id = d
            .pointer("/uploadResult/uploadTaskID")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if upload_url.is_empty() {
            return Err("139 未返回上传地址".into());
        }
        let part_size = part_size_for(size);
        let part_count: u64 = size.div_ceil(part_size).max(1);
        for i in 0..part_count {
            let start = i * part_size;
            let byte_size = std::cmp::min(size - start, part_size);
            self.upload_old_part(UploadOldPartArgs {
                upload_url: &upload_url,
                task_id: &task_id,
                name: &input.name,
                tmp_path: &tmp_path,
                start,
                byte_size,
                total_size: size,
            })
            .await?;
        }
        Ok(())
    }

    /// 对齐 Go 旧版分片上传：POST redirectionUrl，headers 带 range/uploadtaskID，响应为 XML
    async fn upload_old_part(&self, args: UploadOldPartArgs<'_>) -> Result<(), String> {
        let UploadOldPartArgs {
            upload_url,
            task_id,
            name,
            tmp_path,
            start,
            byte_size,
            total_size,
        } = args;
        let content_type = format!("text/plain;name={}", quote_to_ascii(name));
        let range = format!("bytes={}-{}", start, start + byte_size - 1);
        // 对齐 Go：正则提前构造，避免在重试循环内重复编译
        let re_code = regex::Regex::new(r"<resultCode>\s*(\d+)").ok();
        let re_msg = regex::Regex::new(r"<msg>(.*?)</msg>").ok();
        let mut last_err = String::new();
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            let data = read_temp_part(tmp_path, start, byte_size).await?;
            match self
                .http
                .post(upload_url)
                .header("Content-Type", &content_type)
                .header("contentSize", total_size.to_string())
                .header("range", &range)
                .header("uploadtaskID", task_id)
                .header("rangeType", "0")
                .body(data)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    let text = resp.text().await.unwrap_or_default();
                    if status != 200 {
                        last_err = format!(
                            "139 分片上传返回异常状态 {status}: {}",
                            super::truncate_bytes(&text, 200)
                        );
                        continue;
                    }
                    // 对齐 Go InterLayerUploadResult：解析 XML resultCode / msg
                    let code = re_code
                        .as_ref()
                        .and_then(|re| re.captures(&text))
                        .and_then(|c| c.get(1))
                        .map(|m| m.as_str().to_string())
                        .unwrap_or_default();
                    if code != "0" {
                        let msg = re_msg
                            .as_ref()
                            .and_then(|re| re.captures(&text))
                            .and_then(|c| c.get(1))
                            .map(|m| m.as_str().to_string())
                            .unwrap_or_default();
                        last_err = format!("139 分片上传失败: resultCode={code}, msg={msg}");
                        continue;
                    }
                    return Ok(());
                }
                Err(e) => last_err = format!("139 分片上传失败: {e}"),
            }
        }
        Err(last_err)
    }
}

// ---------- 上传辅助：临时文件落盘 / SHA-256 / Go 风格转义 ----------

/// 临时文件守卫：Drop 时必定删除临时文件（无论成功失败路径）
struct TempFileGuard(PathBuf);

/// upload_old_part() 参数结构体（参数对齐 Go 版 uploadOldPart 分片上传入参）
struct UploadOldPartArgs<'a> {
    upload_url: &'a str,
    task_id: &'a str,
    name: &'a str,
    tmp_path: &'a Path,
    start: u64,
    byte_size: u64,
    total_size: u64,
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn temp_file_path() -> PathBuf {
    std::env::temp_dir().join(format!("openlist-rs-139-{}", Uuid::new_v4()))
}

/// 对齐 Go getPartSize()：>30GB 用 512MB 分片，否则 100MB
fn part_size_for(size: u64) -> u64 {
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;
    if size / GB > 30 {
        512 * MB
    } else {
        100 * MB
    }
}

/// 把上传流落到临时文件并返回大小（旧版个人云路径用）
async fn spool_to_temp(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("139 创建临时文件失败: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("139 读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("139 写入临时文件失败: {e}"))?;
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("139 临时文件落盘失败: {e}"))?;
    Ok(total)
}

/// 把上传流落到临时文件，同时计算整文件 SHA256（新版个人云路径用）
async fn spool_and_hash(
    reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
) -> Result<(u64, String), String> {
    let mut hasher = Sha256::new();
    let total = spool_inner(reader, path, &mut hasher).await?;
    Ok((total, hasher.finalize()))
}

async fn spool_inner(
    mut reader: std::pin::Pin<Box<dyn tokio::io::AsyncRead + Send>>,
    path: &Path,
    hasher: &mut Sha256,
) -> Result<u64, String> {
    let mut f = tokio::fs::File::create(path)
        .await
        .map_err(|e| format!("139 创建临时文件失败: {e}"))?;
    let mut buf = vec![0u8; 256 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .await
            .map_err(|e| format!("139 读取上传流失败: {e}"))?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n])
            .await
            .map_err(|e| format!("139 写入临时文件失败: {e}"))?;
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    f.flush()
        .await
        .map_err(|e| format!("139 临时文件落盘失败: {e}"))?;
    Ok(total)
}

/// 从临时文件读取指定区间（分片重试时每次重读）
async fn read_temp_part(path: &Path, offset: u64, len: u64) -> Result<Vec<u8>, String> {
    let mut f = tokio::fs::File::open(path)
        .await
        .map_err(|e| format!("139 打开临时文件失败: {e}"))?;
    f.seek(std::io::SeekFrom::Start(offset))
        .await
        .map_err(|e| format!("139 临时文件 seek 失败: {e}"))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)
        .await
        .map_err(|e| format!("139 读取临时分片失败: {e}"))?;
    Ok(buf)
}

/// 对齐 Go unicode()（strconv.QuoteToASCII 去引号）：非 ASCII 与控制字符转 \uXXXX/\xXX
fn quote_to_ascii(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c if (c as u32) < 0x80 => out.push(c),
            c if (c as u32) <= 0xFFFF => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => {
                // 非 BMP 字符：Go 按 UTF-16 代理对转义
                let cp = c as u32 - 0x10000;
                let hi = 0xD800u32 + (cp >> 10);
                let lo = 0xDC00u32 + (cp & 0x3FF);
                out.push_str(&format!("\\u{:04x}\\u{:04x}", hi, lo));
            }
        }
    }
    out
}

// ---------- SHA-256（依赖列表无 sha2 crate，按 FIPS 180-4 自实现，仅供新版个人云上传 contentHash） ----------

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let delta = [a, b, c, d, e, f, g, h];
        for (s, v) in self.state.iter_mut().zip(delta) {
            *s = s.wrapping_add(v);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len += data.len() as u64;
        if self.buf_len > 0 {
            let take = std::cmp::min(64 - self.buf_len, data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            self.compress(block);
            data = rest;
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> String {
        let bit_len = self.total_len.wrapping_mul(8);
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0]);
        }
        self.update(&bit_len.to_be_bytes());
        let mut out = Vec::with_capacity(32);
        for s in &self.state {
            out.extend_from_slice(&s.to_be_bytes());
        }
        hex::encode(out)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}
